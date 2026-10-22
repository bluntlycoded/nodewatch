"""
nodewatch-server: the master node.

    nodewatch-server                 run (first run serves the setup wizard)
    nodewatch-server add-node        join code + install commands for a new node
    nodewatch-server licence <key>   install a new or renewed licence
    nodewatch-server status          licence, address, node count
    nodewatch-server install         install as a service (Linux systemd / Windows)
    nodewatch-server uninstall       remove the service, keep the data
    nodewatch-server --version

One process supervises everything: PostgreSQL as a child, the ingest API
over HTTPS, the scheduler that replaces pg_cron, alert delivery, and the
built-in probe runner.
"""

import argparse
import asyncio
import logging
import os
import signal
import sys
import threading
import time
import webbrowser
from pathlib import Path

import psycopg

from . import license as lic
from . import migrate, ops, pki
from .config import Store, default_data_dir
from .pg import EmbeddedPostgres, install_binaries

VERSION = "0.2.0"
USER_AGENT = f"nodewatch-server/{VERSION}"

log = logging.getLogger("nodewatch")


def _repo_paths() -> None:
    """Running from source: make api/ and probe/ importable like the bundle does."""
    if hasattr(sys, "_MEIPASS"):
        return
    root = Path(__file__).resolve().parents[2]
    for sub in ("api", "probe"):
        p = str(root / sub)
        if p not in sys.path:
            sys.path.insert(0, p)


def _setup_logging(data_dir: Path) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)
    for h in (logging.StreamHandler(sys.stdout), logging.FileHandler(data_dir / "server.log")):
        h.setFormatter(fmt)
        root.addHandler(h)


class Master:

    def __init__(self, data_dir: Path):
        self.store = Store(data_dir)
        self.cfg = self.store.load()
        self.pki = pki.PKI(data_dir)
        self.pg: EmbeddedPostgres | None = None
        self.servers = []
        self.stopping = False

    # ------------------------------------------------------------ database

    def start_database(self) -> str:
        bin_dir = install_binaries(self.store.dir)
        self.bin_dir = bin_dir
        self.pg = EmbeddedPostgres(bin_dir, self.store.dir, self.cfg.pg_port, self.cfg.pg_password)
        self.pg.init()
        self.pg.start()
        with psycopg.connect(self.pg.url()) as conn:
            n = migrate.migrate(conn)
        if n:
            log.info("applied %d migration(s)", n)
        return self.pg.url()

    def stop_database(self) -> None:
        pg, self.pg = self.pg, None
        if pg:
            try:
                pg.stop()
                log.info("postgres stopped")
            except Exception as e:
                log.warning("postgres did not stop cleanly: %s", e)

    # ------------------------------------------------------------ tls

    def ensure_certificate(self) -> None:
        self.pki.ensure_ca()
        wanted = [self.cfg.public_address] + pki.local_addresses()
        if not self.pki.server_cert.exists() or self._cert_missing(self.cfg.public_address):
            self.pki.issue_server_cert(wanted)

    def _cert_missing(self, address: str) -> bool:
        if not address:
            return False
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(self.pki.server_cert.read_bytes())
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = {str(v) for v in san.get_values_for_type(x509.DNSName)}
        names |= {str(v) for v in san.get_values_for_type(x509.IPAddress)}
        return address.strip("[]") not in names

    # ------------------------------------------------------------ setup

    def complete_setup(self, form: dict, licence: lic.License) -> None:
        with psycopg.connect(self.pg.url()) as conn:
            ops.create_admin(conn, form["email"], form["password"],
                             form.get("org") or licence.customer)
            probe_token = ops.issue_token(conn, kind="probe_runner", label="built-in probe runner",
                                          hours=24 * 7)
        (self.store.dir / "licence.key").write_text(licence.raw + "\n", encoding="utf-8")
        self.cfg.public_address = form["address"]
        self.cfg.probe_token = probe_token
        if form.get("smtp_host"):
            self.cfg.smtp = {"host": form["smtp_host"], "port": int(form.get("smtp_port") or 587),
                             "username": form.get("smtp_user", ""), "password": form.get("smtp_password", ""),
                             "from": form.get("smtp_from") or form.get("smtp_user", ""),
                             "security": "starttls"}
        self.cfg.setup_complete = True
        self.store.save(self.cfg)
        self.pki.issue_server_cert([self.cfg.public_address] + pki.local_addresses())
        log.info("setup complete for %s; restarting to serve %s", licence.customer, self.cfg.public_url)
        threading.Timer(1.5, self.restart).start()

    def restart(self) -> None:
        """Re-exec in place so the new certificate and full app load cleanly."""
        self.stop_database()
        logging.shutdown()
        if hasattr(sys, "_MEIPASS"):
            os.execv(sys.executable, [sys.executable] + sys.argv[1:])
        # From source, argv[0] is server/nodewatch-server.py.
        os.execv(sys.executable, [sys.executable] + sys.argv)

    def licence(self) -> lic.License | None:
        path = self.store.dir / "licence.key"
        if not path.exists():
            return None
        return lic.parse(path.read_text(encoding="utf-8"))

    # ------------------------------------------------------------ run

    def run(self, open_browser: bool) -> None:
        self.ensure_certificate()
        db_url = self.start_database()

        try:
            if not self.cfg.setup_complete:
                self._serve_setup(open_browser)
            else:
                self._serve(db_url)
        finally:
            self.stop_database()

    def _servers(self, app, internal_app=None):
        import uvicorn
        servers = [uvicorn.Server(uvicorn.Config(
            app, host="0.0.0.0", port=self.cfg.https_port,
            ssl_certfile=str(self.pki.server_cert), ssl_keyfile=str(self.pki.server_key),
            proxy_headers=False, server_header=False, log_level="warning", log_config=None))]
        if internal_app is not None:
            servers.append(uvicorn.Server(uvicorn.Config(
                internal_app, host="127.0.0.1", port=self.cfg.internal_port,
                proxy_headers=False, server_header=False, log_level="warning", log_config=None)))
        return servers

    def _run_servers(self, servers) -> None:
        self.servers = servers
        if self.stopping:
            return

        async def main():
            await asyncio.gather(*(s.serve() for s in servers))
        asyncio.run(main())
        if not self.stopping and any(not s.started for s in servers):
            # uvicorn logs why (now into server.log) and returns; make it a
            # failure so a service manager restarts the master.
            raise RuntimeError(f"the web server could not start - is port {self.cfg.https_port} "
                               "already in use by another program?")

    def request_stop(self) -> None:
        """From another thread (the Windows service's stop handler): shut the
        web servers down; run()'s cleanup then stops PostgREST and Postgres."""
        self.stopping = True
        for s in self.servers:
            s.should_exit = True

    def _serve_setup(self, open_browser: bool) -> None:
        from . import web
        suggestions = [a for a in pki.local_addresses() if a not in ("localhost", "127.0.0.1")]
        app = web.build_setup_app(self.cfg, self.store, self.complete_setup, suggestions or ["localhost"])
        host = suggestions[0] if suggestions else "localhost"
        url = f"https://{host}:{self.cfg.https_port}/setup"
        banner = (f"\n  nodewatch master is not set up yet.\n"
                  f"  Open   {url}\n"
                  f"  Setup code: {self.cfg.setup_code}\n")
        print(banner, flush=True)
        log.info("waiting for setup at %s (setup code is in the console and %s)",
                 url, self.store.path)
        if open_browser:
            threading.Timer(1.5, lambda: webbrowser.open(f"https://localhost:{self.cfg.https_port}/setup")).start()
        self._run_servers(self._servers(app))

    # ------------------------------------------------------------ licence

    def licence_limits(self) -> tuple[int, str]:
        """(max nodes, reason new nodes are refused or "")."""
        try:
            licence = self.licence()
        except lic.LicenseError as e:
            return 0, f"the licence on this master is not valid: {e}"
        if not licence:
            return 0, "this master has no licence"
        if licence.state == "expired":
            return licence.nodes, (f"the licence for this master expired on {licence.expires}; "
                                   "install a new licence to add nodes")
        return licence.nodes, ""

    def licence_summary(self) -> dict | None:
        try:
            licence = self.licence()
        except lic.LicenseError as e:
            return {"state": "invalid", "error": str(e)}
        return licence.summary() if licence else None

    def read_only(self) -> bool:
        s = self.licence_summary()
        return not s or s.get("state") in ("expired", "invalid")

    def _apply_licence(self, api_module) -> None:
        """Re-read the licence (it may have expired, or been replaced) and
        push its limits into the running API."""
        nodes, closed = self.licence_limits()
        api_module.MAX_NODES = nodes
        api_module.ENROLL_CLOSED = closed
        s = self.licence_summary() or {}
        if s.get("state") in ("grace", "expired", "invalid"):
            log.warning("licence is %s: %s", s.get("state"), closed or f"{s.get('days_left')} days")

    # ------------------------------------------------------------ serve

    def _serve(self, db_url: str) -> None:
        from types import SimpleNamespace

        from . import web
        from .alerts import AlertSender
        from .auth import Auth
        from .downloads import Agents
        from .postgrest import PostgREST, ensure_role
        from .scheduler import Scheduler

        s = self.licence_summary()
        if s:
            log.info("licence: %s", s)

        nodes, closed = self.licence_limits()
        os.environ.update({
            "NW_DATABASE_URL": db_url,
            "NW_JWT_SECRET": self.cfg.jwt_secret,
            "NW_REQUIRE_TOKEN": "true",
            "NW_REQUIRE_NODE_KEY": "true",
            "NW_TRUST_PROXY": "false",
            "NW_MAX_NODES": str(nodes),
            "NW_ENROLL_CLOSED": closed,
            # Dashboard sessions, checked by the OAuth connect routes.
            "NW_SUPABASE_JWT_SECRET": self.cfg.session_secret,
            "NW_API_URL": self.cfg.public_url,
            "NW_DASHBOARD_URL": self.cfg.public_url + "/",
            # Built-in probe runner, over loopback HTTP (see Config.internal_port).
            "NW_INGEST_URL": f"http://127.0.0.1:{self.cfg.internal_port}",
            "NW_PROBE_ENROLL_TOKEN": self.cfg.probe_token,
            "NW_PROBE_STATE_PATH": str(self.store.dir / "probe-runner.json"),
        })

        import app as api_module          # api/app.py

        ensure_role(db_url, self.cfg.pgrst_password)
        self.postgrest = PostgREST(self.bin_dir, self.store.dir, self.cfg.pg_port, self.cfg.pgrst_password,
                                   self.cfg.session_secret, self.cfg.pgrst_port)
        if not self.postgrest.available:
            raise RuntimeError(f"PostgREST is missing from this build ({self.postgrest.exe})")
        self.postgrest.start()

        sched = Scheduler(db_url)
        sender = AlertSender(db_url, self.cfg.smtp, USER_AGENT)
        sched.add_python_job("nodewatch-send-alerts", "* * * * *", sender.drain)
        sched.add_python_job("nodewatch-licence", "7 * * * *", lambda: self._apply_licence(api_module))
        sched.start()

        threading.Thread(target=self._probe_runner, name="probe-runner", daemon=True).start()

        ctx = SimpleNamespace(
            auth=Auth(db_url, self.cfg.session_secret),
            agents=Agents(self.store.dir),
            ca_fingerprint=self.pki.ca_fingerprint(),
            licence_summary=self.licence_summary,
            read_only=self.read_only,
            postgrest_url=f"http://127.0.0.1:{self.cfg.pgrst_port}",
        )
        log.info("agent builds available: %s", ", ".join(ctx.agents.index) or "none")
        app = web.build_main_app(api_module.app, self.cfg, self.store, ctx)
        log.info("serving %s", self.cfg.public_url)
        try:
            # The loopback port serves the same app: the built-in probe
            # runner uses it, and so can a browser on this machine.
            self._run_servers(self._servers(app, internal_app=app))
        finally:
            self.postgrest.stop()

    def _probe_runner(self) -> None:
        time.sleep(3)                     # let the API bind first
        try:
            import prober                 # probe/prober.py
            prober.main()
        except Exception:
            log.exception("built-in probe runner stopped")


# ---------------------------------------------------------------- commands

def join_code(url: str, token: str, fingerprint: str, site: str | None = None) -> str:
    """Same format as agent/joining.py's decode()."""
    import base64
    import json
    p = {"u": url, "t": token, "f": fingerprint}
    if site:
        p["s"] = site
    raw = json.dumps(p, separators=(",", ":")).encode()
    return "NWJ1-" + base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def install_commands(url: str, code: str, agents: dict) -> dict:
    """Download-verify-join one-liners, as the dashboard shows them."""
    out = {}
    for plat, tool in (("linux", "sha256sum"), ("macos", "shasum -a 256")):
        shas = [v["sha256"] for k, v in agents.items() if k.startswith(plat + "-")]
        if shas:
            out[plat] = (f"curl -fsSk -o nodewatch-agent {url}/download/agent/{plat}-$(uname -m) \\\n"
                         f"  && echo '{' '.join(shas)}' | grep -qw \"$({tool} nodewatch-agent | cut -c1-64)\" \\\n"
                         f"  && chmod +x nodewatch-agent && sudo ./nodewatch-agent join {code} \\\n"
                         f"  || echo 'download failed or checksum mismatch'")
    shas = [v["sha256"] for k, v in agents.items() if k.startswith("windows-")]
    if shas:
        quoted = ",".join(f"'{x}'" for x in shas)
        out["windows"] = (f"curl.exe -fsSk -o nodewatch-agent.exe {url}/download/agent/windows-x64\n"
                          f"if ((Get-FileHash nodewatch-agent.exe).Hash -in @({quoted})) "
                          f"{{ .\\nodewatch-agent.exe join {code} }} else {{ 'checksum mismatch - not running it' }}")
    return out


def cmd_add_node(m: Master, label: str | None, hours: int, site: str | None) -> None:
    from .downloads import Agents
    if not m.cfg.setup_complete:
        sys.exit("finish setup first")
    nodes, closed = m.licence_limits()
    if closed:
        sys.exit(closed)
    with psycopg.connect(f"postgresql://nodewatch:{m.cfg.pg_password}@127.0.0.1:{m.cfg.pg_port}/nodewatch") as conn:
        if nodes and ops.node_count(conn) >= nodes:
            sys.exit(f"the licence allows {nodes} nodes and all are in use")
        token = ops.issue_token(conn, "agent", label, hours)
    code = join_code(m.cfg.public_url, token, m.pki.ca_fingerprint(), site)
    print(f"\nJoin code (single use, valid {hours}h):\n\n  {code}\n")
    print("Paste it into the agent's window, or run on the new node:\n")
    cmds = install_commands(m.cfg.public_url, code, Agents(m.store.dir).public())
    for plat, cmd in cmds.items():
        print(f"  {plat}:\n    " + cmd.replace("\n", "\n    ") + "\n")
    if not cmds:
        print("  (this master has no agent builds bundled - download nodewatch-agent from the release page,\n"
              f"   then run: sudo nodewatch-agent join {code})\n")


def cmd_licence(m: Master, key: str) -> None:
    try:
        licence = lic.parse(key)
    except lic.LicenseError as e:
        sys.exit(str(e))
    if licence.state == "expired":
        sys.exit(f"that licence expired on {licence.expires}")
    path = m.store.dir / "licence.key"
    path.write_text(licence.raw + "\n", encoding="utf-8")
    print(f"installed: {licence.customer}, {licence.nodes} nodes, until {licence.expires}. "
          "A running master picks it up within the hour, or at its next restart.")


def cmd_status(m: Master) -> None:
    print(f"data directory : {m.store.dir}")
    print(f"set up         : {'yes' if m.cfg.setup_complete else 'no (setup code ' + m.cfg.setup_code + ')'}")
    print(f"agents use     : {m.cfg.public_url}")
    try:
        licence = m.licence()
    except lic.LicenseError as e:
        licence = None
        print(f"licence        : INVALID - {e}")
    if licence:
        s = licence.summary()
        print(f"licence        : {s['customer']}, {s['nodes']} nodes, {s['state']} until {s['expires']}")
    if m.pki.ca_cert.exists():
        print(f"CA fingerprint : {m.pki.ca_fingerprint()}")


SYSTEMD_UNIT = """[Unit]
Description=nodewatch master
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nodewatch
Group=nodewatch
Environment=NW_SERVER_DATA={data}
ExecStart={exe} --no-browser
Restart=always
RestartSec=5
KillMode=mixed
TimeoutStopSec=60
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths={data}

[Install]
WantedBy=multi-user.target
"""


def cmd_install(data_dir: Path) -> None:
    import shutil
    import subprocess
    if not sys.platform.startswith("linux"):
        sys.exit("install currently supports Linux (systemd); Windows service support is in the installer phase")
    if os.geteuid() != 0:
        sys.exit("run install as root")
    if not hasattr(sys, "_MEIPASS"):
        sys.exit("install is for the packaged nodewatch-server binary")
    exe = Path("/opt/nodewatch-server/nodewatch-server")
    exe.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(sys.executable, exe)
    os.chmod(exe, 0o755)
    if subprocess.run(["id", "nodewatch"], capture_output=True).returncode != 0:
        subprocess.run(["useradd", "--system", "--home-dir", str(data_dir), "--shell", "/usr/sbin/nologin",
                        "nodewatch"], check=True)
    data_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["chown", "-R", "nodewatch:nodewatch", str(data_dir)], check=True)
    os.chmod(data_dir, 0o700)
    unit = Path("/etc/systemd/system/nodewatch-server.service")
    unit.write_text(SYSTEMD_UNIT.format(exe=exe, data=data_dir))
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "--now", "nodewatch-server"], check=True)
    time.sleep(6)
    print("installed and started. The setup code is in:  journalctl -u nodewatch-server")
    subprocess.run(["journalctl", "-u", "nodewatch-server", "-n", "12", "--no-pager"])


def cmd_selfcheck(data_dir: Path) -> int:
    """
    Proves this build is complete on this OS without setting anything up:
    the bundled PostgreSQL and PostgREST unpack and run, the dashboard and
    migrations are inside, and every module the master and the probe
    runner load lazily can be imported. CI runs it on every platform.
    """
    import importlib
    import subprocess
    from .downloads import Agents
    from .pg import EXE
    from .web import dashboard_dir

    failed = 0

    def check(name, fn):
        nonlocal failed
        try:
            print(f"ok    {name:<22} {fn()}")
        except Exception as e:
            failed += 1
            print(f"FAIL  {name:<22} {type(e).__name__}: {e}")

    def version(exe):
        out = subprocess.run([str(exe), "--version"], capture_output=True, text=True, timeout=30)
        if out.returncode != 0:
            raise RuntimeError((out.stderr or out.stdout).strip()[:200])
        return out.stdout.strip().splitlines()[0]

    bin_dir = install_binaries(data_dir)
    check("postgres", lambda: version(bin_dir / f"postgres{EXE}"))
    check("postgrest", lambda: version(bin_dir / f"postgrest{EXE}"))
    check("dashboard", lambda: f"{(dashboard_dir() / 'index.html').stat().st_size} bytes, "
                               f"{len(list((dashboard_dir() / 'vendor').glob('*.js')))} vendored scripts")
    check("migrations", lambda: f"{len(migrate.migration_files())} files")
    check("licence key", lambda: f"public key loaded ({type(lic.public_key()).__name__})")
    check("agent builds", lambda: ", ".join(Agents(data_dir).index) or "none bundled")
    mods = ["uvicorn", "fastapi", "psycopg", "psycopg_pool", "jwt", "cryptography", "requests",
            "pymysql", "pymssql", "oracledb", "github_app", "slack_app", "teams_app"]
    if sys.platform == "win32":
        mods += ["win32serviceutil", "servicemanager", "win32timezone"]
    for mod in mods:
        check(f"import {mod}", lambda m=mod: getattr(importlib.import_module(m), "__version__", "loaded"))
    # Thin mode is what the probe runner uses; it needs cryptography at runtime.
    check("oracledb thin mode", lambda: str(importlib.import_module("oracledb").is_thin_mode()))
    print(f"nodewatch-server {VERSION} selfcheck: {'all ok' if not failed else f'{failed} failed'}")
    return 1 if failed else 0


def cmd_uninstall() -> None:
    import subprocess
    if not sys.platform.startswith("linux"):
        sys.exit("uninstall supports Linux (systemd) and Windows")
    if os.geteuid() != 0:
        sys.exit("run uninstall as root")
    subprocess.run(["systemctl", "disable", "--now", "nodewatch-server"], check=False)
    Path("/etc/systemd/system/nodewatch-server.service").unlink(missing_ok=True)
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    print("service removed; the data directory is kept.")


def main() -> None:
    ap = argparse.ArgumentParser(prog="nodewatch-server", description="nodewatch master node")
    ap.add_argument("--version", action="store_true")
    ap.add_argument("--data", type=Path, default=None, help="data directory")
    ap.add_argument("--no-browser", action="store_true", help="do not open the setup page")
    sub = ap.add_subparsers(dest="cmd")
    a = sub.add_parser("add-node", help="issue a single-use token for a new node")
    a.add_argument("--label")
    a.add_argument("--hours", type=int, default=24)
    a.add_argument("--site")
    lp = sub.add_parser("licence", help="install a new or renewed licence key")
    lp.add_argument("key")
    sub.add_parser("status")
    sub.add_parser("install", help="install as a service (Linux systemd, Windows service)")
    sub.add_parser("uninstall", help="remove the service; keeps the data directory")
    sub.add_parser("service-run", help=argparse.SUPPRESS)
    sub.add_parser("selfcheck", help="check this build's bundled components run on this OS")
    args = ap.parse_args()

    if args.version:
        print(f"nodewatch-server {VERSION}")
        return

    data_dir = args.data or default_data_dir()
    if args.data:
        os.environ["NW_SERVER_DATA"] = str(args.data)

    if args.cmd == "install":
        if sys.platform == "win32":
            from . import winservice
            winservice.install(data_dir)
        else:
            cmd_install(data_dir)
        return
    if args.cmd == "uninstall":
        if sys.platform == "win32":
            from . import winservice
            winservice.uninstall()
        else:
            cmd_uninstall()
        return
    if args.cmd == "selfcheck":
        _repo_paths()
        sys.exit(cmd_selfcheck(data_dir))
    if args.cmd == "service-run":
        from . import winservice
        _repo_paths()

        def make_master():
            _setup_logging(data_dir)
            log.info("nodewatch-server %s starting as a Windows service, data in %s", VERSION, data_dir)
            return Master(data_dir)
        winservice.dispatch(make_master)
        return

    if sys.platform != "win32" and os.geteuid() == 0:
        sys.exit("PostgreSQL will not run as root. Use `nodewatch-server install` to run it as a "
                 "service user, or run it as an ordinary user.")

    _repo_paths()
    m = Master(data_dir)

    if args.cmd == "add-node":
        cmd_add_node(m, args.label, args.hours, args.site)
        return
    if args.cmd == "licence":
        cmd_licence(m, args.key)
        return
    if args.cmd == "status":
        cmd_status(m)
        return

    _setup_logging(data_dir)
    log.info("nodewatch-server %s starting, data in %s", VERSION, data_dir)

    def on_term(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, on_term)
    if hasattr(signal, "SIGBREAK"):
        # Windows: Ctrl+Break (and CTRL_BREAK_EVENT from a supervisor) is the
        # one stop request a console process can receive. Without a handler
        # Windows ends the process outright and PostgreSQL is left running,
        # holding its port.
        signal.signal(signal.SIGBREAK, on_term)
    try:
        m.run(open_browser=not args.no_browser and sys.stdin is not None and sys.stdin.isatty())
    except KeyboardInterrupt:
        pass
    finally:
        m.stop_database()


if __name__ == "__main__":
    main()
