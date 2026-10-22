#!/usr/bin/env python3
"""
nodewatch agent
Collects host metrics, listening ports and auth events; buffers locally;
ships to the nodewatch ingest API.

Identity: AWS IMDSv2 signed instance identity document (PKCS7).
No shared secrets on the host.
"""

import json
import logging
import os
import socket
import sqlite3
import sys
import time
from pathlib import Path

import psutil
import requests

import checks
import identity as ident_mod
import nwconfig
import osdetect
import inventory

# ---------------------------------------------------------------- config

# agent.json (written by `join` / the GUI) fills in whatever NW_* the
# environment does not set; see nwconfig.py.
nwconfig.apply()

INGEST_URL = os.environ.get(
    "NW_INGEST_URL",
    "http://100.64.0.1:8000"
).rstrip("/")

# Where the buffer lives when NW_STATE_DIR is not set: the same place each
# installer has always used, so a binary started by hand lands there too.
STATE_DIR = Path(
    os.environ.get(
        "NW_STATE_DIR",
        str(nwconfig.default_state_dir())
    )
)

# Optional single-use enrolment token, issued from the dashboard.
# Required when the server is configured with NW_REQUIRE_TOKEN=true.
ENROLL_TOKEN = os.environ.get(
    "NW_ENROLL_TOKEN",
    ""
)

AGENT_VERSION = "0.5.0"

# Identifies the agent to anything inspecting outbound traffic - a proxy,
# an EDR's network module, or an admin reading a packet capture - rather
# than leaving every request looking like an anonymous python-requests
# client, which is itself a pattern some tools flag.
USER_AGENT = f"nodewatch-agent/{AGENT_VERSION}"

DB_PATH = STATE_DIR / "buffer.db"

HEARTBEAT_INTERVAL = 15
PORTS_INTERVAL = 60
AUTH_INTERVAL = 30
CHECKS_INTERVAL = 120
USERS_INTERVAL = 60
INTERFACES_INTERVAL = 60
APPS_INTERVAL = 60
FIM_INTERVAL = 300
PACKAGES_INTERVAL = 21600
FLUSH_INTERVAL = 15

MAX_BUFFER_ROWS = 10_000
FLUSH_BATCH = 40
HTTP_TIMEOUT = 45

IMDS = "http://169.254.169.254"

# Every request to the master goes through this session. When the node
# joined a self-hosted master, NW_CA_FILE is that master's own CA (pinned by
# fingerprint at join time) and is the only CA trusted for these requests;
# otherwise the system trust store applies as before.
HTTP = requests.Session()
HTTP.headers["User-Agent"] = USER_AGENT
HTTP.verify = os.environ.get("NW_CA_FILE") or True

STATUS_PATH = nwconfig.status_path()


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

log = logging.getLogger("nodewatch")


def write_status(**changes) -> None:
    """
    status.json: what the GUI and `nodewatch-agent status` show. No secrets,
    so it is world-readable while the rest of the state directory is not.
    """
    try:
        cur = json.loads(STATUS_PATH.read_text())
    except (OSError, ValueError):
        cur = {}
    cur.update(changes, ingest_url=INGEST_URL, version=AGENT_VERSION,
               pid=os.getpid(), updated_at=time.time())
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        tmp = STATUS_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(cur, indent=2))
        if sys.platform != "win32":
            os.chmod(tmp, 0o644)
        os.replace(tmp, STATUS_PATH)
    except OSError as e:
        log.debug("could not write status: %s", e)


def read_status() -> dict:
    try:
        return json.loads(STATUS_PATH.read_text())
    except (OSError, ValueError):
        return {}


# ---------------------------------------------------------------- buffer

class Buffer:
    """Durable local queue. Survives restarts and network outages."""

    def __init__(self, path: Path):
        path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        self.db = sqlite3.connect(
            str(path),
            isolation_level=None
        )

        self.db.execute(
            "PRAGMA journal_mode=WAL"
        )

        self.db.execute(
            "CREATE TABLE IF NOT EXISTS queue ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " kind TEXT NOT NULL,"
            " payload TEXT NOT NULL,"
            " ts REAL NOT NULL)"
        )

        self.db.execute(
            "CREATE TABLE IF NOT EXISTS meta "
            "(k TEXT PRIMARY KEY, v TEXT)"
        )

    def push(
        self,
        kind: str,
        payload: dict
    ) -> None:

        self.db.execute(
            "INSERT INTO queue "
            "(kind, payload, ts) "
            "VALUES (?, ?, ?)",
            (
                kind,
                json.dumps(payload),
                time.time()
            ),
        )

        # Drop oldest rows if the buffer exceeds the cap.
        self.db.execute(
            "DELETE FROM queue WHERE id NOT IN ("
            " SELECT id FROM queue "
            " ORDER BY id DESC "
            " LIMIT ?)",
            (MAX_BUFFER_ROWS,),
        )

    def peek(
        self,
        limit: int = FLUSH_BATCH
    ):
        rows = self.db.execute(
            "SELECT id, kind, payload, ts "
            "FROM queue "
            "ORDER BY id "
            "LIMIT ?",
            (limit,),
        ).fetchall()

        return [
            {
                "id": r[0],
                "kind": r[1],
                "payload": json.loads(r[2]),
                "ts": r[3],
            }
            for r in rows
        ]

    def drop(self, ids) -> None:

        if not ids:
            return

        marks = ",".join(
            "?" * len(ids)
        )

        self.db.execute(
            f"DELETE FROM queue "
            f"WHERE id IN ({marks})",
            ids,
        )

    def depth(self) -> int:

        return self.db.execute(
            "SELECT COUNT(*) FROM queue"
        ).fetchone()[0]

    def get_meta(
        self,
        key: str,
        default=None
    ):

        row = self.db.execute(
            "SELECT v FROM meta "
            "WHERE k = ?",
            (key,),
        ).fetchone()

        return row[0] if row else default

    def set_meta(
        self,
        key: str,
        value: str
    ) -> None:

        self.db.execute(
            "INSERT INTO meta (k, v) "
            "VALUES (?, ?) "
            "ON CONFLICT(k) "
            "DO UPDATE SET v = excluded.v",
            (
                key,
                value
            ),
        )


# ---------------------------------------------------------------- identity

def imds_token() -> str:

    r = requests.put(
        f"{IMDS}/latest/api/token",
        headers={
            "X-aws-ec2-metadata-token-ttl-seconds": "300"
        },
        timeout=2,
    )

    r.raise_for_status()

    return r.text


def instance_identity():

    """
    Returns:
        (
            instance_id,
            parsed document,
            raw document text,
            signed pkcs7
        )

    The raw text matters because AWS signs those exact bytes.
    """

    tok = imds_token()

    h = {
        "X-aws-ec2-metadata-token": tok
    }

    resp = requests.get(
        f"{IMDS}/latest/dynamic/"
        "instance-identity/document",
        headers=h,
        timeout=2,
    )

    doc_raw = resp.text

    doc = resp.json()

    pkcs7 = requests.get(
        f"{IMDS}/latest/dynamic/"
        "instance-identity/pkcs7",
        headers=h,
        timeout=2,
    ).text

    return (
        doc["instanceId"],
        doc,
        doc_raw,
        pkcs7,
    )


class Session:
    """Holds the short-lived JWT and re-enrolls when it expires."""

    def __init__(self):

        self.token = None
        self.instance_id = None

    def enroll(self) -> bool:

        """
        Provider-agnostic.

        On AWS/GCP/Azure the cloud vouches for the host.
        On anything else the enrolment token is the only evidence.
        """

        try:

            ident = ident_mod.collect_identity()

        except Exception as e:

            log.error(
                "could not establish identity: %s",
                e
            )

            return False

        # Only a node that has never enrolled needs the token; afterwards
        # its signing key is the credential and the spent token is gone.
        if (
            ident.get("provider") == "generic"
            and not ENROLL_TOKEN
            and not read_status().get("agent_id")
        ):

            log.error(
                "this host has no cloud identity, "
                "so NW_ENROLL_TOKEN is required. "
                "Issue one from the dashboard."
            )

            write_status(last_error="no enrolment token - join a master first",
                         last_error_at=time.time())

            return False

        import nodekey

        key = nodekey.load_or_create(STATE_DIR)
        claimed = ident.get("machine_id") or ident.get("node_id") or ""

        body = {
            "identity": ident,
            "enroll_token": (
                ENROLL_TOKEN
                if ENROLL_TOKEN
                else None
            ),
            "hostname": socket.gethostname(),
            "agent_version": AGENT_VERSION,
            "os": platform_string(),
            "node_key": nodekey.public_hex(key),
            "key_proof": nodekey.proof(key, claimed),
        }

        try:

            r = HTTP.post(
                f"{INGEST_URL}/v1/enroll",
                json=body,
                timeout=HTTP_TIMEOUT,
            )

        except Exception as e:

            log.warning(
                "enroll request failed: %s",
                e
            )

            write_status(last_error=f"cannot reach the master: {e}"[:300],
                         last_error_at=time.time())

            return False

        if r.status_code != 200:

            log.error(
                "enroll rejected (%s): %s",
                r.status_code,
                r.text[:200]
            )

            write_status(last_error=f"enrolment refused ({r.status_code}): {r.text[:200]}",
                         last_error_at=time.time())

            return False

        data = r.json()

        self.token = data["token"]

        self.instance_id = data.get(
            "agent_id"
        )

        log.info(
            "enrolled as %s [%s, proof=%s]",
            ident.get("node_id"),
            data.get("provider"),
            data.get("identity_proof"),
        )

        write_status(agent_id=self.instance_id, last_enroll_at=time.time(),
                     last_error=None)

        nwconfig.forget_token()

        return True

    def headers(self):

        return {
            "Authorization": (
                f"Bearer {self.token}"
            ),
            "User-Agent": USER_AGENT,
        }


def platform_string() -> str:

    return osdetect.os_label()


# ---------------------------------------------------------------- collectors

def collect_metrics() -> dict:
    """
    Collect basic host metrics.

    IMPORTANT:
    os.getloadavg() is not available on Windows.

    Linux/macOS:
        load1 = actual 1-minute load average

    Windows:
        load1 = None

    This keeps the API schema stable while allowing the agent
    to run correctly on Windows.
    """

    # --------------------------------------------------------
    # CPU
    # --------------------------------------------------------

    cpu_pct = psutil.cpu_percent(
        interval=1
    )

    # --------------------------------------------------------
    # Memory
    # --------------------------------------------------------

    mem_pct = psutil.virtual_memory().percent

    # --------------------------------------------------------
    # Disk
    # --------------------------------------------------------
    #
    # "/" works on Linux/macOS.
    # Windows is safer using the system drive.

    if sys.platform.startswith("win"):

        system_drive = os.environ.get(
            "SystemDrive",
            "C:"
        )

        disk_path = system_drive + "\\"

    else:

        disk_path = "/"

    try:

        disk_pct = psutil.disk_usage(
            disk_path
        ).percent

    except Exception as e:

        log.warning(
            "disk usage collection failed: %s",
            e
        )

        disk_pct = 0.0

    # --------------------------------------------------------
    # Load average
    # --------------------------------------------------------

    load1 = None

    if hasattr(os, "getloadavg"):

        try:

            load1 = os.getloadavg()[0]

        except (
            AttributeError,
            OSError
        ):

            load1 = None

    # --------------------------------------------------------
    # Uptime
    # --------------------------------------------------------

    try:

        uptime_s = int(
            time.time()
            - psutil.boot_time()
        )

    except Exception as e:

        log.warning(
            "uptime collection failed: %s",
            e
        )

        uptime_s = 0

    # --------------------------------------------------------
    # Process count
    # --------------------------------------------------------

    try:

        proc_count = len(
            psutil.pids()
        )

    except Exception as e:

        log.warning(
            "process count collection failed: %s",
            e
        )

        proc_count = 0

    return {
        "cpu_pct": cpu_pct,
        "mem_pct": mem_pct,
        "disk_pct": disk_pct,
        "load1": load1,
        "uptime_s": uptime_s,
        "proc_count": proc_count,
    }


def collect_ports() -> list:
    """
    Full snapshot of listening sockets.
    The server diffs it.
    """

    out = []

    try:

        connections = psutil.net_connections(
            kind="inet"
        )

    except Exception as e:

        log.warning(
            "network connection collection failed: %s",
            e
        )

        return out

    for c in connections:

        if c.status != psutil.CONN_LISTEN:
            continue

        proc = None

        if c.pid:

            try:

                proc = psutil.Process(
                    c.pid
                ).name()

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied
            ):

                proc = None

        try:

            bind = c.laddr.ip
            port = c.laddr.port

        except Exception:

            continue

        out.append(
            {
                "port": port,
                "proto": (
                    "tcp"
                    if c.type == socket.SOCK_STREAM
                    else "udp"
                ),
                "bind_addr": bind,
                "external": bind in (
                    "0.0.0.0",
                    "::"
                ),
                "pid": c.pid,
                "process": proc,
            }
        )

    return out


def collect_auth_events(buf):
    """
    Sign-in events, however this platform records them.
    """

    try:

        return osdetect.collect_auth_events(
            buf
        )

    except Exception as e:

        log.warning(
            "auth collection failed: %s",
            e
        )

        return []


# ---------------------------------------------------------------- shipping

def flush(
    buf: Buffer,
    sess: Session
) -> None:

    batch = buf.peek()

    if not batch:
        return

    if (
        not sess.token
        and not sess.enroll()
    ):

        return

    body = {
        "events": [
            {
                "kind": b["kind"],
                "ts": b["ts"],
                "data": b["payload"],
            }
            for b in batch
        ]
    }

    try:

        r = HTTP.post(
            f"{INGEST_URL}/v1/ingest",
            json=body,
            headers=sess.headers(),
            timeout=HTTP_TIMEOUT,
        )

    except Exception as e:

        log.warning(
            "ship failed (%s), %d queued",
            e,
            buf.depth()
        )

        write_status(last_error=f"cannot reach the master: {e}"[:300],
                     last_error_at=time.time(), queued=buf.depth())

        return

    if r.status_code == 401:

        log.info(
            "token expired, re-enrolling"
        )

        sess.token = None

        return

    if r.status_code >= 400:

        log.error(
            "ingest rejected (%s): %s",
            r.status_code,
            r.text[:200]
        )

        write_status(last_error=f"master rejected data ({r.status_code})",
                     last_error_at=time.time())

        return

    buf.drop(
        [
            b["id"]
            for b in batch
        ]
    )

    log.info(
        "shipped %d events, %d still queued",
        len(batch),
        buf.depth()
    )

    write_status(last_ship_at=time.time(), last_error=None, queued=buf.depth())


# ---------------------------------------------------------------- main

def main():

    # Under a service there is no console to read, and the GUI shows this
    # file's tail; stdout still goes to journald / launchd's log as before.
    from logging.handlers import RotatingFileHandler

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    fh = RotatingFileHandler(STATE_DIR / "agent.log", maxBytes=5_000_000, backupCount=2)
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logging.getLogger().addHandler(fh)
    if sys.platform == "darwin" and not sys.stderr.isatty():
        # Under launchd, stderr is launchd.log, which nothing rotates: one
        # copy of every line, forever. agent.log (rotated above) has them;
        # launchd.log keeps only what bypasses logging, such as a crash.
        root = logging.getLogger()
        for h in list(root.handlers):
            if type(h) is logging.StreamHandler:
                root.removeHandler(h)

    log.info("nodewatch-agent %s reporting to %s", AGENT_VERSION, INGEST_URL)

    buf = Buffer(
        DB_PATH
    )

    sess = Session()

    sess.enroll()

    next_run = {
        "heartbeat": 0.0,
        "ports": 0.0,
        "auth": 0.0,
        "checks": 0.0,
        "users": 0.0,
        "interfaces": 0.0,
        "apps": 0.0,
        "fim": 0.0,
        "packages": 0.0,
        "flush": 0.0,
    }

    while True:

        now = time.time()

        # ----------------------------------------------------
        # heartbeat
        # ----------------------------------------------------

        if now >= next_run["heartbeat"]:

            try:

                metrics = collect_metrics()

                buf.push(
                    "heartbeat",
                    metrics
                )

            except Exception as e:

                log.exception(
                    "heartbeat collection failed: %s",
                    e
                )

            next_run["heartbeat"] = (
                now
                + HEARTBEAT_INTERVAL
            )

        # ----------------------------------------------------
        # ports
        # ----------------------------------------------------

        if now >= next_run["ports"]:

            try:

                buf.push(
                    "ports",
                    {
                        "listening":
                            collect_ports()
                    }
                )

            except Exception as e:

                log.exception(
                    "port collection failed: %s",
                    e
                )

            next_run["ports"] = (
                now
                + PORTS_INTERVAL
            )

        # ----------------------------------------------------
        # auth
        # ----------------------------------------------------

        if now >= next_run["auth"]:

            try:

                for ev in collect_auth_events(
                    buf
                ):

                    buf.push(
                        "auth",
                        ev
                    )

            except Exception as e:

                log.exception(
                    "auth collection failed: %s",
                    e
                )

            next_run["auth"] = (
                now
                + AUTH_INTERVAL
            )

        # ----------------------------------------------------
        # checks
        # ----------------------------------------------------

        if now >= next_run["checks"]:

            try:

                buf.push(
                    "checks",
                    {
                        "results":
                            checks.collect_checks()
                    }
                )

            except Exception as e:

                log.warning(
                    "checks collection failed: %s",
                    e
                )

            next_run["checks"] = (
                now
                + CHECKS_INTERVAL
            )

        # ----------------------------------------------------
        # users
        # ----------------------------------------------------

        if now >= next_run["users"]:

            try:

                buf.push(
                    "users",
                    {
                        "accounts":
                            checks.collect_users()
                    }
                )

            except Exception as e:

                log.warning(
                    "user collection failed: %s",
                    e
                )

            next_run["users"] = (
                now
                + USERS_INTERVAL
            )

        # ----------------------------------------------------
        # interfaces
        # ----------------------------------------------------

        if now >= next_run["interfaces"]:

            try:

                ifs = inventory.collect_interfaces()

                if ifs:

                    buf.push(
                        "interfaces",
                        {
                            "interfaces": ifs
                        }
                    )

                # Sent alongside interfaces because link speed is one of the
                # signals the physical/virtual classification depends on.
                try:

                    buf.push(
                        "virt",
                        osdetect.collect_virtualization(ifs)
                    )

                except Exception as e:

                    log.warning(
                        "virtualisation detection failed: %s",
                        e
                    )

            except Exception as e:

                log.warning(
                    "interface collection failed: %s",
                    e
                )

            next_run["interfaces"] = (
                now
                + INTERFACES_INTERVAL
            )

        # ----------------------------------------------------
        # applications
        # ----------------------------------------------------

        if now >= next_run["apps"]:

            try:

                apps = osdetect.collect_apps()

                if apps:

                    buf.push(
                        "apps",
                        {
                            "apps": apps
                        }
                    )

            except Exception as e:

                log.warning(
                    "application collection failed: %s",
                    e
                )

            next_run["apps"] = (
                now
                + APPS_INTERVAL
            )

        # ----------------------------------------------------
        # file integrity monitoring
        # ----------------------------------------------------

        if now >= next_run["fim"]:

            try:

                events, summary = (
                    inventory.collect_fim(buf)
                )

                buf.push(
                    "fim",
                    {
                        "events": events,
                        "summary": summary
                    }
                )

                if events:

                    log.info(
                        "fim: %d change(s), %d critical",
                        len(events),
                        sum(
                            1
                            for e in events
                            if e["critical"]
                        )
                    )

            except Exception as e:

                log.warning(
                    "fim collection failed: %s",
                    e
                )

            next_run["fim"] = (
                now
                + FIM_INTERVAL
            )

        # ----------------------------------------------------
        # packages
        # ----------------------------------------------------

        if now >= next_run["packages"]:

            try:

                pkgs = (
                    inventory.collect_packages()
                )

                if pkgs:

                    buf.push(
                        "packages",
                        {
                            "packages": pkgs
                        }
                    )

            except Exception as e:

                log.warning(
                    "package collection failed: %s",
                    e
                )

            next_run["packages"] = (
                now
                + PACKAGES_INTERVAL
            )

        # ----------------------------------------------------
        # flush
        # ----------------------------------------------------

        if now >= next_run["flush"]:

            try:

                flush(
                    buf,
                    sess
                )

            except Exception as e:

                log.exception(
                    "flush failed: %s",
                    e
                )

            next_run["flush"] = (
                now
                + FLUSH_INTERVAL
            )

        # ----------------------------------------------------
        # loop
        # ----------------------------------------------------

        time.sleep(1)


# ---------------------------------------------------------------- self-test

def selftest() -> int:
    """
    Runs every collector once against this host and prints what each
    returned - no enrolment, no network to the ingest API, nothing written
    outside a throwaway buffer. Exists so a packaged binary can prove on
    its own OS that every platform module made it into the build, rather
    than discovering a missing import the first time a cycle fires.
    """
    import tempfile

    tmp = tempfile.mkdtemp(prefix="nodewatch-selftest-")
    buf = Buffer(Path(tmp) / "buffer.db")

    steps = [
        ("platform", lambda: platform_string()),
        ("machine_id", lambda: osdetect.machine_id()),
        ("metrics", collect_metrics),
        ("ports", collect_ports),
        ("auth", lambda: osdetect.collect_auth_events(buf)),
        ("checks", checks.collect_checks),
        ("users", checks.collect_users),
        ("interfaces", inventory.collect_interfaces),
        ("virt", osdetect.collect_virtualization),
        ("apps", osdetect.collect_apps),
        ("packages", inventory.collect_packages),
        ("fim", lambda: inventory.collect_fim(buf)),
    ]

    failed = 0

    for name, fn in steps:

        t0 = time.time()

        try:

            out = fn()

            size = (
                len(out)
                if isinstance(out, (list, tuple, dict))
                else out
            )

            print(
                f"ok    {name:<11} {time.time() - t0:6.1f}s  {size}"
            )

        except Exception as e:

            failed += 1

            print(
                f"FAIL  {name:<11} {time.time() - t0:6.1f}s  "
                f"{type(e).__name__}: {e}"
            )

    buf.db.close()

    print(
        f"nodewatch-agent {AGENT_VERSION} selftest: "
        f"{len(steps) - failed}/{len(steps)} collectors ran"
    )

    return 1 if failed else 0


# ---------------------------------------------------------------- commands

def _wait_for_enrolment(since: float, timeout: float = 75) -> tuple[bool, str]:
    """After (re)starting the service: did it enrol with the master?"""
    deadline = time.time() + timeout
    st = {}
    while time.time() < deadline:
        st = read_status()
        if (st.get("last_enroll_at") or 0) >= since:
            return True, "enrolled with the master"
        if (st.get("last_error_at") or 0) >= since and st.get("last_error"):
            return False, st["last_error"]
        time.sleep(2)
    return False, st.get("last_error") or "the agent has not enrolled yet - check again in a minute"


def cli(argv: list[str]) -> int:
    import argparse

    import joining
    import service

    ap = argparse.ArgumentParser(prog="nodewatch-agent", description="nodewatch agent")
    ap.add_argument("--version", action="store_true")
    ap.add_argument("--selftest", action="store_true", help="run every collector once and exit")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("run", help="run the agent (what the service does)")
    j = sub.add_parser("join", help="join a master with a join code and install the service")
    j.add_argument("code", nargs="?")
    j.add_argument("--code-file", help="read the join code from a file instead")
    j.add_argument("--site")
    j.add_argument("--no-service", action="store_true", help="only write the configuration")
    u = sub.add_parser("set-url", help="the same master at a new address")
    u.add_argument("url")
    sub.add_parser("restart")
    sub.add_parser("status")
    sub.add_parser("uninstall", help="remove the service (keeps configuration and state)")
    sub.add_parser("gui")
    for sp in sub.choices.values():
        sp.add_argument("--result-file", help=argparse.SUPPRESS)
    # Finder on older macOS passes a process serial number to apps it opens.
    argv = [a for a in argv if not a.startswith("-psn_")]
    args = ap.parse_args(argv)

    if args.version:
        print(f"nodewatch-agent {AGENT_VERSION}")
        return 0
    if args.selftest:
        return selftest()

    cmd = args.cmd
    if cmd is None:
        # Double-clicked binary: the window, where there is a desktop for it.
        # Run as a script with no arguments: the agent, as the script
        # installers have always started it.
        if not getattr(sys, "frozen", False):
            cmd = "run"
        elif sys.platform in ("win32", "darwin") or os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"):
            cmd = "gui"
        else:
            ap.print_help()
            return 2

    if cmd == "run":
        main()
        return 0
    if cmd == "gui":
        import gui
        return gui.main(AGENT_VERSION)
    if cmd == "status":
        cfg = nwconfig.load()
        st = read_status()
        print(json.dumps({"master": cfg.get("ingest_url") or INGEST_URL,
                          "service_installed": service.installed(), **st}, indent=2, default=str))
        return 0

    def finish(ok: bool, message: str) -> int:
        print(("ok: " if ok else "error: ") + message)
        if args.result_file:
            try:
                Path(args.result_file).write_text(json.dumps({"ok": ok, "message": message}))
            except OSError:
                pass
        return 0 if ok else 1

    # Installing or controlling the service needs root/Administrator.
    # Writing configuration alone (join --no-service, e.g. with NW_CONFIG
    # pointing somewhere writable) does not.
    if not (cmd == "join" and args.no_service) and not service.is_admin():
        return finish(False, "run this as root / Administrator")

    try:
        if cmd == "join":
            code = args.code
            if args.code_file:
                code = Path(args.code_file).read_text(encoding="utf-8").strip()
            if not code:
                return finish(False, "give a join code")
            since = time.time()
            cfg = joining.join(code, args.site)
            if args.no_service:
                return finish(True, f"configured for {cfg['ingest_url']}; start it with `nodewatch-agent run`")
            service.install()
            ok, detail = _wait_for_enrolment(since)
            return finish(ok, f"joined {cfg['ingest_url']}: {detail}")
        if cmd == "set-url":
            cfg = joining.set_url(args.url)
            since = time.time()
            service.restart()
            ok, detail = _wait_for_enrolment(since)
            return finish(ok, f"now reporting to {cfg['ingest_url']}: {detail}")
        if cmd == "restart":
            since = time.time()
            service.restart()
            ok, detail = _wait_for_enrolment(since)
            return finish(ok, f"restarted: {detail}")
        if cmd == "uninstall":
            service.uninstall()
            return finish(True, "service removed; configuration and state kept")
    except (joining.JoinError, service.ServiceError, OSError) as e:
        return finish(False, str(e))
    return finish(False, f"unknown command {cmd}")


# ---------------------------------------------------------------- entrypoint

if __name__ == "__main__":

    try:

        sys.exit(cli(sys.argv[1:]))

    except KeyboardInterrupt:

        sys.exit(0)

    except Exception:

        log.exception(
            "nodewatch agent crashed"
        )

        sys.exit(1)
