#!/usr/bin/env python3
"""
Smoke test for a built nodewatch-server binary, run by CI on each OS.

Starts it on a throwaway data directory, waits for the setup page, fetches
it over HTTPS verified against the master's own freshly generated CA, then
stops it. Proves on that platform that the bundled PostgreSQL unpacks,
initialises and migrates, and that TLS and the setup wizard are served.

    python packaging/smoke_server.py dist/nodewatch-server-<ver>-<os>-<arch>[.exe]
    python packaging/smoke_server.py --service <binary>    # as root / Administrator

--service installs it as a real service instead (systemd on Linux, a
Windows service on Windows), waits for the service to serve the setup
page, then uninstalls it - proving install, service start and, on
Windows, that PostgreSQL runs under LocalSystem.
"""

import shutil
import signal
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

TIMEOUT_S = 180


def main(binary: str) -> int:
    data = Path(tempfile.mkdtemp(prefix="nw-smoke-"))
    log = data / "console.log"
    with open(log, "w") as out:
        proc = subprocess.Popen([binary, "--data", str(data), "--no-browser"],
                                stdout=out, stderr=subprocess.STDOUT)
    try:
        deadline = time.time() + TIMEOUT_S
        while time.time() < deadline:
            if proc.poll() is not None:
                print(log.read_text(errors="replace"))
                print(f"FAIL: master exited with {proc.returncode} before setup was ready")
                return 1
            if "Setup code" in log.read_text(errors="replace"):
                break
            time.sleep(1)
        else:
            print(log.read_text(errors="replace"))
            print(f"FAIL: setup page not ready after {TIMEOUT_S}s")
            return 1

        ctx = ssl.create_default_context(cafile=str(data / "pki" / "ca.crt"))
        with urllib.request.urlopen("https://localhost:8443/setup", context=ctx, timeout=15) as r:
            body = r.read().decode()
        if r.status != 200 or "Set up this nodewatch master" not in body:
            print(f"FAIL: unexpected setup page (HTTP {r.status})")
            return 1

        applied = log.read_text(errors="replace").count("applying ")
        print(f"ok: postgres initialised, {applied} migrations applied, setup page served over verified TLS")
        return 0
    finally:
        if proc.poll() is None:
            if sys.platform == "win32":
                proc.terminate()
            else:
                proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=60)
            except subprocess.TimeoutExpired:
                proc.kill()
        # Unpacked PostgreSQL plus a cluster: ~180 MB per run otherwise left behind.
        shutil.rmtree(data, ignore_errors=True)


def print_logs(data: Path) -> None:
    """The master's own log and PostgreSQL's, which says why it would not start."""
    for name in ("server.log", "postgres.log", "postgrest.log"):
        log = data / name
        if sys.platform == "win32":
            text = log.read_text(errors="replace")[-4000:] if log.exists() else "(missing)"
        else:
            text = subprocess.run(["sudo", "tail", "-60", str(log)], capture_output=True, text=True).stdout
        print(f"----- {name}\n{text}")


def service(binary: str) -> int:
    if sys.platform == "win32":
        import os
        data = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "nodewatch-server"
        install = [binary, "install"]
        uninstall = [binary, "uninstall"]
    else:
        data = Path("/var/lib/nodewatch-server")
        install = ["sudo", binary, "install"]
        uninstall = ["sudo", "/opt/nodewatch-server/nodewatch-server", "uninstall"]
    res = subprocess.run(install, capture_output=True, text=True, timeout=300)
    print(res.stdout[-2000:], res.stderr[-2000:])
    if res.returncode != 0:
        print(f"FAIL: install exited {res.returncode}")
        return 1
    try:
        deadline = time.time() + TIMEOUT_S
        ca = data / "pki" / "ca.crt"
        while time.time() < deadline:
            try:
                pem = (subprocess.run(["sudo", "cat", str(ca)], capture_output=True, text=True).stdout
                       if sys.platform != "win32" else ca.read_text())
                if pem:
                    ctx = ssl.create_default_context(cadata=pem)
                    with urllib.request.urlopen("https://localhost:8443/setup", context=ctx, timeout=10) as r:
                        if r.status == 200 and "Set up this nodewatch master" in r.read().decode():
                            print("ok: the service started and serves the setup page over verified TLS")
                            return 0
            except (OSError, ssl.SSLError):
                pass
            time.sleep(3)
        print(f"FAIL: the service did not serve the setup page within {TIMEOUT_S}s")
        print_logs(data)
        return 1
    finally:
        subprocess.run(uninstall, capture_output=True, text=True, timeout=120)


if __name__ == "__main__":
    if sys.argv[1] == "--service":
        sys.exit(service(sys.argv[2]))
    sys.exit(main(sys.argv[1]))
