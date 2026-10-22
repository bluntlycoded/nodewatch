"""
PostgREST, run by the master as a child process - the same data API the
hosted dashboard talks to on Supabase, so the dashboard's queries, and the
row-level security policies that guard them, work unchanged.

It connects as `authenticator`, a login role that can do nothing itself
and may only switch to `anon` or `authenticated` per request, based on the
signed session the master issued. Listens on 127.0.0.1 only; browsers reach
it through the master's /rest/v1 proxy.
"""

import logging
import subprocess
import sys
import threading
import time
from pathlib import Path

import psycopg
import requests
from psycopg import sql

log = logging.getLogger("nodewatch.postgrest")

ROLE = "authenticator"
EXE = ".exe" if sys.platform == "win32" else ""
# Supabase's default page cap; the dashboard was written against it.
MAX_ROWS = 1000


def ensure_role(db_url: str, password: str) -> None:
    with psycopg.connect(db_url, autocommit=True) as conn:
        exists = conn.execute("select 1 from pg_roles where rolname = %s", (ROLE,)).fetchone()
        verb = "alter" if exists else "create"
        conn.execute(sql.SQL(f"{verb} role {{}} login noinherit password {{}}").format(
            sql.Identifier(ROLE), sql.Literal(password)))
        conn.execute(f"grant anon, authenticated to {ROLE}")


class PostgREST:

    def __init__(self, bin_dir: Path, data_dir: Path, pg_port: int, password: str,
                 jwt_secret: str, port: int):
        self.exe = bin_dir / f"postgrest{EXE}"
        self.conf = data_dir / "postgrest.conf"
        self.logfile = data_dir / "postgrest.log"
        self.pidfile = data_dir / "postgrest.pid"
        self.port = port
        self.admin_port = port + 1
        self.proc: subprocess.Popen | None = None
        self.stopping = False
        self.conf.write_text("\n".join([
            f'db-uri = "postgresql://{ROLE}:{password}@127.0.0.1:{pg_port}/nodewatch"',
            'db-schemas = "public"',
            'db-anon-role = "anon"',
            "db-pool = 10",
            f"db-max-rows = {MAX_ROWS}",
            "db-channel-enabled = false",
            f'jwt-secret = "{jwt_secret}"',
            'jwt-aud = "authenticated"',
            'server-host = "127.0.0.1"',
            f"server-port = {port}",
            'admin-server-host = "127.0.0.1"',
            f"admin-server-port = {self.admin_port}",
            'openapi-mode = "disabled"',
            'log-level = "warn"',
            "",
        ]))
        if sys.platform != "win32":
            self.conf.chmod(0o600)

    @property
    def available(self) -> bool:
        return self.exe.exists()

    def start(self) -> None:
        self._kill_orphan()
        self._spawn()
        self._wait_ready()
        threading.Thread(target=self._supervise, name="postgrest-supervisor", daemon=True).start()

    def _spawn(self) -> None:
        out = open(self.logfile, "ab")
        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        self.proc = subprocess.Popen([str(self.exe), str(self.conf)], stdout=out, stderr=out,
                                     creationflags=flags)
        self.pidfile.write_text(str(self.proc.pid))
        log.info("postgrest started on 127.0.0.1:%d (pid %d)", self.port, self.proc.pid)

    def _kill_orphan(self) -> None:
        """
        A master that was killed outright (TerminateProcess, SIGKILL) left
        its PostgREST running and holding the port. Stop it - but only if
        the recorded pid is still a postgrest process, not a reused pid.
        """
        try:
            pid = int(self.pidfile.read_text())
        except (OSError, ValueError):
            return
        if sys.platform == "win32":
            out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                                 capture_output=True, text=True).stdout
            if "postgrest" in out.lower():
                subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True)
                log.warning("stopped postgrest left running by a previous master (pid %d)", pid)
        else:
            out = subprocess.run(["ps", "-p", str(pid), "-o", "comm="], capture_output=True, text=True).stdout
            if "postgrest" in out:
                import signal
                import os
                os.kill(pid, signal.SIGTERM)
                log.warning("stopped postgrest left running by a previous master (pid %d)", pid)
                time.sleep(1)
        self.pidfile.unlink(missing_ok=True)

    def _wait_ready(self, timeout: float = 30) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"postgrest exited with {self.proc.returncode}; see {self.logfile}")
            try:
                if requests.get(f"http://127.0.0.1:{self.admin_port}/ready", timeout=2).status_code == 200:
                    return
            except requests.RequestException:
                pass
            time.sleep(0.5)
        raise RuntimeError(f"postgrest did not become ready; see {self.logfile}")

    def _supervise(self) -> None:
        while not self.stopping:
            if self.proc and self.proc.poll() is not None and not self.stopping:
                log.warning("postgrest exited with %s; restarting", self.proc.returncode)
                time.sleep(2)
                try:
                    self._spawn()
                except OSError:
                    log.exception("could not restart postgrest")
            time.sleep(2)

    def stop(self) -> None:
        self.stopping = True
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            log.info("postgrest stopped")
        self.pidfile.unlink(missing_ok=True)
