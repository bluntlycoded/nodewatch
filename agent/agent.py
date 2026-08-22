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
import re
import socket
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import psutil
import requests

import checks
import identity as ident_mod
import osdetect
import inventory

# ---------------------------------------------------------------- config

INGEST_URL = os.environ.get(
    "NW_INGEST_URL",
    "http://100.64.0.1:8000"
).rstrip("/")

STATE_DIR = Path(
    os.environ.get(
        "NW_STATE_DIR",
        "/var/lib/nodewatch"
    )
)

# Optional single-use enrolment token, issued from the dashboard.
# Required when the server is configured with NW_REQUIRE_TOKEN=true.
ENROLL_TOKEN = os.environ.get(
    "NW_ENROLL_TOKEN",
    ""
)

AGENT_VERSION = "0.4.0"

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


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

log = logging.getLogger("nodewatch")


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

        if (
            ident.get("provider") == "generic"
            and not ENROLL_TOKEN
        ):

            log.error(
                "this host has no cloud identity, "
                "so NW_ENROLL_TOKEN is required. "
                "Issue one from the dashboard."
            )

            return False

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
        }

        try:

            r = requests.post(
                f"{INGEST_URL}/v1/enroll",
                json=body,
                timeout=HTTP_TIMEOUT,
            )

        except Exception as e:

            log.warning(
                "enroll request failed: %s",
                e
            )

            return False

        if r.status_code != 200:

            log.error(
                "enroll rejected (%s): %s",
                r.status_code,
                r.text[:200]
            )

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

        return True

    def headers(self):

        return {
            "Authorization": (
                f"Bearer {self.token}"
            )
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

        r = requests.post(
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


# ---------------------------------------------------------------- main

def main():

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


# ---------------------------------------------------------------- entrypoint

if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        sys.exit(0)

    except Exception:

        log.exception(
            "nodewatch agent crashed"
        )

        sys.exit(1)
