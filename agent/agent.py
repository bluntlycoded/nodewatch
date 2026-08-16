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
import inventory

# ---------------------------------------------------------------- config

INGEST_URL = os.environ.get("NW_INGEST_URL", "http://100.64.0.1:8000").rstrip("/")
STATE_DIR = Path(os.environ.get("NW_STATE_DIR", "/var/lib/nodewatch"))
DB_PATH = STATE_DIR / "buffer.db"

HEARTBEAT_INTERVAL = 15
PORTS_INTERVAL = 60
AUTH_INTERVAL = 30
CHECKS_INTERVAL = 120
USERS_INTERVAL = 60
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
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path), isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS queue ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " kind TEXT NOT NULL,"
            " payload TEXT NOT NULL,"
            " ts REAL NOT NULL)"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)"
        )

    def push(self, kind: str, payload: dict) -> None:
        self.db.execute(
            "INSERT INTO queue (kind, payload, ts) VALUES (?, ?, ?)",
            (kind, json.dumps(payload), time.time()),
        )
        # Drop oldest if we've exceeded the cap, so a long outage can't
        # fill the disk.
        self.db.execute(
            "DELETE FROM queue WHERE id NOT IN ("
            " SELECT id FROM queue ORDER BY id DESC LIMIT ?)",
            (MAX_BUFFER_ROWS,),
        )

    def peek(self, limit: int = FLUSH_BATCH):
        rows = self.db.execute(
            "SELECT id, kind, payload, ts FROM queue ORDER BY id LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            {"id": r[0], "kind": r[1], "payload": json.loads(r[2]), "ts": r[3]}
            for r in rows
        ]

    def drop(self, ids) -> None:
        if not ids:
            return
        marks = ",".join("?" * len(ids))
        self.db.execute(f"DELETE FROM queue WHERE id IN ({marks})", ids)

    def depth(self) -> int:
        return self.db.execute("SELECT COUNT(*) FROM queue").fetchone()[0]

    def get_meta(self, key: str, default=None):
        row = self.db.execute("SELECT v FROM meta WHERE k = ?", (key,)).fetchone()
        return row[0] if row else default

    def set_meta(self, key: str, value: str) -> None:
        self.db.execute(
            "INSERT INTO meta (k, v) VALUES (?, ?) "
            "ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            (key, value),
        )


# ---------------------------------------------------------------- identity

def imds_token() -> str:
    r = requests.put(
        f"{IMDS}/latest/api/token",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": "300"},
        timeout=2,
    )
    r.raise_for_status()
    return r.text


def instance_identity():
    """Returns (instance_id, identity document, signed pkcs7)."""
    tok = imds_token()
    h = {"X-aws-ec2-metadata-token": tok}
    doc = requests.get(
        f"{IMDS}/latest/dynamic/instance-identity/document", headers=h, timeout=2
    ).json()
    pkcs7 = requests.get(
        f"{IMDS}/latest/dynamic/instance-identity/pkcs7", headers=h, timeout=2
    ).text
    return doc["instanceId"], doc, pkcs7


class Session:
    """Holds the short-lived JWT and re-enrolls when it expires."""

    def __init__(self):
        self.token = None
        self.instance_id = None

    def enroll(self) -> bool:
        try:
            instance_id, doc, pkcs7 = instance_identity()
        except Exception as e:
            log.error("IMDS unreachable, cannot enroll: %s", e)
            return False

        body = {
            "document": doc,
            "pkcs7": pkcs7,
            "hostname": socket.gethostname(),
            "agent_version": "0.1.0",
            "os": platform_string(),
        }
        try:
            r = requests.post(f"{INGEST_URL}/v1/enroll", json=body, timeout=HTTP_TIMEOUT)
        except Exception as e:
            log.warning("enroll request failed: %s", e)
            return False

        if r.status_code != 200:
            log.error("enroll rejected (%s): %s", r.status_code, r.text[:200])
            return False

        self.token = r.json()["token"]
        self.instance_id = instance_id
        log.info("enrolled as %s", instance_id)
        return True

    def headers(self):
        return {"Authorization": f"Bearer {self.token}"}


def platform_string() -> str:
    try:
        info = {}
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                info[k] = v.strip('"')
        return info.get("PRETTY_NAME", "unknown")
    except Exception:
        return "unknown"


# ---------------------------------------------------------------- collectors

def collect_metrics() -> dict:
    return {
        "cpu_pct": psutil.cpu_percent(interval=1),
        "mem_pct": psutil.virtual_memory().percent,
        "disk_pct": psutil.disk_usage("/").percent,
        "load1": os.getloadavg()[0],
        "uptime_s": int(time.time() - psutil.boot_time()),
        "proc_count": len(psutil.pids()),
    }


def collect_ports() -> list:
    """Full snapshot of listening sockets. The server diffs it."""
    out = []
    for c in psutil.net_connections(kind="inet"):
        if c.status != psutil.CONN_LISTEN:
            continue
        proc = None
        if c.pid:
            try:
                proc = psutil.Process(c.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                proc = None
        bind = c.laddr.ip
        out.append(
            {
                "port": c.laddr.port,
                "proto": "tcp" if c.type == socket.SOCK_STREAM else "udp",
                "bind_addr": bind,
                "external": bind in ("0.0.0.0", "::"),
                "pid": c.pid,
                "process": proc,
            }
        )
    return out


AUTH_PATTERNS = [
    ("login_success", "Accepted "),
    ("login_failed", "Failed password"),
    ("login_failed", "Invalid user"),
    ("session_opened", "session opened for user"),
    ("session_closed", "session closed for user"),
    ("logout", "Disconnected from user"),
]


def classify(message: str):
    for kind, needle in AUTH_PATTERNS:
        if needle in message:
            return kind
    return None


def collect_auth_events(buf: Buffer) -> list:
    """
    Read new sshd/PAM records from journald using a persisted cursor.
    Cursor-based reads mean no duplicate replay across agent restarts.
    """
    cursor = buf.get_meta("journal_cursor")
    cmd = ["journalctl", "-u", "ssh", "-u", "sshd", "-o", "json", "--no-pager"]
    if cursor:
        cmd += ["--after-cursor", cursor]
    else:
        cmd += ["-n", "50"]

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except Exception as e:
        log.warning("journalctl failed: %s", e)
        return []

    events = []
    last_cursor = cursor
    for line in res.stdout.splitlines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        last_cursor = rec.get("__CURSOR", last_cursor)
        msg = rec.get("MESSAGE", "")
        if not isinstance(msg, str):
            continue
        kind = classify(msg)
        if not kind:
            continue
        events.append(
            {
                "kind": kind,
                "ts": int(rec.get("__REALTIME_TIMESTAMP", 0)) / 1e6,
                "username": extract_user(msg),
                "source_ip": extract_ip(msg),
                "raw": msg[:400],
            }
        )

    if last_cursor and last_cursor != cursor:
        buf.set_meta("journal_cursor", last_cursor)
    return events


IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-fA-F:]{6,}:[0-9a-fA-F]{1,4}\b")


def extract_user(msg: str):
    """
    sshd phrasing varies a lot:
      'Accepted publickey for ubuntu from ...'
      'Failed password for invalid user admin from ...'
      'session opened for user ubuntu(uid=1000)'
      'Disconnected from user ubuntu 10.0.0.5 port 22'
    """
    parts = msg.split()
    # 'Invalid user oracle from 1.2.3.4' — username precedes any anchor word.
    if len(parts) > 2 and parts[0].lower() == "invalid" and parts[1] == "user":
        return parts[2].split("(")[0]
    anchor = None
    for word in ("for", "from"):
        if word in parts:
            anchor = parts.index(word) + 1
            break
    if anchor is None:
        return None
    while anchor < len(parts) and parts[anchor] in ("invalid", "user"):
        anchor += 1
    if anchor >= len(parts):
        return None
    cand = parts[anchor].split("(")[0]          # strip '(uid=1000)'
    return cand if cand and not IP_RE.fullmatch(cand) else None


def extract_ip(msg: str):
    m = IP_RE.search(msg)
    return m.group(0) if m else None


# ---------------------------------------------------------------- shipping

def flush(buf: Buffer, sess: Session) -> None:
    batch = buf.peek()
    if not batch:
        return
    if not sess.token and not sess.enroll():
        return

    body = {"events": [{"kind": b["kind"], "ts": b["ts"], "data": b["payload"]} for b in batch]}
    try:
        r = requests.post(
            f"{INGEST_URL}/v1/ingest",
            json=body,
            headers=sess.headers(),
            timeout=HTTP_TIMEOUT,
        )
    except Exception as e:
        log.warning("ship failed (%s), %d queued", e, buf.depth())
        return

    if r.status_code == 401:
        log.info("token expired, re-enrolling")
        sess.token = None
        return
    if r.status_code >= 400:
        log.error("ingest rejected (%s): %s", r.status_code, r.text[:200])
        return

    buf.drop([b["id"] for b in batch])
    log.info("shipped %d events, %d still queued", len(batch), buf.depth())


# ---------------------------------------------------------------- main

def main():
    buf = Buffer(DB_PATH)
    sess = Session()
    sess.enroll()

    next_run = {"heartbeat": 0.0, "ports": 0.0, "auth": 0.0,
                "checks": 0.0, "users": 0.0, "fim": 0.0,
                "packages": 0.0, "flush": 0.0}

    while True:
        now = time.time()

        if now >= next_run["heartbeat"]:
            buf.push("heartbeat", collect_metrics())
            next_run["heartbeat"] = now + HEARTBEAT_INTERVAL

        if now >= next_run["ports"]:
            buf.push("ports", {"listening": collect_ports()})
            next_run["ports"] = now + PORTS_INTERVAL

        if now >= next_run["auth"]:
            for ev in collect_auth_events(buf):
                buf.push("auth", ev)
            next_run["auth"] = now + AUTH_INTERVAL

        if now >= next_run["checks"]:
            buf.push("checks", {"results": checks.collect_checks()})
            next_run["checks"] = now + CHECKS_INTERVAL

        if now >= next_run["users"]:
            try:
                buf.push("users", {"accounts": checks.collect_users()})
            except Exception as e:
                log.warning("user collection failed: %s", e)
            next_run["users"] = now + USERS_INTERVAL

        if now >= next_run["fim"]:
            try:
                events, summary = inventory.collect_fim(buf)
                buf.push("fim", {"events": events, "summary": summary})
                if events:
                    log.info("fim: %d change(s), %d critical",
                             len(events), sum(1 for e in events if e["critical"]))
            except Exception as e:
                log.warning("fim collection failed: %s", e)
            next_run["fim"] = now + FIM_INTERVAL

        if now >= next_run["packages"]:
            try:
                pkgs = inventory.collect_packages()
                if pkgs:
                    buf.push("packages", {"packages": pkgs})
            except Exception as e:
                log.warning("package collection failed: %s", e)
            next_run["packages"] = now + PACKAGES_INTERVAL

        if now >= next_run["flush"]:
            flush(buf, sess)
            next_run["flush"] = now + FLUSH_INTERVAL

        time.sleep(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
