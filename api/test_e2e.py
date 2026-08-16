"""End-to-end: simulate an agent enrolling and shipping telemetry."""
import os, time
os.environ["NW_DATABASE_URL"] = "postgresql://postgres:pw@localhost:5432/nwdemo"
os.environ["NW_VERIFY_MODE"] = "off"
os.environ["NW_JWT_SECRET"] = "test"

from fastapi.testclient import TestClient
import app as api

c = TestClient(api.app)
DOC = {"instanceId": "i-0demo1234", "region": "ap-south-1",
       "accountId": "111122223333", "instanceType": "t3.micro"}

print("health:", c.get("/health").json())

r = c.post("/v1/enroll", json={"document": DOC, "hostname": "node-1",
                               "os": "Ubuntu 24.04.2 LTS", "agent_version": "0.1.0"})
print("enroll:", r.status_code, r.json()["agent_id"])
H = {"Authorization": f"Bearer {r.json()['token']}"}

now = time.time()

# cycle 1: baseline
r = c.post("/v1/ingest", headers=H, json={"events": [
    {"kind": "heartbeat", "ts": now, "data": {"cpu_pct": 12.5, "mem_pct": 40.1,
     "disk_pct": 22.0, "load1": 0.15, "uptime_s": 3600, "proc_count": 98}},
    {"kind": "ports", "ts": now, "data": {"listening": [
        {"port": 22, "proto": "tcp", "bind_addr": "0.0.0.0", "external": True, "pid": 700, "process": "sshd"},
        {"port": 5432, "proto": "tcp", "bind_addr": "127.0.0.1", "external": False, "pid": 800, "process": "postgres"},
    ]}},
    {"kind": "auth", "ts": now, "data": {"kind": "login_failed", "ts": now,
     "username": "admin", "source_ip": "203.0.113.9",
     "raw": "Failed password for invalid user admin from 203.0.113.9 port 51234 ssh2"}},
]})
print("cycle1:", r.json())

# cycle 2: a new external listener appears, postgres goes away
r = c.post("/v1/ingest", headers=H, json={"events": [
    {"kind": "ports", "ts": now + 60, "data": {"listening": [
        {"port": 22, "proto": "tcp", "bind_addr": "0.0.0.0", "external": True, "pid": 700, "process": "sshd"},
        {"port": 8080, "proto": "tcp", "bind_addr": "0.0.0.0", "external": True, "pid": 4417, "process": "python3"},
    ]}},
]})
print("cycle2:", r.json())

# cycle 3: replay cycle 1 verbatim (simulates a lost response / agent retry)
r = c.post("/v1/ingest", headers=H, json={"events": [
    {"kind": "heartbeat", "ts": now, "data": {"cpu_pct": 12.5, "mem_pct": 40.1,
     "disk_pct": 22.0, "load1": 0.15, "uptime_s": 3600, "proc_count": 98}},
    {"kind": "auth", "ts": now, "data": {"kind": "login_failed", "ts": now,
     "username": "admin", "source_ip": "203.0.113.9",
     "raw": "Failed password for invalid user admin from 203.0.113.9 port 51234 ssh2"}},
]})
print("replay:", r.json())

# auth rejection paths
print("no token:", c.post("/v1/ingest", json={"events": []}).status_code)
print("bad token:", c.post("/v1/ingest", headers={"Authorization": "Bearer nope"},
                           json={"events": []}).status_code)

import psycopg
with psycopg.connect(os.environ["NW_DATABASE_URL"]) as conn:
    for label, q in [
        ("metrics rows (replay must not duplicate)", "select count(*) from metrics"),
        ("auth rows (replay must not duplicate)", "select count(*) from auth_events"),
        ("port_state now", "select count(*) from port_state"),
    ]:
        print(f"  {label}:", conn.execute(q).fetchone()[0])
    print("  port change log:")
    for row in conn.execute(
        "select ts, port, process, external, action from port_events order by id"
    ).fetchall():
        print("   ", row)
    print("  health:", conn.execute(
        "select instance_id, status, external_ports, failed_logins_1h from agent_health"
    ).fetchone())
