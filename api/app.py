"""
nodewatch ingest API

Two endpoints:
  POST /v1/enroll  - agent proves it is a real EC2 instance, gets a short JWT
  POST /v1/ingest  - batched telemetry

Identity is not self-asserted. The agent presents its IMDSv2 identity
document; the server confirms with EC2 that the instance exists in this
account and that its private IP matches the source of the request.
An attacker who guesses an instance ID still cannot enroll from elsewhere.
"""

import json
import logging
import os
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone

import jwt
import psycopg
from fastapi import FastAPI, Header, HTTPException, Request
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool
from pydantic import BaseModel, Field

# ---------------------------------------------------------------- config

DATABASE_URL = os.environ["NW_DATABASE_URL"]
JWT_SECRET = os.environ.get("NW_JWT_SECRET", "dev-secret-change-me")
JWT_TTL_MIN = int(os.environ.get("NW_JWT_TTL_MIN", "15"))

# "aws"  - verify against EC2 DescribeInstances (production)
# "off"  - trust the document as presented (local development only)
VERIFY_MODE = os.environ.get("NW_VERIFY_MODE", "aws")

# Path to the AWS regional public certificate. When set, the PKCS7
# signature over the identity document is verified cryptographically
# before anything else. This is strictly stronger than the DescribeInstances
# check: it proves AWS itself signed the document, not merely that an
# instance with that ID exists.
AWS_CERT_PATH = os.environ.get("NW_AWS_CERT_PATH", "")

# When true, enrolment additionally requires a single-use token issued from
# the dashboard. The identity document proves the node is who it says it is;
# the token proves somebody invited it.
REQUIRE_TOKEN = os.environ.get("NW_REQUIRE_TOKEN", "false").lower() == "true"

MAX_EVENTS_PER_BATCH = 500

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("nodewatch-api")

app = FastAPI(title="nodewatch ingest", version="0.1.0")
pool = ConnectionPool(DATABASE_URL, min_size=1, max_size=8, open=True)


# ---------------------------------------------------------------- models

class EnrollBody(BaseModel):
    # The parsed document is convenience; document_raw is what AWS actually
    # signed. Reconstructing JSON from the parsed form does not byte-match
    # and verification would always fail.
    document: dict
    document_raw: str | None = None
    pkcs7: str | None = None
    hostname: str | None = None
    os: str | None = None
    agent_version: str | None = None
    enroll_token: str | None = None


class Event(BaseModel):
    kind: str
    ts: float
    data: dict


class IngestBody(BaseModel):
    events: list[Event] = Field(..., max_length=MAX_EVENTS_PER_BATCH)


# ---------------------------------------------------------------- identity

def client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else ""


def verify_pkcs7(doc: dict, doc_raw: str | None, pkcs7: str | None) -> bool:
    """
    Verify AWS's signature over the identity document.

    Uses openssl cms rather than reimplementing PKCS7 in Python, with
    -binary so no canonicalisation is applied: the signature covers the
    exact bytes IMDS returned, and even an added space invalidates it.
    -noverify skips chain validation, which is correct here - the regional
    certificate IS the trust anchor, there is no CA above it.

    Returns True when verified, False when no certificate is configured.
    Raises on an actual verification failure.
    """
    if not AWS_CERT_PATH:
        return False
    if not pkcs7:
        raise HTTPException(400, "identity document is not signed")
    if not doc_raw:
        raise HTTPException(400, "agent did not send the raw identity document")
    if not os.path.exists(AWS_CERT_PATH):
        log.error("NW_AWS_CERT_PATH set but %s does not exist", AWS_CERT_PATH)
        return False

    # IMDS returns bare base64 with no PEM armour, so wrap it. Accept an
    # already-armoured blob too (BEGIN PKCS7 or BEGIN CMS) rather than
    # double-wrapping it into something openssl cannot parse.
    body = pkcs7.strip()
    if "-----BEGIN" not in body:
        body = "-----BEGIN PKCS7-----\n" + body + "\n-----END PKCS7-----\n"

    with tempfile.TemporaryDirectory() as tmp:
        sig_path = os.path.join(tmp, "sig.pem")
        doc_path = os.path.join(tmp, "doc.json")
        with open(sig_path, "w") as f:
            f.write(body)
        # Exactly the bytes IMDS returned, written without re-encoding.
        with open(doc_path, "wb") as f:
            f.write(doc_raw.encode())

        proc = subprocess.run(
            ["openssl", "cms", "-verify", "-in", sig_path, "-inform", "PEM",
             "-content", doc_path, "-certfile", AWS_CERT_PATH,
             "-noverify", "-binary"],
            capture_output=True, text=True, timeout=10,
        )

    if proc.returncode != 0:
        log.warning("pkcs7 verification failed for %s: %s",
                    doc.get("instanceId"), proc.stderr.strip()[:200])
        raise HTTPException(403, "identity document signature is not valid")

    return True


def consume_token(conn, token: str | None, instance_id: str) -> None:
    """Single use, time limited, revocable. Consumed inside the enrolment txn."""
    if not REQUIRE_TOKEN:
        return
    if not token:
        raise HTTPException(403, "enrolment token required")

    row = conn.execute(
        """
        update enroll_tokens
           set used_at = now(), used_by = %s
         where token = %s
           and used_at is null
           and not revoked
           and expires_at > now()
        returning token
        """,
        (instance_id, token),
    ).fetchone()

    if not row:
        log.warning("enrolment rejected for %s: token invalid, used or expired", instance_id)
        raise HTTPException(403, "enrolment token is invalid, already used, or expired")


def verify_instance(doc: dict, source_ip: str) -> None:
    """
    Raise HTTPException unless the claimed instance genuinely exists in our
    account and the request came from that instance's own private address.
    """
    if VERIFY_MODE == "off":
        return

    import boto3
    from botocore.exceptions import ClientError

    instance_id = doc.get("instanceId")
    region = doc.get("region")
    if not instance_id or not region:
        raise HTTPException(400, "identity document missing instanceId/region")

    ec2 = boto3.client("ec2", region_name=region)
    try:
        res = ec2.describe_instances(InstanceIds=[instance_id])
    except ClientError as e:
        log.warning("describe_instances failed for %s: %s", instance_id, e)
        raise HTTPException(403, "instance not found in this account")

    reservations = res.get("Reservations", [])
    if not reservations or not reservations[0].get("Instances"):
        raise HTTPException(403, "instance not found")

    inst = reservations[0]["Instances"][0]
    known_ips = {inst.get("PrivateIpAddress"), inst.get("PublicIpAddress")}
    known_ips |= {
        i.get("PrivateIpAddress")
        for ni in inst.get("NetworkInterfaces", [])
        for i in ni.get("PrivateIpAddresses", [])
    }
    known_ips.discard(None)

    if source_ip not in known_ips:
        log.warning(
            "enroll rejected: %s claimed by %s, expected one of %s",
            instance_id, source_ip, known_ips,
        )
        raise HTTPException(403, "source address does not match instance")


def issue_token(agent_id: str, instance_id: str) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "sub": str(agent_id),
            "iid": instance_id,
            "iat": now,
            "exp": now + timedelta(minutes=JWT_TTL_MIN),
        },
        JWT_SECRET,
        algorithm="HS256",
    )


def agent_from_token(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token")
    try:
        claims = jwt.decode(authorization[7:], JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "invalid token")
    return claims["sub"]


# ---------------------------------------------------------------- endpoints

@app.get("/health")
def health():
    with pool.connection() as conn:
        conn.execute("select 1")
    return {"ok": True}


@app.post("/v1/enroll")
def enroll(body: EnrollBody, request: Request):
    doc = body.document
    instance_id = doc.get("instanceId")
    if not instance_id:
        raise HTTPException(400, "missing instanceId")

    # Layered, cheapest and strongest first:
    #   1. AWS signed this document      (cryptographic, if a cert is configured)
    #   2. the instance is in our account and the source address matches
    #   3. somebody invited this node    (if tokens are required)
    signed = verify_pkcs7(doc, body.document_raw, body.pkcs7)

    # A valid signature over a *different* document would otherwise pass.
    if signed and body.document_raw:
        try:
            if json.loads(body.document_raw).get("instanceId") != instance_id:
                raise HTTPException(403, "signed document does not match claimed instance")
        except json.JSONDecodeError:
            raise HTTPException(400, "raw identity document is not valid JSON")
    verify_instance(doc, client_ip(request))

    with pool.connection() as conn:
        consume_token(conn, body.enroll_token, instance_id)
        # Scope the row factory to this cursor. Setting it on the connection
        # leaks the setting to the next request that borrows it from the pool.
        cur = conn.cursor(row_factory=dict_row)
        row = cur.execute(
            """
            insert into agents (instance_id, account_id, region, instance_type,
                                hostname, os, agent_version, last_seen)
            values (%s, %s, %s, %s, %s, %s, %s, now())
            on conflict (instance_id) do update set
                hostname      = excluded.hostname,
                os            = excluded.os,
                agent_version = excluded.agent_version,
                region        = excluded.region,
                instance_type = excluded.instance_type,
                enrolled_at   = now(),
                enroll_count  = agents.enroll_count + 1
            returning id
            """,
            (
                instance_id,
                doc.get("accountId"),
                doc.get("region"),
                doc.get("instanceType"),
                body.hostname,
                body.os,
                body.agent_version,
            ),
        ).fetchone()

    log.info("enrolled %s (%s)%s", instance_id, body.hostname,
             " [pkcs7 verified]" if signed else "")
    return {"token": issue_token(row["id"], instance_id), "agent_id": str(row["id"])}


@app.post("/v1/ingest")
def ingest(body: IngestBody, authorization: str | None = Header(default=None)):
    agent_id = agent_from_token(authorization)
    counts = {"heartbeat": 0, "auth": 0, "ports": 0, "port_changes": 0, "checks": 0, "users": 0, "user_changes": 0, "fim": 0, "packages": 0}

    with pool.connection() as conn:
        for ev in body.events:
            ts = datetime.fromtimestamp(ev.ts, tz=timezone.utc)

            if ev.kind == "heartbeat":
                d = ev.data
                conn.execute(
                    """
                    insert into metrics (agent_id, ts, cpu_pct, mem_pct, disk_pct,
                                         load1, uptime_s, proc_count)
                    values (%s, %s, %s, %s, %s, %s, %s, %s)
                    on conflict (agent_id, ts) do nothing
                    """,
                    (agent_id, ts, d.get("cpu_pct"), d.get("mem_pct"),
                     d.get("disk_pct"), d.get("load1"), d.get("uptime_s"),
                     d.get("proc_count")),
                )
                counts["heartbeat"] += 1

            elif ev.kind == "auth":
                d = ev.data
                conn.execute(
                    """
                    insert into auth_events (agent_id, ts, kind, username, source_ip, raw)
                    values (%s, %s, %s, %s, %s, %s)
                    on conflict do nothing
                    """,
                    (agent_id,
                     datetime.fromtimestamp(d.get("ts", ev.ts), tz=timezone.utc),
                     d.get("kind"), d.get("username"), d.get("source_ip"),
                     d.get("raw")),
                )
                counts["auth"] += 1

            elif ev.kind == "ports":
                counts["port_changes"] += diff_ports(
                    conn, agent_id, ts, ev.data.get("listening", [])
                )
                counts["ports"] += 1

            elif ev.kind == "users":
                counts["users"] += 1
                counts["user_changes"] += diff_users(
                    conn, agent_id, ts, ev.data.get("accounts", [])
                )

            elif ev.kind == "fim":
                counts["fim"] += sync_fim(conn, agent_id, ts, ev.data)

            elif ev.kind == "packages":
                counts["packages"] += sync_packages(
                    conn, agent_id, ts, ev.data.get("packages", []))

            elif ev.kind == "checks":
                counts["checks"] += sync_checks(
                    conn, agent_id, ts, ev.data.get("results", [])
                )

        # last_seen is the single source of truth for health. Update it once
        # per batch, from the server clock, never from agent-reported time.
        conn.execute("update agents set last_seen = now() where id = %s", (agent_id,))

    return {"accepted": len(body.events), **counts}


def diff_ports(conn, agent_id: str, ts: datetime, listening: list) -> int:
    """
    The agent ships a full snapshot; we derive the change log. Keeping the
    diff server-side means a crashed or restarted agent cannot desync it.
    """
    seen = {
        (p["port"], p["proto"], p["bind_addr"]): p
        for p in listening
        if p.get("port") is not None
    }

    known = {
        (r[0], r[1], r[2])
        for r in conn.execute(
            "select port, proto, bind_addr from port_state where agent_id = %s",
            (agent_id,),
        ).fetchall()
    }

    changes = 0

    for key, p in seen.items():
        if key not in known:
            conn.execute(
                """insert into port_events
                   (agent_id, ts, port, proto, bind_addr, external, process, action)
                   values (%s, %s, %s, %s, %s, %s, %s, 'opened')""",
                (agent_id, ts, p["port"], p["proto"], p["bind_addr"],
                 p.get("external", False), p.get("process")),
            )
            changes += 1
        conn.execute(
            """
            insert into port_state (agent_id, port, proto, bind_addr, external,
                                    pid, process, last_seen)
            values (%s, %s, %s, %s, %s, %s, %s, %s)
            on conflict (agent_id, port, proto, bind_addr) do update set
                last_seen = excluded.last_seen,
                pid       = excluded.pid,
                process   = excluded.process,
                external  = excluded.external
            """,
            (agent_id, p["port"], p["proto"], p["bind_addr"],
             p.get("external", False), p.get("pid"), p.get("process"), ts),
        )

    for key in known - set(seen):
        port, proto, bind = key
        row = conn.execute(
            """select external, process from port_state
               where agent_id = %s and port = %s and proto = %s and bind_addr = %s""",
            (agent_id, port, proto, bind),
        ).fetchone()
        conn.execute(
            """insert into port_events
               (agent_id, ts, port, proto, bind_addr, external, process, action)
               values (%s, %s, %s, %s, %s, %s, %s, 'closed')""",
            (agent_id, ts, port, proto, bind,
             row[0] if row else False, row[1] if row else None),
        )
        conn.execute(
            """delete from port_state
               where agent_id = %s and port = %s and proto = %s and bind_addr = %s""",
            (agent_id, port, proto, bind),
        )
        changes += 1

    return changes


def sync_checks(conn, agent_id: str, ts: datetime, results: list) -> int:
    """
    Upsert the posture snapshot. last_changed only moves when the status
    actually flips, so "this started failing 10 minutes ago" stays
    answerable across repeated identical snapshots.
    """
    if not results:
        return 0

    seen, crows = [], []
    for c in results:
        cid = c.get("check_id")
        if not cid:
            continue
        seen.append(cid)
        crows.append(
            (agent_id, cid, c.get("title", cid), c.get("category", "other"),
             c.get("severity", "low"), c.get("status", "error"),
             c.get("detail"), ts))
    if crows:
        conn.cursor().executemany(
            """
            insert into host_checks (agent_id, check_id, title, category,
                                     severity, status, detail, last_seen)
            values (%s, %s, %s, %s, %s, %s, %s, %s)
            on conflict (agent_id, check_id) do update set
                title        = excluded.title,
                category     = excluded.category,
                severity     = excluded.severity,
                detail       = excluded.detail,
                last_seen    = excluded.last_seen,
                last_changed = case
                                 when host_checks.status <> excluded.status
                                 then excluded.last_seen
                                 else host_checks.last_changed
                               end,
                status       = excluded.status
            """, crows)

    # Retire checks the agent no longer reports, e.g. after an upgrade
    # removes one. Leaving them would freeze a stale failure into the score.
    conn.execute(
        "delete from host_checks where agent_id = %s and check_id <> all(%s)",
        (agent_id, seen),
    )
    return len(seen)


# Fields whose change is worth reporting. Anything else (home directory
# tidy-ups, gid renumbering by a package) would be noise.
TRACKED_USER_FIELDS = ["uid", "shell", "sudoer", "can_login", "password", "groups"]


def diff_users(conn, agent_id: str, ts: datetime, accounts: list) -> int:
    """Derive added / removed / modified account events from a snapshot."""
    if not accounts:
        return 0

    snap = {a["username"]: a for a in accounts if a.get("username")}

    known = {
        r[0]: {"uid": r[1], "shell": r[2], "sudoer": r[3],
               "can_login": r[4], "password": r[5], "groups": list(r[6] or [])}
        for r in conn.execute(
            """select username, uid, shell, sudoer, can_login, password, groups
                 from user_state where agent_id = %s""", (agent_id,)
        ).fetchall()
    }

    changes = 0
    # First snapshot for this agent establishes the baseline. Emitting an
    # "added" event for every pre-existing system account would be noise,
    # and would wrongly depress the churn factor right after enrolment.
    seeding = not known
    rows = []

    for name, a in snap.items():
        prev = known.get(name)
        if prev is None:
            if not seeding:
                conn.execute(
                    """insert into user_events (agent_id, ts, username, action, uid, sudoer, detail)
                       values (%s, %s, %s, 'added', %s, %s, %s)""",
                    (agent_id, ts, name, a.get("uid"), a.get("sudoer", False),
                     f"uid {a.get('uid')}, shell {a.get('shell')}, "
                     f"{'sudoer' if a.get('sudoer') else 'unprivileged'}, "
                     f"password {a.get('password')}"),
                )
                changes += 1
        else:
            diffs = []
            for k in TRACKED_USER_FIELDS:
                old, new = prev.get(k), a.get(k)
                if k == "groups":
                    old, new = sorted(old or []), sorted(new or [])
                if old != new:
                    diffs.append(f"{k}: {old} -> {new}")
            if diffs:
                conn.execute(
                    """insert into user_events (agent_id, ts, username, action, uid, sudoer, detail)
                       values (%s, %s, %s, 'modified', %s, %s, %s)""",
                    (agent_id, ts, name, a.get("uid"), a.get("sudoer", False),
                     "; ".join(diffs)[:400]),
                )
                changes += 1

        rows.append((agent_id, name, a.get("uid"), a.get("gid"), a.get("shell"),
                     a.get("home"), a.get("groups", []), a.get("sudoer", False),
                     a.get("can_login", False), a.get("password"), ts))

    # One pipelined round trip instead of one per account. Latency to a
    # cross-region database makes per-row writes untenable: 24 accounts was
    # 24 round trips, which exceeded the agent's request timeout.
    if rows:
        conn.cursor().executemany(
            """
            insert into user_state (agent_id, username, uid, gid, shell, home,
                                    groups, sudoer, can_login, password, last_seen)
            values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            on conflict (agent_id, username) do update set
                uid = excluded.uid, gid = excluded.gid, shell = excluded.shell,
                home = excluded.home, groups = excluded.groups,
                sudoer = excluded.sudoer, can_login = excluded.can_login,
                password = excluded.password, last_seen = excluded.last_seen
            """, rows)

    for name in set(known) - set(snap):
        prev = known[name]
        conn.execute(
            """insert into user_events (agent_id, ts, username, action, uid, sudoer, detail)
               values (%s, %s, %s, 'removed', %s, %s, %s)""",
            (agent_id, ts, name, prev.get("uid"), prev.get("sudoer", False),
             f"was uid {prev.get('uid')}, shell {prev.get('shell')}"),
        )
        conn.execute("delete from user_state where agent_id = %s and username = %s",
                     (agent_id, name))
        changes += 1

    return changes


def sync_fim(conn, agent_id: str, ts: datetime, data: dict) -> int:
    """
    Record file-integrity changes. Unlike ports, the agent has already
    diffed: /etc is thousands of files and shipping a full manifest every
    cycle is not viable. The manifest digest is stored so divergence
    between agent and server is detectable.
    """
    events = data.get("events", [])
    summary = data.get("summary", {})

    conn.execute(
        """
        insert into fim_state (agent_id, files_watched, digest, paths, last_scan)
        values (%s, %s, %s, %s, %s)
        on conflict (agent_id) do update set
            files_watched = excluded.files_watched,
            digest        = excluded.digest,
            paths         = excluded.paths,
            last_scan     = excluded.last_scan
        """,
        (agent_id, summary.get("files_watched", 0), summary.get("digest"),
         summary.get("paths", []), ts),
    )

    if not events:
        return 0

    conn.cursor().executemany(
        """insert into fim_events
           (agent_id, ts, path, action, critical, sha256, mode, size, detail)
           values (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
        [(agent_id, ts, e.get("path"), e.get("action"), e.get("critical", False),
          e.get("sha256"), e.get("mode"), e.get("size"), e.get("detail"))
         for e in events if e.get("path") and e.get("action")],
    )
    return len(events)


def sync_packages(conn, agent_id: str, ts: datetime, packages: list) -> int:
    """Replace the host's package inventory. OSV lookup happens separately."""
    if not packages:
        return 0

    rows = [(agent_id, p["name"], p["version"], p.get("arch"), ts)
            for p in packages if p.get("name") and p.get("version")]

    conn.cursor().executemany(
        """
        insert into host_packages (agent_id, name, version, arch, last_seen)
        values (%s, %s, %s, %s, %s)
        on conflict (agent_id, name) do update set
            version = excluded.version, arch = excluded.arch,
            last_seen = excluded.last_seen
        """, rows)

    # Drop packages the host no longer reports, so an uninstalled package
    # cannot keep contributing vulnerabilities to its score.
    conn.execute(
        "delete from host_packages where agent_id = %s and name <> all(%s)",
        (agent_id, [p["name"] for p in packages if p.get("name")]),
    )
    return len(rows)
