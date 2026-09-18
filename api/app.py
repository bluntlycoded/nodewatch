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
import threading
import time
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

# The tenant db/043_multi_tenant.sql backfilled all of this deployment's
# pre-existing data into. With REQUIRE_TOKEN off, a token (the only signal
# that says which tenant a brand new host belongs to) may be absent, so a
# tokenless first contact falls back to this tenant - the same behaviour a
# single-tenant deployment had before multi-tenancy existed. A real
# multi-tenant deployment sets NW_REQUIRE_TOKEN=true so every tenant's hosts
# can only ever enrol with that tenant's own token.
TENANT_ZERO = "00000000-0000-0000-0000-000000000001"

MAX_EVENTS_PER_BATCH = 500

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("nodewatch-api")

app = FastAPI(title="nodewatch ingest", version="0.1.0")
pool = ConnectionPool(DATABASE_URL, min_size=1, max_size=8, open=True)


# ---------------------------------------------------------------- rate limiting

class RateLimiter:
    """
    Token bucket, one per key. In-memory, so this only works correctly
    because the API runs as a single uvicorn process (see
    api/deploy/nodewatch-api.service - no --workers flag); a multi-process
    or multi-replica deployment would need a shared store (e.g. Redis)
    instead, since each process would otherwise track its own quota.
    """

    def __init__(self, capacity: float, refill_per_sec: float, idle_evict_s: float = 3600):
        self.capacity = capacity
        self.refill_per_sec = refill_per_sec
        self.idle_evict_s = idle_evict_s
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()
        self._calls_since_evict = 0

    def allow(self, key: str, cost: float = 1.0) -> bool:
        now = time.monotonic()
        with self._lock:
            self._calls_since_evict += 1
            if self._calls_since_evict >= 1000:
                self._evict_stale(now)
                self._calls_since_evict = 0

            tokens, last = self._buckets.get(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last) * self.refill_per_sec)
            if tokens < cost:
                self._buckets[key] = (tokens, now)
                return False
            self._buckets[key] = (tokens - cost, now)
            return True

    def _evict_stale(self, now: float) -> None:
        stale = [k for k, (_, last) in self._buckets.items() if now - last > self.idle_evict_s]
        for k in stale:
            del self._buckets[k]


# A tenant's whole fleet, aggregated: generous enough for hundreds of hosts
# heartbeating every ~60s, but caps one tenant's traffic from degrading
# ingest latency for everyone else on this shared process.
ingest_tenant_limiter = RateLimiter(capacity=120, refill_per_sec=6)
# A single agent: catches one misbehaving/misconfigured host retrying in a
# tight loop without penalizing the rest of its own tenant's fleet.
ingest_agent_limiter = RateLimiter(capacity=20, refill_per_sec=1)
# Enrolment is rarer and more sensitive (token guessing, identity-document
# replay) than steady-state telemetry, so it's keyed by source IP rather
# than an identity the request hasn't proven yet.
enroll_ip_limiter = RateLimiter(capacity=20, refill_per_sec=0.2)
# A single master node: there is normally exactly one per tenant, polling
# every TICK_S seconds (probe/prober.py), so this only ever fires on a
# genuinely misbehaving runner, not legitimate steady-state traffic.
probe_node_limiter = RateLimiter(capacity=30, refill_per_sec=2)

# GitHub App installation flow (/oauth/github/*) - connects private repos
# to Supply Chain checks without a hand-entered personal access token.
# Only active once NW_GITHUB_APP_ID/NW_GITHUB_APP_SLUG/
# NW_GITHUB_APP_PRIVATE_KEY_PATH/NW_SUPABASE_JWT_SECRET are set; unset,
# the two routes 500 with a clear "not configured" rather than the rest of
# the API failing to start.
import github_app as _github_app  # noqa: E402
_github_app.install(app, pool)

# Slack/Teams OAuth for alert channels (/oauth/slack/*, /oauth/teams/*,
# /teams/*) - connects a channel via a real install flow instead of
# pasting a webhook URL by hand. Only active once each provider's env
# vars are set; unset, those routes 500 with a clear "not configured"
# rather than the rest of the API failing to start.
import slack_app as _slack_app  # noqa: E402
import teams_app as _teams_app  # noqa: E402
_slack_app.install(app, pool)
_teams_app.install(app, pool)


# ---------------------------------------------------------------- models

class EnrollBody(BaseModel):
    # Provider-agnostic identity envelope. The legacy AWS-only fields below
    # are kept so an older agent still enrols during a rolling upgrade.
    identity: dict | None = None
    # Legacy AWS-only fields, optional now that identity carries the payload.
    # document_raw is what AWS actually signed; reconstructing JSON from the
    # parsed form does not byte-match and verification would always fail.
    document: dict | None = None
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


class ProbeEnrollBody(BaseModel):
    # Generated once by the runner and kept in local state (see
    # probe/prober.py's STATE_PATH) - the closest thing this has to
    # instance_id, since there is no cloud attestation for a service
    # process the way there is for a specific piece of cloud hardware.
    client_id: str
    enroll_token: str | None = None
    label: str | None = None
    hostname: str | None = None
    version: str | None = None


class ProbeResultItem(BaseModel):
    probe_id: str
    ok: bool
    latency_ms: int | None = None
    detail: str | None = None
    metrics: dict | None = None
    app_metrics: dict | None = None
    proxmox: dict | None = None
    supply_chain: dict | None = None
    tls_cert: dict | None = None


class ProbeResultsBody(BaseModel):
    ts: float
    results: list[ProbeResultItem] = Field(..., max_length=MAX_EVENTS_PER_BATCH)


class RouteHop(BaseModel):
    hop: int
    ip: str
    rtt_ms: float | None = None


class RouteHopsBody(BaseModel):
    probe_id: str
    traced_at: float
    hops: list[RouteHop]


class ClaimBody(BaseModel):
    limit: int = Field(default=3, ge=1, le=20)


class NettoolCompleteBody(BaseModel):
    status: str
    output: str | None = None
    duration_ms: int | None = None


class AutomationCompleteBody(BaseModel):
    status: str
    response: str | None = None
    http_status: int | None = None


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


def consume_token(conn, token: str | None, instance_id: str, kind: str = "agent") -> str:
    """
    Single use, time limited, revocable. Consumed inside the enrolment txn.
    Returns the tenant the token belongs to, so the new agent (or master
    node) joins the right tenant - or TENANT_ZERO when REQUIRE_TOKEN is
    off and no token was sent.

    kind guards against a token issued for one enrolment path being spent
    on the other - an agent token must not enrol a probe runner, or the
    other way around, even though both are just opaque hex strings once
    issued.
    """
    if not token:
        if not REQUIRE_TOKEN:
            return TENANT_ZERO
        raise HTTPException(403, "enrolment token required")

    row = conn.execute(
        """
        update enroll_tokens
           set used_at = now(), used_by = %s
         where token = %s
           and kind = %s
           and used_at is null
           and not revoked
           and expires_at > now()
        returning tenant_id
        """,
        (instance_id, token, kind),
    ).fetchone()

    if not row:
        log.warning("enrolment rejected for %s: token invalid, used, expired, or wrong kind", instance_id)
        raise HTTPException(403, "enrolment token is invalid, already used, expired, or the wrong kind")

    return row[0]


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


def issue_probe_token(master_node_id: str) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "sub": str(master_node_id),
            # Same secret and algorithm as an agent's token, so this claim
            # is what stops one type being replayed against the other's
            # endpoints - sub alone would still fail safely (an agent id
            # simply won't match any master_nodes row) but this makes the
            # mismatch explicit rather than incidental.
            "typ": "probe",
            "iat": now,
            "exp": now + timedelta(minutes=JWT_TTL_MIN),
        },
        JWT_SECRET,
        algorithm="HS256",
    )


def master_node_from_token(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token")
    try:
        claims = jwt.decode(authorization[7:], JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "invalid token")
    if claims.get("typ") != "probe":
        raise HTTPException(401, "wrong token type")
    return claims["sub"]


# ---------------------------------------------------------------- endpoints

@app.get("/health")
def health():
    with pool.connection() as conn:
        conn.execute("select 1")
    return {"ok": True}


GOOGLE_JWKS = "https://www.googleapis.com/oauth2/v3/certs"
GCP_AUDIENCE = os.environ.get("NW_GCP_AUDIENCE", "nodewatch")
AZURE_CERT_PATH = os.environ.get("NW_AZURE_CERT_PATH", "")

# Cached across requests; Google rotates keys, PyJWKClient handles refresh.
_gcp_jwks = None


def verify_gcp(ident: dict) -> tuple[str, str]:
    """
    Verify Google's signed instance identity JWT against Google's published
    keys. Returns (node_id, proof). No shared secret; the audience must match
    what the agent requested, which stops a token minted for another service
    being replayed here.
    """
    global _gcp_jwks
    token = ident.get("identity_jwt")
    if not token:
        raise HTTPException(400, "gcp identity token missing")

    if _gcp_jwks is None:
        _gcp_jwks = jwt.PyJWKClient(GOOGLE_JWKS)

    try:
        key = _gcp_jwks.get_signing_key_from_jwt(token).key
        claims = jwt.decode(token, key, algorithms=["RS256"], audience=GCP_AUDIENCE)
    except Exception as e:
        log.warning("gcp identity verification failed: %s", e)
        raise HTTPException(403, "gcp identity token is not valid")

    google = claims.get("google", {}).get("compute_engine", {})
    node_id = str(google.get("instance_id") or claims.get("sub") or "")
    if not node_id:
        raise HTTPException(400, "gcp token carries no instance id")
    if ident.get("node_id") and str(ident["node_id"]) != node_id:
        raise HTTPException(403, "gcp token does not match claimed instance")
    return node_id, "signed"


def verify_azure(ident: dict) -> tuple[str, str]:
    """
    Azure's attested document is a PKCS7 signature over the vmId and nonce.
    Verifying it needs the Azure certificate chain; when no certificate is
    configured we fall back to token-only trust and say so rather than
    claiming a verification that did not happen.
    """
    node_id = ident.get("node_id")
    if not node_id:
        raise HTTPException(400, "azure identity missing vmId")

    sig = ident.get("attested_signature")
    if not sig or not AZURE_CERT_PATH or not os.path.exists(AZURE_CERT_PATH):
        return node_id, "token"

    body = "-----BEGIN PKCS7-----\n" + sig.strip() + "\n-----END PKCS7-----\n"
    with tempfile.TemporaryDirectory() as tmp:
        sig_path = os.path.join(tmp, "sig.pem")
        with open(sig_path, "w") as f:
            f.write(body)
        proc = subprocess.run(
            ["openssl", "cms", "-verify", "-in", sig_path, "-inform", "PEM",
             "-CAfile", AZURE_CERT_PATH, "-purpose", "any"],
            capture_output=True, text=True, timeout=10,
        )
    if proc.returncode != 0:
        log.warning("azure attestation failed for %s: %s", node_id, proc.stderr[:200])
        raise HTTPException(403, "azure attested document is not valid")
    if node_id not in proc.stdout:
        raise HTTPException(403, "azure attestation does not match claimed vmId")
    return node_id, "signed"


def verify_generic(ident: dict, conn) -> tuple[str, str, bool, str | None]:
    """
    Nothing vouches for an on-premise host, so an enrolment token is required
    to introduce one. Returns (node_id, proof, is_returning, tenant_id).

    A returning node does NOT need a token. Agents re-enrol whenever their
    short-lived JWT expires - every 15 minutes - and tokens are single use,
    so demanding one every time would lock a host out permanently on its
    first renewal. The token is an invitation to join; the machine id is the
    evidence of continuity afterwards - which is also why tenant_id for a
    returning node comes from its existing row rather than a fresh token: a
    machine id collision between two different tenants' hosts is the same
    astronomically unlikely event as a UUID collision (machine ids are
    cryptographically random on modern systems), the same residual risk
    already accepted for agents.instance_id's uniqueness elsewhere.
    """
    node_id = ident.get("machine_id") or ident.get("node_id")
    if not node_id:
        raise HTTPException(400, "generic host sent no machine id")

    prev = conn.execute(
        "select machine_id, fingerprint, tenant_id from agents where instance_id = %s",
        (node_id,),
    ).fetchone()

    if prev is None:
        return node_id, "token", False, None

    # For a generic host the node id IS the machine id, so a different
    # machine is simply a different node and needs its own invitation. What
    # a returning node can still be checked against is its hardware
    # fingerprint: same machine id but a different board serial or product
    # UUID means the identifier was copied onto another box.
    old = prev[1] or {}
    new = ident.get("fingerprint") or {}
    for field in ("product_uuid", "board_serial"):
        was, now_ = old.get(field), new.get(field)
        if was and now_ and was != now_:
            log.warning("fingerprint mismatch for %s: %s changed", node_id, field)
            raise HTTPException(
                403,
                f"hardware fingerprint changed for a known node ({field}); "
                "delete it from the dashboard and enrol it again if this is expected",
            )

    return node_id, "token", True, prev[2]


@app.post("/v1/enroll")
def enroll(body: EnrollBody, request: Request):
    if not enroll_ip_limiter.allow(client_ip(request)):
        raise HTTPException(429, "too many enrolment attempts from this address")

    # Accept both shapes: the new provider envelope, and the older AWS-only
    # payload from an agent that has not been upgraded yet.
    ident = body.identity or {
        "provider": "aws",
        "node_id": (body.document or {}).get("instanceId"),
        "region": (body.document or {}).get("region"),
        "account": (body.document or {}).get("accountId"),
        "instance_type": (body.document or {}).get("instanceType"),
        "document": body.document,
        "document_raw": body.document_raw,
        "pkcs7": body.pkcs7,
    }
    provider = ident.get("provider", "aws")
    if provider not in ("aws", "gcp", "azure", "generic"):
        raise HTTPException(400, f"unknown provider {provider!r}")

    # Cloud-attested providers re-prove themselves on every enrolment, but a
    # token is single-use. Spending it on every call - not just the first -
    # means an operator who supplies one at install time (the README shows
    # this for every platform) gets a host that fails every re-enrolment
    # after the first, since the JWT expires every JWT_TTL_MIN and the
    # re-sent token has already been consumed. Refined below to true first
    # contact once node_id is known.
    first_contact = True
    tenant_id = None

    with pool.connection() as conn:
        if provider == "aws":
            doc = ident.get("document") or {}
            node_id = doc.get("instanceId") or ident.get("node_id")
            if not node_id:
                raise HTTPException(400, "missing instanceId")
            signed = verify_pkcs7(doc, ident.get("document_raw"), ident.get("pkcs7"))
            if signed and ident.get("document_raw"):
                try:
                    if json.loads(ident["document_raw"]).get("instanceId") != node_id:
                        raise HTTPException(403, "signed document does not match claimed instance")
                except json.JSONDecodeError:
                    raise HTTPException(400, "raw identity document is not valid JSON")
            verify_instance(doc, client_ip(request))
            proof = "signed" if signed else ("account" if VERIFY_MODE == "aws" else "unverified")

        elif provider == "gcp":
            node_id, proof = verify_gcp(ident)

        elif provider == "azure":
            node_id, proof = verify_azure(ident)

        else:
            node_id, proof, returning, tenant_id = verify_generic(ident, conn)
            if not returning and not body.enroll_token:
                # An unattested host must be invited the first time, whatever
                # the global setting says.
                raise HTTPException(403, "on-premise nodes require an enrolment token")
            # Already introduced: its machine id is the credential now. Do not
            # try to spend the token still sitting in its unit file.
            first_contact = not returning

        if provider != "generic":
            # aws/gcp/azure prove identity fresh every time, but the token is
            # still single-use: only spend it the first time this instance_id
            # is seen, the same way the generic branch already does. A
            # returning node's tenant is whatever it already belongs to, not
            # re-derived from a token it isn't sending.
            known = conn.execute(
                "select tenant_id from agents where instance_id = %s", (str(node_id),)
            ).fetchone()
            first_contact = known is None
            if known is not None:
                tenant_id = known[0]

        if first_contact:
            # The only source of tenant_id for a genuinely new host: which
            # tenant issued the token it showed up with.
            tenant_id = consume_token(conn, body.enroll_token, node_id)

        cur = conn.cursor(row_factory=dict_row)
        row = cur.execute(
            """
            insert into agents (instance_id, provider, platform, account_id, account,
                                region, instance_type, hostname, os, agent_version,
                                machine_id, fingerprint, identity_proof, last_seen,
                                tenant_id)
            values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, now(), %s)
            on conflict (tenant_id, instance_id) do update set
                hostname       = excluded.hostname,
                os             = excluded.os,
                agent_version  = excluded.agent_version,
                region         = excluded.region,
                instance_type  = excluded.instance_type,
                provider       = excluded.provider,
                platform       = excluded.platform,
                account        = excluded.account,
                machine_id     = coalesce(excluded.machine_id, agents.machine_id),
                fingerprint    = excluded.fingerprint,
                identity_proof = excluded.identity_proof,
                enrolled_at    = now(),
                enroll_count   = agents.enroll_count + 1
            returning id
            """,
            (str(node_id), provider,
             ident.get("platform") if ident.get("platform") in ("linux","windows","macos") else "linux",
             ident.get("account") if provider == "aws" else None,
             ident.get("account"), ident.get("region"), ident.get("instance_type"),
             body.hostname, body.os, body.agent_version,
             ident.get("machine_id"),
             json.dumps(ident.get("fingerprint")) if ident.get("fingerprint") else None,
             proof, tenant_id),
        ).fetchone()

    log.info("enrolled %s [%s, proof=%s] (%s)", node_id, provider, proof, body.hostname)
    return {"token": issue_token(row["id"], str(node_id)),
            "agent_id": str(row["id"]), "provider": provider, "identity_proof": proof}


@app.post("/v1/ingest")
def ingest(body: IngestBody, authorization: str | None = Header(default=None)):
    agent_id = agent_from_token(authorization)

    # Cheap check before any DB work: one misbehaving host retrying in a
    # tight loop shouldn't cost a connection-pool checkout every time.
    if not ingest_agent_limiter.allow(agent_id):
        raise HTTPException(429, "too many requests from this agent")

    counts = {"heartbeat": 0, "auth": 0, "ports": 0, "port_changes": 0, "checks": 0, "users": 0, "user_changes": 0, "fim": 0, "packages": 0, "interfaces": 0, "apps": 0, "virt": 0}

    with pool.connection() as conn:
        # Every event in this batch is from the same agent, so its tenant is
        # resolved once, from the agents row itself (denormalized there at
        # enrolment) rather than trusted from a client-supplied claim.
        tenant_row = conn.execute(
            "select tenant_id from agents where id = %s", (agent_id,)
        ).fetchone()
        if tenant_row is None:
            raise HTTPException(401, "unknown agent")
        tenant_id = tenant_row[0]

        # Costed by event count, not request count: a batch of 500 events
        # is real aggregate load on this tenant's slice of the process,
        # even from a single well-behaved request.
        if not ingest_tenant_limiter.allow(str(tenant_id), cost=max(1, len(body.events))):
            raise HTTPException(429, "this tenant's ingest rate limit was exceeded")

        for ev in body.events:
            ts = datetime.fromtimestamp(ev.ts, tz=timezone.utc)

            if ev.kind == "heartbeat":
                d = ev.data
                conn.execute(
                    """
                    insert into metrics (agent_id, ts, cpu_pct, mem_pct, disk_pct,
                                         load1, uptime_s, proc_count, tenant_id)
                    values (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    on conflict (agent_id, ts) do nothing
                    """,
                    (agent_id, ts, d.get("cpu_pct"), d.get("mem_pct"),
                     d.get("disk_pct"), d.get("load1"), d.get("uptime_s"),
                     d.get("proc_count"), tenant_id),
                )
                counts["heartbeat"] += 1

            elif ev.kind == "auth":
                d = ev.data
                conn.execute(
                    """
                    insert into auth_events (agent_id, ts, kind, username, source_ip, raw, tenant_id)
                    values (%s, %s, %s, %s, %s, %s, %s)
                    on conflict do nothing
                    """,
                    (agent_id,
                     datetime.fromtimestamp(d.get("ts", ev.ts), tz=timezone.utc),
                     d.get("kind"), d.get("username"), d.get("source_ip"),
                     d.get("raw"), tenant_id),
                )
                counts["auth"] += 1

            elif ev.kind == "ports":
                counts["port_changes"] += diff_ports(
                    conn, agent_id, ts, ev.data.get("listening", []), tenant_id
                )
                counts["ports"] += 1

            elif ev.kind == "users":
                counts["users"] += 1
                counts["user_changes"] += diff_users(
                    conn, agent_id, ts, ev.data.get("accounts", []), tenant_id
                )

            elif ev.kind == "interfaces":
                counts["interfaces"] += sync_interfaces(
                    conn, agent_id, ts, ev.data.get("interfaces", []), tenant_id)

            elif ev.kind == "apps":
                counts["apps"] += sync_apps(conn, agent_id, ts, ev.data.get("apps", []), tenant_id)

            elif ev.kind == "fim":
                counts["fim"] += sync_fim(conn, agent_id, ts, ev.data, tenant_id)

            elif ev.kind == "packages":
                counts["packages"] += sync_packages(
                    conn, agent_id, ts, ev.data.get("packages", []), tenant_id)

            elif ev.kind == "checks":
                counts["checks"] += sync_checks(
                    conn, agent_id, ts, ev.data.get("results", []), tenant_id
                )

            elif ev.kind == "virt":
                counts["virt"] += sync_virt(conn, agent_id, ev.data)

        # last_seen is the single source of truth for health. Update it once
        # per batch, from the server clock, never from agent-reported time.
        conn.execute("update agents set last_seen = now() where id = %s", (agent_id,))

    return {"accepted": len(body.events), **counts}


def diff_ports(conn, agent_id: str, ts: datetime, listening: list, tenant_id: str) -> int:
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
                   (agent_id, ts, port, proto, bind_addr, external, process, action, tenant_id)
                   values (%s, %s, %s, %s, %s, %s, %s, 'opened', %s)""",
                (agent_id, ts, p["port"], p["proto"], p["bind_addr"],
                 p.get("external", False), p.get("process"), tenant_id),
            )
            changes += 1
        conn.execute(
            """
            insert into port_state (agent_id, port, proto, bind_addr, external,
                                    pid, process, last_seen, tenant_id)
            values (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            on conflict (agent_id, port, proto, bind_addr) do update set
                last_seen = excluded.last_seen,
                pid       = excluded.pid,
                process   = excluded.process,
                external  = excluded.external
            """,
            (agent_id, p["port"], p["proto"], p["bind_addr"],
             p.get("external", False), p.get("pid"), p.get("process"), ts, tenant_id),
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
               (agent_id, ts, port, proto, bind_addr, external, process, action, tenant_id)
               values (%s, %s, %s, %s, %s, %s, %s, 'closed', %s)""",
            (agent_id, ts, port, proto, bind,
             row[0] if row else False, row[1] if row else None, tenant_id),
        )
        conn.execute(
            """delete from port_state
               where agent_id = %s and port = %s and proto = %s and bind_addr = %s""",
            (agent_id, port, proto, bind),
        )
        changes += 1

    return changes


def sync_checks(conn, agent_id: str, ts: datetime, results: list, tenant_id: str) -> int:
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
             c.get("detail"), ts, tenant_id))
    if crows:
        conn.cursor().executemany(
            """
            insert into host_checks (agent_id, check_id, title, category,
                                     severity, status, detail, last_seen, tenant_id)
            values (%s, %s, %s, %s, %s, %s, %s, %s, %s)
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


def diff_users(conn, agent_id: str, ts: datetime, accounts: list, tenant_id: str) -> int:
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
                    """insert into user_events (agent_id, ts, username, action, uid, sudoer, detail, tenant_id)
                       values (%s, %s, %s, 'added', %s, %s, %s, %s)""",
                    (agent_id, ts, name, a.get("uid"), a.get("sudoer", False),
                     f"uid {a.get('uid')}, shell {a.get('shell')}, "
                     f"{'sudoer' if a.get('sudoer') else 'unprivileged'}, "
                     f"password {a.get('password')}", tenant_id),
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
                    """insert into user_events (agent_id, ts, username, action, uid, sudoer, detail, tenant_id)
                       values (%s, %s, %s, 'modified', %s, %s, %s, %s)""",
                    (agent_id, ts, name, a.get("uid"), a.get("sudoer", False),
                     "; ".join(diffs)[:400], tenant_id),
                )
                changes += 1

        rows.append((agent_id, name, a.get("uid"), a.get("gid"), a.get("shell"),
                     a.get("home"), a.get("groups", []), a.get("sudoer", False),
                     a.get("can_login", False), a.get("password"), ts, tenant_id))

    # One pipelined round trip instead of one per account. Latency to a
    # cross-region database makes per-row writes untenable: 24 accounts was
    # 24 round trips, which exceeded the agent's request timeout.
    if rows:
        conn.cursor().executemany(
            """
            insert into user_state (agent_id, username, uid, gid, shell, home,
                                    groups, sudoer, can_login, password, last_seen, tenant_id)
            values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            on conflict (agent_id, username) do update set
                uid = excluded.uid, gid = excluded.gid, shell = excluded.shell,
                home = excluded.home, groups = excluded.groups,
                sudoer = excluded.sudoer, can_login = excluded.can_login,
                password = excluded.password, last_seen = excluded.last_seen
            """, rows)

    for name in set(known) - set(snap):
        prev = known[name]
        conn.execute(
            """insert into user_events (agent_id, ts, username, action, uid, sudoer, detail, tenant_id)
               values (%s, %s, %s, 'removed', %s, %s, %s, %s)""",
            (agent_id, ts, name, prev.get("uid"), prev.get("sudoer", False),
             f"was uid {prev.get('uid')}, shell {prev.get('shell')}", tenant_id),
        )
        conn.execute("delete from user_state where agent_id = %s and username = %s",
                     (agent_id, name))
        changes += 1

    return changes


def sync_fim(conn, agent_id: str, ts: datetime, data: dict, tenant_id: str) -> int:
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
        insert into fim_state (agent_id, files_watched, digest, paths, last_scan, tenant_id)
        values (%s, %s, %s, %s, %s, %s)
        on conflict (agent_id) do update set
            files_watched = excluded.files_watched,
            digest        = excluded.digest,
            paths         = excluded.paths,
            last_scan     = excluded.last_scan
        """,
        (agent_id, summary.get("files_watched", 0), summary.get("digest"),
         summary.get("paths", []), ts, tenant_id),
    )

    if not events:
        return 0

    conn.cursor().executemany(
        """insert into fim_events
           (agent_id, ts, path, action, critical, sha256, mode, size, detail, tenant_id)
           values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
        [(agent_id, ts, e.get("path"), e.get("action"), e.get("critical", False),
          e.get("sha256"), e.get("mode"), e.get("size"), e.get("detail"), tenant_id)
         for e in events if e.get("path") and e.get("action")],
    )
    return len(events)


def sync_packages(conn, agent_id: str, ts: datetime, packages: list, tenant_id: str) -> int:
    """Replace the host's package inventory. OSV lookup happens separately."""
    if not packages:
        return 0

    rows = [(agent_id, p["name"], p["version"], p.get("arch"), ts, tenant_id)
            for p in packages if p.get("name") and p.get("version")]

    conn.cursor().executemany(
        """
        insert into host_packages (agent_id, name, version, arch, last_seen, tenant_id)
        values (%s, %s, %s, %s, %s, %s)
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


def sync_interfaces(conn, agent_id: str, ts: datetime, ifaces: list, tenant_id: str) -> int:
    """
    Current interface state plus a counter sample. State is upserted so the
    inventory reflects now; counters are appended so throughput can be
    derived from consecutive samples server-side.
    """
    if not ifaces:
        return 0

    rows = [(agent_id, i.get("name"), bool(i.get("is_up")), i.get("speed_mbps"),
             i.get("mtu"), i.get("ipv4"), i.get("mac"), ts, tenant_id)
            for i in ifaces if i.get("name")]

    conn.cursor().executemany(
        """
        insert into net_interfaces (agent_id, name, is_up, speed_mbps, mtu,
                                    ipv4, mac, last_seen, tenant_id)
        values (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        on conflict (agent_id, name) do update set
            is_up = excluded.is_up, speed_mbps = excluded.speed_mbps,
            mtu = excluded.mtu, ipv4 = excluded.ipv4, mac = excluded.mac,
            last_seen = excluded.last_seen
        """, rows)

    conn.cursor().executemany(
        """
        insert into net_traffic (agent_id, name, ts, bytes_sent, bytes_recv,
                                 packets_sent, packets_recv,
                                 errin, errout, dropin, dropout, tenant_id)
        values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        on conflict (agent_id, name, ts) do nothing
        """,
        [(agent_id, i.get("name"), ts, i.get("bytes_sent"), i.get("bytes_recv"),
          i.get("packets_sent"), i.get("packets_recv"), i.get("errin"),
          i.get("errout"), i.get("dropin"), i.get("dropout"), tenant_id)
         for i in ifaces if i.get("name")])

    # An interface that disappeared was removed or renamed; leaving it would
    # show a phantom NIC as permanently down.
    conn.execute(
        "delete from net_interfaces where agent_id = %s and name <> all(%s)",
        (agent_id, [i["name"] for i in ifaces if i.get("name")]))

    return len(rows)


def sync_apps(conn, agent_id: str, ts: datetime, apps: list, tenant_id: str) -> int:
    """
    Application measurements read locally by the agent. Only IIS today. The
    row is keyed by agent and app name rather than a probe, since there is no
    probe polling it.
    """
    if not apps:
        return 0
    rows = [(agent_id, a.get("app_name"), ts,
             a.get("requests_total"), a.get("errors_total"),
             a.get("active_conns"), json.dumps(a.get("extra") or {}), tenant_id)
            for a in apps if a.get("app_name")]
    if not rows:
        return 0
    conn.cursor().executemany(
        """
        insert into app_metrics (agent_id, app_name, ts, requests_total,
                                 errors_total, active_conns, extra, tenant_id)
        values (%s, %s, %s, %s, %s, %s, %s, %s)
        on conflict do nothing
        """, rows)
    return len(rows)


def sync_virt(conn, agent_id: str, data: dict) -> int:
    """
    Virtualisation role. Stored on the agent row rather than as a time series
    because it changes when someone rebuilds a machine, not minute to minute.
    """
    role = data.get("role")
    if role not in ("physical", "type1_host", "type2_host", "guest"):
        return 0
    conn.execute(
        """update agents set virt_role = %s, hypervisor = %s, virt_detail = %s
            where id = %s""",
        (role, data.get("hypervisor"), json.dumps(data), agent_id))
    return 1


# ---------------------------------------------------------------- probe runner
#
# Everything below is phase 2 of multi-tenancy: the probe runner
# (probe/prober.py) used to hold NW_DATABASE_URL, a service-role credential
# that bypasses RLS and can read/write every tenant's data - unsafe to run
# on a customer's own infrastructure. It now enrols and authenticates
# exactly like an agent does, and these five endpoints are the only way it
# ever touches the database: everything it used to do with direct SQL
# (select probes/probe_secrets, insert results, claim nettool/automation
# jobs) goes through here instead, tenant-scoped from the caller's JWT,
# never from a client-supplied tenant_id.

@app.post("/v1/probe-enroll")
def probe_enroll(body: ProbeEnrollBody, request: Request):
    if not enroll_ip_limiter.allow(client_ip(request)):
        raise HTTPException(429, "too many enrolment attempts from this address")

    with pool.connection() as conn:
        # client_id is a locally-generated UUID (128 bits, not derived from
        # anything guessable), so a bare lookup - not yet scoped to a
        # tenant, since enrolling for the first time means there is none
        # yet - carries the same negligible collision risk already accepted
        # for a generic agent's machine_id in verify_generic().
        existing = conn.execute(
            "select tenant_id from master_nodes where client_id = %s", (body.client_id,)
        ).fetchone()

        if existing is not None:
            tenant_id = existing[0]
        else:
            tenant_id = consume_token(conn, body.enroll_token, body.client_id, kind="probe_runner")

        cur = conn.cursor(row_factory=dict_row)
        row = cur.execute(
            """
            insert into master_nodes (tenant_id, client_id, label, hostname, version, last_seen, enroll_count)
            values (%s, %s, %s, %s, %s, now(), 1)
            on conflict (tenant_id, client_id) do update set
                label        = excluded.label,
                hostname     = excluded.hostname,
                version      = excluded.version,
                last_seen    = now(),
                enroll_count = master_nodes.enroll_count + 1
            returning id
            """,
            (tenant_id, body.client_id, body.label, body.hostname, body.version),
        ).fetchone()

    log.info("probe runner enrolled: client_id=%s master_node_id=%s", body.client_id, row["id"])
    return {"token": issue_probe_token(row["id"]), "master_node_id": str(row["id"])}


@app.get("/v1/probes")
def list_probes(authorization: str | None = Header(default=None)):
    master_node_id = master_node_from_token(authorization)
    if not probe_node_limiter.allow(master_node_id):
        raise HTTPException(429, "too many requests from this master node")

    with pool.connection() as conn:
        tenant_row = conn.execute(
            "select tenant_id from master_nodes where id = %s", (master_node_id,)
        ).fetchone()
        if tenant_row is None:
            raise HTTPException(401, "unknown master node")
        tenant_id = tenant_row[0]
        conn.execute("update master_nodes set last_seen = now() where id = %s", (master_node_id,))

        cur = conn.cursor(row_factory=dict_row)
        probes = cur.execute(
            """
            select p.id::text, p.kind, p.name, p.target, p.port,
                   p.interval_s, p.timeout_ms, p.expect_status,
                   p.expect_text, s.config
              from probes p
              left join probe_secrets s on s.probe_id = p.id
             where p.enabled and p.tenant_id = %s
            """,
            (tenant_id,),
        ).fetchall()

    return {"probes": probes}


@app.post("/v1/probe-results")
def probe_results(body: ProbeResultsBody, authorization: str | None = Header(default=None)):
    master_node_id = master_node_from_token(authorization)
    ts = datetime.fromtimestamp(body.ts, tz=timezone.utc)

    with pool.connection() as conn:
        tenant_row = conn.execute(
            "select tenant_id from master_nodes where id = %s", (master_node_id,)
        ).fetchone()
        if tenant_row is None:
            raise HTTPException(401, "unknown master node")
        tenant_id = tenant_row[0]
        conn.execute("update master_nodes set last_seen = now() where id = %s", (master_node_id,))

        if not probe_node_limiter.allow(master_node_id, cost=max(1, len(body.results))):
            raise HTTPException(429, "too many requests from this master node")
        if not ingest_tenant_limiter.allow(str(tenant_id), cost=max(1, len(body.results))):
            raise HTTPException(429, "this tenant's ingest rate limit was exceeded")

        # A master node only ever reports on its own tenant's probes -
        # verified here, not trusted from the request, in case a
        # compromised or misconfigured runner sends a probe_id it merely
        # guessed or cached stale from before a probe was reassigned.
        ids = [r.probe_id for r in body.results]
        valid = {row[0] for row in conn.execute(
            "select id::text from probes where id = any(%s) and tenant_id = %s",
            (ids, tenant_id),
        ).fetchall()}
        results = [r for r in body.results if r.probe_id in valid]
        dropped = len(body.results) - len(results)
        if dropped:
            log.warning("master node %s: dropped %d results for probes outside its tenant",
                        master_node_id, dropped)
        if not results:
            return {"accepted": 0}

        conn.cursor().executemany(
            """insert into probe_results (probe_id, ts, ok, latency_ms, detail, tenant_id)
               values (%s, %s, %s, %s, %s, %s)
               on conflict (probe_id, ts) do nothing""",
            [(r.probe_id, ts, r.ok, r.latency_ms, r.detail, tenant_id) for r in results],
        )

        dbrows = [
            (r.probe_id, ts, r.metrics.get("connections"), r.metrics.get("max_connections"),
             r.metrics.get("conn_pct"), r.metrics.get("cache_hit_pct"),
             r.metrics.get("slow_queries"), r.metrics.get("longest_query_s"),
             r.metrics.get("replication_lag_s"), r.metrics.get("size_bytes"),
             r.metrics.get("uptime_s"), r.metrics.get("qps"),
             json.dumps(r.metrics.get("extra") or {}), tenant_id)
            for r in results if r.ok and r.metrics
        ]
        if dbrows:
            conn.cursor().executemany(
                """insert into db_metrics (probe_id, ts, connections,
                       max_connections, conn_pct, cache_hit_pct,
                       slow_queries, longest_query_s, replication_lag_s,
                       size_bytes, uptime_s, qps, extra, tenant_id)
                   values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   on conflict (probe_id, ts) do nothing""",
                dbrows)

        approws = [
            (r.probe_id, ts, r.app_metrics.get("requests_total"), r.app_metrics.get("errors_total"),
             r.app_metrics.get("active_conns"), r.app_metrics.get("p95_latency_s"),
             r.app_metrics.get("avg_latency_s"), r.app_metrics.get("memory_bytes"),
             r.app_metrics.get("cpu_seconds"), r.app_metrics.get("uptime_s"),
             json.dumps(r.app_metrics.get("extra") or {}), tenant_id)
            for r in results if r.ok and r.app_metrics
        ]
        if approws:
            # app_metrics_key (024_iis.sql) is a coalesce()-based expression
            # index, not a plain (probe_id, ts) unique constraint - it has
            # to allow either probe_id or agent_id to be null, since IIS
            # metrics come from the agent while everything else here comes
            # from a probe. ON CONFLICT inference requires an exact
            # expression match, not just matching column names.
            conn.cursor().executemany(
                """insert into app_metrics (probe_id, ts, requests_total,
                       errors_total, active_conns, p95_latency_s,
                       avg_latency_s, memory_bytes, cpu_seconds,
                       uptime_s, extra, tenant_id)
                   values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   on conflict (
                       (coalesce(probe_id, '00000000-0000-0000-0000-000000000000'::uuid)),
                       (coalesce(agent_id, '00000000-0000-0000-0000-000000000000'::uuid)),
                       (coalesce(app_name, '')),
                       ts
                   ) do nothing""",
                approws)

        # Proxmox attaches guests, storage and backups alongside the
        # cluster-level metrics row - four writes instead of one.
        pxrows = [(r.probe_id, r.proxmox) for r in results if r.ok and r.proxmox]
        if pxrows:
            conn.cursor().executemany(
                """insert into proxmox_metrics (probe_id, ts, nodes_total,
                       nodes_online, guests_total, guests_running, cpu_pct,
                       mem_pct, storage_pct_worst, backups_failed_24h, extra,
                       tenant_id)
                   values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   on conflict (probe_id, ts) do nothing""",
                [(pid, ts, m["nodes_total"], m["nodes_online"],
                  m["guests_total"], m["guests_running"], m["cpu_pct"],
                  m["mem_pct"], m["storage_pct_worst"], m["backups_failed_24h"],
                  json.dumps(m.get("extra") or {}), tenant_id)
                 for pid, px in pxrows for m in [px["metrics"]]])

            guest_rows = [(pid, g["vmid"], g["node"], g["name"], g["kind"],
                           g["status"], g["cpu_pct"], g["mem_bytes"],
                           g["mem_max_bytes"], g["disk_bytes"],
                           g["disk_max_bytes"], g["uptime_s"], ts, tenant_id)
                          for pid, px in pxrows for g in px["guests"]]
            if guest_rows:
                conn.cursor().executemany(
                    """insert into proxmox_guests (probe_id, vmid, node, name,
                           kind, status, cpu_pct, mem_bytes, mem_max_bytes,
                           disk_bytes, disk_max_bytes, uptime_s, last_seen, tenant_id)
                       values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                       on conflict (probe_id, vmid) do update set
                           node = excluded.node, name = excluded.name,
                           status = excluded.status, cpu_pct = excluded.cpu_pct,
                           mem_bytes = excluded.mem_bytes,
                           mem_max_bytes = excluded.mem_max_bytes,
                           disk_bytes = excluded.disk_bytes,
                           disk_max_bytes = excluded.disk_max_bytes,
                           uptime_s = excluded.uptime_s,
                           last_seen = excluded.last_seen""",
                    guest_rows)
                # A guest that disappeared was deleted or migrated off this
                # cluster; leaving it would show a phantom VM forever.
                for pid, px in pxrows:
                    seen = [g["vmid"] for g in px["guests"]]
                    conn.execute(
                        "delete from proxmox_guests where probe_id = %s and vmid <> all(%s)",
                        (pid, seen or [-1]))

            storage_rows = [(pid, s["node"], s["storage"], s["kind"],
                             s["used_bytes"], s["total_bytes"], ts, tenant_id)
                            for pid, px in pxrows for s in px["storage"]]
            if storage_rows:
                conn.cursor().executemany(
                    """insert into proxmox_storage (probe_id, node, storage,
                           kind, used_bytes, total_bytes, last_seen, tenant_id)
                       values (%s,%s,%s,%s,%s,%s,%s,%s)
                       on conflict (probe_id, node, storage) do update set
                           kind = excluded.kind, used_bytes = excluded.used_bytes,
                           total_bytes = excluded.total_bytes,
                           last_seen = excluded.last_seen""",
                    storage_rows)

            backup_rows = [
                (pid, b["upid"], b["vmid"], b["node"],
                 datetime.fromtimestamp(b["ts"], tz=timezone.utc), b["ok"],
                 b["duration_s"], b["detail"], tenant_id)
                for pid, px in pxrows for b in px["backups"] if b.get("ts")
            ]
            if backup_rows:
                conn.cursor().executemany(
                    """insert into proxmox_backups (probe_id, upid, vmid, node,
                           ts, ok, duration_s, detail, tenant_id)
                       values (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                       on conflict (probe_id, upid) do nothing""",
                    backup_rows)

        # Supply-chain attaches a scan rollup plus its current findings,
        # upserted like host_checks - what's wrong right now, not a
        # growing log of the same CVE reappearing on every scan.
        scrows = [(r.probe_id, r.supply_chain) for r in results if r.ok and r.supply_chain]
        if scrows:
            conn.cursor().executemany(
                """insert into supply_chain_scans (probe_id, ts, risk_score,
                       severity, recommendation, finding_count, scan_mode,
                       target_kind, extra, tenant_id)
                   values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   on conflict (probe_id, ts) do nothing""",
                [(pid, ts, s["scan"]["risk_score"], s["scan"]["severity"],
                  s["scan"]["recommendation"], s["scan"]["finding_count"],
                  s["scan"]["scan_mode"], s["scan"].get("target_kind", "repo"),
                  json.dumps(s["scan"].get("extra") or {}), tenant_id)
                 for pid, s in scrows])

            finding_rows = [(pid, f["rule_id"], f["category"], f["severity"],
                             f["message"], f["location"], ts, ts, tenant_id)
                            for pid, s in scrows for f in s["findings"]]
            if finding_rows:
                conn.cursor().executemany(
                    """insert into supply_chain_findings (probe_id, rule_id,
                           category, severity, message, location,
                           first_seen, last_seen, tenant_id)
                       values (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                       on conflict (probe_id, rule_id) do update set
                           category = excluded.category, severity = excluded.severity,
                           message = excluded.message, location = excluded.location,
                           last_seen = excluded.last_seen""",
                    finding_rows)
            # A finding that's gone was fixed or the dependency was
            # removed; leaving it would freeze a stale CVE in place.
            for pid, s in scrows:
                seen = [f["rule_id"] for f in s["findings"]]
                conn.execute(
                    "delete from supply_chain_findings where probe_id = %s and rule_id <> all(%s)",
                    (pid, seen or ["-"]))

        # TLS certificate detail attaches to https url checks independent
        # of whether the check itself passed - a broken chain is exactly
        # the case worth still recording, not just "unreachable".
        tlsrows = [(r.probe_id, r.tls_cert) for r in results if r.tls_cert]
        if tlsrows:
            conn.cursor().executemany(
                """insert into tls_cert_scans (probe_id, ts, subject, issuer,
                       not_before, not_after, days_remaining, chain_valid,
                       chain_error, tenant_id)
                   values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   on conflict (probe_id, ts) do nothing""",
                [(pid, ts, tc["subject"], tc["issuer"], tc["not_before"],
                  tc["not_after"], tc["days_remaining"], tc["chain_valid"],
                  tc["chain_error"], tenant_id)
                 for pid, tc in tlsrows])

    return {"accepted": len(results)}


@app.post("/v1/route-hops")
def route_hops(body: RouteHopsBody, authorization: str | None = Header(default=None)):
    master_node_id = master_node_from_token(authorization)
    if not probe_node_limiter.allow(master_node_id):
        raise HTTPException(429, "too many requests from this master node")

    with pool.connection() as conn:
        tenant_row = conn.execute(
            "select tenant_id from master_nodes where id = %s", (master_node_id,)
        ).fetchone()
        if tenant_row is None:
            raise HTTPException(401, "unknown master node")
        tenant_id = tenant_row[0]

        owned = conn.execute(
            "select 1 from probes where id = %s and tenant_id = %s",
            (body.probe_id, tenant_id),
        ).fetchone()
        if owned is None:
            raise HTTPException(403, "probe does not belong to this master node's tenant")

        traced_at = datetime.fromtimestamp(body.traced_at, tz=timezone.utc)
        conn.cursor().executemany(
            """insert into route_hops (probe_id, traced_at, hop, ip, rtt_ms, tenant_id)
               values (%s, %s, %s, %s, %s, %s)
               on conflict (probe_id, traced_at, hop) do nothing""",
            [(body.probe_id, traced_at, h.hop, h.ip, h.rtt_ms, tenant_id) for h in body.hops],
        )

    return {"accepted": len(body.hops)}


@app.post("/v1/nettool-jobs/claim")
def claim_nettool_jobs(body: ClaimBody, authorization: str | None = Header(default=None)):
    master_node_id = master_node_from_token(authorization)
    if not probe_node_limiter.allow(master_node_id):
        raise HTTPException(429, "too many requests from this master node")

    with pool.connection() as conn:
        tenant_row = conn.execute(
            "select tenant_id from master_nodes where id = %s", (master_node_id,)
        ).fetchone()
        if tenant_row is None:
            raise HTTPException(401, "unknown master node")
        tenant_id = tenant_row[0]

        cur = conn.cursor(row_factory=dict_row)
        jobs = cur.execute(
            """
            update nettool_jobs set status = 'running', started_at = now()
             where id in (select id from nettool_jobs
                           where status = 'queued' and tenant_id = %s
                           order by created_at limit %s)
            returning id::text, tool, target, options
            """,
            (tenant_id, body.limit),
        ).fetchall()

    return {"jobs": jobs}


@app.post("/v1/nettool-jobs/{job_id}/complete")
def complete_nettool_job(job_id: str, body: NettoolCompleteBody,
                          authorization: str | None = Header(default=None)):
    master_node_id = master_node_from_token(authorization)

    with pool.connection() as conn:
        tenant_row = conn.execute(
            "select tenant_id from master_nodes where id = %s", (master_node_id,)
        ).fetchone()
        if tenant_row is None:
            raise HTTPException(401, "unknown master node")
        tenant_id = tenant_row[0]

        row = conn.execute(
            """update nettool_jobs
                  set status = %s, output = %s, duration_ms = %s, finished_at = now()
                where id = %s and tenant_id = %s
              returning id""",
            (body.status, body.output, body.duration_ms, job_id, tenant_id),
        ).fetchone()
        if row is None:
            raise HTTPException(404, "job not found")

    return {"ok": True}


@app.post("/v1/automation-runs/claim")
def claim_automation_runs(body: ClaimBody, authorization: str | None = Header(default=None)):
    master_node_id = master_node_from_token(authorization)
    if not probe_node_limiter.allow(master_node_id):
        raise HTTPException(429, "too many requests from this master node")

    with pool.connection() as conn:
        tenant_row = conn.execute(
            "select tenant_id from master_nodes where id = %s", (master_node_id,)
        ).fetchone()
        if tenant_row is None:
            raise HTTPException(401, "unknown master node")
        tenant_id = tenant_row[0]

        cur = conn.cursor(row_factory=dict_row)
        runs = cur.execute(
            """
            update automation_runs set status = 'running'
             where id in (select id from automation_runs
                           where status = 'approved' and tenant_id = %s
                           order by created_at limit %s)
            returning id::text, request
            """,
            (tenant_id, body.limit),
        ).fetchall()

    return {"runs": runs}


@app.post("/v1/automation-runs/{run_id}/complete")
def complete_automation_run(run_id: str, body: AutomationCompleteBody,
                             authorization: str | None = Header(default=None)):
    master_node_id = master_node_from_token(authorization)

    with pool.connection() as conn:
        tenant_row = conn.execute(
            "select tenant_id from master_nodes where id = %s", (master_node_id,)
        ).fetchone()
        if tenant_row is None:
            raise HTTPException(401, "unknown master node")
        tenant_id = tenant_row[0]

        row = conn.execute(
            """update automation_runs
                  set status = %s, response = %s, http_status = %s, finished_at = now()
                where id = %s and tenant_id = %s
              returning id""",
            (body.status, body.response, body.http_status, run_id, tenant_id),
        ).fetchone()
        if row is None:
            raise HTTPException(404, "run not found")

    return {"ok": True}
