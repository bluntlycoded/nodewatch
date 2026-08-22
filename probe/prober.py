#!/usr/bin/env python3
"""
nodewatch probe runner.

Polls agentless checks and writes results straight to Postgres. It runs on
the API host rather than in an Edge Function for two reasons: ICMP needs a
raw socket, and the interesting targets - switches, iDRACs, internal
databases - live on private networks that only the API host can reach.

Checks run concurrently in a thread pool, so one unreachable target with a
5-second timeout does not delay the rest of the cycle.
"""

import json
import logging
import os
import re
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import psycopg
from psycopg.rows import dict_row

DATABASE_URL = os.environ["NW_DATABASE_URL"]
WORKERS = int(os.environ.get("NW_PROBE_WORKERS", "16"))
TICK_S = 5                    # how often to look for checks that are due
USER_AGENT = "nodewatch-probe/1.0"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("nodewatch-probe")

# Last run time per probe, in memory. Persisting it would mean a write per
# probe per tick; losing it on restart just means one extra early check.
_last_run: dict[str, float] = {}


# ---------------------------------------------------------------- checks

def check_ping(p: dict) -> tuple[bool, int | None, str]:
    """
    Uses the system ping binary rather than a raw socket, so the runner does
    not need CAP_NET_RAW. -c1 -W keeps it to a single packet.
    """
    timeout_s = max(1, p["timeout_ms"] // 1000)
    t0 = time.monotonic()
    try:
        res = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout_s), "-n", p["target"]],
            capture_output=True, text=True, timeout=timeout_s + 2,
        )
    except subprocess.TimeoutExpired:
        return False, None, "timed out"
    except FileNotFoundError:
        return False, None, "ping binary not available on the probe host"

    elapsed = int((time.monotonic() - t0) * 1000)
    if res.returncode != 0:
        first = (res.stdout or res.stderr or "no response").strip().splitlines()
        return False, None, (first[-1] if first else "unreachable")[:200]

    # Prefer the RTT ping itself reports over our wall-clock measurement.
    m = re.search(r"time[=<]([\d.]+)\s*ms", res.stdout)
    rtt = int(float(m.group(1))) if m else elapsed
    return True, rtt, "reachable"


def check_port(p: dict) -> tuple[bool, int | None, str]:
    if not p.get("port"):
        return False, None, "no port configured"
    t0 = time.monotonic()
    try:
        with socket.create_connection((p["target"], p["port"]),
                                      timeout=p["timeout_ms"] / 1000):
            pass
    except socket.timeout:
        return False, None, "connection timed out"
    except ConnectionRefusedError:
        return False, None, "connection refused"
    except socket.gaierror as e:
        return False, None, f"dns failure: {e}"
    except OSError as e:
        return False, None, str(e)[:200]
    return True, int((time.monotonic() - t0) * 1000), "connected"


def check_url(p: dict) -> tuple[bool, int | None, str]:
    req = urllib.request.Request(p["target"], headers={"User-Agent": USER_AGENT})
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=p["timeout_ms"] / 1000) as r:
            code = r.status
            body = r.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        # An HTTP error is still a response, and may be the expected one.
        code, body = e.code, ""
    except urllib.error.URLError as e:
        return False, None, f"unreachable: {e.reason}"[:200]
    except socket.timeout:
        return False, None, "timed out"
    except Exception as e:
        return False, None, str(e)[:200]

    ms = int((time.monotonic() - t0) * 1000)

    want = p.get("expect_status")
    if want is not None:
        if code != want:
            return False, ms, f"status {code}, expected {want}"
    elif not (200 <= code < 400):
        return False, ms, f"status {code}"

    if p.get("expect_text") and p["expect_text"] not in body:
        return False, ms, f"status {code}, body missing expected text"

    return True, ms, f"status {code}"


# ---------------------------------------------------------------- databases
#
# Database checks return a set of measurements rather than a single verdict,
# so they write to db_metrics as well as probe_results. Both connect with a
# read-only account: a monitoring agent has no business being able to write.

DB_CONNECT_TIMEOUT = 8


def _pct(num, den):
    """
    Postgres returns bigint sums as Decimal, which will not multiply with a
    float. Coercing both sides keeps the helper engine-agnostic.
    """
    try:
        num, den = float(num or 0), float(den or 0)
    except (TypeError, ValueError):
        return None
    return round(100.0 * num / den, 2) if den else None


def check_postgres(p) -> tuple[bool, int | None, str]:
    cfg = p.get("config") or {}
    dsn = {
        "host": cfg.get("host") or p["target"],
        "port": int(cfg.get("port") or p.get("port") or 5432),
        "user": cfg.get("user"),
        "password": cfg.get("password"),
        "dbname": cfg.get("dbname") or "postgres",
        "sslmode": cfg.get("sslmode") or "prefer",
        "connect_timeout": DB_CONNECT_TIMEOUT,
    }
    if not dsn["user"]:
        return False, None, "no credentials configured"

    t0 = time.monotonic()
    try:
        with psycopg.connect(**dsn, row_factory=dict_row) as c:
            ms = int((time.monotonic() - t0) * 1000)

            conns = c.execute("""
                select count(*) filter (where state is not null)          as total,
                       count(*) filter (where state = 'active')           as active,
                       count(*) filter (where state = 'idle in transaction') as idle_tx,
                       coalesce(max(extract(epoch from (now() - query_start)))
                                filter (where state = 'active'), 0)       as longest
                  from pg_stat_activity where backend_type = 'client backend'
            """).fetchone()

            maxc = int(c.execute("show max_connections").fetchone()["max_connections"])

            db = c.execute("""
                select coalesce(sum(blks_hit), 0)      as hit,
                       coalesce(sum(blks_read), 0)     as read,
                       coalesce(sum(xact_commit), 0)   as commits,
                       coalesce(sum(xact_rollback), 0) as rollbacks,
                       coalesce(sum(deadlocks), 0)     as deadlocks,
                       coalesce(sum(temp_files), 0)    as temp_files
                  from pg_stat_database where datname is not null
            """).fetchone()

            size = c.execute("select pg_database_size(current_database()) as b").fetchone()["b"]
            up = c.execute("""
                select extract(epoch from (now() - pg_postmaster_start_time()))::bigint as s
            """).fetchone()["s"]

            # Lag only exists on a replica; in_recovery tells us which we are.
            lag = None
            rec = c.execute("select pg_is_in_recovery() as r").fetchone()["r"]
            if rec:
                lag = c.execute("""
                    select coalesce(extract(epoch from
                        (now() - pg_last_xact_replay_timestamp())), 0)::float as lag
                """).fetchone()["lag"]

            metrics = {
                "connections": conns["total"],
                "max_connections": maxc,
                "conn_pct": _pct(conns["total"], maxc),
                "cache_hit_pct": _pct(db["hit"], db["hit"] + db["read"]),
                "slow_queries": None,
                "longest_query_s": round(float(conns["longest"] or 0), 2),
                "replication_lag_s": round(lag, 2) if lag is not None else None,
                "size_bytes": int(size or 0),
                "uptime_s": int(up or 0),
                "qps": None,
                # int() throughout: Postgres returns bigint sums as Decimal,
                # which json.dumps refuses and jsonb cannot take.
                "extra": {
                    "active": int(conns["active"] or 0),
                    "idle_in_transaction": int(conns["idle_tx"] or 0),
                    "deadlocks": int(db["deadlocks"] or 0),
                    "rollbacks": int(db["rollbacks"] or 0),
                    "temp_files": int(db["temp_files"] or 0),
                    "is_replica": bool(rec),
                },
            }
    except psycopg.OperationalError as e:
        return False, None, str(e).strip().splitlines()[0][:200]
    except Exception as e:
        return False, None, f"{type(e).__name__}: {e}"[:200]

    p["_metrics"] = metrics
    return True, ms, (f"{metrics['connections']}/{maxc} connections, "
                      f"{metrics['cache_hit_pct']}% cache hit")


def check_mysql(p) -> tuple[bool, int | None, str]:
    cfg = p.get("config") or {}
    if not cfg.get("user"):
        return False, None, "no credentials configured"
    try:
        import pymysql
    except ImportError:
        return False, None, "pymysql is not installed on the probe host"

    t0 = time.monotonic()
    try:
        conn = pymysql.connect(
            host=cfg.get("host") or p["target"],
            port=int(cfg.get("port") or p.get("port") or 3306),
            user=cfg.get("user"), password=cfg.get("password") or "",
            database=cfg.get("dbname") or None,
            connect_timeout=DB_CONNECT_TIMEOUT, read_timeout=DB_CONNECT_TIMEOUT,
        )
    except Exception as e:
        return False, None, str(e)[:200]

    ms = int((time.monotonic() - t0) * 1000)
    try:
        with conn.cursor() as cur:
            cur.execute("show global status")
            status = {k: v for k, v in cur.fetchall()}
            cur.execute("show global variables like 'max_connections'")
            maxc = int(dict(cur.fetchall()).get("max_connections", 0) or 0)

            def num(key, default=0):
                try:
                    return int(status.get(key, default))
                except (TypeError, ValueError):
                    return default

            reads = num("Innodb_buffer_pool_reads")
            reqs = num("Innodb_buffer_pool_read_requests")
            up = num("Uptime")
            questions = num("Questions")
            conns_now = num("Threads_connected")

            # Replication lag is only meaningful on a replica, and the
            # statement needs REPLICATION CLIENT rather than SELECT.
            lag = None
            try:
                cur.execute("show replica status")
                row = cur.fetchone()
                if row is None:
                    cur.execute("show slave status")   # pre-8.0.22 naming
                    row = cur.fetchone()
                if row:
                    cur.execute("select 1")            # clear any pending result
                    lag = None
            except Exception:
                pass

            cur.execute("""
                select coalesce(sum(data_length + index_length), 0)
                  from information_schema.tables
            """)
            size = int(cur.fetchone()[0] or 0)

            metrics = {
                "connections": conns_now,
                "max_connections": maxc,
                "conn_pct": _pct(conns_now, maxc),
                "cache_hit_pct": _pct(reqs - reads, reqs) if reqs else None,
                "slow_queries": num("Slow_queries"),
                "longest_query_s": None,
                "replication_lag_s": lag,
                "size_bytes": size,
                "uptime_s": up,
                # Averaged since start rather than instantaneous: a delta
                # would need state the prober deliberately does not keep.
                "qps": round(questions / up, 2) if up else None,
                "extra": {
                    "aborted_connects": num("Aborted_connects"),
                    "threads_running": num("Threads_running"),
                    "table_locks_waited": num("Table_locks_waited"),
                    "max_used_connections": num("Max_used_connections"),
                },
            }
    except Exception as e:
        return False, ms, f"{type(e).__name__}: {e}"[:200]
    finally:
        conn.close()

    p["_metrics"] = metrics
    return True, ms, (f"{conns_now}/{maxc} connections, "
                      f"{metrics['cache_hit_pct']}% buffer hit, "
                      f"{metrics['slow_queries']} slow queries")


# ---------------------------------------------------------------- applications

# Prometheus text exposition format. Parsed structurally rather than by
# regex over the whole document: sample lines are `name{labels} value`, and
# label values may contain spaces, braces and escaped quotes.
PROM_LINE = re.compile(r"""
    ^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)      # metric name
    (?:\{(?P<labels>.*)\})?                  # optional label set
    \s+(?P<value>[^\s]+)                     # value
    (?:\s+[0-9]+)?$                          # optional timestamp
""", re.VERBOSE)

LABEL_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')


def parse_prometheus(text: str) -> list:
    """Returns [(name, {labels}, float value)] for every sample line."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = PROM_LINE.match(line)
        if not m:
            continue
        try:
            value = float(m.group("value"))
        except ValueError:
            continue          # NaN, +Inf and friends carry no signal here
        labels = {}
        if m.group("labels"):
            for k, v in LABEL_RE.findall(m.group("labels")):
                labels[k] = v.replace('\\"', '"').replace("\\\\", "\\")
        out.append((m.group("name"), labels, value))
    return out


# Instrumentation libraries disagree on metric names. Rather than support one
# framework, match the families each is known to emit and take the first that
# is present.
REQUEST_FAMILIES = [
    "http_requests_total",                              # FastAPI, generic
    "http_request_total",
    "flask_http_request_total",                         # flask-exporter
    "django_http_responses_total_by_status_total",      # django-prometheus
    "starlette_requests_total",
    "gunicorn_requests_total",
]
DURATION_FAMILIES = [
    "http_request_duration_seconds",
    "http_request_duration_highr_seconds",
    "flask_http_request_duration_seconds",
    "django_http_requests_latency_seconds_by_view_method",
    "starlette_request_duration_seconds",
]
STATUS_LABELS = ("status", "status_code", "code", "http_status", "response_code")


def _status_of(labels: dict) -> str | None:
    for key in STATUS_LABELS:
        if key in labels:
            return str(labels[key])
    return None


def _p95_from_histogram(samples, family) -> float | None:
    """
    Linear interpolation within the bucket that crosses the 95th percentile.
    Histogram buckets are cumulative, so the count in a bucket includes every
    smaller one; the true value lies between this bucket's bound and the
    previous one.
    """
    buckets = []
    for name, labels, value in samples:
        if name == family + "_bucket" and "le" in labels:
            try:
                buckets.append((float(labels["le"]), value))
            except ValueError:
                continue
    if not buckets:
        return None

    merged = {}
    for le, v in buckets:
        merged[le] = merged.get(le, 0) + v
    ordered = sorted(merged.items())
    total = max(v for _, v in ordered)
    if total <= 0:
        return None

    target = 0.95 * total
    prev_le, prev_count = 0.0, 0.0
    for le, count in ordered:
        if count >= target:
            if le == float("inf"):
                return prev_le or None
            if count == prev_count:
                return le
            frac = (target - prev_count) / (count - prev_count)
            return round(prev_le + frac * (le - prev_le), 4)
        prev_le, prev_count = le, count
    return None


def check_prometheus(p) -> tuple[bool, int | None, str]:
    cfg = p.get("config") or {}
    url = p["target"]
    headers = {"User-Agent": USER_AGENT, "Accept": "text/plain"}
    if cfg.get("bearer_token"):
        headers["Authorization"] = "Bearer " + cfg["bearer_token"]
    elif cfg.get("user"):
        import base64
        raw = f"{cfg['user']}:{cfg.get('password','')}".encode()
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode()

    req = urllib.request.Request(url, headers=headers)
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=p["timeout_ms"] / 1000) as r:
            body = r.read(4 * 1024 * 1024).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return False, None, f"status {e.code} from {url}"
    except urllib.error.URLError as e:
        return False, None, f"unreachable: {e.reason}"[:200]
    except Exception as e:
        return False, None, str(e)[:200]

    ms = int((time.monotonic() - t0) * 1000)
    samples = parse_prometheus(body)
    if not samples:
        return False, ms, "endpoint returned no parseable Prometheus metrics"

    by_name = {}
    for name, labels, value in samples:
        by_name.setdefault(name, []).append((labels, value))

    requests_total = errors_total = None
    for fam in REQUEST_FAMILIES:
        if fam in by_name:
            total = err = 0.0
            for labels, value in by_name[fam]:
                total += value
                st = _status_of(labels)
                # 5xx only: a 404 is usually the client's problem, and
                # counting it as an application error makes the rate useless.
                if st and st[:1] == "5":
                    err += value
            requests_total, errors_total = int(total), int(err)
            break

    p95 = None
    for fam in DURATION_FAMILIES:
        if fam + "_bucket" in by_name:
            p95 = _p95_from_histogram(samples, fam)
            break

    avg = None
    for fam in DURATION_FAMILIES:
        if fam + "_sum" in by_name and fam + "_count" in by_name:
            s_ = sum(v for _, v in by_name[fam + "_sum"])
            c_ = sum(v for _, v in by_name[fam + "_count"])
            if c_ > 0:
                avg = round(s_ / c_, 4)
            break

    def first(name):
        vals = by_name.get(name)
        return vals[0][1] if vals else None

    start = first("process_start_time_seconds")
    metrics = {
        "requests_total": requests_total,
        "errors_total": errors_total,
        "active_conns": None,
        "p95_latency_s": p95,
        "avg_latency_s": avg,
        "memory_bytes": int(first("process_resident_memory_bytes") or 0) or None,
        "cpu_seconds": first("process_cpu_seconds_total"),
        "uptime_s": int(time.time() - start) if start else None,
        "extra": {
            "series": len(samples),
            "families": len(by_name),
            "open_fds": first("process_open_fds"),
        },
    }
    p["_app_metrics"] = metrics

    detail = f"{len(by_name)} metric families"
    if requests_total is not None:
        detail += f", {requests_total} requests"
        if errors_total:
            detail += f", {errors_total} 5xx"
    if p95 is not None:
        detail += f", p95 {p95}s"
    return True, ms, detail


# nginx stub_status is a fixed five-line block, not Prometheus format:
#   Active connections: 43
#   server accepts handled requests
#    7368 7368 10993
#   Reading: 0 Writing: 5 Waiting: 38
NGINX_ACTIVE = re.compile(r"Active connections:\s+(\d+)")
NGINX_TOTALS = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s*$", re.M)
NGINX_STATES = re.compile(r"Reading:\s+(\d+)\s+Writing:\s+(\d+)\s+Waiting:\s+(\d+)")


def check_nginx(p) -> tuple[bool, int | None, str]:
    req = urllib.request.Request(p["target"], headers={"User-Agent": USER_AGENT})
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=p["timeout_ms"] / 1000) as r:
            body = r.read(8192).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return False, None, f"status {e.code}"
    except urllib.error.URLError as e:
        return False, None, f"unreachable: {e.reason}"[:200]
    except Exception as e:
        return False, None, str(e)[:200]

    ms = int((time.monotonic() - t0) * 1000)
    active = NGINX_ACTIVE.search(body)
    totals = NGINX_TOTALS.search(body)
    states = NGINX_STATES.search(body)
    if not (active and totals):
        return False, ms, "not an nginx stub_status response"

    accepts, handled, requests = (int(g) for g in totals.groups())
    p["_app_metrics"] = {
        "requests_total": requests,
        # A connection accepted but not handled was dropped, usually at a
        # resource limit. That is the closest thing stub_status has to an
        # error count.
        "errors_total": accepts - handled,
        "active_conns": int(active.group(1)),
        "p95_latency_s": None,
        "avg_latency_s": None,
        "memory_bytes": None,
        "cpu_seconds": None,
        "uptime_s": None,
        "extra": {
            "accepts": accepts, "handled": handled,
            "reading": int(states.group(1)) if states else None,
            "writing": int(states.group(2)) if states else None,
            "waiting": int(states.group(3)) if states else None,
        },
    }
    return True, ms, (f"{active.group(1)} active, {requests} requests"
                      + (f", {accepts - handled} dropped" if accepts != handled else ""))


# ---------------------------------------------------------------- java app servers

def _basic_opener(cfg, url, digest=False):
    """
    Tomcat's manager app uses Basic auth; WildFly's management interface uses
    Digest by default. Both need a realm-agnostic password manager.
    """
    mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    mgr.add_password(None, url, cfg.get("user", ""), cfg.get("password", ""))
    handler = (urllib.request.HTTPDigestAuthHandler(mgr) if digest
               else urllib.request.HTTPBasicAuthHandler(mgr))
    return urllib.request.build_opener(handler)


def check_tomcat(p) -> tuple[bool, int | None, str]:
    """
    Reads the manager app's XML status. Needs a user with the
    manager-status role - that role is read-only, unlike manager-script,
    which can deploy and undeploy applications.
    """
    cfg = p.get("config") or {}
    if not cfg.get("user"):
        return False, None, "no credentials configured (needs the manager-status role)"

    url = p["target"]
    if "XML=true" not in url:
        url = url.rstrip("/") + ("&" if "?" in url else "?") + "XML=true"

    t0 = time.monotonic()
    try:
        opener = _basic_opener(cfg, url)
        with opener.open(url, timeout=p["timeout_ms"] / 1000) as r:
            body = r.read(2 * 1024 * 1024).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return False, None, f"status {e.code}: check the manager-status role"
        return False, None, f"status {e.code}"
    except urllib.error.URLError as e:
        return False, None, f"unreachable: {e.reason}"[:200]
    except Exception as e:
        return False, None, str(e)[:200]

    ms = int((time.monotonic() - t0) * 1000)
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return False, ms, "response was not the manager XML status"

    mem = root.find("./jvm/memory")
    heap_free = int(mem.get("free", 0)) if mem is not None else 0
    heap_total = int(mem.get("total", 0)) if mem is not None else 0
    heap_max = int(mem.get("max", 0)) if mem is not None else 0
    heap_used = heap_total - heap_free

    requests = errors = 0
    busy = maxthreads = threads = 0
    proc_time = max_time = 0
    connectors = []
    for c in root.findall("./connector"):
        ti = c.find("threadInfo")
        ri = c.find("requestInfo")
        if ti is not None:
            maxthreads += int(ti.get("maxThreads", 0))
            threads += int(ti.get("currentThreadCount", 0))
            busy += int(ti.get("currentThreadsBusy", 0))
        if ri is not None:
            requests += int(ri.get("requestCount", 0))
            errors += int(ri.get("errorCount", 0))
            proc_time += int(ri.get("processingTime", 0))
            max_time = max(max_time, int(ri.get("maxTime", 0)))
        connectors.append(c.get("name"))

    p["_app_metrics"] = {
        "requests_total": requests,
        "errors_total": errors,
        "active_conns": busy,
        # Tomcat reports total processing time, not a distribution, so the
        # mean is all that can honestly be derived. maxTime goes in extra
        # rather than being passed off as a percentile.
        "p95_latency_s": None,
        "avg_latency_s": round(proc_time / 1000.0 / requests, 4) if requests else None,
        "memory_bytes": heap_used or None,
        "cpu_seconds": None,
        "uptime_s": None,
        "extra": {
            "heap_used": heap_used, "heap_total": heap_total, "heap_max": heap_max,
            "heap_pct": round(100.0 * heap_used / heap_max, 1) if heap_max else None,
            "threads": threads, "threads_busy": busy, "threads_max": maxthreads,
            "thread_pct": round(100.0 * busy / maxthreads, 1) if maxthreads else None,
            "max_time_ms": max_time,
            "connectors": [c for c in connectors if c],
        },
    }
    return True, ms, (f"{requests} requests, {errors} errors, "
                      f"heap {p['_app_metrics']['extra']['heap_pct']}%, "
                      f"{busy}/{maxthreads} threads busy")


def _wildfly(opener, base, payload, timeout):
    req = urllib.request.Request(
        base, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"})
    with opener.open(req, timeout=timeout) as r:
        return json.loads(r.read(1024 * 1024).decode("utf-8", "replace"))


def check_jboss(p) -> tuple[bool, int | None, str]:
    """
    WildFly and JBoss EAP expose a management API on 9990. Digest auth by
    default, and the management realm is separate from the application
    realm - the account comes from add-user.sh, not from the app.
    """
    cfg = p.get("config") or {}
    if not cfg.get("user"):
        return False, None, "no credentials configured (needs a management-realm user)"

    base = p["target"].rstrip("/")
    if not base.endswith("/management"):
        base = base + "/management"
    timeout = p["timeout_ms"] / 1000

    t0 = time.monotonic()
    try:
        opener = _basic_opener(cfg, base, digest=True)
        heap = _wildfly(opener, base, {
            "operation": "read-resource", "include-runtime": True,
            "address": [{"core-service": "platform-mbean"}, {"type": "memory"}],
        }, timeout)
        threads = _wildfly(opener, base, {
            "operation": "read-resource", "include-runtime": True,
            "address": [{"core-service": "platform-mbean"}, {"type": "threading"}],
        }, timeout)
        runtime = _wildfly(opener, base, {
            "operation": "read-resource", "include-runtime": True,
            "address": [{"core-service": "platform-mbean"}, {"type": "runtime"}],
        }, timeout)
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return False, None, f"status {e.code}: check the management-realm user"
        return False, None, f"status {e.code}"
    except urllib.error.URLError as e:
        return False, None, f"unreachable: {e.reason}"[:200]
    except Exception as e:
        return False, None, f"{type(e).__name__}: {e}"[:200]

    ms = int((time.monotonic() - t0) * 1000)

    def res(d):
        return d.get("result", d) if isinstance(d, dict) else {}

    hu = res(heap).get("heap-memory-usage") or {}
    nh = res(heap).get("non-heap-memory-usage") or {}
    th = res(threads)
    rt = res(runtime)

    used = int(hu.get("used") or 0)
    maxi = int(hu.get("max") or 0)
    uptime_ms = int(rt.get("uptime") or 0)

    p["_app_metrics"] = {
        "requests_total": None,   # not exposed by platform-mbean
        "errors_total": None,
        "active_conns": int(th.get("thread-count") or 0) or None,
        "p95_latency_s": None,
        "avg_latency_s": None,
        "memory_bytes": used or None,
        "cpu_seconds": None,
        "uptime_s": int(uptime_ms / 1000) if uptime_ms else None,
        "extra": {
            "heap_used": used,
            "heap_max": maxi,
            "heap_pct": round(100.0 * used / maxi, 1) if maxi else None,
            "non_heap_used": int(nh.get("used") or 0),
            "threads": int(th.get("thread-count") or 0),
            "daemon_threads": int(th.get("daemon-thread-count") or 0),
            "peak_threads": int(th.get("peak-thread-count") or 0),
            "jvm": rt.get("vm-name"),
            "jvm_version": rt.get("spec-version"),
        },
    }
    pct = p["_app_metrics"]["extra"]["heap_pct"]
    return True, ms, (f"heap {pct}%, {th.get('thread-count')} threads, "
                      f"up {int(uptime_ms/3600000)}h")


# ---------------------------------------------------------------- sql server

# One round trip rather than six: SQL Server's DMVs are cheap individually
# but the probe host is cross-region, so latency dominates.
MSSQL_SQL = """
select
  (select count(*) from sys.dm_exec_connections)                        as connections,
  (select cast(value_in_use as int) from sys.configurations
    where name = 'user connections')                                    as max_connections,
  (select cntr_value from sys.dm_os_performance_counters
    where counter_name like 'Buffer cache hit ratio%'
      and object_name like '%Buffer Manager%')                          as bchr,
  (select cntr_value from sys.dm_os_performance_counters
    where counter_name like 'Buffer cache hit ratio base%'
      and object_name like '%Buffer Manager%')                          as bchr_base,
  (select cntr_value from sys.dm_os_performance_counters
    where counter_name = 'Page life expectancy'
      and object_name like '%Buffer Manager%')                          as ple,
  (select cntr_value from sys.dm_os_performance_counters
    where counter_name = 'Batch Requests/sec')                          as batch_requests,
  (select count(*) from sys.dm_exec_requests
    where blocking_session_id <> 0)                                     as blocked,
  (select isnull(max(datediff(second, start_time, getdate())), 0)
     from sys.dm_exec_requests where session_id > 50)                   as longest_s,
  (select datediff(second, sqlserver_start_time, getdate())
     from sys.dm_os_sys_info)                                           as uptime_s,
  (select isnull(sum(cast(size as bigint)) * 8192, 0) from sys.master_files) as size_bytes,
  (select count(*) from sys.databases where state_desc <> 'ONLINE')     as db_offline,
  (select count(*) from sys.databases)                                  as db_total
"""


def check_mssql(p) -> tuple[bool, int | None, str]:
    """
    Needs a login with VIEW SERVER STATE, which grants the DMVs and nothing
    else. It does not permit reading application data.
    """
    cfg = p.get("config") or {}
    if not cfg.get("user"):
        return False, None, "no credentials configured (needs VIEW SERVER STATE)"
    try:
        import pymssql
    except ImportError:
        return False, None, "pymssql is not installed on the probe host"

    t0 = time.monotonic()
    try:
        conn = pymssql.connect(
            server=cfg.get("host") or p["target"],
            port=str(cfg.get("port") or p.get("port") or 1433),
            user=cfg.get("user"), password=cfg.get("password") or "",
            database=cfg.get("dbname") or "master",
            login_timeout=DB_CONNECT_TIMEOUT, timeout=DB_CONNECT_TIMEOUT,
        )
    except Exception as e:
        return False, None, str(e)[:200]

    ms = int((time.monotonic() - t0) * 1000)
    try:
        with conn.cursor(as_dict=True) as cur:
            cur.execute(MSSQL_SQL)
            r = cur.fetchone() or {}
    except Exception as e:
        return False, ms, f"{type(e).__name__}: {e}"[:200]
    finally:
        conn.close()

    def num(k, d=0):
        v = r.get(k)
        return d if v is None else int(v)

    conns, maxc = num("connections"), num("max_connections")
    # 'user connections' set to 0 means unlimited, so a percentage is
    # meaningless; SQL Server's practical ceiling is 32767.
    if maxc == 0:
        maxc = 32767

    # Buffer cache hit ratio is a ratio of two counters, not a percentage.
    base = num("bchr_base")
    hit = _pct(num("bchr"), base) if base else None
    ple = num("ple")

    metrics = {
        "connections": conns,
        "max_connections": maxc,
        "conn_pct": _pct(conns, maxc),
        "cache_hit_pct": hit,
        "slow_queries": None,
        "longest_query_s": float(num("longest_s")),
        "replication_lag_s": None,
        "size_bytes": num("size_bytes"),
        "uptime_s": num("uptime_s"),
        "qps": None,
        "extra": {
            # Under about 300 seconds means the buffer pool is churning,
            # which is the usual first sign of memory pressure.
            "page_life_expectancy_s": ple,
            "blocked_sessions": num("blocked"),
            "databases": num("db_total"),
            "databases_offline": num("db_offline"),
        },
    }
    p["_metrics"] = metrics
    detail = f"{conns}/{maxc} connections"
    if hit is not None:
        detail += f", {hit}% cache hit"
    if num("blocked"):
        detail += f", {num('blocked')} blocked"
    return True, ms, detail


# ---------------------------------------------------------------- oracle

ORACLE_SQL = {
    "sessions": """
        select (select count(*) from v$session where type = 'USER') as sessions,
               (select to_number(value) from v$parameter where name = 'sessions') as max_sessions,
               (select count(*) from v$session where blocking_session is not null) as blocked,
               (select nvl(max(last_call_et), 0) from v$session
                 where status = 'ACTIVE' and type = 'USER') as longest_s
          from dual""",
    "cache": """
        select round(100 * (1 - (phy.value - lob.value - dir.value) /
                           nullif(ses.value + con.value, 0)), 2) as hit_ratio
          from v$sysstat ses, v$sysstat con, v$sysstat phy, v$sysstat lob, v$sysstat dir
         where ses.name = 'session logical reads'
           and con.name = 'consistent gets'
           and phy.name = 'physical reads'
           and lob.name = 'physical reads direct (lob)'
           and dir.name = 'physical reads direct'""",
    "instance": """
        select (sysdate - startup_time) * 86400 as uptime_s, instance_name, version, status
          from v$instance""",
    "tablespace": """
        select nvl(max(used_percent), 0) as worst_pct,
               count(*) as total,
               sum(case when used_percent > 90 then 1 else 0 end) as critical
          from dba_tablespace_usage_metrics""",
}


def check_oracle(p) -> tuple[bool, int | None, str]:
    """
    Uses python-oracledb in thin mode, which speaks the wire protocol
    directly and needs no Oracle Instant Client on the probe host. The
    account needs SELECT_CATALOG_ROLE, or grants on the specific v$ views.
    """
    cfg = p.get("config") or {}
    if not cfg.get("user"):
        return False, None, "no credentials configured (needs SELECT_CATALOG_ROLE)"
    try:
        import oracledb
    except ImportError:
        return False, None, "oracledb is not installed on the probe host"

    host = cfg.get("host") or p["target"]
    port = int(cfg.get("port") or p.get("port") or 1521)
    service = cfg.get("service_name") or cfg.get("dbname") or "ORCL"

    t0 = time.monotonic()
    try:
        conn = oracledb.connect(
            user=cfg["user"], password=cfg.get("password") or "",
            dsn=f"{host}:{port}/{service}",
            tcp_connect_timeout=DB_CONNECT_TIMEOUT,
        )
    except Exception as e:
        return False, None, str(e).strip().splitlines()[0][:200]

    ms = int((time.monotonic() - t0) * 1000)
    out = {}
    try:
        with conn.cursor() as cur:
            for key, sql in ORACLE_SQL.items():
                try:
                    cur.execute(sql)
                    row = cur.fetchone()
                    cols = [d[0].lower() for d in cur.description]
                    out[key] = dict(zip(cols, row)) if row else {}
                except Exception as e:
                    # A missing grant on one view should cost that metric,
                    # not the whole check. dba_tablespace_usage_metrics is
                    # the one most often not granted.
                    out[key] = {"_error": str(e).splitlines()[0][:120]}
    finally:
        conn.close()

    ses = out.get("sessions", {})
    inst = out.get("instance", {})
    ts = out.get("tablespace", {})

    def num(d, k, default=0):
        v = d.get(k)
        try:
            return float(v) if v is not None else default
        except (TypeError, ValueError):
            return default

    sessions = int(num(ses, "sessions"))
    max_sessions = int(num(ses, "max_sessions")) or None

    metrics = {
        "connections": sessions,
        "max_connections": max_sessions,
        "conn_pct": _pct(sessions, max_sessions) if max_sessions else None,
        "cache_hit_pct": num(out.get("cache", {}), "hit_ratio", None) or None,
        "slow_queries": None,
        "longest_query_s": num(ses, "longest_s"),
        "replication_lag_s": None,
        "size_bytes": None,
        "uptime_s": int(num(inst, "uptime_s")),
        "qps": None,
        "extra": {
            "instance": inst.get("instance_name"),
            "version": inst.get("version"),
            "status": inst.get("status"),
            "blocked_sessions": int(num(ses, "blocked")),
            "tablespace_worst_pct": num(ts, "worst_pct", None),
            "tablespaces_over_90": int(num(ts, "critical")),
            "errors": {k: v["_error"] for k, v in out.items() if "_error" in v} or None,
        },
    }
    p["_metrics"] = metrics
    detail = f"{sessions}/{max_sessions or '?'} sessions"
    if metrics["cache_hit_pct"]:
        detail += f", {metrics['cache_hit_pct']}% cache hit"
    if metrics["extra"]["tablespace_worst_pct"]:
        detail += f", worst tablespace {metrics['extra']['tablespace_worst_pct']}%"
    return True, ms, detail


CHECKS = {"ping": check_ping, "port": check_port, "url": check_url,
          "postgres": check_postgres, "mysql": check_mysql,
          "mssql": check_mssql, "oracle": check_oracle,
          "prometheus": check_prometheus, "nginx": check_nginx,
          "tomcat": check_tomcat, "jboss": check_jboss}


def run_one(p: dict) -> tuple[str, bool, int | None, str, dict | None, dict | None]:
    fn = CHECKS.get(p["kind"])
    if not fn:
        return p["id"], False, None, f"unknown probe kind {p['kind']}", None, None
    try:
        ok, ms, detail = fn(p)
    except Exception as e:
        # A bug in one check must not take the runner down.
        log.exception("probe %s raised", p["name"])
        ok, ms, detail = False, None, f"probe error: {e}"[:200]
    # Database checks attach a measurement set; the others do not.
    return p["id"], ok, ms, detail, p.get("_metrics"), p.get("_app_metrics")


# ---------------------------------------------------------------- net tools

# On-demand diagnostics requested from the dashboard. They run here because
# the probe host is the only machine with a route to internal targets.
#
# Every tool is bounded: a fixed argument list built from validated input,
# never a shell string, and a hard timeout. A diagnostic tool that accepted
# arbitrary arguments would be a remote shell with extra steps.

TARGET_RE = re.compile(r"^[A-Za-z0-9._:\-\[\]]{1,253}$")
URL_RE = re.compile(r"^https?://[^\s\"\'<>]{1,500}$")

NETTOOL_TIMEOUT = 60
PORTSCAN_MAX = 64


def valid_target(t: str, tool: str) -> bool:
    if tool == "http":
        return bool(URL_RE.match(t))
    # A hostname or IP only. Rejecting the leading dash matters as much as
    # rejecting metacharacters: "--help" or "-f" would otherwise be read as
    # a flag by ping, dig or traceroute rather than as a target.
    if t.startswith("-"):
        return False
    return bool(TARGET_RE.match(t))


def tool_ping(target, opts):
    n = min(int(opts.get("count", 4)), 10)
    return ["ping", "-c", str(n), "-W", "2", "-n", target]


def tool_traceroute(target, opts):
    hops = min(int(opts.get("max_hops", 20)), 30)
    if shutil.which("traceroute"):
        return ["traceroute", "-n", "-w", "2", "-q", "1", "-m", str(hops), target]
    if shutil.which("tracepath"):
        return ["tracepath", "-n", "-m", str(hops), target]
    return None


def tool_dns(target, opts):
    rtype = str(opts.get("type", "A")).upper()
    if rtype not in ("A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "PTR"):
        rtype = "A"
    if shutil.which("dig"):
        return ["dig", "+short", "+time=3", "+tries=1", target, rtype]
    return ["getent", "hosts", target]


def tool_http(target, opts):
    return ["curl", "-sS", "-o", "/dev/null", "-L", "--max-time", "15",
            "-w", "status=%{http_code} time=%{time_total}s size=%{size_download}B "
                  "redirects=%{num_redirects} ip=%{remote_ip}\n", target]


def run_portscan(target, opts):
    """
    Written in Python rather than shelling out to nmap: no extra dependency,
    and the port list stays bounded to something a monitoring tool should be
    doing rather than a general scanner.
    """
    raw = opts.get("ports") or "22,80,443,3389,5432,3306,8080,8443"
    ports = []
    for part in str(raw).split(","):
        part = part.strip()
        if part.isdigit() and 1 <= int(part) <= 65535:
            ports.append(int(part))
        if len(ports) >= PORTSCAN_MAX:
            break
    if not ports:
        return "no valid ports requested"

    lines = []
    for port in ports:
        t0 = time.monotonic()
        try:
            with socket.create_connection((target, port), timeout=1.5):
                lines.append(f"{port:>6}/tcp  open      {int((time.monotonic()-t0)*1000)} ms")
        except socket.timeout:
            lines.append(f"{port:>6}/tcp  filtered")
        except ConnectionRefusedError:
            lines.append(f"{port:>6}/tcp  closed")
        except OSError as e:
            lines.append(f"{port:>6}/tcp  error     {e}")
    return "\n".join(lines)


BUILDERS = {"ping": tool_ping, "traceroute": tool_traceroute,
            "dns": tool_dns, "http": tool_http}


def run_nettool(job: dict) -> tuple[bool, str, int]:
    tool, target = job["tool"], (job["target"] or "").strip()
    opts = job.get("options") or {}
    t0 = time.monotonic()

    if not valid_target(target, tool):
        return False, "target rejected: expected a hostname, IP or URL", 0

    if tool == "portscan":
        try:
            return True, run_portscan(target, opts), int((time.monotonic()-t0)*1000)
        except Exception as e:
            return False, str(e)[:500], int((time.monotonic()-t0)*1000)

    builder = BUILDERS.get(tool)
    if not builder:
        return False, f"unknown tool {tool}", 0
    try:
        cmd = builder(target, opts)
    except (TypeError, ValueError) as e:
        return False, f"bad options: {e}", 0
    if cmd is None:
        return False, f"{tool} is not installed on the probe host", 0

    try:
        res = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=NETTOOL_TIMEOUT)
    except subprocess.TimeoutExpired:
        return False, f"timed out after {NETTOOL_TIMEOUT}s", NETTOOL_TIMEOUT * 1000
    except FileNotFoundError:
        return False, f"{cmd[0]} is not installed on the probe host", 0

    out = (res.stdout or "") + (res.stderr or "")
    return res.returncode == 0, out[:8000].strip() or "(no output)", \
           int((time.monotonic() - t0) * 1000)


def drain_nettools(conn):
    """Claim queued jobs before running them, so two cycles cannot overlap."""
    jobs = conn.execute(
        """update nettool_jobs set status = 'running', started_at = now()
            where id in (select id from nettool_jobs where status = 'queued'
                          order by created_at limit 3)
        returning id::text, tool, target, options"""
    ).fetchall()
    if not jobs:
        return 0
    for j in jobs:
        ok, output, ms = run_nettool(j)
        conn.execute(
            """update nettool_jobs
                  set status = %s, output = %s, duration_ms = %s, finished_at = now()
                where id = %s""",
            ("done" if ok else "failed", output, ms, j["id"]),
        )
        log.info("nettool %s %s -> %s", j["tool"], j["target"], "ok" if ok else "failed")
    return len(jobs)


# ---------------------------------------------------------------- automation

# Only ever executes runs a human approved, and only outbound HTTP. Nothing
# here touches a monitored host: nodewatch decides when, an automation
# platform decides what.
AUTOMATION_TIMEOUT = 30


def run_automation(conn):
    rows = conn.execute(
        """update automation_runs set status = 'running'
            where id in (select id from automation_runs
                          where status = 'approved'
                          order by created_at limit 3)
        returning id::text, request"""
    ).fetchall()
    if not rows:
        return 0

    for r in rows:
        req = r["request"] or {}
        url = req.get("url")
        if not url or not str(url).lower().startswith(("http://", "https://")):
            conn.execute(
                """update automation_runs set status='failed', finished_at=now(),
                       response='no valid url on the rule' where id = %s""", (r["id"],))
            continue

        body = json.dumps(req.get("body") or {}).encode()
        headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT}
        for k, v in (req.get("headers") or {}).items():
            headers[str(k)] = str(v)

        request = urllib.request.Request(
            url, data=body, headers=headers,
            method=(req.get("method") or "POST").upper())
        try:
            with urllib.request.urlopen(request, timeout=AUTOMATION_TIMEOUT) as resp:
                out, code = resp.read(8192).decode("utf-8", "replace"), resp.status
            status = "done"
        except urllib.error.HTTPError as e:
            out, code, status = e.read(4096).decode("utf-8", "replace"), e.code, "failed"
        except Exception as e:
            out, code, status = str(e)[:500], None, "failed"

        conn.execute(
            """update automation_runs
                  set status = %s, response = %s, http_status = %s, finished_at = now()
                where id = %s""",
            (status, out[:4000], code, r["id"]))
        log.info("automation run %s -> %s", r["id"][:8], status)

    return len(rows)


# ---------------------------------------------------------------- topology

# Traceroute is slow and the path rarely changes, so it runs far less often
# than the checks themselves. Hourly is enough to notice a rerouted path
# without turning the probe host into a traffic source.
TRACE_INTERVAL_S = 3600
_last_trace: dict[str, float] = {}

HOP_RE = re.compile(r"^\s*(\d+)[:\s]\s*(.*)$")
HOP_IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
HOP_RTT = re.compile(r"([\d.]+)\s*ms")


def parse_traceroute(text: str) -> list:
    """
    [(hop, ip, rtt_ms)]. Unresponsive hops appear as asterisks and are
    skipped rather than recorded as unknown routers - a firewall dropping
    ICMP TTL-exceeded is not a device worth drawing.
    """
    out = []
    for line in text.splitlines():
        m = HOP_RE.match(line)
        if not m:
            continue
        rest = m.group(2)
        ip = HOP_IP.search(rest)
        if not ip:
            continue
        rtt = HOP_RTT.search(rest)
        out.append((int(m.group(1)), ip.group(1),
                    float(rtt.group(1)) if rtt else None))
    return out


def trace_targets(conn):
    """Trace each enabled check whose target is a literal address."""
    if not shutil.which("traceroute") and not shutil.which("tracepath"):
        return 0

    targets = conn.execute(
        r"""select id::text, target from probes
             where enabled and target ~ '^\d{1,3}(\.\d{1,3}){3}$'"""
    ).fetchall()

    now = time.monotonic()
    due = [t for t in targets
           if now - _last_trace.get(t["id"], 0) >= TRACE_INTERVAL_S]
    if not due:
        return 0

    traced = 0
    for t in due[:5]:            # a few per cycle; this is not urgent work
        cmd = (["traceroute", "-n", "-w", "2", "-q", "1", "-m", "20", t["target"]]
               if shutil.which("traceroute")
               else ["tracepath", "-n", "-m", "20", t["target"]])
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            _last_trace[t["id"]] = now
            continue

        hops = parse_traceroute(res.stdout or "")
        _last_trace[t["id"]] = now
        if not hops:
            continue

        ts = datetime.now(timezone.utc)
        conn.cursor().executemany(
            """insert into route_hops (probe_id, traced_at, hop, ip, rtt_ms)
               values (%s, %s, %s, %s, %s)
               on conflict (probe_id, traced_at, hop) do nothing""",
            [(t["id"], ts, h, ip, rtt) for h, ip, rtt in hops])
        traced += 1

    if traced:
        log.info("traced %d path(s)", traced)
    return traced


# ---------------------------------------------------------------- loop

def due(probes: list[dict]) -> list[dict]:
    now = time.monotonic()
    out = []
    for p in probes:
        last = _last_run.get(p["id"])
        if last is None or now - last >= p["interval_s"]:
            out.append(p)
    return out


def main():
    log.info("probe runner starting, %d workers", WORKERS)
    pool = ThreadPoolExecutor(max_workers=WORKERS)

    while True:
        cycle_started = time.monotonic()
        try:
            with psycopg.connect(DATABASE_URL, row_factory=dict_row) as conn:
                probes = conn.execute(
                    """select p.id::text, p.kind, p.name, p.target, p.port,
                              p.interval_s, p.timeout_ms, p.expect_status,
                              p.expect_text, s.config
                         from probes p
                         left join probe_secrets s on s.probe_id = p.id
                        where p.enabled"""
                ).fetchall()

                batch = due(probes)
                if batch:
                    ts = datetime.now(timezone.utc)
                    results = list(pool.map(run_one, batch))

                    # One round trip for the whole cycle. The database is
                    # cross-region, so per-probe writes would cost more than
                    # the checks themselves.
                    conn.cursor().executemany(
                        """insert into probe_results (probe_id, ts, ok, latency_ms, detail)
                           values (%s, %s, %s, %s, %s)
                           on conflict (probe_id, ts) do nothing""",
                        [(pid, ts, ok, ms, detail) for pid, ok, ms, detail, _, _ in results],
                    )

                    # Database measurements go to their own table. One
                    # round trip for the cycle, same as probe_results.
                    dbrows = [
                        (pid, ts, m.get("connections"), m.get("max_connections"),
                         m.get("conn_pct"), m.get("cache_hit_pct"),
                         m.get("slow_queries"), m.get("longest_query_s"),
                         m.get("replication_lag_s"), m.get("size_bytes"),
                         m.get("uptime_s"), m.get("qps"), json.dumps(m.get("extra") or {}))
                        for pid, ok, _, _, m, _ in results if ok and m
                    ]
                    approws = [
                        (pid, ts, a.get("requests_total"), a.get("errors_total"),
                         a.get("active_conns"), a.get("p95_latency_s"),
                         a.get("avg_latency_s"), a.get("memory_bytes"),
                         a.get("cpu_seconds"), a.get("uptime_s"),
                         json.dumps(a.get("extra") or {}))
                        for pid, ok, _, _, _, a in results if ok and a
                    ]
                    if approws:
                        conn.cursor().executemany(
                            """insert into app_metrics (probe_id, ts, requests_total,
                                   errors_total, active_conns, p95_latency_s,
                                   avg_latency_s, memory_bytes, cpu_seconds,
                                   uptime_s, extra)
                               values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                               on conflict (probe_id, ts) do nothing""",
                            approws)

                    if dbrows:
                        conn.cursor().executemany(
                            """insert into db_metrics (probe_id, ts, connections,
                                   max_connections, conn_pct, cache_hit_pct,
                                   slow_queries, longest_query_s, replication_lag_s,
                                   size_bytes, uptime_s, qps, extra)
                               values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                               on conflict (probe_id, ts) do nothing""",
                            dbrows)

                    now = time.monotonic()
                    for p in batch:
                        _last_run[p["id"]] = now

                    failed = sum(1 for _, ok, _, _, _, _ in results if not ok)
                    log.info("checked %d, %d failing", len(results), failed)

                drain_nettools(conn)
                trace_targets(conn)
                run_automation(conn)

                # Forget probes that have been deleted, so the dict cannot
                # grow without bound over a long uptime.
                live = {p["id"] for p in probes}
                for gone in set(_last_run) - live:
                    _last_run.pop(gone, None)

        except Exception as e:
            log.warning("probe cycle failed: %s", e)

        time.sleep(max(0.0, TICK_S - (time.monotonic() - cycle_started)))


if __name__ == "__main__":
    main()
