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


CHECKS = {"ping": check_ping, "port": check_port, "url": check_url,
          "postgres": check_postgres, "mysql": check_mysql}


def run_one(p: dict) -> tuple[str, bool, int | None, str, dict | None]:
    fn = CHECKS.get(p["kind"])
    if not fn:
        return p["id"], False, None, f"unknown probe kind {p['kind']}", None
    try:
        ok, ms, detail = fn(p)
    except Exception as e:
        # A bug in one check must not take the runner down.
        log.exception("probe %s raised", p["name"])
        ok, ms, detail = False, None, f"probe error: {e}"[:200]
    # Database checks attach a measurement set; the others do not.
    return p["id"], ok, ms, detail, p.get("_metrics")


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
                        [(pid, ts, ok, ms, detail) for pid, ok, ms, detail, _ in results],
                    )

                    # Database measurements go to their own table. One
                    # round trip for the cycle, same as probe_results.
                    dbrows = [
                        (pid, ts, m.get("connections"), m.get("max_connections"),
                         m.get("conn_pct"), m.get("cache_hit_pct"),
                         m.get("slow_queries"), m.get("longest_query_s"),
                         m.get("replication_lag_s"), m.get("size_bytes"),
                         m.get("uptime_s"), m.get("qps"), json.dumps(m.get("extra") or {}))
                        for pid, ok, _, _, m in results if ok and m
                    ]
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

                    failed = sum(1 for _, ok, _, _, _ in results if not ok)
                    log.info("checked %d, %d failing", len(results), failed)

                drain_nettools(conn)

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
