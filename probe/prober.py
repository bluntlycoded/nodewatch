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


CHECKS = {"ping": check_ping, "port": check_port, "url": check_url}


def run_one(p: dict) -> tuple[str, bool, int | None, str]:
    fn = CHECKS.get(p["kind"])
    if not fn:
        return p["id"], False, None, f"unknown probe kind {p['kind']}"
    try:
        ok, ms, detail = fn(p)
    except Exception as e:
        # A bug in one check must not take the runner down.
        log.exception("probe %s raised", p["name"])
        ok, ms, detail = False, None, f"probe error: {e}"[:200]
    return p["id"], ok, ms, detail


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
                    "select id::text, kind, name, target, port, interval_s, "
                    "timeout_ms, expect_status, expect_text "
                    "from probes where enabled"
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
                        [(pid, ts, ok, ms, detail) for pid, ok, ms, detail in results],
                    )

                    now = time.monotonic()
                    for p in batch:
                        _last_run[p["id"]] = now

                    failed = sum(1 for _, ok, _, _ in results if not ok)
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
