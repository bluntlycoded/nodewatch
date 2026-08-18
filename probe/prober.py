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
