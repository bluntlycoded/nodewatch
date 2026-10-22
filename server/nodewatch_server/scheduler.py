"""
Runs the jobs the migrations register with cron.schedule().

Stands in for pg_cron: same table, same five-field schedules, evaluated in
UTC as pg_cron does. Each job runs in its own connection and transaction,
and a job still running from the previous minute is not started again -
the overlap that 033_probe_state_perf.sql was written to stop.
"""

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import psycopg

log = logging.getLogger("nodewatch.scheduler")

JOB_TIMEOUT_MS = 55_000
RANGES = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 7)]


def _field(spec: str, lo: int, hi: int) -> set[int]:
    out: set[int] = set()
    for part in spec.split(","):
        rng, _, step = part.partition("/")
        step_n = int(step) if step else 1
        if rng == "*":
            a, b = lo, hi
        elif "-" in rng:
            a, b = (int(x) for x in rng.split("-", 1))
        else:
            a = int(rng)
            b = hi if step else a
        if a < lo or b > hi or a > b or step_n < 1:
            raise ValueError(f"{part!r} out of range {lo}-{hi}")
        out.update(range(a, b + 1, step_n))
    return out


def parse(schedule: str) -> list[set[int]]:
    fields = schedule.split()
    if len(fields) != 5:
        raise ValueError(f"expected 5 fields, got {schedule!r}")
    sets = [_field(f, lo, hi) for f, (lo, hi) in zip(fields, RANGES)]
    if 7 in sets[4]:
        sets[4].add(0)          # 7 and 0 are both Sunday
    return sets


def matches(schedule: str, at: datetime) -> bool:
    minute, hour, dom, month, dow = parse(schedule)
    fields = schedule.split()
    dow_now = (at.weekday() + 1) % 7
    day_ok_dom, day_ok_dow = at.day in dom, dow_now in dow
    # Vixie cron: when both day fields are restricted, either may match.
    if fields[2] != "*" and fields[4] != "*":
        day_ok = day_ok_dom or day_ok_dow
    else:
        day_ok = day_ok_dom and day_ok_dow
    return at.minute in minute and at.hour in hour and at.month in month and day_ok


class Scheduler:

    def __init__(self, db_url: str, workers: int = 6):
        self.db_url = db_url
        self.pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="cron")
        self.running: set[int] = set()
        self.lock = threading.Lock()
        self.extra: list[tuple[str, str, callable]] = []
        self.stop = threading.Event()

    def add_python_job(self, name: str, schedule: str, fn) -> None:
        """Jobs the master runs itself, e.g. alert delivery."""
        parse(schedule)
        self.extra.append((name, schedule, fn))

    def start(self) -> None:
        threading.Thread(target=self._loop, name="scheduler", daemon=True).start()

    def _loop(self) -> None:
        last = None
        while not self.stop.is_set():
            now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
            if now != last:
                last = now
                try:
                    self._tick(now)
                except Exception:
                    log.exception("scheduler tick failed")
            self.stop.wait(1)

    def _tick(self, now: datetime) -> None:
        with psycopg.connect(self.db_url, autocommit=True) as conn:
            jobs = conn.execute(
                "select jobid, jobname, schedule, command from cron.job where active").fetchall()
        for jobid, name, schedule, command in jobs:
            try:
                due = matches(schedule, now)
            except ValueError as e:
                log.warning("job %s has an unsupported schedule %r: %s", name, schedule, e)
                continue
            if due:
                self._submit(jobid, name, lambda c=command: self._run_sql(c))
        for i, (name, schedule, fn) in enumerate(self.extra):
            if matches(schedule, now):
                self._submit(-(i + 1), name, fn)

    def _submit(self, key: int, name: str, fn) -> None:
        with self.lock:
            if key in self.running:
                log.warning("job %s still running from the previous minute; skipping", name)
                return
            self.running.add(key)
        self.pool.submit(self._guard, key, name, fn)

    def _guard(self, key: int, name: str, fn) -> None:
        started = datetime.now(timezone.utc)
        status, message = "succeeded", None
        t0 = time.monotonic()
        try:
            fn()
        except Exception as e:
            status, message = "failed", str(e)[:1000]
            log.warning("job %s failed: %s", name, message)
        finally:
            with self.lock:
                self.running.discard(key)
        if key > 0:
            self._record(key, status, message, started)
        log.debug("job %s %s in %.1fs", name, status, time.monotonic() - t0)

    def _run_sql(self, command: str) -> None:
        with psycopg.connect(self.db_url, autocommit=True) as conn:
            conn.execute(f"set statement_timeout = {JOB_TIMEOUT_MS}")
            conn.execute(command)

    def _record(self, jobid: int, status: str, message: str | None, started: datetime) -> None:
        try:
            with psycopg.connect(self.db_url, autocommit=True) as conn:
                conn.execute(
                    "insert into cron.job_run_details (jobid, status, return_message, start_time, end_time) "
                    "values (%s, %s, %s, %s, now())", (jobid, status, message, started))
        except Exception:
            log.exception("could not record run of job %s", jobid)
