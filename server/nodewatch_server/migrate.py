"""
Applies the schema: the self-hosted compatibility layer, then db/*.sql in
order, each in its own transaction and recorded so it runs once.

The migrations are the same files the hosted deployment applies by hand in
the Supabase SQL editor. Two statements in them load Supabase-only
extensions (pg_cron, pg_net); those are skipped here because compat.sql
provides the objects they would have created.
"""

import hashlib
import logging
import re
import sys
from pathlib import Path

log = logging.getLogger("nodewatch.migrate")

SKIP_EXTENSIONS = re.compile(
    r"^[ \t]*create[ \t]+extension[ \t]+if[ \t]+not[ \t]+exists[ \t]+(pg_cron|pg_net)[ \t]*;",
    re.IGNORECASE | re.MULTILINE,
)

# Jobs that call Supabase Edge Functions through pg_net. The master does
# that work itself (alerts.py), so on every start these are removed again
# in case a migration re-scheduled them.
EDGE_FUNCTION_JOBS = ("nodewatch-drain", "nodewatch-vuln-scan")


def sql_root() -> Path:
    """db/ and compat.sql, from the bundle when frozen or the repo otherwise."""
    if hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parents[2]


def migration_files() -> list[tuple[str, str]]:
    root = sql_root()
    compat = Path(__file__).resolve().parent / "sql" / "compat.sql"
    if hasattr(sys, "_MEIPASS"):
        compat = root / "nodewatch_server" / "sql" / "compat.sql"
    files = [("000_selfhosted_compat.sql", compat.read_text(encoding="utf-8"))]
    for path in sorted((root / "db").glob("[0-9][0-9][0-9]_*.sql")):
        files.append((path.name, path.read_text(encoding="utf-8")))
    return files


def migrate(conn) -> int:
    """Returns how many files were applied this run."""
    conn.execute("""
        create table if not exists public.nw_schema_migrations (
            name       text primary key,
            sha256     text not null,
            applied_at timestamptz not null default now()
        )""")
    conn.commit()

    applied = dict(conn.execute("select name, sha256 from public.nw_schema_migrations").fetchall())
    count = 0

    for name, sql in migration_files():
        digest = hashlib.sha256(sql.encode()).hexdigest()
        if name in applied:
            if applied[name] != digest:
                if name.startswith("000_"):
                    # compat.sql is idempotent by construction; re-apply it.
                    pass
                else:
                    log.warning("%s changed after it was applied; not re-running it", name)
                    continue
            else:
                continue

        log.info("applying %s", name)
        try:
            with conn.transaction():
                conn.execute(SKIP_EXTENSIONS.sub("-- skipped on self-hosted: \\g<0>", sql))
                conn.execute(
                    "insert into public.nw_schema_migrations (name, sha256) values (%s, %s) "
                    "on conflict (name) do update set sha256 = excluded.sha256, applied_at = now()",
                    (name, digest),
                )
        except Exception as e:
            raise RuntimeError(f"migration {name} failed: {e}") from e
        count += 1

    conn.execute("delete from cron.job where jobname = any(%s)", (list(EDGE_FUNCTION_JOBS),))
    conn.commit()
    return count
