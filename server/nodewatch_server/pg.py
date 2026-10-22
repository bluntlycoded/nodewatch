"""
The PostgreSQL the master runs as a child process.

Binaries ship inside the master as one compressed archive and are unpacked
once into the data directory; the cluster lives beside them. Postgres
listens on 127.0.0.1 only and requires a password generated at first run,
so another local account cannot open the database the way it could with
trust authentication.
"""

import hashlib
import logging
import os
import secrets
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

log = logging.getLogger("nodewatch.pg")

SUPERUSER = "nodewatch"
DATABASE = "nodewatch"
EXE = ".exe" if sys.platform == "win32" else ""


def bundled_archive() -> Path | None:
    """The postgres-*.txz shipped with this build, if any."""
    override = os.environ.get("NW_PG_ARCHIVE")
    if override:
        return Path(override)
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    hits = sorted((base / "pgdist").glob("postgres-*.txz"))
    return hits[0] if hits else None


def install_binaries(data_dir: Path) -> Path:
    """
    Unpack the bundled archive into data_dir/pg/<digest>/ and return its
    bin directory. Keyed by digest so an upgraded master unpacks its own
    Postgres beside the old one instead of half-overwriting it.
    """
    override = os.environ.get("NW_PG_BIN")
    if override:
        return Path(override)

    archive = bundled_archive()
    if archive is None or not archive.exists():
        raise RuntimeError("this build has no bundled PostgreSQL (set NW_PG_BIN to use an installed one)")

    digest = hashlib.sha256(archive.read_bytes()).hexdigest()[:16]
    root = data_dir / "pg" / digest
    marker = root / ".complete"
    if not marker.exists():
        log.info("unpacking PostgreSQL into %s", root)
        shutil.rmtree(root, ignore_errors=True)
        root.mkdir(parents=True)
        with tarfile.open(archive, "r:xz") as tf:
            tf.extractall(root, filter="tar")
        marker.write_text(archive.name)
    return root / "bin"


class EmbeddedPostgres:

    def __init__(self, bin_dir: Path, data_dir: Path, port: int, password: str):
        self.bin = bin_dir
        self.pgdata = data_dir / "pgdata"
        self.logfile = data_dir / "postgres.log"
        self.port = port
        self.password = password

    def _tool(self, name: str) -> str:
        return str(self.bin / f"{name}{EXE}")

    def _run(self, *args: str) -> None:
        # Output goes to a temporary file, not a pipe: on Windows the
        # postgres server pg_ctl starts inherits pg_ctl's handles and keeps
        # them open, so reading a pipe to EOF would wait forever.
        import tempfile
        with tempfile.TemporaryFile(mode="w+") as out:
            rc = subprocess.run(args, stdout=out, stderr=out, stdin=subprocess.DEVNULL).returncode
            out.seek(0)
            text = out.read()
        if rc != 0:
            raise RuntimeError(f"{Path(args[0]).name} failed: {text.strip()[-800:]}")

    @property
    def initialised(self) -> bool:
        return (self.pgdata / "PG_VERSION").exists()

    def init(self) -> None:
        if self.initialised:
            return
        log.info("initialising database cluster in %s", self.pgdata)
        self.pgdata.parent.mkdir(parents=True, exist_ok=True)
        pwfile = self.pgdata.parent / ".pgpass-init"
        pwfile.write_text(self.password)
        try:
            self._run(
                self._tool("initdb"),
                "-D", str(self.pgdata),
                "-U", SUPERUSER,
                "--pwfile", str(pwfile),
                "--auth", "scram-sha-256",
                "--encoding", "UTF8",
                "--locale", "C",
            )
        finally:
            pwfile.unlink(missing_ok=True)

    def start(self) -> None:
        if self.is_running():
            return
        opts = f"-p {self.port} -c listen_addresses=127.0.0.1"
        if sys.platform != "win32":
            # No Unix socket: one less way in, and no dependency on /tmp.
            opts += " -c unix_socket_directories=''"
        self._run(self._tool("pg_ctl"), "start", "-w", "-t", "60",
                  "-D", str(self.pgdata), "-l", str(self.logfile), "-o", opts)
        log.info("postgres listening on 127.0.0.1:%d", self.port)
        self._ensure_database()

    def stop(self) -> None:
        if self.is_running():
            self._run(self._tool("pg_ctl"), "stop", "-w", "-m", "fast", "-D", str(self.pgdata))

    def is_running(self) -> bool:
        res = subprocess.run([self._tool("pg_ctl"), "status", "-D", str(self.pgdata)],
                             capture_output=True, text=True)
        return res.returncode == 0

    def url(self, database: str = DATABASE) -> str:
        return f"postgresql://{SUPERUSER}:{self.password}@127.0.0.1:{self.port}/{database}"

    def _ensure_database(self) -> None:
        import psycopg
        with psycopg.connect(self.url("postgres"), autocommit=True) as conn:
            if not conn.execute("select 1 from pg_database where datname = %s", (DATABASE,)).fetchone():
                conn.execute(f'create database "{DATABASE}"')


def new_password() -> str:
    return secrets.token_urlsafe(32)
