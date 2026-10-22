"""
The master's on-disk state: one data directory holding config.json, the
licence, the PKI and the database. Everything secret in config.json is
generated on first run, never typed in, and the file is owner-only.
"""

import json
import os
import secrets
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

TENANT_ZERO = "00000000-0000-0000-0000-000000000001"


def default_data_dir() -> Path:
    override = os.environ.get("NW_SERVER_DATA")
    if override:
        return Path(override)
    if sys.platform == "win32":
        return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "nodewatch-server"
    if sys.platform == "darwin":
        return Path("/Library/Application Support/nodewatch-server")
    return Path("/var/lib/nodewatch-server")


@dataclass
class Config:
    https_port: int = 8443
    # Loopback-only plain HTTP for the built-in probe runner, so it does not
    # have to trust the master's own CA through process-wide settings.
    internal_port: int = 8442
    pg_port: int = 54329
    pg_password: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    # PostgREST (dashboard data API), loopback only; its admin port is +1.
    pgrst_port: int = 54331
    pgrst_password: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    jwt_secret: str = field(default_factory=lambda: secrets.token_hex(32))
    session_secret: str = field(default_factory=lambda: secrets.token_hex(32))
    # Printed at first start and required by the setup page, so whoever can
    # reach port 8443 first cannot claim the master before its owner does.
    setup_code: str = field(default_factory=lambda: secrets.token_hex(4).upper())
    setup_complete: bool = False
    # The address agents use to reach this master: the "one URL" every node
    # is pointed at. Also a SAN on the server certificate.
    public_address: str = ""
    probe_token: str = ""
    smtp: dict = field(default_factory=dict)

    @property
    def public_url(self) -> str:
        host = self.public_address or "localhost"
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        return f"https://{host}:{self.https_port}"


class Store:

    def __init__(self, data_dir: Path):
        self.dir = data_dir
        self.path = data_dir / "config.json"

    def load(self) -> Config:
        if self.path.exists():
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            known = {k: v for k, v in raw.items() if k in Config.__dataclass_fields__}
            cfg = Config(**known)
            if set(known) != set(Config.__dataclass_fields__):
                # Written by an older master: persist the new fields'
                # generated secrets instead of regenerating them each start.
                self.save(cfg)
            return cfg
        cfg = Config()
        self.save(cfg)
        return cfg

    def save(self, cfg: Config) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(cfg), indent=2), encoding="utf-8")
        restrict(tmp)
        os.replace(tmp, self.path)


def restrict(path: Path) -> None:
    """Owner-only. On Windows the data directory's ACL does this job."""
    if sys.platform != "win32":
        os.chmod(path, 0o600)
