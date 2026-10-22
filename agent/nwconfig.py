"""
Where the agent keeps its settings, and loading them.

A node that joined a master with `nodewatch-agent join` (or the GUI) has
an agent.json beside the binary holding the master's address, the pinned
CA certificate and, until first enrolment, the single-use token. The
service definition carries no secrets, only the path to the binary.

Environment variables still win over the file, so hosts installed by the
older install.sh / install.ps1 / install-macos.sh, which set NW_* in the
unit, plist or launcher, keep working unchanged.
"""

import json
import os
import sys
from pathlib import Path

# config key -> environment variable the rest of the agent reads
KEYS = {
    "ingest_url": "NW_INGEST_URL",
    "enroll_token": "NW_ENROLL_TOKEN",
    "provider": "NW_PROVIDER",
    "site": "NW_SITE",
    "ca_file": "NW_CA_FILE",
    "state_dir": "NW_STATE_DIR",
}


def platform() -> str:
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def install_root() -> Path:
    p = platform()
    if p == "windows":
        return Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "nodewatch"
    if p == "macos":
        return Path("/usr/local/nodewatch")
    return Path("/opt/nodewatch")


def config_path() -> Path:
    override = os.environ.get("NW_CONFIG")
    if override:
        return Path(override)
    if platform() == "linux":
        return Path("/etc/nodewatch/agent.json")
    return install_root() / "agent.json"


def default_state_dir() -> Path:
    """Matches what each installer has always used."""
    if platform() == "linux":
        return Path("/var/lib/nodewatch")
    return install_root() / "state"


def status_path() -> Path:
    """
    status.json, which the GUI reads as an ordinary user. On Windows the
    state directory is locked to SYSTEM/Administrators (it holds the node
    key), so status lives one level up, under the install root.
    """
    if platform() == "windows":
        return install_root() / "status.json"
    return Path(os.environ.get("NW_STATE_DIR") or default_state_dir()) / "status.json"


def binary_path() -> Path:
    name = "nodewatch-agent.exe" if platform() == "windows" else "nodewatch-agent"
    return install_root() / name


def load() -> dict:
    try:
        return json.loads(config_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save(cfg: dict) -> None:
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    if platform() != "windows":
        os.chmod(tmp, 0o600)         # holds the token until first enrolment
    os.replace(tmp, path)


def apply() -> dict:
    """Fill in NW_* from the config file wherever the environment has not."""
    cfg = load()
    for key, env in KEYS.items():
        if cfg.get(key) and not os.environ.get(env):
            os.environ[env] = str(cfg[key])
    return cfg


def forget_token() -> None:
    """
    Drop the enrolment token once it has been spent. It is single use, so
    it is worthless afterwards - but there is no reason to keep a secret on
    disk that has no further purpose.
    """
    cfg = load()
    if cfg.pop("enroll_token", None) is not None:
        try:
            save(cfg)
        except OSError:
            pass
