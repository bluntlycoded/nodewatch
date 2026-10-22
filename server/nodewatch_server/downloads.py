"""
Agent binaries the master hands out, so a node never needs internet access
to install: built into the master at release time, and overridable by
dropping a newer nodewatch-agent-<version>-<os>-<arch>[.exe] into the data
directory's agents/ folder.
"""

import hashlib
import re
import sys
from pathlib import Path

NAME = re.compile(r"^nodewatch-agent-(\d+(?:\.\d+)*)-(linux|macos|windows)-(x64|arm64)(\.exe)?$")

# What `uname -m` prints, so install one-liners can use it directly.
ALIASES = {"x86_64": "x64", "amd64": "x64", "aarch64": "arm64", "arm64": "arm64", "x64": "x64"}


def _version_key(v: str):
    return tuple(int(x) for x in v.split("."))


class Agents:

    def __init__(self, data_dir: Path):
        bundled = Path(getattr(sys, "_MEIPASS", "")) / "agents" if hasattr(sys, "_MEIPASS") else None
        self.dirs = [d for d in (bundled, data_dir / "agents") if d]
        self.index: dict[str, dict] = {}
        self.scan()

    def scan(self) -> None:
        best: dict[str, dict] = {}
        for d in self.dirs:
            if not d.is_dir():
                continue
            for f in d.iterdir():
                m = NAME.match(f.name)
                if not m:
                    continue
                version, os_name, arch = m.group(1), m.group(2), m.group(3)
                key = f"{os_name}-{arch}"
                if key in best and _version_key(best[key]["version"]) >= _version_key(version):
                    continue
                best[key] = {"path": f, "version": version,
                             "sha256": hashlib.sha256(f.read_bytes()).hexdigest()}
        self.index = best

    def public(self) -> dict:
        return {k: {"version": v["version"], "sha256": v["sha256"]} for k, v in sorted(self.index.items())}

    def find(self, platform: str) -> dict | None:
        os_name, _, arch = platform.lower().partition("-")
        if os_name == "darwin":
            os_name = "macos"
        return self.index.get(f"{os_name}-{ALIASES.get(arch, arch)}")
