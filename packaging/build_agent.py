#!/usr/bin/env python3
"""
Build the nodewatch agent into a single self-contained executable for the
OS and CPU this script runs on.

PyInstaller does not cross-compile: a Windows binary has to be built on
Windows, a macOS one on macOS, an arm64 one on arm64. Run this once per
target - natively, in packaging/linux/Dockerfile, or via
.github/workflows/build-agent.yml, which does all of them.

    python -m pip install -r agent/requirements.txt -r packaging/requirements-build.txt
    python packaging/build_agent.py

Output lands in dist/:

    nodewatch-agent-<version>-<os>-<arch>[.exe]
    nodewatch-agent-<version>-<os>-<arch>[.exe].sha256

The binary is the agent and nothing else - same environment variables,
same behaviour as `python agent.py`. It needs no Python on the host.
"""

import hashlib
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENT = ROOT / "agent"
DIST = ROOT / "dist"
WORK = ROOT / "build" / "pyinstaller"

# Imported inside functions by osdetect, so PyInstaller's analysis already
# finds them - listed anyway so a future refactor to importlib cannot
# silently ship a binary without its platform module.
PLATFORM_MODULES = ["os_linux", "os_windows", "os_darwin", "virt",
                    "nwconfig", "nodekey", "joining", "service", "gui"]

# Nothing in the agent or master uses these; leaving them out keeps the
# binaries small. tkinter is excluded from the master only - the agent's
# window (gui.py) needs it.
EXCLUDES = ["unittest", "pydoc", "test", "lib2to3", "idlelib"]


def agent_version() -> str:
    src = (AGENT / "agent.py").read_text(encoding="utf-8")
    m = re.search(r'^AGENT_VERSION = "([^"]+)"', src, re.M)
    if not m:
        sys.exit("AGENT_VERSION not found in agent/agent.py")
    return m.group(1)


def target() -> tuple[str, str]:
    os_name = {"linux": "linux", "win32": "windows", "darwin": "macos"}.get(sys.platform)
    if not os_name:
        sys.exit(f"unsupported build platform: {sys.platform}")
    machine = platform.machine().lower()
    arch = {"x86_64": "x64", "amd64": "x64", "arm64": "arm64", "aarch64": "arm64"}.get(machine)
    if not arch:
        sys.exit(f"unsupported build architecture: {machine}")
    return os_name, arch


def windows_version_file(version: str) -> Path:
    """
    Version resource for the .exe. An unsigned binary with no publisher or
    description is one more reason for an EDR to treat it as anonymous; the
    agent already identifies itself in its User-Agent for the same reason.
    """
    parts = [int(p) for p in re.findall(r"\d+", version)[:4]]
    parts += [0] * (4 - len(parts))
    tup = tuple(parts)
    path = WORK / "version_info.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers={tup}, prodvers={tup}, mask=0x3f, flags=0x0,
                    OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', 'nodewatch'),
      StringStruct('FileDescription', 'nodewatch host telemetry agent'),
      StringStruct('FileVersion', '{version}'),
      StringStruct('InternalName', 'nodewatch-agent'),
      StringStruct('OriginalFilename', 'nodewatch-agent.exe'),
      StringStruct('ProductName', 'nodewatch'),
      StringStruct('ProductVersion', '{version}')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
""", encoding="utf-8")
    return path


def main() -> None:
    version = agent_version()
    os_name, arch = target()
    exe = ".exe" if os_name == "windows" else ""
    name = f"nodewatch-agent-{version}-{os_name}-{arch}"

    shutil.rmtree(WORK, ignore_errors=True)
    DIST.mkdir(exist_ok=True)

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--console",          # runs headless under systemd/launchd/Task Scheduler; logs go to stdout
        "--clean",
        "--noconfirm",
        "--name", name,
        "--paths", str(AGENT),
        "--distpath", str(DIST),
        "--workpath", str(WORK),
        "--specpath", str(WORK),
    ]
    for mod in PLATFORM_MODULES:
        cmd += ["--hidden-import", mod]
    for mod in EXCLUDES:
        cmd += ["--exclude-module", mod]
    if os_name == "windows":
        cmd += ["--version-file", str(windows_version_file(version))]
    cmd.append(str(AGENT / "agent.py"))

    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True)

    binary = DIST / f"{name}{exe}"
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    (DIST / f"{binary.name}.sha256").write_text(f"{digest}  {binary.name}\n", newline="\n")

    print(f"\nbuilt {binary}  ({binary.stat().st_size / 1e6:.1f} MB)")
    print(f"sha256 {digest}")

    # Smoke test: the binary starts and reports the version it was built from.
    out = subprocess.run([str(binary), "--version"], capture_output=True, text=True)
    if out.returncode != 0:
        # Show why: a frozen binary that cannot start says so on stderr.
        sys.exit(f"{binary.name} --version exited {out.returncode}\n{out.stdout}{out.stderr}")
    if version not in out.stdout:
        sys.exit(f"--version printed {out.stdout!r}, expected {version}")
    print(out.stdout.strip())


if __name__ == "__main__":
    main()
