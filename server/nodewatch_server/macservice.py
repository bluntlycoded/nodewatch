"""
The master as a macOS background service (launchd).

`nodewatch-server install --user <name>` (run as root - the Master window
does it through the macOS administrator prompt) copies "nodewatch
Master.app" to /Applications if it is running from somewhere else, writes
/Library/LaunchDaemons/com.nodewatch.server.plist and starts it.

The daemon runs at boot, whether or not anyone is logged in, but as the
named ordinary user rather than root: PostgreSQL refuses to run as root,
and the master needs nothing beyond its data directory and a port - the
same least privilege the Linux master gets from its own `nodewatch` user
and the Windows one from NetworkService. Using the installing user's
account, rather than creating a hidden one, lets the Master window (which
runs as that user) read the setup code from config.json.
"""

import os
import plistlib
import pwd
import shutil
import subprocess
import sys
import time
from pathlib import Path

LABEL = "com.nodewatch.server"
PLIST = Path("/Library/LaunchDaemons") / f"{LABEL}.plist"
APP_NAME = "nodewatch Master.app"
APPS = Path("/Applications")


def _run(cmd, check=True):
    res = subprocess.run(cmd, capture_output=True, text=True)
    if check and res.returncode != 0:
        raise RuntimeError(f"{' '.join(map(str, cmd[:3]))} failed: {(res.stderr or res.stdout).strip()[:300]}")
    return res


def app_bundle() -> Path | None:
    """The .app this executable runs from, if it is the app build."""
    if not getattr(sys, "frozen", False):
        return None             # from source, sys.executable may be Python.app
    for parent in Path(sys.executable).resolve().parents:
        if parent.suffix == ".app":
            return parent
    return None


def installed() -> bool:
    return PLIST.exists()


def _install_app() -> Path:
    """
    Copy the app to /Applications so the daemon runs a stable path - not
    the DMG (unmounted later) or a translocated copy in a random folder.
    Returns the executable inside the installed app.
    """
    bundle = app_bundle()
    if bundle is None:
        # The plain single-file binary: put it beside where the app would be.
        target = Path("/usr/local/nodewatch-server/nodewatch-server")
        target.parent.mkdir(parents=True, exist_ok=True)
        if Path(sys.executable).resolve() != target.resolve():
            shutil.copy2(sys.executable, target)
            os.chmod(target, 0o755)
        return target
    exe_rel = Path(sys.executable).resolve().relative_to(bundle)
    target = APPS / APP_NAME
    if not (target.exists() and target.resolve() == bundle):
        tmp = APPS / (APP_NAME + ".new")
        shutil.rmtree(tmp, ignore_errors=True)
        shutil.copytree(bundle, tmp, symlinks=True)
        shutil.rmtree(target, ignore_errors=True)
        tmp.rename(target)
    return target / exe_rel


def install(data_dir: Path, user: str) -> None:
    if os.geteuid() != 0:
        sys.exit("install must run as root (the Master window asks for the administrator password)")
    try:
        account = pwd.getpwnam(user)
    except KeyError:
        sys.exit(f"no such user: {user}")
    if account.pw_uid == 0:
        sys.exit("choose an ordinary user account: PostgreSQL will not run as root")

    if installed():
        _run(["launchctl", "bootout", "system", str(PLIST)], check=False)
        time.sleep(2)
    exe = _install_app()

    data_dir.mkdir(parents=True, exist_ok=True)
    _run(["chown", "-R", f"{account.pw_uid}:{account.pw_gid}", str(data_dir)])
    os.chmod(data_dir, 0o700)

    PLIST.write_bytes(plistlib.dumps({
        "Label": LABEL,
        "ProgramArguments": [str(exe), "--data", str(data_dir), "--no-browser", "serve"],
        "UserName": user,
        "RunAtLoad": True,
        # Restart after a crash, not after a clean stop.
        "KeepAlive": {"SuccessfulExit": False},
        "ThrottleInterval": 10,
        "ExitTimeOut": 60,
        "StandardOutPath": str(data_dir / "launchd.log"),
        "StandardErrorPath": str(data_dir / "launchd.log"),
        "EnvironmentVariables": {"NW_SERVER_DATA": str(data_dir)},
    }))
    os.chmod(PLIST, 0o644)
    _run(["launchctl", "bootstrap", "system", str(PLIST)])
    print(f"installed and started the nodewatch master as {user}; data in {data_dir}")


def uninstall() -> None:
    if os.geteuid() != 0:
        sys.exit("uninstall must run as root")
    if installed():
        _run(["launchctl", "bootout", "system", str(PLIST)], check=False)
        PLIST.unlink(missing_ok=True)
    print("service removed; the data directory and the app are kept.")


def restart() -> None:
    if os.geteuid() != 0:
        sys.exit("restart must run as root")
    _run(["launchctl", "kickstart", "-k", f"system/{LABEL}"])
