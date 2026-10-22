"""
Installing the agent as a background service, per OS.

Same service names the script installers use - nodewatch-agent.service,
com.nodewatch.agent, and the nodewatch-agent scheduled task - so installing
the binary over a script install replaces it rather than running a second
agent beside it. The service definition carries no secrets: it runs the
binary with `run`, and the binary reads agent.json.
"""

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import nwconfig

UNIT = Path("/etc/systemd/system/nodewatch-agent.service")
PLIST = Path("/Library/LaunchDaemons/com.nodewatch.agent.plist")
LABEL = "com.nodewatch.agent"
TASK = "nodewatch-agent"

SYSTEMD_UNIT = """[Unit]
Description=nodewatch agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart={exe} run
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""

LAUNCHD_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{label}</string>
  <key>ProgramArguments</key>
  <array><string>{exe}</string><string>run</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>{state}/launchd.log</string>
  <key>StandardErrorPath</key><string>{state}/launchd.log</string>
</dict>
</plist>
"""

# Mirrors install.ps1's task: SYSTEM, at startup, restarted every minute on
# failure, no execution time limit.
WINDOWS_TASK = r"""
$ErrorActionPreference = 'Stop'
$a = New-ScheduledTaskAction -Execute '{exe}' -Argument 'run'
$t = New-ScheduledTaskTrigger -AtStartup
$p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
       -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
       -ExecutionTimeLimit (New-TimeSpan -Seconds 0)
Unregister-ScheduledTask -TaskName '{task}' -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName '{task}' -Action $a -Trigger $t -Principal $p -Settings $s `
  -Description 'nodewatch host telemetry and trust verification agent' | Out-Null
Start-ScheduledTask -TaskName '{task}'
"""


class ServiceError(RuntimeError):
    pass


def is_admin() -> bool:
    if sys.platform == "win32":
        import ctypes
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def _run(cmd, check=True) -> subprocess.CompletedProcess:
    res = subprocess.run(cmd, capture_output=True, text=True)
    if check and res.returncode != 0:
        raise ServiceError(f"{' '.join(map(str, cmd[:3]))} failed: {(res.stderr or res.stdout).strip()[:400]}")
    return res


def _powershell(script: str, check=True):
    return _run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                 "-Command", script], check=check)


def lock_down(path: Path) -> None:
    """
    Windows: SYSTEM and Administrators only. Program Files is readable by
    every user, and the state directory holds the node's private key.
    """
    if sys.platform == "win32" and path.exists():
        _run(["icacls", str(path), "/inheritance:r", "/grant:r",
              "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"])


def install_binary() -> Path:
    """Copy the running binary to its permanent place, if it is not there."""
    target = nwconfig.binary_path()
    if not getattr(sys, "frozen", False):
        raise ServiceError("installing a service needs the packaged nodewatch-agent binary")
    me = Path(sys.executable).resolve()
    if target.exists() and me == target.resolve():
        return target
    target.parent.mkdir(parents=True, exist_ok=True)
    stop()                      # Windows cannot overwrite a running executable
    tmp = target.with_suffix(target.suffix + ".new")
    shutil.copy2(me, tmp)
    if sys.platform != "win32":
        os.chmod(tmp, 0o755)
    os.replace(tmp, target)
    return target


def install() -> None:
    exe = install_binary()
    state = nwconfig.default_state_dir()
    state.mkdir(parents=True, exist_ok=True)
    plat = nwconfig.platform()
    if plat == "linux":
        UNIT.write_text(SYSTEMD_UNIT.format(exe=exe))
        os.chmod(UNIT, 0o644)
        _run(["systemctl", "daemon-reload"])
        _run(["systemctl", "enable", "nodewatch-agent"])
        _run(["systemctl", "restart", "nodewatch-agent"])
    elif plat == "macos":
        PLIST.write_text(LAUNCHD_PLIST.format(label=LABEL, exe=exe, state=state))
        os.chmod(PLIST, 0o644)
        _run(["launchctl", "bootout", "system", str(PLIST)], check=False)
        _run(["launchctl", "bootstrap", "system", str(PLIST)])
    else:
        lock_down(state)
        lock_down(nwconfig.config_path())
        _powershell(WINDOWS_TASK.format(exe=str(exe).replace("'", "''"), task=TASK))


def stop() -> None:
    plat = nwconfig.platform()
    if plat == "linux":
        _run(["systemctl", "stop", "nodewatch-agent"], check=False)
    elif plat == "macos":
        _run(["launchctl", "bootout", "system", str(PLIST)], check=False)
    else:
        exe = str(nwconfig.binary_path()).replace("'", "''")
        # Stop-ScheduledTask returns before the process has gone. Only the
        # installed copy is killed - never a GUI started from Downloads.
        _powershell(f"Stop-ScheduledTask -TaskName '{TASK}' -ErrorAction SilentlyContinue; "
                    f"Get-Process -ErrorAction SilentlyContinue | Where-Object {{ $_.Path -eq '{exe}' }} "
                    f"| Stop-Process -Force", check=False)
        time.sleep(1)


def restart() -> None:
    plat = nwconfig.platform()
    if plat == "linux":
        _run(["systemctl", "restart", "nodewatch-agent"])
    elif plat == "macos":
        _run(["launchctl", "kickstart", "-k", f"system/{LABEL}"])
    else:
        stop()
        _powershell(f"Start-ScheduledTask -TaskName '{TASK}'")


def uninstall() -> None:
    stop()
    plat = nwconfig.platform()
    if plat == "linux":
        _run(["systemctl", "disable", "nodewatch-agent"], check=False)
        UNIT.unlink(missing_ok=True)
        _run(["systemctl", "daemon-reload"], check=False)
    elif plat == "macos":
        PLIST.unlink(missing_ok=True)
    else:
        _powershell(f"Unregister-ScheduledTask -TaskName '{TASK}' -Confirm:$false "
                    "-ErrorAction SilentlyContinue", check=False)


def installed() -> bool:
    plat = nwconfig.platform()
    if plat == "linux":
        return UNIT.exists()
    if plat == "macos":
        return PLIST.exists()
    return _powershell(f"Get-ScheduledTask -TaskName '{TASK}'", check=False).returncode == 0
