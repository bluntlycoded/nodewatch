"""
The master as a real Windows service.

`nodewatch-server install` on Windows copies the binary to
%ProgramFiles%\\nodewatch-server, registers it with the Service Control
Manager (automatic start, restart on failure) as `<exe> service-run`, and
starts it. The service answers SCM stop requests by shutting the web
servers down, which then stops PostgREST and PostgreSQL cleanly - the same
path Ctrl-C and SIGTERM take on Linux.

pywin32 is needed only here, and only in the Windows build.
"""

import logging
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

NAME = "nodewatch-server"
DISPLAY = "nodewatch master"
DESCRIPTION = "nodewatch master node: dashboard, ingest API, database, alerting and probes."

log = logging.getLogger("nodewatch.service")


def _sc(*args, check=True):
    res = subprocess.run(["sc.exe", *args], capture_output=True, text=True)
    if check and res.returncode != 0:
        raise RuntimeError(f"sc.exe {' '.join(args[:2])} failed: {(res.stdout or res.stderr).strip()[:300]}")
    return res


def install(data_dir: Path) -> None:
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
        sys.exit("run install from an elevated (Administrator) prompt")
    if not hasattr(sys, "_MEIPASS"):
        sys.exit("install is for the packaged nodewatch-server.exe")

    root = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "nodewatch-server"
    exe = root / "nodewatch-server.exe"
    if _sc("query", NAME, check=False).returncode == 0:
        _sc("stop", NAME, check=False)
        time.sleep(5)
    root.mkdir(parents=True, exist_ok=True)
    if Path(sys.executable).resolve() != exe.resolve():
        shutil.copy2(sys.executable, exe)

    # SYSTEM and Administrators only: config.json and the CA key live here.
    data_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["icacls", str(data_dir), "/inheritance:r", "/grant:r",
                    "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"], capture_output=True, check=True)

    bin_path = f'"{exe}" --data "{data_dir}" service-run'
    if _sc("query", NAME, check=False).returncode == 0:
        _sc("config", NAME, "binPath=", bin_path, "start=", "auto")
    else:
        _sc("create", NAME, "binPath=", bin_path, "start=", "auto", "DisplayName=", DISPLAY)
    _sc("description", NAME, DESCRIPTION)
    # Restart 5 s, 5 s, then 30 s after a crash; reset the count after a day.
    _sc("failure", NAME, "reset=", "86400", "actions=", "restart/5000/restart/5000/restart/30000")
    _sc("start", NAME)
    print(f"installed and started the {DISPLAY} service.")
    print(f"The setup code is in {data_dir / 'server.log'} and {data_dir / 'config.json'}.")


def uninstall() -> None:
    _sc("stop", NAME, check=False)
    time.sleep(5)
    _sc("delete", NAME, check=False)
    print("service removed; the data directory is kept.")


def dispatch(make_master) -> None:
    """Called as `<exe> service-run` by the SCM."""
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil

    class MasterService(win32serviceutil.ServiceFramework):
        _svc_name_ = NAME
        _svc_display_name_ = DISPLAY
        _svc_description_ = DESCRIPTION

        def __init__(self, args):
            super().__init__(args)
            self.stop_event = win32event.CreateEvent(None, 0, 0, None)
            self.master = None

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING, waitHint=60_000)
            if self.master:
                self.master.request_stop()
            win32event.SetEvent(self.stop_event)

        def SvcDoRun(self):
            servicemanager.LogInfoMsg(f"{DISPLAY} starting")
            try:
                self.master = make_master()
                self.master.run(open_browser=False)
            except Exception as e:
                log.exception("master stopped with an error")
                servicemanager.LogErrorMsg(f"{DISPLAY} stopped: {e}")
                raise
            finally:
                if self.master:
                    self.master.stop_database()
            servicemanager.LogInfoMsg(f"{DISPLAY} stopped")

    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(MasterService)
    servicemanager.StartServiceCtrlDispatcher()
