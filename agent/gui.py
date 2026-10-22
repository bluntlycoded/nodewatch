"""
The agent's window: join a master, see whether this machine is reporting,
change the master's address, restart the agent.

It runs as the signed-in user and never touches the service or its files
directly. Anything that needs root/Administrator re-runs this same binary
elevated - UAC on Windows, the system password prompt on macOS, pkexec on
Linux - with a one-shot command, and shows that command's result. The join
code travels through a private temp file rather than the command line, so
it never appears in a process listing.
"""

import json
import os
import shlex
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import ttk

import nwconfig

POLL_MS = 3000
STALE_S = 120


def self_command() -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable]
    return [sys.executable, str(Path(__file__).resolve().parent / "agent.py")]


def run_elevated(args: list[str], why: str = "make this change") -> tuple[bool, str]:
    """Run `nodewatch-agent <args>` as admin; returns (ok, message). `why`
    finishes the sentence on macOS's password dialog."""
    fd, result = tempfile.mkstemp(prefix="nw-result-", suffix=".json")
    os.close(fd)
    cmd = self_command() + args + ["--result-file", result]
    try:
        if sys.platform == "win32":
            rc = _shell_execute_runas(cmd)
        elif sys.platform == "darwin":
            def quoted(s: str) -> str:
                return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
            line = " ".join(shlex.quote(c) for c in cmd)
            prompt = f"nodewatch agent needs an administrator password to {why}."
            # osascript asks on behalf of a background helper, so without
            # "activate" the password dialog can open behind other windows
            # and look as if nothing happened. Output is kept as bytes: it
            # is not needed, and decoding it must never be able to fail.
            rc = subprocess.run(["osascript", "-e", "activate", "-e",
                                 f"do shell script {quoted(line)} with prompt {quoted(prompt)} "
                                 "with administrator privileges"], capture_output=True).returncode
        else:
            if not _which("pkexec"):
                return False, ("Run this in a terminal instead:\n  sudo "
                               + " ".join(shlex.quote(c) for c in self_command() + args))
            rc = subprocess.run(["pkexec"] + cmd, capture_output=True).returncode
        try:
            out = json.loads(Path(result).read_text() or "{}")
        except (OSError, ValueError):
            out = {}
        if out:
            return bool(out.get("ok")), out.get("message", "")
        return rc == 0, "" if rc == 0 else "cancelled, or administrator rights were refused"
    finally:
        try:
            os.unlink(result)
        except OSError:
            pass


def _which(name):
    from shutil import which
    return which(name)


def _shell_execute_runas(cmd: list[str]) -> int:
    import ctypes
    from ctypes import wintypes

    class SHELLEXECUTEINFOW(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD), ("fMask", wintypes.ULONG),
                    ("hwnd", wintypes.HWND), ("lpVerb", wintypes.LPCWSTR),
                    ("lpFile", wintypes.LPCWSTR), ("lpParameters", wintypes.LPCWSTR),
                    ("lpDirectory", wintypes.LPCWSTR), ("nShow", ctypes.c_int),
                    ("hInstApp", wintypes.HINSTANCE), ("lpIDList", ctypes.c_void_p),
                    ("lpClass", wintypes.LPCWSTR), ("hkeyClass", wintypes.HKEY),
                    ("dwHotKey", wintypes.DWORD), ("hIconOrMonitor", wintypes.HANDLE),
                    ("hProcess", wintypes.HANDLE)]

    sei = SHELLEXECUTEINFOW()
    sei.cbSize = ctypes.sizeof(sei)
    sei.fMask = 0x00000040          # SEE_MASK_NOCLOSEPROCESS
    sei.lpVerb = "runas"
    sei.lpFile = cmd[0]
    sei.lpParameters = subprocess.list2cmdline(cmd[1:])
    sei.nShow = 0                   # SW_HIDE: no console flash
    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei)):
        return 1223                 # ERROR_CANCELLED - the UAC prompt was declined
    ctypes.windll.kernel32.WaitForSingleObject(sei.hProcess, 0xFFFFFFFF)
    code = wintypes.DWORD()
    ctypes.windll.kernel32.GetExitCodeProcess(sei.hProcess, ctypes.byref(code))
    ctypes.windll.kernel32.CloseHandle(sei.hProcess)
    return code.value


def read_status() -> dict:
    try:
        return json.loads(nwconfig.status_path().read_text())
    except (OSError, ValueError):
        return {}


def _ago(ts) -> str:
    if not ts:
        return "never"
    s = int(time.time() - ts)
    if s < 90:
        return f"{s}s ago"
    if s < 5400:
        return f"{s // 60} min ago"
    return f"{s // 3600} h ago"


class App:

    def __init__(self, root: tk.Tk, version: str):
        self.root = root
        self.busy = False
        self.op = 0
        root.title("nodewatch agent")
        root.minsize(560, 420)

        outer = ttk.Frame(root, padding=18)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="nodewatch agent", font=("TkDefaultFont", 15, "bold")).pack(anchor="w")
        ttk.Label(outer, text=f"version {version} · {nwconfig.platform()}",
                  foreground="#6b7280").pack(anchor="w", pady=(0, 12))

        st = ttk.LabelFrame(outer, text="This machine", padding=12)
        st.pack(fill="x")
        self.master_var = tk.StringVar()
        self.state_var = tk.StringVar()
        self.detail_var = tk.StringVar()
        ttk.Label(st, textvariable=self.master_var).pack(anchor="w")
        self.state_label = ttk.Label(st, textvariable=self.state_var, font=("TkDefaultFont", 12, "bold"))
        self.state_label.pack(anchor="w", pady=(6, 0))
        ttk.Label(st, textvariable=self.detail_var, foreground="#6b7280", wraplength=500,
                  justify="left").pack(anchor="w")

        jf = ttk.LabelFrame(outer, text="Join a master", padding=12)
        jf.pack(fill="x", pady=12)
        ttk.Label(jf, text="Join code (from the master's Add node page)").pack(anchor="w")
        self.code = ttk.Entry(jf)
        self.code.pack(fill="x", pady=(2, 8))
        row = ttk.Frame(jf)
        row.pack(fill="x")
        ttk.Label(row, text="Site (optional)").pack(side="left")
        self.site = ttk.Entry(row, width=24)
        self.site.pack(side="left", padx=8)
        self.join_btn = ttk.Button(row, text="Join", command=self.join)
        self.join_btn.pack(side="right")

        af = ttk.LabelFrame(outer, text="Master address", padding=12)
        af.pack(fill="x")
        row2 = ttk.Frame(af)
        row2.pack(fill="x")
        self.url = ttk.Entry(row2)
        self.url.pack(side="left", fill="x", expand=True)
        self.url_btn = ttk.Button(row2, text="Change", command=self.change_url)
        self.url_btn.pack(side="left", padx=(8, 0))
        ttk.Label(af, text="For the same master at a new address. A different master needs a join code.",
                  foreground="#6b7280").pack(anchor="w", pady=(4, 0))

        bottom = ttk.Frame(outer)
        bottom.pack(fill="x", pady=(12, 0))
        self.msg = tk.StringVar()
        ttk.Label(bottom, textvariable=self.msg, wraplength=380, justify="left").pack(side="left")
        self.restart_btn = ttk.Button(bottom, text="Restart agent", command=self.restart)
        self.restart_btn.pack(side="right")

        self.refresh()

    # ------------------------------------------------------------ status

    def refresh(self):
        cfg = nwconfig.load()
        s = read_status()
        url = cfg.get("ingest_url") or s.get("ingest_url") or ""
        self.master_var.set(f"Master: {url}" if url else "Master: not joined yet")
        if url and not self.url.get() and self.root.focus_get() is not self.url:
            self.url.insert(0, url)

        shipped = s.get("last_ship_at") or 0
        if not url:
            self.state_var.set("○ Not joined")
            self.detail_var.set("Paste a join code from your nodewatch master below.")
        elif shipped and time.time() - shipped < STALE_S:
            self.state_var.set("● Reporting")
            self.detail_var.set(f"Last report {_ago(shipped)}"
                                + (f" · {s['queued']} queued" if s.get("queued") else ""))
        elif s.get("last_error"):
            self.state_var.set("● Not reporting")
            self.detail_var.set(f"{s['last_error']} ({_ago(s.get('last_error_at'))})")
        elif s.get("agent_id"):
            self.state_var.set("● Starting")
            self.detail_var.set(f"Enrolled {_ago(s.get('last_enroll_at'))}; waiting for the first report.")
        else:
            self.state_var.set("● Waiting")
            self.detail_var.set("The agent has not reported yet.")
        self.root.after(POLL_MS, self.refresh)

    # ------------------------------------------------------------ actions

    def _do(self, label: str, args: list[str], why: str, code: str | None = None):
        if self.busy:
            return
        self.busy = True
        self.op += 1
        op = self.op
        for b in (self.join_btn, self.url_btn, self.restart_btn):
            b.state(["disabled"])
        self.msg.set(f"{label}… enter your administrator password when asked.")

        def still_waiting():
            if self.busy and self.op == op:
                self.msg.set(f"{label}… still working. If no password dialog appeared, it may be behind "
                             "other windows or on another desktop.")
        self.root.after(15000, still_waiting)

        def work():
            code_file = None
            ok, message = False, ""
            try:
                if code is not None:
                    fd, code_file = tempfile.mkstemp(prefix="nw-join-")
                    with os.fdopen(fd, "w") as f:
                        f.write(code)
                    args.extend(["--code-file", code_file])
                ok, message = run_elevated(args, why)
            except Exception as e:
                # Report it: a silent failure here left the window saying
                # "Joining…" forever with every button disabled.
                ok, message = False, f"could not run the administrator step: {e}"
            finally:
                if code_file:
                    try:
                        os.unlink(code_file)
                    except OSError:
                        pass
                self.root.after(0, lambda: self._done(ok, message))

        threading.Thread(target=work, daemon=True).start()

    def _done(self, ok: bool, message: str):
        self.busy = False
        for b in (self.join_btn, self.url_btn, self.restart_btn):
            b.state(["!disabled"])
        self.msg.set(("✓ " if ok else "✗ ") + (message or ("Done." if ok else "Failed.")))
        if ok:
            self.code.delete(0, "end")

    def join(self):
        code = self.code.get().strip()
        if not code:
            self.msg.set("Paste a join code first.")
            return
        args = ["join"]
        if self.site.get().strip():
            args += ["--site", self.site.get().strip()]
        self._do("Joining", args, "join this computer to your nodewatch master", code=code)

    def change_url(self):
        url = self.url.get().strip()
        if url:
            self._do("Changing address", ["set-url", url], "change the nodewatch master's address")

    def restart(self):
        self._do("Restarting", ["restart"], "restart the nodewatch agent")


def main(version: str) -> int:
    if sys.platform == "win32":
        # Double-clicked from Explorer, a console binary also opens a console
        # window; hide it while the GUI is up.
        # Only when the console is ours alone - started from a terminal, it
        # is the user's terminal and stays.
        import ctypes
        pids = (ctypes.c_uint * 4)()
        alone = ctypes.windll.kernel32.GetConsoleProcessList(pids, 4) <= 1
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd and alone:
            ctypes.windll.user32.ShowWindow(hwnd, 0)
    root = tk.Tk()
    App(root, version)
    root.mainloop()
    return 0
