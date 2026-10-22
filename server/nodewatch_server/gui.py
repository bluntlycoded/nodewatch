"""
The nodewatch Master window (macOS app).

Shows whether the master is installed and running, the setup code until
setup is finished, and buttons to install/start, open the setup page or
dashboard, restart and remove the service. It runs as the signed-in user;
installing, restarting and removing re-run this same executable through
the macOS administrator prompt, which is macOS's own requirement for
anything that starts at boot.
"""

import json
import os
import pwd
import shlex
import ssl
import subprocess
import sys
import threading
import tkinter as tk
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path
from tkinter import ttk

POLL_MS = 3000


def _self_cmd() -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable]
    return [sys.executable, str(Path(__file__).resolve().parents[1] / "nodewatch-server.py")]


def run_as_admin(args: list[str]) -> tuple[bool, str]:
    line = " ".join(shlex.quote(c) for c in _self_cmd() + args)
    script = 'do shell script "%s" with administrator privileges' % line.replace("\\", "\\\\").replace('"', '\\"')
    res = subprocess.run(["osascript", "-e", script], capture_output=True, text=True)
    if res.returncode == 0:
        return True, res.stdout.strip().splitlines()[-1] if res.stdout.strip() else "done"
    err = (res.stderr or "").strip()
    if "-128" in err:                       # the user pressed Cancel
        return False, "cancelled"
    return False, err[-300:] or "failed"


class MasterWindow:

    def __init__(self, root: tk.Tk, data_dir: Path, version: str, installed):
        self.root, self.data, self.installed = root, data_dir, installed
        self.busy = False
        self.state = {"kind": "unknown"}
        root.title("nodewatch master")
        root.minsize(520, 380)

        f = ttk.Frame(root, padding=20)
        f.pack(fill="both", expand=True)
        ttk.Label(f, text="nodewatch master", font=("TkDefaultFont", 16, "bold")).pack(anchor="w")
        ttk.Label(f, text=f"version {version} · data in {data_dir}", foreground="#6b7280").pack(anchor="w", pady=(0, 14))

        box = ttk.LabelFrame(f, text="Status", padding=14)
        box.pack(fill="x")
        self.status = tk.StringVar(value="Checking…")
        self.detail = tk.StringVar()
        ttk.Label(box, textvariable=self.status, font=("TkDefaultFont", 13, "bold")).pack(anchor="w")
        ttk.Label(box, textvariable=self.detail, foreground="#6b7280", wraplength=460, justify="left").pack(anchor="w", pady=(4, 0))

        self.codebox = ttk.LabelFrame(f, text="Setup code", padding=14)
        self.code = tk.StringVar()
        ttk.Label(self.codebox, textvariable=self.code, font=("Menlo", 26, "bold")).pack(anchor="w")
        ttk.Label(self.codebox, text="Enter it on the setup page with your licence key.",
                  foreground="#6b7280").pack(anchor="w")

        self.buttons = ttk.Frame(f)
        self.buttons.pack(fill="x", side="bottom", pady=(14, 0))
        self.primary = ttk.Button(self.buttons, command=self.primary_action)
        self.primary.pack(side="left")
        self.restart_btn = ttk.Button(self.buttons, text="Restart", command=lambda: self.admin(["restart"], "Restarting"))
        self.remove_btn = ttk.Button(self.buttons, text="Stop and remove service",
                                     command=lambda: self.admin(["uninstall"], "Removing the service"))
        self.msg = tk.StringVar()
        ttk.Label(f, textvariable=self.msg, wraplength=460, justify="left").pack(side="bottom", anchor="w")
        self.refresh()

    # ------------------------------------------------------------ state

    def _config(self) -> dict | None:
        try:
            return json.loads((self.data / "config.json").read_text())
        except PermissionError:
            return {"_unreadable": True}
        except (OSError, ValueError):
            return None

    def _probe(self, port: int) -> str:
        """'ready', 'setup' or 'down' - a status check only, nothing is sent."""
        ctx = ssl.create_default_context()
        ca = self.data / "pki" / "ca.crt"
        try:
            ctx.load_verify_locations(str(ca))
            ctx.check_hostname = False
        except OSError:
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        try:
            with urllib.request.urlopen(f"https://localhost:{port}/health", context=ctx, timeout=2) as r:
                return "ready" if r.status == 200 else "down"
        except urllib.error.HTTPError as e:
            return "setup" if e.code == 503 else "down"
        except (OSError, ssl.SSLError):
            return "down"

    def refresh(self):
        def work():
            cfg = self._config()
            port = (cfg or {}).get("https_port", 8443)
            st = {"cfg": cfg, "port": port, "installed": self.installed(), "net": self._probe(port)}
            self.root.after(0, lambda: self._show(st))
        threading.Thread(target=work, daemon=True).start()
        self.root.after(POLL_MS, self.refresh)

    def _show(self, st):
        self.state = st
        cfg, net, inst = st["cfg"] or {}, st["net"], st["installed"]
        self.codebox.pack_forget()
        for b in (self.restart_btn, self.remove_btn):
            b.pack_forget()
        if cfg.get("_unreadable"):
            self.status.set("Installed by another account")
            self.detail.set("Open this app while signed in as the account that installed the master.")
            self.primary.config(text="Open dashboard")
        elif net == "setup":
            self.status.set("● Running — waiting for setup")
            self.detail.set("Open the setup page, enter the setup code below, your licence key and an administrator "
                            "account for the dashboard. Your browser will warn about the certificate the first time.")
            self.code.set(cfg.get("setup_code", "—"))
            self.codebox.pack(fill="x", pady=(12, 0))
            self.primary.config(text="Open setup page")
        elif net == "ready":
            addr = cfg.get("public_address") or "localhost"
            self.status.set("● Running")
            self.detail.set(f"Nodes report to https://{addr}:{st['port']}. Add nodes from the dashboard: "
                            "Servers → Add server.")
            self.primary.config(text="Open dashboard")
        elif inst:
            self.status.set("○ Starting or stopped")
            self.detail.set("The service is installed but not answering yet. The first start takes up to a minute "
                            "while the database is created. If it stays like this, use Reinstall and start - "
                            "also the way to upgrade to this version of the app.")
            self.primary.config(text="Reinstall and start")
        else:
            self.status.set("○ Not installed")
            self.detail.set("Install the master as a background service. It starts at boot, keeps running when "
                            "nobody is signed in, and holds the dashboard and database for your whole network. "
                            "macOS asks for an administrator password.")
            self.primary.config(text="Install and start")
        if inst:
            self.restart_btn.pack(side="left", padx=(8, 0))
            self.remove_btn.pack(side="right")
        state = ["disabled"] if self.busy else ["!disabled"]
        for b in (self.primary, self.restart_btn, self.remove_btn):
            b.state(state)

    # ------------------------------------------------------------ actions

    def primary_action(self):
        st = self.state
        if st.get("net") == "setup":
            webbrowser.open(f"https://localhost:{st['port']}/setup")
        elif st.get("net") == "ready" or (st.get("cfg") or {}).get("_unreadable"):
            webbrowser.open(f"https://localhost:{st.get('port', 8443)}/")
        else:
            user = pwd.getpwuid(os.getuid()).pw_name
            self.admin(["--data", str(self.data), "install", "--user", user], "Installing")

    def admin(self, args, label):
        if self.busy:
            return
        self.busy = True
        self.msg.set(f"{label}… (approve the administrator prompt)")
        self._show(self.state)

        def work():
            ok, out = run_as_admin(args)
            def done():
                self.busy = False
                self.msg.set(("✓ " if ok else "✗ ") + out)
                self._show(self.state)
            self.root.after(0, done)
        threading.Thread(target=work, daemon=True).start()


def main(data_dir: Path, version: str, installed) -> int:
    root = tk.Tk()
    MasterWindow(root, data_dir, version, installed)
    root.mainloop()
    return 0
