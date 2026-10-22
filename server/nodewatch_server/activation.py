"""
Licence activation: binding the licence to this machine.

A licence key says what the customer bought; an activation, signed by the
vendor's licence server, says which machine it runs on. Setup activates
online, or - on a network with no internet - offline: the master shows a
request code, the customer pastes it into the offline activation page,
and pastes the activation code it returns back into the master.

Online masters check in every few hours. That is how a renewed key
arrives without anyone touching the master, and how a master learns its
licence was moved to another machine or revoked. A check-in that cannot
reach the server changes nothing.

Masters set up before activation existed get ACTIVATION_GRACE_DAYS to
activate; they try on their own, but never take a licence that is active
on another machine.

Files in the data directory:
    activation.key    the signed activation (NWA1-...)
    activation.json   grace start, last check-in, what the server last said
"""

import datetime as dt
import hashlib
import json
import logging
import os
import socket
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature

from . import license as lic
from .config import restrict

log = logging.getLogger("nodewatch.activation")

ACTIVATION_PREFIX = "NWA1-"
REQUEST_PREFIX = "NWR1-"
ACTIVATION_DOMAIN = b"nodewatch-activation:"
ACTIVATION_GRACE_DAYS = 14

# The vendor's licence server (licensing/ in this repository) and the page
# air-gapped customers use. NW_LICENSING_URL overrides the server for tests.
LICENSING_URL = "https://REPLACE-WITH-PROJECT-REF.supabase.co/functions/v1/licensing"
OFFLINE_PAGE = "https://bluntlycoded.github.io/nodewatch/activate/"


def server_url() -> str:
    return os.environ.get("NW_LICENSING_URL") or LICENSING_URL


class ActivationError(Exception):
    """A refusal to show the user. unreachable: the server could not be
    asked at all, so offline activation is the way forward."""

    def __init__(self, message: str, unreachable: bool = False, code: str = ""):
        super().__init__(message)
        self.unreachable = unreachable
        self.code = code


@dataclass
class Activation:
    lid: str
    machine: str
    name: str
    activated: str
    method: str
    raw: str


def parse_activation(code: str) -> Activation:
    code = "".join((code or "").split())
    if not code.startswith(ACTIVATION_PREFIX) or "." not in code:
        raise ActivationError("that is not a nodewatch activation code (it starts with NWA1-)")
    body, _, sig = code[len(ACTIVATION_PREFIX):].partition(".")
    try:
        payload, signature = lic._b64d(body), lic._b64d(sig)
    except Exception:
        raise ActivationError("the activation code is damaged - copy it again")
    try:
        lic.public_key().verify(signature, ACTIVATION_DOMAIN + payload)
    except InvalidSignature:
        raise ActivationError("the activation code's signature is not valid")
    try:
        p = json.loads(payload)
        if p.get("kind") != "activation":
            raise ValueError("kind")
        return Activation(lid=str(p["lid"]), machine=str(p["machine"]), name=str(p.get("name", "")),
                          activated=str(p.get("activated", "")), method=str(p.get("method", "")), raw=code)
    except (KeyError, ValueError, TypeError):
        raise ActivationError("the activation code's contents are invalid")


# ---------------------------------------------------------------- machine

def _platform_id() -> str:
    if sys.platform == "darwin":
        out = subprocess.run(["/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                             capture_output=True, text=True, timeout=10).stdout
        for line in out.splitlines():
            if "IOPlatformUUID" in line:
                return line.split("=", 1)[1].strip().strip('"')
    elif sys.platform == "win32":
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0,
                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            return str(winreg.QueryValueEx(k, "MachineGuid")[0])
    else:
        for p in ("/etc/machine-id", "/var/lib/dbus/machine-id", "/sys/class/dmi/id/product_uuid"):
            try:
                v = Path(p).read_text().strip()
                if v:
                    return v
            except OSError:
                pass
    return ""


def machine_id(data_dir: Path) -> str:
    """32 hex characters identifying this machine, the same on every start.
    From the OS's own machine identifier; a machine without one (some
    containers) gets a random one kept in the data directory."""
    try:
        raw = _platform_id()
    except Exception as e:
        log.warning("could not read this machine's identifier: %s", e)
        raw = ""
    if not raw:
        path = data_dir / "machine-id"
        if not path.exists():
            path.write_text(os.urandom(16).hex() + "\n", encoding="utf-8")
        raw = "data-dir:" + path.read_text(encoding="utf-8").strip()
    return hashlib.sha256(b"nodewatch-machine:" + raw.encode()).hexdigest()[:32]


# ---------------------------------------------------------------- server

def _call(path: str, body: dict, timeout: float = 20) -> dict:
    import requests
    url = server_url().rstrip("/") + "/" + path
    if "REPLACE-WITH" in url:
        raise ActivationError("this build has no licence server address", unreachable=True)
    try:
        r = requests.post(url, json=body, timeout=timeout, headers={"User-Agent": "nodewatch-server"})
    except requests.RequestException as e:
        raise ActivationError(f"could not reach the licence server ({type(e).__name__})", unreachable=True)
    try:
        data = r.json()
    except ValueError:
        data = {}
    if r.status_code >= 500 or (r.status_code != 200 and not data.get("message")):
        raise ActivationError(f"the licence server answered {r.status_code}", unreachable=True)
    if r.status_code != 200:
        raise ActivationError(str(data.get("message")))
    return data


class Activator:

    def __init__(self, data_dir: Path, version: str):
        self.dir = data_dir
        self.version = version
        self.key_path = data_dir / "activation.key"
        self.state_path = data_dir / "activation.json"
        self._machine = None

    @property
    def machine(self) -> str:
        if self._machine is None:
            self._machine = machine_id(self.dir)
        return self._machine

    @property
    def name(self) -> str:
        return socket.gethostname()[:100]

    # ---- files

    def _state(self) -> dict:
        try:
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _save_state(self, st: dict) -> None:
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(st, indent=2), encoding="utf-8")
        restrict(tmp)
        os.replace(tmp, self.state_path)

    def current(self) -> Activation | None:
        try:
            return parse_activation(self.key_path.read_text(encoding="utf-8"))
        except (OSError, ActivationError):
            return None

    def valid_for(self, licence: lic.License) -> bool:
        a = self.current()
        return bool(a and a.lid == licence.lid and a.machine == self.machine)

    def _store(self, a: Activation) -> None:
        self.key_path.write_text(a.raw + "\n", encoding="utf-8")
        restrict(self.key_path)
        st = self._state()
        st.pop("server", None)            # a fresh activation supersedes "moved" / "revoked"
        st["last_checkin"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
        self._save_state(st)

    # ---- activation

    def activate_online(self, licence: lic.License, allow_move: bool = True) -> lic.License:
        """Activate on this machine. Returns the licence to install: the
        server's current key, which is newer than ours if it was renewed."""
        r = _call("activate", {"key": licence.raw, "machine": self.machine, "name": self.name,
                               "version": self.version, "allow_move": allow_move})
        if not r.get("ok"):
            raise ActivationError(r.get("message") or "the licence server refused activation",
                                  code=r.get("code", ""))
        a = parse_activation(r.get("activation", ""))
        if a.lid != licence.lid or a.machine != self.machine:
            raise ActivationError("the licence server returned an activation for another licence or machine")
        self._store(a)
        if r.get("moved_from"):
            log.warning("licence moved here from %s", r["moved_from"])
        return self._newer(licence, r.get("key"))

    def install(self, licence: lic.License, code: str) -> Activation:
        """An activation code from the offline activation page."""
        a = parse_activation(code)
        if a.lid != licence.lid:
            raise ActivationError("that activation code is for a different licence key")
        if a.machine != self.machine:
            raise ActivationError("that activation code was made for a different machine - "
                                  "use the request code this master shows")
        self._store(a)
        return a

    def request_code(self, licence: lic.License) -> str:
        p = json.dumps({"lid": licence.lid, "m": self.machine, "n": self.name}, separators=(",", ":"))
        return REQUEST_PREFIX + lic.b64e(p.encode())

    def _newer(self, licence: lic.License, key: str | None) -> lic.License:
        if not key or key == licence.raw:
            return licence
        try:
            new = lic.parse(key)
        except lic.LicenseError as e:
            log.warning("licence server sent a key this master cannot use: %s", e)
            return licence
        if new.lid != licence.lid:
            return licence
        return new

    # ---- running master

    def sync(self, licence: lic.License) -> lic.License | None:
        """Check in (or, unactivated, try to activate without taking the
        licence from another machine). Returns a renewed licence to install,
        or None. Never raises for network trouble."""
        if not self.valid_for(licence):
            try:
                new = self.activate_online(licence, allow_move=False)
                log.info("licence activated on this machine")
                return new if new.raw != licence.raw else None
            except ActivationError as e:
                log.warning("licence not activated: %s", e)
                return None
        try:
            r = _call("checkin", {"lid": licence.lid, "machine": self.machine, "version": self.version})
        except ActivationError as e:
            log.info("licence check-in skipped: %s", e)
            return None
        st = self._state()
        status = r.get("status")
        if status == "active":
            st.pop("server", None)
            st["last_checkin"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
            self._save_state(st)
            new = self._newer(licence, r.get("key"))
            return new if new.raw != licence.raw else None
        if status in ("released", "revoked"):
            if (st.get("server") or {}).get("status") != status:
                log.warning("licence server: %s", r.get("message") or status)
            st["server"] = {"status": status, "lid": licence.lid, "message": r.get("message", ""),
                            "at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")}
            self._save_state(st)
        return None

    def state(self, licence: lic.License) -> dict:
        """Activation part of the licence summary. activation is one of
        active, pending (not yet, within the grace period), required
        (grace over), released (moved elsewhere) or revoked."""
        st = self._state()
        server = st.get("server") or {}
        if server.get("lid") == licence.lid and server.get("status") in ("released", "revoked"):
            return {"activation": server["status"], "activation_message": server.get("message", "")}
        a = self.current()
        if a and a.lid == licence.lid and a.machine == self.machine:
            return {"activation": "active", "activated": a.activated, "activation_method": a.method,
                    "last_checkin": st.get("last_checkin", "")}
        grace = st.get("grace") or {}
        if grace.get("lid") != licence.lid:
            grace = {"lid": licence.lid, "from": dt.date.today().isoformat()}
            st["grace"] = grace
            try:
                self._save_state(st)
            except OSError:
                pass
        left = ACTIVATION_GRACE_DAYS - (dt.date.today() - dt.date.fromisoformat(grace["from"])).days
        if left >= 0:
            return {"activation": "pending", "activate_within_days": left}
        return {"activation": "required"}
