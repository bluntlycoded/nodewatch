"""
macOS collectors.

Uses the tools that ship with the OS - dscl, log, pkgutil, spctl, fdesetup,
csrutil, socketfilterfw - so there is nothing to install beyond psutil and
requests. No Homebrew dependency: a managed Mac may not have it, and the
security posture that matters is Apple's, not the package manager's.
"""

import json
import os
import plistlib
import re
import subprocess

SEV_HIGH, SEV_MED, SEV_LOW = "high", "medium", "low"

WATCH_PATHS = ["/etc", "/Library/LaunchDaemons", "/Library/LaunchAgents"]

CRITICAL_PATHS = {
    "/etc/sudoers", "/etc/hosts", "/etc/ssh/sshd_config",
    "/etc/pam.d/sudo", "/etc/pam.d/login", "/etc/pam.d/authorization",
}
# LaunchDaemons and LaunchAgents are how persistence is installed on macOS,
# which puts them in the same class as cron and systemd units on Linux.
CRITICAL_DIRS = (
    "/etc/sudoers.d/", "/etc/pam.d/", "/etc/ssh/sshd_config.d/",
    "/Library/LaunchDaemons/", "/Library/LaunchAgents/",
)

NOISE_PATTERNS = [
    re.compile(r"^/etc/(?:localtime|resolv\.conf|hosts\.equiv)$"),
    re.compile(r"^/etc/ssl/certs/[0-9a-f]{8}\.\d+$"),
    re.compile(r"^/etc/.*\.pyc$"),
    re.compile(r"^/private/var/.*"),
]

TIMEOUT = 30


def run(cmd, timeout=TIMEOUT):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        return ""


def _check(cid, title, cat, sev, ok, detail):
    return {"check_id": cid, "title": title, "category": cat, "severity": sev,
            "status": "pass" if ok else "fail", "detail": detail}


def _error(cid, title, cat, sev, detail):
    return {"check_id": cid, "title": title, "category": cat, "severity": sev,
            "status": "error", "detail": detail}


# ---------------------------------------------------------------- sign-in events

def collect_auth_events(buf):
    """
    Unified logging replaced syslog, so sshd and authorisation events come
    from `log show`. It has no cursor, so a timestamp high-water mark plays
    the same role as journald's __CURSOR.
    """
    last = buf.get_meta("mac_auth_high_water")
    window = "15m" if last else "1h"

    out_text = run([
        "log", "show", "--style", "ndjson", "--last", window,
        "--predicate",
        'process == "sshd" OR process == "loginwindow" OR '
        'eventMessage CONTAINS "Authentication" OR eventMessage CONTAINS "authentication"',
    ], timeout=60)

    events, newest = [], last or ""
    for line in out_text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue

        ts_iso = rec.get("timestamp") or ""
        if last and ts_iso <= last:
            continue
        msg = rec.get("eventMessage") or ""
        kind = classify(msg)
        if not kind:
            continue

        try:
            import datetime
            clean = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", ts_iso.replace(" ", "T", 1))
            ts = datetime.datetime.fromisoformat(clean).timestamp()
        except Exception:
            continue

        events.append({
            "kind": kind, "ts": ts,
            "username": extract_user(msg),
            "source_ip": extract_ip(msg),
            "raw": msg[:400],
        })
        newest = max(newest, ts_iso)

    if newest:
        buf.set_meta("mac_auth_high_water", newest)
    return events


AUTH_PATTERNS = [
    ("login_success", "Accepted "),
    ("login_failed", "Failed password"),
    ("login_failed", "Invalid user"),
    ("login_failed", "authentication failed"),
    ("login_failed", "Authentication failure"),
    ("session_opened", "session opened for user"),
    ("session_closed", "session closed for user"),
    ("logout", "Disconnected from user"),
]

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def classify(msg):
    for kind, needle in AUTH_PATTERNS:
        if needle in msg:
            return kind
    return None


def extract_user(msg):
    parts = msg.split()
    if len(parts) > 2 and parts[0].lower() == "invalid" and parts[1] == "user":
        return parts[2].split("(")[0]
    anchor = None
    for word in ("for", "from", "user"):
        if word in parts:
            anchor = parts.index(word) + 1
            break
    if anchor is None:
        return None
    while anchor < len(parts) and parts[anchor] in ("invalid", "user"):
        anchor += 1
    if anchor >= len(parts):
        return None
    cand = parts[anchor].split("(")[0].strip(":,")
    return cand if cand and not IP_RE.fullmatch(cand) else None


def extract_ip(msg):
    m = IP_RE.search(msg)
    return m.group(0) if m else None


# ---------------------------------------------------------------- accounts

def collect_users():
    """
    dscl is the directory service; /etc/passwd on macOS is vestigial and does
    not list real accounts. Anything with a UID below 500 is a system account.
    """
    names = [n for n in run(["dscl", ".", "-list", "/Users"]).split()
             if not n.startswith("_")]
    admins = set(run(["dscl", ".", "-read", "/Groups/admin", "GroupMembership"])
                 .replace("GroupMembership:", "").split())

    out = []
    for name in names:
        detail = run(["dscl", ".", "-read", f"/Users/{name}",
                      "UniqueID", "PrimaryGroupID", "UserShell", "NFSHomeDirectory"])
        def field(key):
            m = re.search(rf"^{key}:\s*(.+)$", detail, re.M)
            return m.group(1).strip() if m else None

        uid = field("UniqueID")
        shell = field("UserShell") or ""
        uid_i = int(uid) if uid and uid.isdigit() else None

        # AuthenticationAuthority absent means no password can be set, which
        # is how macOS marks a disabled or passwordless account.
        auth = run(["dscl", ".", "-read", f"/Users/{name}", "AuthenticationAuthority"])
        pw = "none" if "No such key" in auth or not auth.strip() else "set"

        out.append({
            "username": name,
            "uid": uid_i,
            "gid": int(field("PrimaryGroupID")) if (field("PrimaryGroupID") or "").isdigit() else None,
            "shell": shell,
            "home": field("NFSHomeDirectory"),
            "groups": ["admin"] if name in admins else [],
            "sudoer": name in admins,
            "can_login": bool(uid_i and uid_i >= 500)
                         and not shell.endswith(("false", "nologin")),
            "password": pw,
        })
    return out


# ---------------------------------------------------------------- posture

def collect_checks():
    results = []

    sip = run(["csrutil", "status"])
    results.append(_check("mac-sip", "System Integrity Protection is enabled",
                          "system", SEV_HIGH, "enabled" in sip.lower(),
                          sip.strip()[:80] or "csrutil unavailable"))

    fv = run(["fdesetup", "status"])
    results.append(_check("mac-filevault", "FileVault disk encryption is on",
                          "filesystem", SEV_HIGH, "FileVault is On" in fv,
                          fv.strip()[:80] or "fdesetup unavailable"))

    fw = run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
    results.append(_check("mac-firewall", "Application firewall is enabled",
                          "system", SEV_HIGH, "enabled" in fw.lower(),
                          fw.strip()[:80] or "socketfilterfw unavailable"))

    stealth = run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode"])
    results.append(_check("mac-stealth", "Firewall stealth mode is on", "network",
                          SEV_LOW, "enabled" in stealth.lower(),
                          stealth.strip()[:80]))

    gk = run(["spctl", "--status"])
    results.append(_check("mac-gatekeeper", "Gatekeeper is enabled", "system",
                          SEV_HIGH, "assessments enabled" in gk.lower(),
                          gk.strip()[:80] or "spctl unavailable"))

    ssh = run(["systemsetup", "-getremotelogin"])
    if "Remote Login" in ssh:
        results.append(_check("mac-remotelogin", "Remote Login (SSH) is off",
                              "network", SEV_MED, "Off" in ssh,
                              ssh.strip()[:80]))
    else:
        results.append(_error("mac-remotelogin", "Remote Login (SSH) is off",
                              "network", SEV_MED, "needs root to query"))

    # Software Update preferences live in a plist rather than a command.
    try:
        with open("/Library/Preferences/com.apple.SoftwareUpdate.plist", "rb") as f:
            su = plistlib.load(f)
    except Exception:
        su = {}
    results.append(_check("mac-autoupdate", "Automatic security updates are enabled",
                          "system", SEV_MED,
                          su.get("AutomaticCheckEnabled", False) is True,
                          f"AutomaticCheckEnabled = {su.get('AutomaticCheckEnabled')}"))

    updates = run(["softwareupdate", "-l"], timeout=120)
    pending = len([l for l in updates.splitlines() if l.strip().startswith("*")])
    results.append(_check("mac-updates", "No pending software updates", "system",
                          SEV_HIGH if pending > 3 else SEV_MED, pending == 0,
                          f"{pending} update(s) available"))

    guest = run(["defaults", "read", "/Library/Preferences/com.apple.loginwindow",
                 "GuestEnabled"]).strip()
    results.append(_check("mac-guest", "The Guest account is disabled", "accounts",
                          SEV_MED, guest != "1",
                          "guest enabled" if guest == "1" else "guest disabled"))

    for path, mode, sev in (("/etc/sudoers", 0o440, SEV_HIGH),
                            ("/etc/ssh/sshd_config", 0o644, SEV_MED)):
        try:
            import stat as _stat
            m = _stat.S_IMODE(os.stat(path).st_mode)
            results.append(_check(f"mac-perm-{os.path.basename(path)}",
                                  f"{path} is not writable by others",
                                  "filesystem", sev, m & ~mode == 0,
                                  f"{path} mode {oct(m)}"))
        except FileNotFoundError:
            pass

    return results


# ---------------------------------------------------------------- packages

def collect_packages():
    """
    pkgutil lists Apple-installer receipts, which covers the OS and anything
    installed from a .pkg. Homebrew is added when present because on a
    developer Mac it is where most third-party software actually lives.
    """
    out = []
    for pid in run(["pkgutil", "--pkgs"], timeout=60).split():
        info = run(["pkgutil", "--pkg-info", pid], timeout=10)
        m = re.search(r"^version:\s*(.+)$", info, re.M)
        out.append({"name": pid[:200], "version": (m.group(1).strip() if m else "unknown")[:100],
                    "arch": None})

    brew = run(["brew", "list", "--versions"], timeout=60)
    for line in brew.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            out.append({"name": f"brew:{parts[0]}"[:200], "version": parts[1][:100],
                        "arch": None})
    return out


# ---------------------------------------------------------------- identity

def machine_id():
    """IOPlatformUUID is stable per machine and survives reinstalls."""
    out = run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"])
    m = re.search(r'"IOPlatformUUID"\s*=\s*"([^"]+)"', out)
    return m.group(1).replace("-", "").lower() if m else None


def hardware_fingerprint():
    out = run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"])
    def pick(key):
        # ioreg renders strings as "x" but data as <"x">, so handle both
        # rather than stopping at the opening angle bracket.
        m = re.search(rf'"{key}"\s*=\s*<?"([^"]+)"', out)
        if m:
            return m.group(1).strip()
        m = re.search(rf'"{key}"\s*=\s*([^\n<>"]+)', out)
        return m.group(1).strip() if m else None
    import platform as _p, socket as _s
    return {
        "hostname": _s.gethostname(),
        "fqdn": _s.getfqdn(),
        "product_uuid": pick("IOPlatformUUID"),
        "board_serial": pick("IOPlatformSerialNumber"),
        "kernel": _p.release(),
        "model": pick("model"),
    }
