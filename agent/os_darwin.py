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
import shutil
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

    results.append(check_screen_lock())
    results.append(check_edr())
    results.append(check_remote_access())
    results.append(check_ai_skills())

    return results


# ---------------------------------------------------------------- end-user computing

def _console_user():
    """
    The interactively logged-in user, if any. Root is what /dev/console
    shows before anyone has logged in, so it means no session, not a user
    named root.
    """
    out = run(["stat", "-f%Su", "/dev/console"]).strip()
    return out if out and out != "root" else None


def check_screen_lock():
    """
    com.apple.screensaver is a per-user preference domain, not a system
    one, and the agent runs as a root launchd daemon with no session of
    its own - hence -currentHost plus running as the actual console user,
    the same technique macOS's own MDM profiles rely on.
    """
    user = _console_user()
    if not user:
        return _error("mac-screen-lock", "Screen lock is enabled", "euc", SEV_MED,
                      "no console user session found")

    ask = run(["sudo", "-u", user, "defaults", "-currentHost", "read",
              "com.apple.screensaver", "askForPassword"]).strip()
    delay = run(["sudo", "-u", user, "defaults", "-currentHost", "read",
                "com.apple.screensaver", "askForPasswordDelay"]).strip()

    if ask not in ("0", "1"):
        return _error("mac-screen-lock", "Screen lock is enabled", "euc", SEV_MED,
                      f"could not read the screensaver setting for {user}")
    return _check("mac-screen-lock", "Screen lock is enabled", "euc", SEV_MED,
                  ask == "1", f"askForPassword = {ask}, delay {delay or '0'}s (user {user})")


# Presence is reported, not required - fleets standardise on different
# vendors - but a desktop running none of them is worth knowing about.
EDR_PROCESSES = {
    "falcon-sensor": "CrowdStrike Falcon", "SentinelAgent": "SentinelOne",
    "SentinelServiceHelper": "SentinelOne", "wdavdaemon": "Microsoft Defender",
    "SophosScanD": "Sophos", "sophos_agent": "Sophos", "osqueryd": "osquery",
    "cbagentd": "Carbon Black", "elastic-agent": "Elastic Agent",
}


def check_edr():
    procs = run(["ps", "-axo", "comm"])
    found = sorted({label for needle, label in EDR_PROCESSES.items() if needle in procs})
    return _check("mac-edr", "A recognised security agent is running", "euc",
                  SEV_MED, bool(found),
                  ", ".join(found) if found else "none of the known agents were found")


# A visibility check, not a policy one: presence fails at low severity so
# it surfaces for review, since only a person knows whether a given
# install is IT-sanctioned.
REMOTE_ACCESS_PROCESSES = {
    "TeamViewer": "TeamViewer", "AnyDesk": "AnyDesk",
    "vncserver": "VNC", "ScreenConnect.ClientService": "ScreenConnect",
    "LMIGuardianSvc": "LogMeIn",
}


def check_remote_access():
    procs = run(["ps", "-axo", "comm"])
    found = sorted({label for needle, label in REMOTE_ACCESS_PROCESSES.items() if needle in procs})
    return _check("mac-remote-access", "No remote-access software is running", "euc",
                  SEV_LOW, not found,
                  "none found" if not found else "running: " + ", ".join(found))


# Known AI-CLI skill directories, relative to a user's home. Claude Code's
# convention is well documented and stable; others get added here once
# confirmed rather than guessed at.
AI_SKILL_DIRS = {"Claude Code": ".claude/skills"}
AI_SKILLS_SCAN_MAX = 15   # bounded like every other unbounded-input check here


def _find_ai_skills():
    """[(tool, skill_dir, [skill_name, ...])] for every populated skill
    directory found across every real user's home under /Users."""
    found = []
    try:
        homes = [f"/Users/{d}" for d in os.listdir("/Users")
                 if d not in ("Shared", "Guest") and not d.startswith(".")
                 and os.path.isdir(f"/Users/{d}")]
    except OSError:
        homes = []
    for home in homes:
        for tool, rel in AI_SKILL_DIRS.items():
            base = os.path.join(home, rel)
            if not os.path.isdir(base):
                continue
            try:
                skills = [d for d in os.listdir(base)
                         if os.path.isfile(os.path.join(base, d, "SKILL.md"))]
            except OSError:
                continue
            if skills:
                found.append((tool, base, skills))
    return found


def check_ai_skills():
    """
    Installed AI-agent skills (Claude Code, etc.) run with implicit trust
    and minimal vetting - this doesn't install or execute anything, it
    only reports whether skillspector (github.com/NVIDIA/skillspector),
    if present on the host, considers what's already installed safe.
    """
    dirs = _find_ai_skills()
    if not dirs:
        return _check("mac-ai-skills", "Installed AI-agent skills carry no unreviewed risk",
                      "ai_skills", SEV_MED, True, "no AI-agent skills found")

    total = sum(len(skills) for _, _, skills in dirs)
    scanner = shutil.which("skillspector")
    if not scanner:
        return _error("mac-ai-skills", "Installed AI-agent skills carry no unreviewed risk",
                      "ai_skills", SEV_MED,
                      f"{total} skill(s) found but skillspector is not installed to assess them")

    order = {"SAFE": 0, "CAUTION": 1, "DO_NOT_INSTALL": 2}
    worst, flagged, scanned = "SAFE", [], 0
    for tool, base, skills in dirs:
        for name in skills:
            if scanned >= AI_SKILLS_SCAN_MAX:
                break
            scanned += 1
            # --no-llm: static analysis only, nothing about the skill's
            # contents leaves this host.
            out = run([scanner, "scan", os.path.join(base, name), "--no-llm", "--format", "json"],
                     timeout=20)
            try:
                verdict = json.loads(out)["risk_assessment"]
                rec = verdict.get("recommendation", "SAFE")
            except Exception:
                continue
            if order.get(rec, 0) > order.get(worst, 0):
                worst = rec
            if rec != "SAFE":
                flagged.append(f"{name} ({rec}, score {verdict.get('score', '?')})")

    sev = SEV_HIGH if worst == "DO_NOT_INSTALL" else SEV_MED
    detail = f"{scanned} of {total} skill(s) scanned"
    detail += f", flagged: {', '.join(flagged)}" if flagged else ", none flagged"
    return _check("mac-ai-skills", "Installed AI-agent skills carry no unreviewed risk",
                  "ai_skills", sev, worst == "SAFE", detail)


# A browser dragged into /Applications rather than installed from a .pkg
# has no pkgutil receipt and no Homebrew formula, so it would otherwise be
# invisible to inventory and vulnerability scanning entirely - which
# matters here specifically because the browser is the most exposed piece
# of software on an end-user machine.
BROWSER_APPS = {
    "Google Chrome.app": "Google Chrome",
    "Firefox.app": "Mozilla Firefox",
    "Microsoft Edge.app": "Microsoft Edge",
    "Brave Browser.app": "Brave Browser",
}


def _browser_packages():
    out = []
    for app_name, pkg_name in BROWSER_APPS.items():
        try:
            with open(f"/Applications/{app_name}/Contents/Info.plist", "rb") as f:
                version = plistlib.load(f).get("CFBundleShortVersionString")
        except Exception:
            continue
        if version:
            out.append({"name": pkg_name, "version": str(version)[:100], "arch": None})
    return out


# ---------------------------------------------------------------- packages

def collect_packages():
    """
    pkgutil lists Apple-installer receipts, which covers the OS and anything
    installed from a .pkg. Homebrew is added when present because on a
    developer Mac it is where most third-party software actually lives.
    Browsers are checked separately since a drag-installed .app has neither.
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

    out.extend(_browser_packages())
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
