"""
Host posture checks: configuration hardening and account anomalies.

Every check is local and read-only. Each returns pass/fail/error with a
short detail string, so a failure is actionable rather than just a number.
The agent ships a full snapshot; the server diffs it, same as ports.
"""

import os
import re
import stat
import subprocess

SEV_HIGH, SEV_MED, SEV_LOW = "high", "medium", "low"


def _run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception:
        return ""


def _read(path):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except Exception:
        return None


def _check(cid, title, cat, sev, ok, detail):
    return {
        "check_id": cid, "title": title, "category": cat, "severity": sev,
        "status": "pass" if ok else "fail", "detail": detail,
    }


# ---------------------------------------------------------------- ssh

SSHD_RULES = [
    ("ssh-root-login",   "Root login over SSH is disabled",      "permitrootlogin",       lambda v: v in ("no", "prohibit-password"), SEV_HIGH),
    ("ssh-password-auth","Password authentication is disabled",  "passwordauthentication",lambda v: v == "no",  SEV_HIGH),
    ("ssh-empty-pass",   "Empty passwords are rejected",         "permitemptypasswords",  lambda v: v == "no",  SEV_HIGH),
    ("ssh-x11",          "X11 forwarding is disabled",           "x11forwarding",         lambda v: v == "no",  SEV_LOW),
    ("ssh-max-auth",     "MaxAuthTries is 4 or fewer",           "maxauthtries",          lambda v: v.isdigit() and int(v) <= 4, SEV_MED),
    ("ssh-gateway-ports","Gateway ports are disabled",           "gatewayports",          lambda v: v == "no",  SEV_MED),
    ("ssh-permit-tunnel","Tunnelling is disabled",               "permittunnel",          lambda v: v == "no",  SEV_LOW),
]


def check_sshd():
    """`sshd -T` prints the effective config, including compiled defaults."""
    out = _run(["sshd", "-T"]) or _run(["/usr/sbin/sshd", "-T"])
    if not out:
        return [{"check_id": "ssh-config", "title": "SSH configuration is readable",
                 "category": "ssh", "severity": SEV_MED, "status": "error",
                 "detail": "could not read effective sshd config"}]

    cfg = {}
    for line in out.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            cfg[parts[0].lower()] = parts[1].strip()

    results = []
    for cid, title, key, ok_fn, sev in SSHD_RULES:
        val = cfg.get(key, "")
        results.append(_check(cid, title, "ssh", sev, bool(val) and ok_fn(val.lower()),
                              f"{key} = {val or 'unset'}"))
    return results


# ---------------------------------------------------------------- filesystem

PERM_RULES = [
    ("perm-shadow",  "/etc/shadow is not world or group readable", "/etc/shadow",  0o640, SEV_HIGH),
    ("perm-gshadow", "/etc/gshadow is not world or group readable","/etc/gshadow", 0o640, SEV_MED),
    ("perm-passwd",  "/etc/passwd is not writable by others",      "/etc/passwd",  0o644, SEV_MED),
    ("perm-group",   "/etc/group is not writable by others",       "/etc/group",   0o644, SEV_LOW),
]


def check_permissions():
    results = []
    for cid, title, path, maxmode, sev in PERM_RULES:
        try:
            mode = stat.S_IMODE(os.stat(path).st_mode)
            results.append(_check(cid, title, "filesystem", sev,
                                  mode & ~maxmode == 0, f"{path} mode {oct(mode)}"))
        except FileNotFoundError:
            results.append({"check_id": cid, "title": title, "category": "filesystem",
                            "severity": sev, "status": "error", "detail": f"{path} not found"})
    return results


def check_world_writable():
    out = _run(["find", "/etc", "-xdev", "-type", "f", "-perm", "-0002"], timeout=20)
    files = [f for f in out.strip().splitlines() if f]
    return [_check("fs-world-writable", "No world-writable files under /etc",
                   "filesystem", SEV_HIGH, not files,
                   "none found" if not files else f"{len(files)} found: " + ", ".join(files[:3]))]


# ---------------------------------------------------------------- kernel

SYSCTL_RULES = [
    ("sysctl-rp-filter",   "Reverse path filtering is enabled",  "net.ipv4.conf.all.rp_filter",        "1", SEV_MED),
    ("sysctl-redirects",   "ICMP redirects are not accepted",    "net.ipv4.conf.all.accept_redirects", "0", SEV_MED),
    ("sysctl-src-route",   "Source routed packets are dropped",  "net.ipv4.conf.all.accept_source_route", "0", SEV_MED),
    ("sysctl-syncookies",  "TCP SYN cookies are enabled",        "net.ipv4.tcp_syncookies",            "1", SEV_MED),
    ("sysctl-aslr",        "Full address space randomisation",   "kernel.randomize_va_space",          "2", SEV_HIGH),
    ("sysctl-ip-forward",  "IP forwarding is disabled",          "net.ipv4.ip_forward",                "0", SEV_LOW),
]


def check_sysctl():
    results = []
    for cid, title, key, want, sev in SYSCTL_RULES:
        val = (_read("/proc/sys/" + key.replace(".", "/")) or "").strip()
        results.append(_check(cid, title, "kernel", sev, val == want,
                              f"{key} = {val or 'unreadable'}"))
    return results


# ---------------------------------------------------------------- accounts

def check_accounts():
    """Account anomalies: extra root-equivalent users, passwordless logins."""
    results = []
    passwd = _read("/etc/passwd") or ""
    shadow = _read("/etc/shadow")

    uid0, uids, login_users = [], {}, []
    for line in passwd.splitlines():
        f = line.split(":")
        if len(f) < 7:
            continue
        name, uid, shell = f[0], f[2], f[6]
        uids.setdefault(uid, []).append(name)
        if uid == "0":
            uid0.append(name)
        if not shell.endswith(("nologin", "false", "sync")):
            login_users.append(name)

    extra_root = [u for u in uid0 if u != "root"]
    results.append(_check("acct-uid0", "Only root has UID 0", "accounts", SEV_HIGH,
                          not extra_root,
                          "root only" if not extra_root else "also: " + ", ".join(extra_root)))

    dupes = {u: n for u, n in uids.items() if len(n) > 1}
    results.append(_check("acct-dup-uid", "No duplicate UIDs", "accounts", SEV_MED,
                          not dupes,
                          "none" if not dupes else "; ".join(f"uid {u}: {','.join(n)}" for u, n in dupes.items())))

    if shadow is None:
        results.append({"check_id": "acct-empty-pass",
                        "title": "No accounts with an empty password",
                        "category": "accounts", "severity": SEV_HIGH,
                        "status": "error", "detail": "/etc/shadow unreadable (needs root)"})
    else:
        empty = [l.split(":")[0] for l in shadow.splitlines()
                 if len(l.split(":")) > 1 and l.split(":")[1] == ""]
        results.append(_check("acct-empty-pass", "No accounts with an empty password",
                              "accounts", SEV_HIGH, not empty,
                              "none" if not empty else ", ".join(empty)))

    results.append(_check("acct-login-count", "Interactive accounts are limited",
                          "accounts", SEV_LOW, len(login_users) <= 3,
                          f"{len(login_users)}: " + ", ".join(login_users[:5])))
    return results


# ---------------------------------------------------------------- system

def check_firewall():
    out = _run(["ufw", "status"])
    if not out:
        nft = _run(["nft", "list", "ruleset"])
        active = bool(nft.strip())
        return [_check("sys-firewall", "A host firewall is active", "system", SEV_MED,
                       active, "nftables ruleset present" if active else "ufw not installed, no nftables rules")]
    active = "Status: active" in out
    return [_check("sys-firewall", "A host firewall is active", "system", SEV_MED,
                   active, out.splitlines()[0] if out.splitlines() else "unknown")]


def check_auto_updates():
    present = os.path.exists("/etc/apt/apt.conf.d/20auto-upgrades")
    detail = "not configured"
    if present:
        content = _read("/etc/apt/apt.conf.d/20auto-upgrades") or ""
        enabled = '"1"' in content
        return [_check("sys-auto-updates", "Automatic security updates are enabled",
                       "system", SEV_MED, enabled,
                       "enabled" if enabled else "file present but disabled")]
    return [_check("sys-auto-updates", "Automatic security updates are enabled",
                   "system", SEV_MED, False, detail)]


def check_pending_updates():
    out = _run(["/usr/lib/update-notifier/apt-check"], timeout=15)
    err = _run(["sh", "-c", "/usr/lib/update-notifier/apt-check 2>&1 1>/dev/null"], timeout=15)
    raw = (err or out).strip()
    m = re.match(r"^(\d+);(\d+)$", raw)
    if not m:
        return [{"check_id": "sys-security-updates",
                 "title": "No pending security updates", "category": "system",
                 "severity": SEV_MED, "status": "error", "detail": "apt-check unavailable"}]
    sec = int(m.group(2))
    return [_check("sys-security-updates", "No pending security updates", "system",
                   SEV_HIGH if sec > 5 else SEV_MED, sec == 0,
                   f"{sec} security update(s) pending")]


# ---------------------------------------------------------------- entry point

COLLECTORS = [
    check_sshd, check_permissions, check_world_writable, check_sysctl,
    check_accounts, check_firewall, check_auto_updates, check_pending_updates,
]


def collect_checks():
    """Never raise: a broken check must not stop the agent's main loop."""
    out = []
    for fn in COLLECTORS:
        try:
            out.extend(fn())
        except Exception as e:
            out.append({"check_id": f"error-{fn.__name__}",
                        "title": f"Check group {fn.__name__} ran",
                        "category": "system", "severity": SEV_LOW,
                        "status": "error", "detail": str(e)[:200]})
    return out


if __name__ == "__main__":
    import json
    res = collect_checks()
    passed = sum(1 for r in res if r["status"] == "pass")
    print(json.dumps(res, indent=2))
    print(f"\n{passed}/{len(res)} passed")


# ---------------------------------------------------------------- accounts inventory

def collect_users():
    """
    Full snapshot of local accounts. The server diffs it into added /
    removed / modified events, so the agent stays stateless about accounts.

    Group membership is included because 'user added to sudo' is the change
    that actually matters — a new unprivileged account is routine, the same
    account gaining sudo an hour later is not.
    """
    passwd = _read("/etc/passwd") or ""
    group = _read("/etc/group") or ""
    shadow = _read("/etc/shadow")

    # Supplementary groups, keyed by member.
    member_of = {}
    primary_gid_name = {}
    for line in group.splitlines():
        f = line.split(":")
        if len(f) < 4:
            continue
        gname, gid, members = f[0], f[2], f[3]
        primary_gid_name[gid] = gname
        for m in filter(None, members.split(",")):
            member_of.setdefault(m, set()).add(gname)

    # Password state per account.
    pw_state = {}
    if shadow:
        for line in shadow.splitlines():
            f = line.split(":")
            if len(f) < 2:
                continue
            h = f[1]
            pw_state[f[0]] = (
                "none" if h == "" else
                "locked" if h.startswith(("!", "*")) else
                "set"
            )

    users = []
    for line in passwd.splitlines():
        f = line.split(":")
        if len(f) < 7:
            continue
        name, uid, gid, home, shell = f[0], f[2], f[3], f[5], f[6]
        groups = set(member_of.get(name, set()))
        if gid in primary_gid_name:
            groups.add(primary_gid_name[gid])
        users.append({
            "username": name,
            "uid": int(uid) if uid.isdigit() else None,
            "gid": int(gid) if gid.isdigit() else None,
            "shell": shell,
            "home": home,
            "groups": sorted(groups),
            "sudoer": bool(groups & {"sudo", "admin", "wheel"}),
            "can_login": not shell.endswith(("nologin", "false", "sync")),
            "password": pw_state.get(name, "unknown"),
        })
    return users
