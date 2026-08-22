"""
Platform dispatch.

The agent collects the same five things everywhere - metrics, listening
ports, sign-in events, local accounts, configuration posture, installed
packages and file integrity - but only metrics and ports are portable
(psutil handles both). Everything else is per-OS: journald against the
Windows Security event log against unified logging, dpkg against the
registry against pkgutil.

Each OS module exposes the same functions, so the agent itself contains no
platform conditionals. Adding an OS means adding a module, not editing the
collectors.
"""

import platform
import sys

LINUX, WINDOWS, MACOS = "linux", "windows", "macos"


def detect() -> str:
    p = sys.platform
    if p.startswith("linux"):
        return LINUX
    if p in ("win32", "cygwin"):
        return WINDOWS
    if p == "darwin":
        return MACOS
    return LINUX          # best effort; the Linux collectors degrade quietly


PLATFORM = detect()


def os_label() -> str:
    """Human-readable OS string for the dashboard."""
    if PLATFORM == WINDOWS:
        rel = platform.win32_ver()
        return f"Windows {rel[0]} {rel[1]}".strip()
    if PLATFORM == MACOS:
        mac = platform.mac_ver()
        return f"macOS {mac[0]}".strip()
    try:
        info = {}
        for line in open("/etc/os-release"):
            if "=" in line:
                k, v = line.split("=", 1)
                info[k] = v.strip().strip('"')
        return info.get("PRETTY_NAME", "Linux")
    except OSError:
        return f"Linux {platform.release()}"


def _module():
    if PLATFORM == WINDOWS:
        import os_windows as m
    elif PLATFORM == MACOS:
        import os_darwin as m
    else:
        import os_linux as m
    return m


# ---------------------------------------------------------------- interface
#
# Every OS module implements these. Each returns the same shape regardless of
# platform, so the ingest API and the dashboard stay platform-agnostic.

def collect_auth_events(buf):
    """[{kind, ts, username, source_ip, raw}] - sign-in and session events."""
    return _module().collect_auth_events(buf)


def collect_users():
    """[{username, uid, gid, shell, home, groups, sudoer, can_login, password}]"""
    return _module().collect_users()


def collect_checks():
    """[{check_id, title, category, severity, status, detail}]"""
    return _module().collect_checks()


def collect_packages():
    """[{name, version, arch}]"""
    return _module().collect_packages()


def collect_apps():
    """
    [{app_name, requests_total, errors_total, active_conns, extra}] for
    application servers the agent can read locally. Only Windows has one
    today - IIS - so everything else returns nothing rather than raising.
    """
    m = _module()
    fn = getattr(m, "collect_iis", None)
    return fn() if fn else []


def watch_paths():
    """Directories worth hashing for integrity monitoring on this OS."""
    return _module().WATCH_PATHS


def critical_paths():
    """(exact_paths_set, prefix_tuple) an attacker would edit on this OS."""
    m = _module()
    return m.CRITICAL_PATHS, m.CRITICAL_DIRS


def noise_patterns():
    """Compiled regexes for machine-generated churn to ignore."""
    return _module().NOISE_PATTERNS


def machine_id():
    """Stable per-install identifier."""
    return _module().machine_id()


def hardware_fingerprint():
    """{product_uuid, board_serial, ...} - evidence a node was not swapped."""
    return _module().hardware_fingerprint()


if __name__ == "__main__":
    print("platform:", PLATFORM)
    print("os label:", os_label())
    print("machine id:", machine_id())
    print("watch paths:", watch_paths())
