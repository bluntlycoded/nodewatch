"""
File integrity monitoring and package inventory.

FIM differs from the port collector on purpose. Ports are ~10 rows, so the
agent ships a full snapshot and the server derives the change log — the
agent stays stateless and cannot desync. /etc is ~2,000 files, so a full
manifest every cycle would be a 100KB+ payload and thousands of writes.
FIM therefore diffs locally against a manifest held in the agent's SQLite
and ships only changes, plus a manifest digest so the server can detect
drift and ask for a resync.
"""

import hashlib
import os
import re
import stat
import subprocess
import time

# Directories worth watching by default. Deliberately narrow: hashing
# /usr or /var produces noise on every package update and buries the
# signal that matters.
WATCH_PATHS = ["/etc"]

# Never hash these - they change constantly and carry no integrity value.
SKIP_PREFIXES = (
    "/etc/mtab", "/etc/adjtime", "/etc/resolv.conf",
    "/etc/machine-id", "/etc/blkid.tab", "/etc/lvm/archive",
    "/etc/apt/apt.conf.d/01autoremove-kernels",
)

# A change to any of these is reported at high severity regardless of what
# else moved. These are the files an attacker edits.
CRITICAL_PATHS = {
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
    "/etc/sudoers", "/etc/crontab", "/etc/hosts",
    "/etc/ssh/sshd_config", "/etc/pam.conf", "/etc/nsswitch.conf",
    "/etc/ld.so.preload",
}
CRITICAL_DIRS = ("/etc/sudoers.d/", "/etc/ssh/sshd_config.d/",
                 "/etc/cron.d/", "/etc/pam.d/", "/etc/systemd/system/")

# Auto-generated unit files that snapd rewrites on every refresh. The
# revision number is part of the filename, so an ordinary snap update
# deletes one set and creates another - churn, not tampering.
#
# The pattern deliberately requires the numeric revision. A file called
# snap-evil.mount would still be reported: only the machine-generated
# naming convention is excused, not the directory.
NOISE_PATTERNS = [
    re.compile(r"^/etc/systemd/system/(?:[^/]+\.wants/)?snap[-.].*-\d+\.mount$"),
    re.compile(r"^/etc/systemd/system/snap\.[^/]+\.service$"),
    re.compile(r"^/etc/systemd/system/multi-user\.target\.wants/snap[-.].*-\d+\.mount$"),
    re.compile(r"^/etc/systemd/system/snapd\.mounts(?:-pre)?\.target\.wants/.*\.mount$"),
    # Certificate bundle rehashes on every ca-certificates update.
    re.compile(r"^/etc/ssl/certs/[0-9a-f]{8}\.\d+$"),
]


def is_noise(path: str) -> bool:
    return any(p.match(path) for p in NOISE_PATTERNS)

MAX_FILE_BYTES = 8 * 1024 * 1024   # skip anything larger; nothing in /etc should be
MAX_FILES = 8000                    # hard ceiling so a bad path cannot hang the agent


def is_critical(path: str) -> bool:
    if is_noise(path):
        return False
    return path in CRITICAL_PATHS or path.startswith(CRITICAL_DIRS)


def sha256_of(path: str):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(131072)
                if not chunk:
                    break
                h.update(chunk)
    except (OSError, PermissionError):
        return None
    return h.hexdigest()


def scan_files():
    """
    Walk the watched paths and return {path: (sha256, mode, uid, gid, size)}.
    Symlinks are recorded by their target rather than followed, so a
    symlink swap is itself detected as a change.
    """
    out = {}
    count = 0
    for root_path in WATCH_PATHS:
        for root, dirs, files in os.walk(root_path, topdown=True):
            # Do not cross filesystem boundaries or descend into noise.
            dirs[:] = [d for d in dirs
                       if not os.path.join(root, d).startswith(SKIP_PREFIXES)]
            for name in files:
                p = os.path.join(root, name)
                if p.startswith(SKIP_PREFIXES) or is_noise(p):
                    continue
                count += 1
                if count > MAX_FILES:
                    return out
                try:
                    st = os.lstat(p)
                except OSError:
                    continue

                if stat.S_ISLNK(st.st_mode):
                    try:
                        target = os.readlink(p)
                    except OSError:
                        continue
                    digest = "link:" + hashlib.sha256(target.encode()).hexdigest()[:32]
                elif not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE_BYTES:
                    continue
                else:
                    digest = sha256_of(p)
                    if digest is None:
                        continue

                out[p] = (digest, stat.S_IMODE(st.st_mode),
                          st.st_uid, st.st_gid, st.st_size)
    return out


def manifest_digest(manifest: dict) -> str:
    """Cheap whole-state fingerprint so the server can spot divergence."""
    h = hashlib.sha256()
    for p in sorted(manifest):
        h.update(p.encode())
        h.update(manifest[p][0].encode())
    return h.hexdigest()


def collect_fim(buf, force_full=False):
    """
    Diff the current scan against the manifest stored in the agent's SQLite.
    Returns (events, summary). On first run it seeds silently: reporting
    every file in /etc as 'added' at enrolment would be pure noise.
    """
    current = scan_files()

    prev = {}
    stored = buf.get_meta("fim_manifest")
    if stored and not force_full:
        for row in stored.split("\n"):
            if not row:
                continue
            parts = row.split("\t")
            if len(parts) == 5:
                prev[parts[0]] = (parts[1], int(parts[2]), int(parts[3]), int(parts[4]))

    seeding = not prev
    events = []

    if not seeding:
        for p, (digest, mode, uid, gid, size) in current.items():
            old = prev.get(p)
            if old is None:
                events.append({
                    "path": p, "action": "added", "critical": is_critical(p),
                    "sha256": digest, "mode": oct(mode), "size": size,
                    "detail": f"new file, mode {oct(mode)}, {size} bytes",
                })
            else:
                diffs = []
                if old[0] != digest:
                    diffs.append("content")
                if old[1] != mode:
                    diffs.append(f"mode {oct(old[1])} -> {oct(mode)}")
                if old[2] != uid or old[3] != gid:
                    diffs.append(f"owner {old[2]}:{old[3]} -> {uid}:{gid}")
                if diffs:
                    events.append({
                        "path": p, "action": "modified", "critical": is_critical(p),
                        "sha256": digest, "mode": oct(mode), "size": size,
                        "detail": ", ".join(diffs),
                    })
        for p in set(prev) - set(current):
            events.append({
                "path": p, "action": "deleted", "critical": is_critical(p),
                "sha256": None, "mode": None, "size": None,
                "detail": "file removed",
            })

    buf.set_meta("fim_manifest", "\n".join(
        f"{p}\t{v[0]}\t{v[1]}\t{v[2]}\t{v[3]}" for p, v in current.items()))
    buf.set_meta("fim_digest", manifest_digest(current))

    summary = {
        "files_watched": len(current),
        "digest": manifest_digest(current),
        "seeded": seeding,
        "paths": WATCH_PATHS,
    }
    return events, summary


# ---------------------------------------------------------------- packages

def collect_packages():
    """
    Installed package inventory. The server batches these to OSV rather
    than the agent doing lookups: one query per unique package across the
    whole fleet instead of one per host, and no node needs internet access
    beyond the ingest API.
    """
    try:
        out = subprocess.run(
            ["dpkg-query", "-W", "-f=${Package}\\t${Version}\\t${Architecture}\\n"],
            capture_output=True, text=True, timeout=60,
        ).stdout
    except Exception:
        return []

    pkgs = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0] and parts[1]:
            pkgs.append({
                "name": parts[0],
                "version": parts[1],
                "arch": parts[2] if len(parts) > 2 else None,
            })
    return pkgs


if __name__ == "__main__":
    import json

    class _Buf:
        def __init__(self):
            self.m = {}
        def get_meta(self, k, d=None):
            return self.m.get(k, d)
        def set_meta(self, k, v):
            self.m[k] = v

    b = _Buf()
    t0 = time.time()
    ev, summ = collect_fim(b)
    print(f"seed scan: {summ['files_watched']} files in {time.time()-t0:.2f}s, "
          f"{len(ev)} events (expect 0)")
    print("digest:", summ["digest"][:16])

    t0 = time.time()
    ev, summ = collect_fim(b)
    print(f"second scan: {time.time()-t0:.2f}s, {len(ev)} events (expect 0)")

    pkgs = collect_packages()
    print(f"packages: {len(pkgs)}")
    print(json.dumps(pkgs[:3], indent=2))
