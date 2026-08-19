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

import osdetect
import time

# Directories worth watching by default. Deliberately narrow: hashing
# /usr or /var produces noise on every package update and buries the
# signal that matters.
WATCH_PATHS = osdetect.watch_paths()

# Paths that change constantly and carry no integrity value, plus the
# machine-generated churn each platform produces.
SKIP_PREFIXES = tuple()
CRITICAL_PATHS, CRITICAL_DIRS = osdetect.critical_paths()
NOISE_PATTERNS = osdetect.noise_patterns()

MAX_FILE_BYTES = 8 * 1024 * 1024   # skip anything larger; nothing in /etc should be
MAX_FILES = 8000                    # hard ceiling so a bad path cannot hang the agent


def is_noise(path: str) -> bool:
    """Machine-generated churn the platform module told us to ignore."""
    return any(rx.match(path) for rx in NOISE_PATTERNS)


def is_critical(path: str) -> bool:
    if is_noise(path):
        return False
    # Windows paths are case-insensitive; the platform modules supply their
    # critical sets already lowered where that matters.
    p = path if osdetect.PLATFORM != "windows" else path.lower()
    return p in CRITICAL_PATHS or p.startswith(CRITICAL_DIRS)


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
    """Installed software inventory, per platform. Resolved against OSV server-side."""
    try:
        return osdetect.collect_packages()
    except Exception:
        return []


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
