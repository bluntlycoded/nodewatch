#!/usr/bin/env python3
"""
Build the master node (nodewatch-server) into a single executable for the
OS and CPU this script runs on, with PostgreSQL bundled inside.

    python -m pip install -r api/requirements.txt -r probe/requirements.txt \
                          -r packaging/requirements-build.txt
    python packaging/build_server.py

Like the agent, this cannot cross-compile; .github/workflows/build-agent.yml
builds every target on its own runner.

PostgreSQL comes from the zonky embedded-postgres-binaries on Maven Central
(PostgreSQL licence binaries, Apache-2.0 packaging), pinned by SHA-256 below
so a build can only ever bundle the exact archive that was reviewed.
"""

import hashlib
import io
import os
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_agent import EXCLUDES, target  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SERVER = ROOT / "server"
DIST = ROOT / "dist"
WORK = ROOT / "build" / "pyinstaller-server"
CACHE = ROOT / "build" / "pgcache"

PG_VERSION = "17.11.0"
PG_PINS = {
    ("macos", "arm64"): ("darwin-arm64v8", "a1c2786acb0c398f9b2d76806fc52f5dc8b222cbc8e9383a9b9702084daaf3a5"),
    ("macos", "x64"): ("darwin-amd64", "d464ff178e9860ba204662ac23fa547504b7fd392392ff2fb92e3fd73b5bdb64"),
    ("linux", "x64"): ("linux-amd64", "0dd7b72b6f335b8ecfb355fa24c5781e8a93edd09880bb77eb52ebbf29b3e96d"),
    ("linux", "arm64"): ("linux-arm64v8", "8b042e0ea418b1927d95399207950da0734d27fe01e29503ade3bdc464ad4c2b"),
    ("windows", "x64"): ("windows-amd64", "98040fae18dd9633ff95932125b0cecf0a45a1a9312e216e2a33ad03a31d4251"),
}

# PostgREST (MIT): the dashboard's data API. Unpacked beside postgres in
# the bundled archive's bin/.
PGRST_VERSION = "v16.4"
PGRST_PINS = {
    ("macos", "arm64"): ("macos-aarch64.tar.xz", "5720fbde4a19ade9fb189791615c84beb9f0e58201b1b6d17fe3b698faf60776"),
    ("macos", "x64"): ("macos-x86-64.tar.xz", "9c50547cddf94ede6abf42dacc586caa18e17db4557aee386c6e45e6806aaed2"),
    ("linux", "x64"): ("linux-static-x86-64.tar.xz", "b47ecc82fce1dcebbbc4183d839e52f07f7630c9d7ad0f54db753d1939299354"),
    ("linux", "arm64"): ("linux-static-aarch64.tar.xz", "bf544f94f305a1ff37d82f5ef1298d584f1f98b51dfd8182d1437a02073d8731"),
    ("windows", "x64"): ("windows-x86-64.zip", "29a5b56e5a09b7168bb552ef14aa7ade40bf0a81dd0687cffa86610187b89d78"),
}

# Never needed at runtime: headers, static libraries, build metadata, docs.
DROP = re.compile(r"(^|/)(include|pkgconfig|pgxs|doc)(/|$)|\.a$|\.lib$|\.pdb$")

# The modules main.py imports by name at runtime (api/ and probe/ are
# top-level modules, not a package), plus the database drivers the probe
# runner imports lazily inside its check functions.
HIDDEN = ["app", "github_app", "slack_app", "teams_app", "prober",
          "pymysql", "pymssql", "oracledb", "psycopg_pool", "boto3"]
# pywin32, for the Windows service (winservice.py).
HIDDEN_WINDOWS = ["win32serviceutil", "win32service", "win32event", "servicemanager", "win32timezone"]


def server_version() -> str:
    src = (SERVER / "nodewatch_server" / "main.py").read_text(encoding="utf-8")
    return re.search(r'^VERSION = "([^"]+)"', src, re.M).group(1)


def fetch_postgres(os_name: str, arch: str) -> bytes:
    platform, pin = PG_PINS[(os_name, arch)]
    name = f"embedded-postgres-binaries-{platform}-{PG_VERSION}.jar"
    jar = CACHE / name
    if not jar.exists():
        CACHE.mkdir(parents=True, exist_ok=True)
        url = (f"https://repo1.maven.org/maven2/io/zonky/test/postgres/"
               f"embedded-postgres-binaries-{platform}/{PG_VERSION}/{name}")
        print(f"downloading {url}", flush=True)
        urllib.request.urlretrieve(url, jar)
    digest = hashlib.sha256(jar.read_bytes()).hexdigest()
    if digest != pin:
        jar.unlink()
        sys.exit(f"{name}: sha256 {digest} does not match the pinned {pin}")
    with zipfile.ZipFile(jar) as z:
        inner = next(n for n in z.namelist() if n.endswith(".txz"))
        return z.read(inner)


def fetch_postgrest(os_name: str, arch: str) -> tuple[str, bytes]:
    """Returns (file name, executable bytes)."""
    asset, pin = PGRST_PINS[(os_name, arch)]
    name = f"postgrest-{PGRST_VERSION}-{asset}"
    path = CACHE / name
    if not path.exists():
        CACHE.mkdir(parents=True, exist_ok=True)
        url = f"https://github.com/PostgREST/postgrest/releases/download/{PGRST_VERSION}/{name}"
        print(f"downloading {url}", flush=True)
        urllib.request.urlretrieve(url, path)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != pin:
        path.unlink()
        sys.exit(f"{name}: sha256 {digest} does not match the pinned {pin}")
    if name.endswith(".zip"):
        with zipfile.ZipFile(path) as z:
            return "postgrest.exe", z.read("postgrest.exe")
    with tarfile.open(path, "r:xz") as tf:
        return "postgrest", tf.extractfile("postgrest").read()


def fix_macos_postgrest(data: bytes) -> bytes:
    """
    The macOS PostgREST build links libpq from a Homebrew path, which a
    customer's Mac will not have. Point it at the libpq shipped in the
    bundled Postgres (bin/../lib) and re-sign, since editing load commands
    invalidates the signature.
    """
    tmp = WORK / "postgrest"
    tmp.write_bytes(data)
    tmp.chmod(0o755)
    libs = subprocess.run(["otool", "-L", str(tmp)], capture_output=True, text=True, check=True).stdout
    for line in libs.splitlines():
        lib = line.strip().split(" ")[0]
        if lib.endswith("/libpq.5.dylib") and not lib.startswith("@"):
            subprocess.run(["install_name_tool", "-change", lib, "@rpath/libpq.5.dylib", str(tmp)], check=True)
    subprocess.run(["install_name_tool", "-add_rpath", "@executable_path/../lib", str(tmp)], check=True)
    subprocess.run(["codesign", "-s", "-", "-f", str(tmp)], check=True, capture_output=True)
    return tmp.read_bytes()


def repack(txz: bytes, out: Path, use_symlinks: bool, extra: dict[str, bytes] | None = None) -> None:
    """
    Drop what the runtime never loads and store byte-identical files once.
    The macOS archive ships libicudata and friends as three full copies
    each (x.dylib, x.68.dylib, x.68.2.dylib) - ~170 MB unpacked - which
    become symlinks to one copy here.
    """
    seen: dict[tuple[str, str], str] = {}
    out.parent.mkdir(parents=True, exist_ok=True)
    kept = linked = 0
    with tarfile.open(fileobj=io.BytesIO(txz), mode="r:xz") as src, \
            tarfile.open(out, "w:xz") as dst:
        for m in src.getmembers():
            if DROP.search(m.name):
                continue
            if m.isfile():
                data = src.extractfile(m).read()
                key = (os.path.dirname(m.name), hashlib.sha256(data).hexdigest())
                if use_symlinks and key in seen:
                    link = tarfile.TarInfo(m.name)
                    link.type = tarfile.SYMTYPE
                    link.linkname = os.path.basename(seen[key])
                    link.mode = 0o777
                    dst.addfile(link)
                    linked += 1
                    continue
                seen[key] = m.name
                dst.addfile(m, io.BytesIO(data))
                kept += 1
            else:
                dst.addfile(m)
        for name, data in (extra or {}).items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755
            dst.addfile(info, io.BytesIO(data))
    print(f"postgres: {kept} files, {linked} duplicates stored as links, "
          f"{out.stat().st_size / 1e6:.1f} MB compressed")


def main() -> None:
    version = server_version()
    os_name, arch = target()
    exe = ".exe" if os_name == "windows" else ""
    name = f"nodewatch-server-{version}-{os_name}-{arch}"

    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir(parents=True)
    pgdist = WORK / "pgdist"
    pgrst_name, pgrst = fetch_postgrest(os_name, arch)
    if os_name == "macos":
        pgrst = fix_macos_postgrest(pgrst)
    repack(fetch_postgres(os_name, arch), pgdist / f"postgres-{os_name}-{arch}.txz",
           use_symlinks=os_name != "windows", extra={f"bin/{pgrst_name}": pgrst})

    sep = os.pathsep
    pkg = SERVER / "nodewatch_server"
    datas = [
        (pgdist, "pgdist"),
        (pkg / "sql" / "compat.sql", "nodewatch_server/sql"),
        (pkg / "license_pubkey.txt", "nodewatch_server"),
    ]
    datas += [(p, "db") for p in sorted((ROOT / "db").glob("[0-9][0-9][0-9]_*.sql"))]
    datas.append((ROOT / "docs" / "index.html", "dashboard"))
    datas += [(p, "dashboard/vendor") for p in sorted((ROOT / "docs" / "vendor").glob("*.js"))]
    # Agent binaries the master hands to joining nodes: whatever was built
    # into dist/ for the current agent version, for any OS (CI downloads
    # all of them first). Older versions are never bundled.
    agent_v = re.search(r'^AGENT_VERSION = "([^"]+)"',
                        (ROOT / "agent" / "agent.py").read_text(encoding="utf-8"), re.M).group(1)
    agents = sorted(p for p in DIST.glob(f"nodewatch-agent-{agent_v}-*") if not p.name.endswith(".sha256"))
    datas += [(p, "agents") for p in agents]
    print(f"bundling agent {agent_v} for: {', '.join(p.name.split(agent_v + '-')[1] for p in agents) or 'none'}")

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile", "--console", "--clean", "--noconfirm",
        "--name", name,
        "--paths", str(SERVER), "--paths", str(ROOT / "api"), "--paths", str(ROOT / "probe"),
        "--distpath", str(DIST), "--workpath", str(WORK), "--specpath", str(WORK),
        "--collect-submodules", "uvicorn",
        # oracledb's thin driver is compiled Cython that imports cryptography
        # at runtime, invisible to PyInstaller's analysis.
        "--collect-submodules", "cryptography",
        "--collect-submodules", "oracledb",
    ]
    for src, dest in datas:
        cmd += ["--add-data", f"{src}{sep}{dest}"]
    for mod in HIDDEN + (HIDDEN_WINDOWS if os_name == "windows" else []):
        cmd += ["--hidden-import", mod]
    for mod in EXCLUDES + ["tkinter"]:
        cmd += ["--exclude-module", mod]
    cmd.append(str(SERVER / "nodewatch-server.py"))

    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True)

    binary = DIST / f"{name}{exe}"
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    (DIST / f"{binary.name}.sha256").write_text(f"{digest}  {binary.name}\n")
    print(f"\nbuilt {binary}  ({binary.stat().st_size / 1e6:.1f} MB)")
    print(f"sha256 {digest}")

    out = subprocess.run([str(binary), "--version"], capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit(f"{binary.name} --version exited {out.returncode}\n{out.stdout}{out.stderr}")
    if version not in out.stdout:
        sys.exit(f"--version printed {out.stdout!r}, expected {version}")
    print(out.stdout.strip())


if __name__ == "__main__":
    main()
