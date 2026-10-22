#!/usr/bin/env python3
"""
Vendor-side licence tool. Never shipped to customers.

    # once: create the signing key pair
    python tools/license_tool.py keygen --out ~/.nodewatch-vendor/license-signing.key

    # per customer
    python tools/license_tool.py issue --key ~/.nodewatch-vendor/license-signing.key \
        --customer "Acme Ltd" --nodes 50 --days 365

keygen prints the public key; put it in
server/nodewatch_server/license_pubkey.txt and rebuild the master. The
private key must never enter the repository: anyone holding it can issue
licences.
"""

import argparse
import datetime as dt
import json
import os
import sys
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))
from nodewatch_server.license import PREFIX, b64e  # noqa: E402


def keygen(out: Path) -> None:
    if out.exists():
        sys.exit(f"{out} already exists - refusing to overwrite a signing key")
    out.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    out.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
    os.chmod(out, 0o600)
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    print(f"private key: {out}  (back it up; never commit it)")
    print(f"public key:  {pub.hex()}")


def issue(keyfile: Path, customer: str, nodes: int, days: int, features: list[str]) -> str:
    key = serialization.load_pem_private_key(keyfile.read_bytes(), password=None)
    payload = json.dumps({
        "v": 1,
        "lid": str(uuid.uuid4()),
        "customer": customer,
        "nodes": nodes,
        "issued": dt.date.today().isoformat(),
        "expires": (dt.date.today() + dt.timedelta(days=days)).isoformat(),
        "features": features,
    }, separators=(",", ":")).encode()
    return PREFIX + b64e(payload) + "." + b64e(key.sign(payload))


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen")
    k.add_argument("--out", type=Path, required=True)
    i = sub.add_parser("issue")
    i.add_argument("--key", type=Path, required=True)
    i.add_argument("--customer", required=True)
    i.add_argument("--nodes", type=int, required=True)
    i.add_argument("--days", type=int, default=365)
    i.add_argument("--feature", action="append", default=[])
    a = ap.parse_args()
    if a.cmd == "keygen":
        keygen(a.out.expanduser())
    else:
        print(issue(a.key.expanduser(), a.customer, a.nodes, a.days, a.feature))


if __name__ == "__main__":
    main()
