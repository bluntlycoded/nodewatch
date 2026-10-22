"""
The node's own signing key.

Generated on first run and kept in the state directory, readable only by
root/SYSTEM. The public half is registered with the master at first
enrolment; every later enrolment (each time the 15-minute session expires)
must be signed with the private half. Knowing a host's machine ID - which
any local user can read, and dashboard viewers can see - is therefore no
longer enough to impersonate it.
"""

import os
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

FILENAME = "node.key"


def _restrict(path: Path) -> None:
    if sys.platform != "win32":
        os.chmod(path, 0o600)
    # On Windows the state directory sits under Program Files, which only
    # Administrators and SYSTEM can write; the installers own its ACL.


def load_or_create(state_dir: Path) -> Ed25519PrivateKey:
    path = state_dir / FILENAME
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    state_dir.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
    _restrict(tmp)
    os.replace(tmp, path)
    return key


def public_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw).hex()


def proof(key: Ed25519PrivateKey, node_id: str) -> dict:
    """
    Signature over the claimed node id and the current time. The server
    accepts it within a few minutes of ts, and only over TLS, so a captured
    proof is useless elsewhere and soon useless everywhere.
    """
    ts = int(time.time())
    msg = f"nodewatch-enroll:{node_id}:{ts}".encode()
    return {"ts": ts, "sig": key.sign(msg).hex()}
