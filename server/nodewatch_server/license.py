"""
Licence keys.

A key is a signed statement from the vendor: who it was issued to, how many
nodes, until when, which features. It is verified offline against the
Ed25519 public key built into the master (license_pubkey.txt), so a master
on an isolated network can still check it. Only the vendor holds the
private key; tools/license_tool.py issues keys with it.

    NW1-<base64url(payload json)>.<base64url(signature)>

This module answers "is this key genuine, and what does it allow";
activation.py binds it to one machine through the licence server.
"""

import base64
import datetime as dt
import json
import sys
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PREFIX = "NW1-"
GRACE_DAYS = 14


class LicenseError(ValueError):
    pass


@dataclass
class License:
    lid: str
    customer: str
    nodes: int
    expires: dt.date
    features: list
    raw: str

    def days_left(self, today: dt.date | None = None) -> int:
        return (self.expires - (today or dt.date.today())).days

    @property
    def state(self) -> str:
        """valid, grace (expired but monitoring continues), or expired."""
        left = self.days_left()
        if left >= 0:
            return "valid"
        if left >= -GRACE_DAYS:
            return "grace"
        return "expired"

    def summary(self) -> dict:
        return {"id": self.lid, "customer": self.customer, "nodes": self.nodes,
                "expires": self.expires.isoformat(), "features": self.features,
                "state": self.state, "days_left": self.days_left()}


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def public_key() -> Ed25519PublicKey:
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
    path = base / "nodewatch_server" / "license_pubkey.txt"
    hexkey = path.read_text(encoding="utf-8").split()[0]
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(hexkey))


def parse(key: str) -> License:
    key = "".join((key or "").split())          # tolerate line-wrapped paste
    if not key.startswith(PREFIX) or "." not in key:
        raise LicenseError("not a nodewatch licence key")
    body, _, sig = key[len(PREFIX):].partition(".")
    try:
        payload, signature = _b64d(body), _b64d(sig)
    except Exception:
        raise LicenseError("licence key is damaged")
    try:
        public_key().verify(signature, payload)
    except InvalidSignature:
        raise LicenseError("licence key signature is not valid")
    try:
        p = json.loads(payload)
        return License(lid=str(p["lid"]), customer=str(p["customer"]), nodes=int(p["nodes"]),
                       expires=dt.date.fromisoformat(p["expires"]),
                       features=list(p.get("features", [])), raw=key)
    except (KeyError, ValueError, TypeError) as e:
        raise LicenseError(f"licence key payload is invalid: {e}")
