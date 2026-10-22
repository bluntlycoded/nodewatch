"""
Joining a self-hosted master.

A join code is issued by the master (dashboard "Add node", or
`nodewatch-server add-node`) and carries three things:

    u  the master's address        https://10.0.0.5:8443
    t  a single-use enrolment token
    f  SHA-256 fingerprint of the master's own CA certificate

    NWJ1-<base64url(json)>

The CA certificate is fetched from the master and accepted only if its
fingerprint matches f, so the code - not the network - decides which
master this node trusts. From then on the agent trusts that CA and nothing
else for its connection to the master.
"""

import base64
import hashlib
import hmac
import json
import time
from pathlib import Path

import requests
import urllib3
from cryptography import x509
from cryptography.hazmat.primitives import serialization

import nwconfig

PREFIX = "NWJ1-"
CA_NAME = "master-ca.crt"


class JoinError(ValueError):
    pass


def encode(url: str, token: str, fingerprint: str, site: str | None = None) -> str:
    payload = {"u": url, "t": token, "f": fingerprint}
    if site:
        payload["s"] = site
    raw = json.dumps(payload, separators=(",", ":")).encode()
    return PREFIX + base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def decode(code: str) -> dict:
    code = "".join((code or "").split())
    if not code.startswith(PREFIX):
        raise JoinError("that is not a nodewatch join code")
    body = code[len(PREFIX):]
    try:
        data = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    except (ValueError, TypeError):
        raise JoinError("the join code is damaged - copy it again")
    if not all(isinstance(data.get(k), str) and data.get(k) for k in ("u", "t", "f")):
        raise JoinError("the join code is incomplete")
    if not data["u"].startswith("https://"):
        raise JoinError("the master address in the join code is not https")
    return data


def fetch_ca(url: str, fingerprint: str) -> bytes:
    """
    The one request made without certificate verification: there is no
    trusted CA yet. What comes back is accepted only if it hashes to the
    fingerprint the join code carries.
    """
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    try:
        r = requests.get(f"{url.rstrip('/')}/ca.crt", verify=False, timeout=15)
    except requests.RequestException as e:
        raise JoinError(f"cannot reach the master at {url}: {e}")
    if r.status_code != 200:
        raise JoinError(f"the master did not return its certificate (HTTP {r.status_code})")
    try:
        cert = x509.load_pem_x509_certificate(r.content)
    except ValueError:
        raise JoinError("the master returned something that is not a certificate")
    got = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    if not hmac.compare_digest(got, fingerprint.lower().replace(":", "")):
        raise JoinError("the master's certificate does not match the join code - "
                        "this may not be the master that issued it")
    return r.content


def check_master(url: str, ca_file: Path) -> None:
    try:
        r = requests.get(f"{url.rstrip('/')}/health", verify=str(ca_file), timeout=15)
    except requests.exceptions.SSLError as e:
        raise JoinError(f"the master's certificate does not cover {url}: {e}")
    except requests.RequestException as e:
        raise JoinError(f"cannot reach the master at {url}: {e}")
    if r.status_code != 200:
        raise JoinError(f"the master answered HTTP {r.status_code} - has it finished setup?")


def ca_path() -> Path:
    return nwconfig.config_path().parent / CA_NAME


def join(code: str, site: str | None = None) -> dict:
    """Pin the CA and write agent.json. Installing the service is separate."""
    data = decode(code)
    url = data["u"].rstrip("/")
    pem = fetch_ca(url, data["f"])

    path = ca_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pem)
    check_master(url, path)

    cfg = nwconfig.load()
    switching = cfg.get("ingest_url") and cfg.get("ingest_url") != url
    cfg.update({
        "ingest_url": url,
        "enroll_token": data["t"],
        "ca_file": str(path),
        "ca_fingerprint": data["f"],
        "provider": cfg.get("provider") or "generic",
        "joined_at": int(time.time()),
    })
    if site or data.get("s"):
        cfg["site"] = site or data["s"]
    nwconfig.save(cfg)
    if switching:
        # A different master has never seen this node: forget the old
        # enrolment so the new token is used.
        _reset_status()
    return cfg


def set_url(url: str) -> dict:
    """
    The same master at a new address. The pinned CA must still vouch for
    it, so this cannot be used to point the node at a different master -
    that needs a join code from the new one.
    """
    url = url.strip().rstrip("/")
    if not url.startswith("https://"):
        raise JoinError("the address must start with https://")
    cfg = nwconfig.load()
    if not cfg.get("ca_file"):
        raise JoinError("this node has not joined a master yet - use a join code")
    check_master(url, Path(cfg["ca_file"]))
    cfg["ingest_url"] = url
    nwconfig.save(cfg)
    return cfg


def _reset_status() -> None:
    for p in (nwconfig.default_state_dir() / "status.json", nwconfig.install_root() / "status.json"):
        try:
            p.unlink()
        except OSError:
            pass
