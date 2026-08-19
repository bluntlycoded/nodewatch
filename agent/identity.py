"""
Provider detection and identity collection.

Enrolment identity is strongest on AWS (a signed document verifiable against
a published certificate) and weakest on a bare on-premise box (nothing but a
machine ID). Rather than pretend they are equivalent, each host reports which
provider it is and what evidence it can offer, and the server records the
strength of that evidence per node.

    aws      IMDSv2 signed identity document  - cryptographic
    gcp      metadata service identity JWT    - cryptographic
    azure    IMDS attested document           - cryptographic
    generic  machine ID + enrolment token     - invitation only

A generic host must present a single-use enrolment token, because there is
no third party willing to vouch for it.
"""

import json
import os
import socket
import subprocess

import requests

import osdetect

AWS_IMDS = "http://169.254.169.254"
GCP_MD = "http://metadata.google.internal/computeMetadata/v1"
AZURE_IMDS = "http://169.254.169.254/metadata"

PROBE_TIMEOUT = 1.5          # metadata services are link-local; slow means absent
IDENTITY_AUDIENCE = "nodewatch"


# ---------------------------------------------------------------- detection

def detect_provider() -> str:
    """
    Probe each metadata service once. Order matters only for speed; the
    services are mutually exclusive in practice.
    """
    try:
        r = requests.put(
            f"{AWS_IMDS}/latest/api/token",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
            timeout=PROBE_TIMEOUT,
        )
        if r.status_code == 200 and r.text:
            return "aws"
    except Exception:
        pass

    try:
        r = requests.get(f"{GCP_MD}/instance/id",
                         headers={"Metadata-Flavor": "Google"},
                         timeout=PROBE_TIMEOUT)
        if r.status_code == 200:
            return "gcp"
    except Exception:
        pass

    try:
        r = requests.get(f"{AZURE_IMDS}/instance?api-version=2021-02-01",
                         headers={"Metadata": "true"}, timeout=PROBE_TIMEOUT)
        if r.status_code == 200:
            return "azure"
    except Exception:
        pass

    return "generic"


def machine_id() -> str | None:
    """
    Stable per-install identifier: machine-id on Linux, MachineGuid on
    Windows, IOPlatformUUID on macOS. Not a secret and not proof on its own,
    but it lets the server notice when a known node is suddenly a different
    machine reusing the same name.
    """
    try:
        return osdetect.machine_id()
    except Exception:
        return None


def _dmi(field: str) -> str | None:
    try:
        return open(f"/sys/class/dmi/id/{field}").read().strip() or None
    except OSError:
        return None


# ---------------------------------------------------------------- per provider

def aws_identity() -> dict:
    tok = requests.put(
        f"{AWS_IMDS}/latest/api/token",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": "300"},
        timeout=PROBE_TIMEOUT,
    ).text
    h = {"X-aws-ec2-metadata-token": tok}
    resp = requests.get(f"{AWS_IMDS}/latest/dynamic/instance-identity/document",
                        headers=h, timeout=PROBE_TIMEOUT)
    # The raw text matters: AWS signs those exact bytes.
    doc_raw = resp.text
    doc = resp.json()
    pkcs7 = requests.get(f"{AWS_IMDS}/latest/dynamic/instance-identity/pkcs7",
                         headers=h, timeout=PROBE_TIMEOUT).text
    return {
        "provider": "aws",
        "node_id": doc["instanceId"],
        "region": doc.get("region"),
        "account": doc.get("accountId"),
        "instance_type": doc.get("instanceType"),
        "document": doc,
        "document_raw": doc_raw,
        "pkcs7": pkcs7,
    }


def gcp_identity() -> dict:
    h = {"Metadata-Flavor": "Google"}

    def md(path):
        r = requests.get(f"{GCP_MD}/{path}", headers=h, timeout=PROBE_TIMEOUT)
        return r.text.strip() if r.status_code == 200 else None

    # A Google-signed JWT over the instance's identity. The server verifies it
    # against Google's published JWKS, so no shared secret is involved.
    jwt_token = md(f"instance/service-accounts/default/identity"
                   f"?audience={IDENTITY_AUDIENCE}&format=full")
    zone = (md("instance/zone") or "").split("/")[-1] or None
    return {
        "provider": "gcp",
        "node_id": md("instance/id"),
        "region": zone,
        "account": md("project/project-id"),
        "instance_type": (md("instance/machine-type") or "").split("/")[-1] or None,
        "identity_jwt": jwt_token,
    }


def azure_identity() -> dict:
    h = {"Metadata": "true"}

    def md(path):
        r = requests.get(f"{AZURE_IMDS}/{path}", headers=h, timeout=PROBE_TIMEOUT)
        return r.json() if r.status_code == 200 else {}

    inst = md("instance?api-version=2021-02-01").get("compute", {})
    # Azure's attested document is a PKCS7 signature over a nonce plus the
    # vmId, verifiable against the Azure certificate chain.
    attested = md("attested/document?api-version=2020-09-01&nonce=nodewatch")
    return {
        "provider": "azure",
        "node_id": inst.get("vmId"),
        "region": inst.get("location"),
        "account": inst.get("subscriptionId"),
        "instance_type": inst.get("vmSize"),
        "attested_signature": attested.get("signature"),
        "compute": inst,
    }


def generic_identity() -> dict:
    """
    On-premise, a VPS, or any cloud without a metadata service. There is no
    external attestation available, so the enrolment token carries the trust
    and the fingerprint exists to detect substitution later.
    """
    mid = machine_id()
    try:
        fp = osdetect.hardware_fingerprint()
    except Exception:
        fp = {"hostname": socket.gethostname()}
    return {
        "provider": "generic",
        "node_id": mid or socket.getfqdn(),
        "region": os.environ.get("NW_SITE") or None,
        "account": None,
        "instance_type": None,
        "machine_id": mid,
        "platform": osdetect.PLATFORM,
        "fingerprint": fp,
    }


COLLECTORS = {
    "aws": aws_identity,
    "gcp": gcp_identity,
    "azure": azure_identity,
    "generic": generic_identity,
}


def collect_identity(forced: str | None = None) -> dict:
    """
    Returns the identity payload for enrolment. NW_PROVIDER overrides
    detection, which matters for a VM that has a metadata service but should
    be treated as on-premise.
    """
    provider = forced or os.environ.get("NW_PROVIDER") or detect_provider()
    fn = COLLECTORS.get(provider, generic_identity)
    try:
        ident = fn()
    except Exception:
        # A metadata service that answered the probe but failed the full read
        # should degrade to generic rather than block enrolment entirely.
        ident = generic_identity()
        ident["degraded_from"] = provider

    ident.setdefault("machine_id", machine_id())
    ident.setdefault("platform", osdetect.PLATFORM)
    return ident


if __name__ == "__main__":
    print("detected provider:", detect_provider())
    ident = collect_identity()
    redacted = {k: (v if k not in ("pkcs7", "identity_jwt", "attested_signature")
                    else f"<{len(str(v))} chars>")
                for k, v in ident.items()}
    print(json.dumps(redacted, indent=2, default=str))
