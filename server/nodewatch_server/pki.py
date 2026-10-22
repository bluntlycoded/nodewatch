"""
The master's own certificate authority.

Generated at first run. Signs the master's HTTPS certificate now and, in
phase 3, each node's client certificate at join time. Agents pin the CA's
fingerprint from the join code, so no public CA and no domain name is
needed - the same model Proxmox and UniFi controllers use.
"""

import datetime as dt
import ipaddress
import socket
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .config import restrict


def _now():
    return dt.datetime.now(dt.timezone.utc)


def _write_key(path: Path, key) -> None:
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    restrict(path)


class PKI:

    def __init__(self, data_dir: Path):
        self.dir = data_dir / "pki"
        self.ca_cert = self.dir / "ca.crt"
        self.ca_key = self.dir / "ca.key"
        self.server_cert = self.dir / "server.crt"
        self.server_key = self.dir / "server.key"

    def ensure_ca(self) -> None:
        if self.ca_cert.exists() and self.ca_key.exists():
            return
        self.dir.mkdir(parents=True, exist_ok=True)
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "nodewatch"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"nodewatch master CA ({socket.gethostname()})"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_now() - dt.timedelta(minutes=5))
            .not_valid_after(_now() + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256())
        )
        _write_key(self.ca_key, key)
        self.ca_cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    def ca_fingerprint(self) -> str:
        cert = x509.load_pem_x509_certificate(self.ca_cert.read_bytes())
        return cert.fingerprint(hashes.SHA256()).hex()

    def issue_server_cert(self, addresses: list[str]) -> None:
        """
        HTTPS certificate covering every name and IP agents might use.
        Reissued whenever the public address changes, so the certificate
        always matches the URL nodes are given.
        """
        self.ensure_ca()
        ca_key = serialization.load_pem_private_key(self.ca_key.read_bytes(), password=None)
        ca = x509.load_pem_x509_certificate(self.ca_cert.read_bytes())

        sans, seen = [], set()
        for a in addresses:
            a = (a or "").strip().strip("[]")
            if not a or a in seen:
                continue
            seen.add(a)
            try:
                sans.append(x509.IPAddress(ipaddress.ip_address(a)))
            except ValueError:
                sans.append(x509.DNSName(a))

        key = ec.generate_private_key(ec.SECP256R1())
        cn = next((a for a in addresses if a), "nodewatch-master")
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn[:64])]))
            .issuer_name(ca.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_now() - dt.timedelta(minutes=5))
            .not_valid_after(_now() + dt.timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                           critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        _write_key(self.server_key, key)
        # Leaf then CA, so clients that were not given the CA still see the chain.
        self.server_cert.write_bytes(
            cert.public_bytes(serialization.Encoding.PEM) + ca.public_bytes(serialization.Encoding.PEM))


def local_addresses() -> list[str]:
    """Hostname, FQDN and this machine's own non-loopback IPs, best effort."""
    out = [socket.gethostname(), socket.getfqdn(), "localhost", "127.0.0.1"]
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            out.append(info[4][0])
    except OSError:
        pass
    # The address the OS would route outbound traffic from - usually the
    # LAN IP, even when the hostname does not resolve to it.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))
            out.append(s.getsockname()[0])
    except OSError:
        pass
    return [a for a in dict.fromkeys(out) if a and not a.startswith("fe80")]
