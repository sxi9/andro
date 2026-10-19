"""Sentinel's own proxy CA — so the dashboard is self-contained (generate a CA,
install it, intercept) like Reqable / HTTP Toolkit, instead of making the
operator bring a Burp/mitmproxy cert.

The CA key never leaves this computer. mitmproxy mints per-host leaf certs from
it at runtime (we hand it the CA via its confdir); the device only ever trusts
the CA certificate, which the Intercept tab installs. Authorized own-device /
in-scope testing only.
"""
from __future__ import annotations

import datetime
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _dir(hub) -> Path:
    d = Path(hub.cfg.data_dir) / "ca"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _cert_path(hub) -> Path:
    return _dir(hub) / "sentinel-ca-cert.pem"


def _key_path(hub) -> Path:
    return _dir(hub) / "sentinel-ca-key.pem"


def exists(hub) -> bool:
    return _cert_path(hub).exists() and _key_path(hub).exists()


def generate(hub, *, force: bool = False) -> dict:
    """Create and persist a fresh CA (RSA-2048, 10 years). Reuses the existing
    one unless force. Returns inspect_ca info for the cert."""
    if exists(hub) and not force:
        return info(hub)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Sentinel Proxy CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Android Sentinel"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            key_encipherment=False, content_commitment=False, data_encipherment=False,
            key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption())
    _cert_path(hub).write_bytes(cert_pem)
    kp = _key_path(hub)
    kp.write_bytes(key_pem)
    try:
        os.chmod(kp, 0o600)   # the CA private key stays readable only to us
    except OSError:
        pass
    return info(hub)


def cert_pem(hub) -> bytes:
    """The CA certificate PEM (to install on the device / download). Generates
    the CA on first use."""
    if not exists(hub):
        generate(hub)
    return _cert_path(hub).read_bytes()


def info(hub) -> dict:
    """inspect_ca over the built-in CA, plus whether it exists."""
    from .intercept import inspect_ca
    if not exists(hub):
        return {"exists": False}
    d = inspect_ca(_cert_path(hub).read_bytes())
    d["exists"] = True
    return d


def mitm_confdir(hub) -> str:
    """A mitmproxy confdir seeded with our CA so mitmdump mints leaf certs from
    it. mitmproxy expects `mitmproxy-ca.pem` = private key followed by the CA
    cert. Returns the directory path."""
    if not exists(hub):
        generate(hub)
    conf = _dir(hub) / "mitm"
    conf.mkdir(parents=True, exist_ok=True)
    combined = conf / "mitmproxy-ca.pem"
    data = _key_path(hub).read_bytes().rstrip() + b"\n" + _cert_path(hub).read_bytes()
    combined.write_bytes(data)
    try:
        os.chmod(combined, 0o600)
    except OSError:
        pass
    # mitmproxy also serves the cert-only file to clients; keep it in sync
    (conf / "mitmproxy-ca-cert.pem").write_bytes(_cert_path(hub).read_bytes())
    return str(conf)
