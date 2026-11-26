"""
One-shot set-up of a Docker installation (the "setup" service of docker-compose.yml), run before everything else:

* the TLS certificate of nginx, written to the "pyfrc2g-tls" volume:
    - the files fullchain.pem and privkey.pem found in ./nginx/certs (your certificate) are checked and installed;
    - otherwise a self-signed certificate for PYFRC2G_SERVER_NAME is made, and renewed when the name changes or
      30 days before it expires (browsers warn about it: put your own certificate for a real use);
* the password of Redis, generated once in the "pyfrc2g-secrets" volume (nobody has to choose or type it).

It stops with an error, and so does the whole start, if the certificate given is not valid: a mistake is never
silently replaced by a self-signed certificate.
"""

import ipaddress
import json
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

CUSTOM, TLS, SECRETS = "/custom", "/tls", "/secrets"
CERT, KEY, MARKER = "fullchain.pem", "privkey.pem", "self-signed.json"
RENEW_DAYS = 30
VALID_DAYS = 365


class SetupError(Exception):
    pass


NGINX_UID = 101  # The user of the nginx-unprivileged image.


def _write(path, data, mode, owner=None):
    """Write a file atomically with its final permissions.

    owner: a uid that must own it (the private key is only readable by nginx). Without the right to change the
    owner (not run as root) the file is made readable by everybody instead, so that it still works.
    """
    tmp = path + ".tmp"
    if os.path.lexists(tmp):  # Left by an interrupted run.
        os.remove(tmp)
    with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as f:
        f.write(data)
    os.chmod(tmp, mode)  # Before the change of owner: afterwards this process may no longer be allowed to.
    if owner is not None:
        try:
            os.chown(tmp, owner, owner)
        except PermissionError:
            os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def ensure_password(directory):
    """Create the Redis password once. Return True if it was created."""
    path = os.path.join(directory, "redis_password")
    if os.path.isfile(path) and os.path.getsize(path) >= 20:
        return False
    _write(path, secrets.token_urlsafe(32).encode(), 0o644)  # Only the redis and web containers see this volume.
    return True


def _load_pair(cert_path, key_path):
    try:
        with open(cert_path, "rb") as f:
            certs = x509.load_pem_x509_certificates(f.read())
        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
    except (OSError, ValueError, TypeError) as e:
        raise SetupError(f"the certificate or its key cannot be read ({e.__class__.__name__}); the key must not "
                         "be protected by a passphrase") from e
    if not certs:
        raise SetupError("fullchain.pem holds no certificate")
    public = lambda k: k.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)  # noqa: E731
    if public(certs[0].public_key()) != public(key.public_key()):
        raise SetupError("the private key does not belong to the first certificate of fullchain.pem")
    if certs[0].not_valid_after_utc < datetime.now(timezone.utc):
        raise SetupError(f"the certificate expired on {certs[0].not_valid_after_utc:%Y-%m-%d}")
    return certs[0]


def install_custom(custom, tls):
    """Install the certificate and key of ./nginx/certs. Return True if there were some."""
    cert_path, key_path = os.path.join(custom, CERT), os.path.join(custom, KEY)
    if not (os.path.isfile(cert_path) and os.path.isfile(key_path)):
        return False
    _load_pair(cert_path, key_path)  # Raises SetupError.
    with open(cert_path, "rb") as f:
        cert = f.read()
    with open(key_path, "rb") as f:
        key = f.read()
    _write(os.path.join(tls, CERT), cert, 0o644)
    _write(os.path.join(tls, KEY), key, 0o600, NGINX_UID)
    marker = os.path.join(tls, MARKER)
    if os.path.exists(marker):
        os.remove(marker)
    return True


def make_self_signed(tls, name):
    """Write a self-signed certificate (ECDSA P-256) for the name, and remember what it is for."""
    key = ec.generate_private_key(ec.SECP256R1())
    try:
        alt = x509.IPAddress(ipaddress.ip_address(name))
    except ValueError:
        alt = x509.DNSName(name)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name[:64])])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=VALID_DAYS))
            .add_extension(x509.SubjectAlternativeName([alt]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    _write(os.path.join(tls, CERT), cert.public_bytes(serialization.Encoding.PEM), 0o644)
    _write(os.path.join(tls, KEY), key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                      serialization.NoEncryption()), 0o600, NGINX_UID)
    _write(os.path.join(tls, MARKER),
           json.dumps({"name": name, "expires": cert.not_valid_after_utc.isoformat()}).encode(), 0o644)


def ensure_certificate(custom, tls, name):
    """Return "custom", "created", "renewed" or "kept"."""
    if install_custom(custom, tls):
        return "custom"
    cert, marker = os.path.join(tls, CERT), os.path.join(tls, MARKER)
    if not (os.path.isfile(cert) and os.path.isfile(os.path.join(tls, KEY))):
        make_self_signed(tls, name)
        return "created"
    if os.path.isfile(marker):  # Ours: renew it when needed. A certificate installed earlier is never touched.
        with open(marker, encoding="utf-8") as f:
            info = json.load(f)
        expires = datetime.fromisoformat(info["expires"])
        if info.get("name") != name or expires - datetime.now(timezone.utc) < timedelta(days=RENEW_DAYS):
            make_self_signed(tls, name)
            return "renewed"
    return "kept"


def main():
    name = os.environ.get("PYFRC2G_SERVER_NAME", "").strip() or "localhost"
    try:
        for directory in (TLS, SECRETS):
            os.makedirs(directory, exist_ok=True)
            os.chmod(directory, 0o755)
        state = ensure_certificate(CUSTOM, TLS, name)
        created = ensure_password(SECRETS)
    except SetupError as e:
        print(f"setup: {e}", file=sys.stderr)
        return 1
    print(f"setup: TLS certificate {state} for {name}" + (" (self-signed: browsers will warn)"
          if state in ("created", "renewed", "kept") and os.path.exists(os.path.join(TLS, MARKER)) else ""))
    print("setup: Redis password " + ("generated" if created else "already there"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
