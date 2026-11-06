"""
Application-level encryption of the database content (Fernet: AES-128-CBC + HMAC-SHA256).

The key comes from PYFRC2G_SECRET_KEY, either a Fernet key (44 characters, generate one with
`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`)
or any passphrase, derived with scrypt and a random salt stored in the database. Without
PYFRC2G_SECRET_KEY, a key is generated in <data dir>/secret.key (mode 600): convenient, but
the key then sits next to the database, so set the variable in production.

PYFRC2G_SECRET_KEY_OLD (optional) lets the application read data encrypted with a previous
key while writing with the new one (key rotation).
"""

import base64
import hashlib
import hmac
import json
import logging
import os

KEY_FILE = "secret.key"
_CHECK_VALUE = b"pyfrc2g-key-check"


class CryptoKeyError(Exception):
    """Wrong or missing encryption key."""


def _is_fernet_key(value):
    try:
        return len(base64.urlsafe_b64decode(value.encode())) == 32 and len(value) == 44
    except (ValueError, TypeError):
        return False


def _derive(passphrase, salt):
    raw = hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return base64.urlsafe_b64encode(raw)


def _key_from(value, salt):
    value = value.strip()
    return value.encode() if _is_fernet_key(value) else _derive(value, salt)


class Cipher:
    """Encrypts / decrypts bytes, text and JSON values stored in the database."""

    def __init__(self, keys):
        from cryptography.fernet import Fernet, MultiFernet

        self._primary = keys[0]
        self._fernet = MultiFernet([Fernet(k) for k in keys])

    @classmethod
    def load(cls, data_dir, salt):
        """Build the cipher from PYFRC2G_SECRET_KEY (or the generated key file)."""
        from cryptography.fernet import Fernet

        secret = os.environ.get("PYFRC2G_SECRET_KEY", "").strip()
        if not secret:
            path = os.path.join(data_dir, KEY_FILE)
            if not os.path.isfile(path):
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as f:
                    f.write(Fernet.generate_key().decode())
                logging.warning(f"PYFRC2G_SECRET_KEY not set: encryption key generated in {path}. "
                                "Keep a copy of it and prefer the environment variable in production "
                                "(the key should not live next to the database).")
            with open(path, encoding="utf-8") as f:
                secret = f.read().strip()
        keys = [_key_from(secret, salt)]
        old = os.environ.get("PYFRC2G_SECRET_KEY_OLD", "").strip()
        if old:
            keys.append(_key_from(old, salt))
        return cls(keys)

    @property
    def session_secret(self):
        """Secret for the Flask session cookie, derived from (not equal to) the data key."""
        return hmac.new(self._primary, b"flask-session", hashlib.sha256).hexdigest()

    # ------------------------------------------------------------------ values

    def encrypt(self, data):
        if data is None:
            return None
        if isinstance(data, str):
            data = data.encode("utf-8")
        return self._fernet.encrypt(data)

    def decrypt(self, token):
        from cryptography.fernet import InvalidToken

        if token is None:
            return None
        try:
            return self._fernet.decrypt(bytes(token))
        except InvalidToken as e:
            raise CryptoKeyError("cannot decrypt the database: wrong PYFRC2G_SECRET_KEY") from e

    def encrypt_json(self, value):
        return self.encrypt(json.dumps(value, separators=(",", ":")))

    def decrypt_json(self, token, default=None):
        data = self.decrypt(token)
        return default if data is None else json.loads(data)

    def decrypt_text(self, token, default=""):
        data = self.decrypt(token)
        return default if data is None else data.decode("utf-8")

    # ------------------------------------------------------------------ key check

    def check_token(self):
        return self.encrypt(_CHECK_VALUE)

    def verify(self, token):
        """Raise CryptoKeyError if token (from check_token) was not made with one of our keys."""
        if self.decrypt(token) != _CHECK_VALUE:
            raise CryptoKeyError("cannot decrypt the database: wrong PYFRC2G_SECRET_KEY")

    def rotate(self, token):
        """Re-encrypt a token with the primary key."""
        return self._fernet.rotate(bytes(token)) if token is not None else None
