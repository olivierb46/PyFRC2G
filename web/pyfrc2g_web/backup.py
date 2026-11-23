"""
Encrypted backup of the database and re-encryption of the stored data after a key rotation.

Backup: a consistent snapshot of the SQLite database (sqlite3 backup API), encrypted with a
passphrase chosen at download time (scrypt + Fernet, by chunks), so that the file can be stored
anywhere. The database content is also encrypted with PYFRC2G_SECRET_KEY: restoring a backup
needs both the passphrase of the file and that key.

File format: MAGIC | salt (16 bytes) | [length (4 bytes, big endian) | Fernet token]...

Key rotation: set the new key in PYFRC2G_SECRET_KEY and the previous one in PYFRC2G_SECRET_KEY_OLD,
restart, then run rotate() (button in Administration > Backup & keys): every encrypted value is
re-encrypted with the new key. Afterwards PYFRC2G_SECRET_KEY_OLD can be removed.
"""

import base64
import hashlib
import os
import sqlite3
import struct
import tempfile

MAGIC = b"PYFRC2G-BACKUP-1\n"
CHUNK = 4 * 1024 * 1024
MIN_PASSPHRASE = 12


class BackupError(Exception):
    pass


def _key(passphrase, salt):
    raw = hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=2 ** 15, r=8, p=1, dklen=32, maxmem=64 * 1024 * 1024)
    return base64.urlsafe_b64encode(raw)


def snapshot(db_path, destination):
    """Copy the live database (WAL included) consistently into the file `destination`."""
    source = sqlite3.connect(db_path, timeout=30)
    target = sqlite3.connect(destination)
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()


def encrypt_file(source, destination, passphrase):
    """Encrypt `source` into `destination` with a key derived from the passphrase (minimum length enforced)."""
    from cryptography.fernet import Fernet

    if len(passphrase or "") < MIN_PASSPHRASE:
        raise BackupError(f"The passphrase needs at least {MIN_PASSPHRASE} characters.")
    salt = os.urandom(16)
    fernet = Fernet(_key(passphrase, salt))
    with open(source, "rb") as src, open(destination, "wb") as out:
        out.write(MAGIC + salt)
        while chunk := src.read(CHUNK):
            token = fernet.encrypt(chunk)
            out.write(struct.pack(">I", len(token)) + token)


def decrypt_file(source, destination, passphrase):
    """Decrypt a backup file into `destination`. Raise BackupError on a wrong passphrase or a damaged file."""
    from cryptography.fernet import Fernet, InvalidToken

    with open(source, "rb") as src, open(destination, "wb") as out:
        if src.read(len(MAGIC)) != MAGIC:
            raise BackupError("Not a PyFRC2G backup file.")
        fernet = Fernet(_key(passphrase, src.read(16)))
        try:
            while header := src.read(4):
                (length,) = struct.unpack(">I", header)
                if length > 2 * CHUNK:
                    raise BackupError("Corrupted backup file.")
                token = src.read(length)
                if len(token) != length:
                    raise BackupError("Truncated backup file.")
                out.write(fernet.decrypt(token))
        except InvalidToken as e:
            raise BackupError("Wrong passphrase, or corrupted backup file.") from e


def make_backup(db, tmp_dir, passphrase):
    """Return the path of a temporary encrypted backup file; the caller must delete it."""
    os.makedirs(tmp_dir, mode=0o700, exist_ok=True)
    fd, plain = tempfile.mkstemp(dir=tmp_dir, suffix=".db")
    os.close(fd)
    fd, encrypted = tempfile.mkstemp(dir=tmp_dir, suffix=".bak")
    os.close(fd)
    try:
        snapshot(db.path, plain)
        encrypt_file(plain, encrypted, passphrase)
    except Exception:
        os.unlink(encrypted)
        raise
    finally:
        os.unlink(plain)
    return encrypted


def restore(backup_file, passphrase, db_path, force=False):
    """Implement pyfrc2g-web --restore-backup: decrypt the backup to db_path, refusing to overwrite without force."""
    if os.path.exists(db_path) and not force:
        raise BackupError(f"{db_path} exists: stop the application, then use --force to replace it.")
    tmp = db_path + ".restoring"
    try:
        decrypt_file(backup_file, tmp, passphrase)
        check = sqlite3.connect(tmp)
        try:
            if check.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise BackupError("The restored database failed its integrity check.")
        finally:
            check.close()
        for suffix in ("-wal", "-shm"):  # Stale journals of the replaced database.
            if os.path.exists(db_path + suffix):
                os.unlink(db_path + suffix)
        os.chmod(tmp, 0o600)
        os.replace(tmp, db_path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


# ---------------------------------------------------------------------------
# Key rotation
# ---------------------------------------------------------------------------

ENCRYPTED_COLUMNS = (("meta", "value_enc"), ("firewalls", "config_enc"), ("settings", "value_enc"),
                     ("uploads", "filename_enc"), ("uploads", "content_enc"), ("gateways", "state_enc"),
                     ("gateways", "options_enc"), ("runs", "log_enc"), ("analyses", "data_enc"),
                     ("artifacts", "content_enc"), ("ciso_uploads", "message_enc"), ("exceptions", "reason_enc"),
                     ("notification_channels", "target_enc"), ("notification_channels", "secret_enc"),
                     ("report_schedules", "recipients_enc"), ("rule_notes", "comment_enc"),
                     ("users", "totp_secret_enc"), ("users", "recovery_enc"))


def _is_current(cipher, token):
    """Return True if the token is already encrypted with the primary key."""
    from cryptography.fernet import Fernet, InvalidToken

    try:
        Fernet(cipher._primary).decrypt(bytes(token))
        return True
    except InvalidToken:
        return False


def rotation_status(db):
    """Return {"total", "old"}: the number of encrypted values and how many are still under a previous key."""
    total = old = 0
    with db._conn() as c:
        for table, column in ENCRYPTED_COLUMNS:
            for (token,) in c.execute(f"SELECT {column} FROM {table} WHERE {column} IS NOT NULL"):  # noqa: S608
                total += 1
                old += not _is_current(db.cipher, token)
    return {"total": total, "old": old}


def rotate(db):
    """Re-encrypt every value still under a previous key with the current key; return how many were updated."""
    count = 0
    with db._conn() as c:
        for table, column in ENCRYPTED_COLUMNS:
            rowids = [r[0] for r in c.execute(f"SELECT rowid FROM {table} WHERE {column} IS NOT NULL")]  # noqa: S608
            for rowid in rowids:  # One value at a time: artifacts can be large.
                token = c.execute(f"SELECT {column} FROM {table} WHERE rowid=?", (rowid,)).fetchone()[0]  # noqa: S608
                if not _is_current(db.cipher, token):
                    c.execute(f"UPDATE {table} SET {column}=? WHERE rowid=?",  # noqa: S608
                              (db.cipher.rotate(token), rowid))
                    count += 1
    return count
