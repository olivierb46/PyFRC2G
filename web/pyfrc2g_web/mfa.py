"""
Two-factor authentication (TOTP, RFC 6238) for local accounts.

The user enrols an authenticator app (Aegis, FreeOTP, Google / Microsoft Authenticator, Bitwarden, 1Password...)
by scanning a QR code, confirms with a first code, and gets recovery codes (single use). At sign-in, the password
is followed by a 6-digit code. Codes are SHA-1, 30 seconds, 6 digits (what every authenticator app supports); one
code can be used only once (replay protection) and a window of one step either side tolerates clock drift.

    PYFRC2G_MFA_REQUIRED   "" (default: optional), "admin" (administrators must enrol) or "all" (every local user)

The secret and the recovery code hashes are stored encrypted. Single sign-on users are not concerned: their
identity provider is in charge of the second factor.
"""

import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
from urllib.parse import quote

ISSUER = "PyFRC2G"
STEP = 30
DIGITS = 6
WINDOW = 1
RECOVERY_COUNT = 10
_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"  # No look-alike characters (i, l, o, 0, 1).


def new_secret():
    """Return a fresh base32 secret (160 bits)."""
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def _code(secret, counter):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{number % 10 ** DIGITS:0{DIGITS}d}"


def verify(secret, code, last_step=0, now=None):
    """Return the time step matching `code` (and newer than last_step), else None."""
    code = "".join(str(code).split())
    if len(code) != DIGITS or not (code.isascii() and code.isdigit()):
        return None
    current = int((now if now is not None else time.time()) // STEP)
    for step in range(current - WINDOW, current + WINDOW + 1):
        if step > (last_step or 0) and hmac.compare_digest(_code(secret, step), code):
            return step
    return None


def uri(secret, username):
    """otpauth:// URI read by the authenticator apps."""
    label = quote(f"{ISSUER}:{username}", safe="")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(ISSUER)}&algorithm=SHA1&digits={DIGITS}&period={STEP}"


def qr_svg(text):
    """Inline SVG of a QR code, or None when the optional 'segno' library is not installed."""
    try:
        import segno
    except ImportError:
        return None
    # Border 4 is the quiet zone the standard asks. The viewBox lets the page shrink the image on a narrow screen;
    # the size is a whole number of pixels per module (5), so that every module is drawn sharp.
    code = segno.make(text, error="m")
    pixels = code.symbol_size(scale=1, border=4)[0] * 5
    svg = code.svg_inline(scale=1, border=4, dark="#000000", light="#ffffff", omitsize=True)
    return svg.replace("<svg ", f'<svg width="{pixels}" height="{pixels}" ', 1)


def spaced(secret):
    """The secret in groups of four, for manual entry."""
    return " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))


# ---------------------------------------------------------------------------
# Recovery codes
# ---------------------------------------------------------------------------

def new_recovery_codes():
    """Return [clear codes, e.g. 'k3m9p-x7q2d'] to show once."""
    return ["".join(secrets.choice(_ALPHABET) for _ in range(5)) + "-" + "".join(secrets.choice(_ALPHABET)
                                                                                 for _ in range(5))
            for _ in range(RECOVERY_COUNT)]


def normalise(code):
    return "".join(ch for ch in str(code).lower() if ch.isalnum())


def hash_code(code):
    return hashlib.sha256(normalise(code).encode()).hexdigest()


def match_recovery(code, hashes):
    """Return the stored hash matching a recovery code, or None (constant time on the list)."""
    wanted, found = hash_code(code), None
    for stored in hashes:
        if hmac.compare_digest(stored, wanted):
            found = stored
    return found if len(normalise(code)) == 10 else None


def required_for(user):
    """True if the policy (PYFRC2G_MFA_REQUIRED) makes the second factor mandatory for this local user."""
    policy = os.environ.get("PYFRC2G_MFA_REQUIRED", "").strip().lower()
    return policy == "all" or (policy == "admin" and user["role"] == "admin")
