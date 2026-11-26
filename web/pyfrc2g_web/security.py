"""
Authentication and request protection: user sessions (revocable), roles and permissions,
CSRF tokens, sign-in throttling (in memory or shared through Redis) and security headers.
"""

import functools
import hashlib
import hmac
import logging
import secrets
import threading
import time

from flask import abort, current_app, flash, g, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

# Roles, from the most to the least privileged (the first matching role wins for SSO users).
ROLES = ("admin", "operator", "auditor", "viewer")
ROLE_HELP = {
    "admin": "everything: configuration, firewalls, users, accepted-risk approval",
    "operator": "runs analyses and uploads files, proposes accepted risks (an admin approves them)",
    "auditor": "reads everything, exports reports, event log and accepted risks (read only)",
    "viewer": "reads dashboards, reports and graphs, exports them",
}
PERMISSIONS = {
    "viewer": frozenset({"view", "export"}),
    "auditor": frozenset({"view", "export", "audit"}),
    "operator": frozenset({"view", "export", "analyse", "propose_risk"}),
    "admin": frozenset({"view", "export", "audit", "analyse", "propose_risk", "approve_risk", "manage"}),
}
MIN_PASSWORD_LENGTH = 10
MAX_FAILURES = 5
LOCK_SECONDS = 600

CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
       "frame-ancestors 'none'; form-action 'self'; base-uri 'none'; object-src 'none'")
# Generated HTML reports use inline styles and scripts: served sandboxed.
REPORT_CSP = ("default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
              "img-src data:; sandbox allow-scripts")
SVG_CSP = "default-src 'none'; style-src 'unsafe-inline'; sandbox"


def hash_password(password):
    """Return a salted hash of the password (werkzeug format)."""
    return generate_password_hash(password)


def password_problem(password):
    """Return a message if the password is too weak, else None."""
    if len(password or "") < MIN_PASSWORD_LENGTH:
        return f"The password must have at least {MIN_PASSWORD_LENGTH} characters."
    return None


class Throttle:
    """
    Locks sign-in for an address (and a user name) after MAX_FAILURES failures within LOCK_SECONDS.
    In memory by default; with a Redis client the counters are shared by every instance (keys are
    hashed: no user name or address is stored in clear). Falls back to memory if Redis fails.
    """

    def __init__(self, redis_client=None):
        self.failures = {}
        self.counts, self.locks, self.strikes, self.tallies = {}, {}, {}, {}  # Local copies of the progressive locks.
        self.lock = threading.Lock()
        self.redis = redis_client

    @staticmethod
    def _key(key):
        return "throttle:" + hashlib.sha256(key.encode()).hexdigest()[:32]

    def _redis_call(self, action):
        if self.redis is None:
            return None, False
        try:
            return action(self.redis), True
        except Exception as e:  # redis.RedisError, but the import is optional
            logging.warning(f"Redis throttle unavailable ({e.__class__.__name__}): using the local counters")
            return None, False

    def blocked(self, *keys):
        def check(r):
            values = r.mget([self._key(k) for k in keys])
            return any(int(v or 0) >= MAX_FAILURES for v in values)

        shared, ok = self._redis_call(check)
        if ok and shared:
            return True
        now = time.time()
        with self.lock:
            return any(len([t for t in self.failures.get(k, []) if now - t < LOCK_SECONDS]) >= MAX_FAILURES
                       for k in keys)

    def fail(self, *keys):
        def count(r):
            pipe = r.pipeline()
            for key in keys:
                pipe.incr(self._key(key))
                pipe.expire(self._key(key), LOCK_SECONDS)
            pipe.execute()

        self._redis_call(count)
        now = time.time()
        with self.lock:
            for key in keys:
                self.failures[key] = [t for t in self.failures.get(key, []) if now - t < LOCK_SECONDS] + [now]

    def reset(self, *keys):
        self._redis_call(lambda r: r.delete(*[self._key(k) for k in keys]))
        with self.lock:
            for key in keys:
                self.failures.pop(key, None)

    # ------------------------------------------------------------------ progressive locks (sign-in)
    # A key counts its failures in a window; reaching the limit locks it for base * 2**strikes seconds (up to
    # cap), and each lock is one more strike, remembered for a day: whoever comes back is blocked for longer.

    STRIKE_MEMORY = 86400

    def lock_remaining(self, key):
        """Seconds left before the key may try again (0 if it is not locked)."""
        base = self._key(key)

        def read(r):
            return r.ttl(base + ":l")

        ttl, ok = self._redis_call(read)
        if ok:
            return max(0, int(ttl or 0))
        with self.lock:
            return max(0, int(self.locks.get(key, 0) - time.time()))

    def strike(self, key, limit, window, base_lock, cap):
        """Count a failure of the key. Return the number of seconds it is now locked for (0: not locked)."""
        base = self._key(key)

        def count(r):
            n = r.incr(base + ":n")
            if n == 1:
                r.expire(base + ":n", window)
            if n < limit:
                return 0
            strikes = int(r.get(base + ":s") or 0)
            seconds = int(min(base_lock * 2 ** strikes, cap))
            pipe = r.pipeline()
            pipe.set(base + ":l", 1, ex=seconds)
            pipe.incr(base + ":s")
            pipe.expire(base + ":s", self.STRIKE_MEMORY)
            pipe.delete(base + ":n")
            pipe.execute()
            return seconds

        seconds, ok = self._redis_call(count)
        if ok:
            return seconds
        now = time.time()
        with self.lock:
            self._prune(now)
            recent = [t for t in self.counts.get(key, []) if now - t < window] + [now]
            if len(recent) < limit:
                self.counts[key] = recent
                return 0
            strikes, expires = self.strikes.get(key, (0, 0))
            strikes = strikes if expires > now else 0
            seconds = int(min(base_lock * 2 ** strikes, cap))
            self.locks[key] = now + seconds
            self.strikes[key] = (strikes + 1, now + self.STRIKE_MEMORY)
            self.counts.pop(key, None)
            return seconds

    def tally(self, key, window):
        """Count one event of the key in the window and return how many there are (for the alerts)."""
        base = self._key(key)

        def count(r):
            n = r.incr(base + ":c")
            if n == 1:
                r.expire(base + ":c", window)
            return int(n)

        n, ok = self._redis_call(count)
        if ok:
            return n
        now = time.time()
        with self.lock:
            self._prune(now)
            events = [t for t in self.tallies.get(key, []) if now - t < window] + [now]
            self.tallies[key] = events
            return len(events)

    def forget(self, *keys):
        """Clear the counters, the locks and the strikes of keys."""
        def clear(r):
            r.delete(*[self._key(k) + suffix for k in keys for suffix in (":n", ":l", ":s", ":c")])

        self._redis_call(clear)
        with self.lock:
            for key in keys:
                for store in (self.counts, self.locks, self.strikes, self.tallies):
                    store.pop(key, None)

    def _prune(self, now):
        """Drop the expired entries of the local counters (called with the lock held, now and then)."""
        if sum(map(len, (self.counts, self.locks, self.strikes, self.tallies))) < 5000:
            return
        for store, alive in ((self.locks, lambda v: v > now), (self.strikes, lambda v: v[1] > now),
                             (self.counts, lambda v: bool(v) and now - v[-1] < 3600),
                             (self.tallies, lambda v: bool(v) and now - v[-1] < 7200)):
            for key in [k for k, v in store.items() if not alive(v)]:
                del store[key]


def _password_marker(password_hash):
    """Short value stored in the session: changing the password invalidates other sessions."""
    return hashlib.sha256(password_hash.encode()).hexdigest()[:16]


def login_user(user):
    """Start a fresh registered session for the user."""
    regenerate = getattr(current_app.session_interface, "regenerate", None)
    if regenerate:  # Server-side sessions (Flask-Session): new identifier, no fixation.
        session["_rotate"] = True  # regenerate() ignores an empty session.
        regenerate(session)
    session.clear()  # New session content: no fixation.
    session.permanent = True
    session["uid"] = user["id"]
    session["pw"] = _password_marker(user["password_hash"])
    session["csrf"] = secrets.token_urlsafe(32)
    # Registered session: listed and revocable by the administrators, limited per user.
    session["tok"] = secrets.token_urlsafe(24)
    lifetime = current_app.config["PERMANENT_SESSION_LIFETIME"]
    current_app.db.add_session(session["tok"], user["id"], request.remote_addr or "?",
                               request.headers.get("User-Agent", ""), lifetime.total_seconds(),
                               current_app.config.get("MAX_SESSIONS", 0))


def _max_age(user):
    """Absolute life of a session. A single sign-on session is shorter: the user has to go back to the identity
    provider every PYFRC2G_OIDC_REVALIDATE_MINUTES, so that a revoked account or a changed group is noticed."""
    lifetime = current_app.config["PERMANENT_SESSION_LIFETIME"].total_seconds()
    if user["password_hash"] == "!oidc":
        return min(lifetime, current_app.config.get("OIDC_REVALIDATE_MINUTES", 60) * 60)
    return lifetime


def load_user():
    """before_request: g.user from the session (None if signed out or password changed)."""
    g.user = None
    g.session_token = None
    uid = session.get("uid")
    if uid is None:
        return
    user = current_app.db.user(user_id=uid)
    if (user is None or session.get("pw") != _password_marker(user["password_hash"]) or user["role"] not in ROLES
            or not current_app.db.session_alive(session.get("tok") or "", max_age=_max_age(user))):
        session.clear()  # Password changed, user deleted, or session revoked.
        return
    g.user = user
    g.session_token = session["tok"]


_ALLOWED_DURING_SETUP = frozenset({"main.account", "main.account_mfa", "main.logout", "main.health", "static",
                                  "main.metrics"})


def require_password_change():
    """before_request: a user who must choose a password or enrol the second factor only reaches the account page."""
    user = g.get("user")
    if not user or request.endpoint in _ALLOWED_DURING_SETUP:
        return None
    if user.get("must_change"):
        flash("Choose a new password before going further.", "error")
        return redirect(url_for("main.account"))
    from pyfrc2g_web import mfa
    from pyfrc2g_web.oidc import is_sso_user

    if not user.get("totp_enabled") and not is_sso_user(user) and mfa.required_for(user):
        flash("This server requires two-factor authentication: set it up before going further.", "error")
        return redirect(url_for("main.account"))
    return None


def csrf_token():
    """Return the session CSRF token, creating it if needed."""
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def check_csrf():
    """before_request: every POST must carry the session CSRF token."""
    if request.method != "POST" or request.path.startswith("/api/"):  # The API uses bearer tokens, not cookies.
        return
    sent = request.form.get("csrf", "")
    expected = session.get("csrf", "")
    if not expected or not hmac.compare_digest(sent.encode(), expected.encode()):
        abort(400, "Invalid or expired form. Reload the page and try again.")


def can(permission):
    """True if the signed-in user has the permission (also available in the templates)."""
    return g.get("user") is not None and permission in PERMISSIONS.get(g.user["role"], ())


def permission_required(permission):
    """Decorator: require sign-in and the given permission (403 otherwise)."""
    def decorator(view):
        @functools.wraps(view)
        @login_required
        def wrapper(*args, **kwargs):
            if not can(permission):
                abort(403)
            return view(*args, **kwargs)
        return wrapper
    return decorator


def login_required(view):
    """Decorator: redirect anonymous users to the sign-in page."""
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("main.login", next=request.full_path if request.method == "GET" else None))
        return view(*args, **kwargs)
    return wrapper


def admin_required(view):
    return permission_required("manage")(view)


def safe_next(target):
    """Only local paths are accepted as redirect target after sign-in (no scheme, host or control character)."""
    from urllib.parse import unquote, urlsplit

    if target and len(target) <= 500 and target.startswith("/") and not target.startswith("//"):
        decoded = unquote(target)
        parts = urlsplit(target)
        if (not any(ord(ch) < 32 or ord(ch) == 127 for ch in target + decoded) and "\\" not in decoded
                and not decoded.startswith("//") and not parts.scheme and not parts.netloc):
            return target
    return url_for("main.dashboard")


def security_headers(response):
    """after_request: add the security headers (CSP is kept if the view already set one)."""
    response.headers.setdefault("Content-Security-Policy", CSP)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    if current_app.config.get("SESSION_COOKIE_SECURE"):  # Served over HTTPS.
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response


_DUMMY_HASH = generate_password_hash("not-a-real-password")


def check_password(user, password):
    """True if the user exists and the password matches its hash (same work for an unknown user)."""
    if user is None:
        check_password_hash(_DUMMY_HASH, password or "")  # Do not tell by the response time that the name is unknown.
        return False
    return check_password_hash(user["password_hash"], password or "")
