"""
Authentication and request protection: user sessions, roles (admin / viewer), CSRF tokens,
sign-in throttling and security headers.
"""

import functools
import hashlib
import hmac
import secrets
import threading
import time

from flask import abort, current_app, g, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

ROLES = ("admin", "viewer")
MIN_PASSWORD_LENGTH = 10
MAX_FAILURES = 5
LOCK_SECONDS = 600

CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
       "frame-ancestors 'none'; form-action 'self'; base-uri 'none'; object-src 'none'")
# Generated HTML reports use inline styles / scripts; shown in a sandboxed context.
REPORT_CSP = ("default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
              "img-src data:; sandbox allow-scripts")
SVG_CSP = "default-src 'none'; style-src 'unsafe-inline'; sandbox"


def hash_password(password):
    return generate_password_hash(password)


def password_problem(password):
    if len(password or "") < MIN_PASSWORD_LENGTH:
        return f"The password must have at least {MIN_PASSWORD_LENGTH} characters."
    return None


class Throttle:
    """Locks sign-in for an address (and a user name) after MAX_FAILURES failures."""

    def __init__(self):
        self.failures = {}
        self.lock = threading.Lock()

    def blocked(self, *keys):
        now = time.time()
        with self.lock:
            return any(len([t for t in self.failures.get(k, []) if now - t < LOCK_SECONDS]) >= MAX_FAILURES
                       for k in keys)

    def fail(self, *keys):
        now = time.time()
        with self.lock:
            for key in keys:
                self.failures[key] = [t for t in self.failures.get(key, []) if now - t < LOCK_SECONDS] + [now]

    def reset(self, *keys):
        with self.lock:
            for key in keys:
                self.failures.pop(key, None)


def _password_marker(password_hash):
    """Short value stored in the session: changing the password invalidates other sessions."""
    return hashlib.sha256(password_hash.encode()).hexdigest()[:16]


def login_user(user):
    session.clear()  # New session id content: no fixation.
    session.permanent = True
    session["uid"] = user["id"]
    session["pw"] = _password_marker(user["password_hash"])
    session["csrf"] = secrets.token_urlsafe(32)


def load_user():
    """before_request: g.user from the session (None if signed out or password changed)."""
    g.user = None
    uid = session.get("uid")
    if uid is None:
        return
    user = current_app.db.user(user_id=uid)
    if user is None or session.get("pw") != _password_marker(user["password_hash"]):
        session.clear()
        return
    g.user = user


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def check_csrf():
    """before_request: every POST must carry the session CSRF token."""
    if request.method != "POST":
        return
    sent = request.form.get("csrf", "")
    expected = session.get("csrf", "")
    if not expected or not hmac.compare_digest(sent.encode(), expected.encode()):
        abort(400, "Invalid or expired form. Reload the page and try again.")


def login_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("main.login", next=request.full_path if request.method == "GET" else None))
        return view(*args, **kwargs)
    return wrapper


def admin_required(view):
    @functools.wraps(view)
    @login_required
    def wrapper(*args, **kwargs):
        if g.user["role"] != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapper


def safe_next(target):
    """Only local paths are accepted as redirect target after sign-in."""
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return url_for("main.dashboard")


def security_headers(response):
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


def check_password(user, password):
    return user is not None and check_password_hash(user["password_hash"], password or "")
