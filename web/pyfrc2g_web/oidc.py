"""
Optional single sign-on with OpenID Connect (flask-oidc) and server-side sessions (Flask-Session).

Enabled only when PYFRC2G_OIDC_ISSUER is set; otherwise the application behaves as before
(local accounts, signed cookie sessions). Local sign-in always stays available as a
break-glass access (e.g. the identity provider is down).

Environment variables
    PYFRC2G_OIDC_ISSUER           issuer URL (".well-known/openid-configuration" is read from it)
    PYFRC2G_OIDC_CLIENT_ID
    PYFRC2G_OIDC_CLIENT_SECRET
    PYFRC2G_OIDC_SCOPES           default "openid email profile"
    PYFRC2G_OIDC_USERNAME_CLAIM   default "preferred_username" (falls back to "email")
    PYFRC2G_OIDC_GROUPS_CLAIM     default "groups"
    PYFRC2G_OIDC_ADMIN_GROUPS     comma separated: members become administrators
    PYFRC2G_OIDC_OPERATOR_GROUPS  ... operators (analyses, uploads, proposed accepted risks)
    PYFRC2G_OIDC_AUDITOR_GROUPS   ... auditors (read, exports, event log)
    PYFRC2G_OIDC_VIEWER_GROUPS    ... viewers (the most privileged matching role wins)
    PYFRC2G_OIDC_ALLOWED_GROUPS   comma separated: if set, only these groups (and the groups above)
                                  may sign in; others are refused
    PYFRC2G_OIDC_DEFAULT_ROLE     role of the other users (default "viewer")

The firewalls a non-admin user sees are set by the access scopes (Administration > Users): they map
IdP groups to sites / tags / firewalls and are recomputed at each sign-in.
    PYFRC2G_OIDC_REVALIDATE_MINUTES  an SSO session lasts at most this long (default 60), then the user goes back
                                  to the identity provider: a revoked account or a changed group is noticed
    PYFRC2G_OIDC_AUTH_METHOD      "client_secret_post" (default) or "client_secret_basic"
    PYFRC2G_OIDC_REDIRECT_URI     force the callback URL (default: <this server>/oidc/authorize)

Session store: files in <data dir>/sessions by default, or Redis when PYFRC2G_REDIS_URL is set
(needed with several instances; see redisutil.py).

Users coming from the identity provider are stored in the users table with the unusable
password hash OIDC_MARKER; their role is re-evaluated at each sign-in. An identity provider
account whose name matches a local account is refused (no takeover of a local administrator).
"""

import logging
import os

from flask import abort, current_app, flash, request, session, url_for

from pyfrc2g_web import security

OIDC_MARKER = "!oidc"  # password_hash of SSO users: never matches a password.
CALLBACK_PREFIX = "/oidc"


class OidcConfigError(Exception):
    pass


def _csv(value):
    return {item.strip() for item in (value or "").split(",") if item.strip()}


def settings_from_env(env=None):
    """Return the OIDC settings from the environment, or None when SSO is not configured."""
    env = os.environ if env is None else env
    issuer = env.get("PYFRC2G_OIDC_ISSUER", "").strip()
    if not issuer:
        return None
    client_id = env.get("PYFRC2G_OIDC_CLIENT_ID", "").strip()
    client_secret = env.get("PYFRC2G_OIDC_CLIENT_SECRET", "").strip()
    if not client_id or not client_secret:
        raise OidcConfigError("PYFRC2G_OIDC_ISSUER is set: PYFRC2G_OIDC_CLIENT_ID and "
                              "PYFRC2G_OIDC_CLIENT_SECRET are required too.")
    default_role = env.get("PYFRC2G_OIDC_DEFAULT_ROLE", "viewer").strip() or "viewer"
    if default_role not in security.ROLES:
        raise OidcConfigError(f"PYFRC2G_OIDC_DEFAULT_ROLE must be one of {', '.join(security.ROLES)}.")
    auth_method = env.get("PYFRC2G_OIDC_AUTH_METHOD", "client_secret_post").strip()
    if auth_method not in ("client_secret_post", "client_secret_basic"):
        raise OidcConfigError("PYFRC2G_OIDC_AUTH_METHOD must be client_secret_post or client_secret_basic.")
    return {
        "issuer": issuer,
        "client_id": client_id,
        "client_secret": client_secret,
        "scopes": env.get("PYFRC2G_OIDC_SCOPES", "openid email profile").strip(),
        "username_claim": env.get("PYFRC2G_OIDC_USERNAME_CLAIM", "preferred_username").strip(),
        "groups_claim": env.get("PYFRC2G_OIDC_GROUPS_CLAIM", "groups").strip(),
        "role_groups": {role: _csv(env.get(f"PYFRC2G_OIDC_{role.upper()}_GROUPS")) for role in security.ROLES},
        "allowed_groups": _csv(env.get("PYFRC2G_OIDC_ALLOWED_GROUPS")),
        "default_role": default_role,
        "auth_method": auth_method,
        "redirect_uri": env.get("PYFRC2G_OIDC_REDIRECT_URI", "").strip() or None,
    }


def init_app(app, data_dir, settings, redis_client=None):
    """Enable server-side sessions and the OIDC routes (/oidc/login, /oidc/authorize, /oidc/logout)."""
    try:
        from flask_oidc import OpenIDConnect
        from flask_oidc.signals import after_authorize
        from flask_session import Session
    except ImportError as e:
        raise OidcConfigError(f"OIDC needs flask-oidc and Flask-Session ({e}): "
                              "pip install flask-oidc Flask-Session") from e

    if redis_client is not None:
        store = {"SESSION_TYPE": "redis", "SESSION_REDIS": redis_client}
    else:
        sessions_dir = os.path.join(data_dir, "sessions")
        os.makedirs(sessions_dir, mode=0o700, exist_ok=True)
        store = {"SESSION_TYPE": "filesystem", "SESSION_FILE_DIR": sessions_dir}
    app.config.update(
        # Server-side sessions: the cookie only carries an opaque identifier.
        **store,
        SESSION_KEY_PREFIX="session:",
        SESSION_PERMANENT=True,
        SESSION_USE_SIGNER=False,
        OIDC_ENABLED=True,
        OIDC_CLIENT_SECRETS={"web": {"client_id": settings["client_id"],
                                     "client_secret": settings["client_secret"],
                                     "issuer": settings["issuer"]}},
        OIDC_SCOPES=settings["scopes"],
        OIDC_INTROSPECTION_AUTH_METHOD=settings["auth_method"],
        OIDC_USER_INFO_ENABLED=True,
        OIDC_OVERWRITE_REDIRECT_URI=settings["redirect_uri"],
    )
    Session(app)  # Must come before anything uses the session.
    OpenIDConnect(app, prefix=CALLBACK_PREFIX)
    app.extensions["pyfrc2g_oidc"] = settings

    @app.before_request
    def _local_next_only():  # The library accepts "//evil.example" as a return address: only local paths are.
        nxt = request.args.get("next")
        if request.path.startswith(CALLBACK_PREFIX) and nxt is not None and security.safe_next(nxt) != nxt:
            abort(400, "Invalid return address.")
    app.jinja_env.globals["sso_enabled"] = True
    # weak=False: the receiver is a module-level function, kept alive anyway.
    after_authorize.connect(_on_authorize, weak=False)
    logging.info(f"OIDC sign-in enabled (issuer {settings['issuer']}, sessions in "
                 f"{'Redis' if redis_client is not None else 'files'}); redirect URI: "
                 f"{settings['redirect_uri'] or '<server URL>' + CALLBACK_PREFIX + '/authorize'}")


def _claims(token, profile):
    claims = dict((token or {}).get("userinfo") or {})  # Claims of the ID token.
    claims.update(profile or {})  # The userinfo endpoint takes precedence.
    return claims


def _groups(claims, claim):
    value = claims.get(claim)
    if isinstance(value, str):
        value = [value]
    return {str(g).lstrip("/") for g in value} if isinstance(value, (list, tuple, set)) else set()


def resolve_role(settings, claims):
    """Return the most privileged role matching the user's groups, or None when the user may not sign in."""
    groups = _groups(claims, settings["groups_claim"])
    clean = {role: {g.lstrip("/") for g in names} for role, names in settings["role_groups"].items()}
    for role in security.ROLES:  # Ordered from the most privileged role.
        if groups & clean[role]:
            return role
    allowed = {g.lstrip("/") for g in settings["allowed_groups"]}
    if allowed and not groups & allowed:
        return None
    return settings["default_role"]


def _username(settings, claims):
    name = claims.get(settings["username_claim"]) or claims.get("email")
    name = str(name).strip() if name else ""
    return name[:100] or None


def _refuse(message, username, detail):
    db = current_app.db
    db.add_event(username or "?", "failed sign-in (SSO)", detail)
    logging.warning(f"web: SSO sign-in refused for {username!r}: {detail}")
    flash(message, "error")


def _on_authorize(sender, token=None, return_to=None, **kwargs):
    """Handle the flask-oidc after_authorize signal: apply the role and scope rules, then open the local session."""
    settings = current_app.extensions["pyfrc2g_oidc"]
    claims = _claims(token, session.get("oidc_auth_profile"))
    session.clear()  # The OIDC tokens are discarded: only the application session is kept.
    username = _username(settings, claims)
    if not username:
        return _refuse("Sign-in refused: the identity provider did not send a user name.", None,
                       f"claim {settings['username_claim']!r} missing")
    role = resolve_role(settings, claims)
    if role is None:
        return _refuse("Sign-in refused: your account is not allowed to use this application.", username,
                       "not in an allowed group")
    db = current_app.db
    user = db.user(username=username)
    if user is None:
        db.create_user(username, OIDC_MARKER, role)
        db.add_event(username, "user created", f"{role} (SSO)")
        user = db.user(username=username)
    elif user["password_hash"] != OIDC_MARKER:
        return _refuse("Sign-in refused: a local account has the same name.", username,
                       "name of a local account")
    elif user["role"] != role:
        db.update_user(user["id"], role=role)
        db.delete_user_api_tokens(user["id"])  # Tokens were made with the previous role.
        db.add_event(username, "role changed", f"{role} (SSO)")
        user = db.user(username=username)
    from pyfrc2g_web import access

    scope = None if role == "admin" else access.scope_for_groups(db.settings().get("group_scopes"),
                                                                   _groups(claims, settings["groups_claim"]))
    if scope != access.parse_scope(user.get("scope")):
        db.update_user(user["id"], scope=scope)
        db.delete_user_api_tokens(user["id"])
        db.add_event(username, "scope changed", access.describe(scope) + " (SSO)")
        user = db.user(username=username)
    security.login_user(user)
    db.touch_login(user["id"])
    db.add_event(username, "sign-in", "SSO")


def sso_login_url(next_url=None):
    """Return the SSO login URL, carrying `next_url` only when it is a safe local redirect."""
    return url_for("oidc_auth.login", next=security.safe_next(next_url) if next_url else None)


def is_sso_user(user):
    return bool(user) and user["password_hash"] == OIDC_MARKER

