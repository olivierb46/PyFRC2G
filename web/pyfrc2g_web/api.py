"""
REST API (JSON) authenticated with personal API tokens: /api/v1/...

A token is created by its owner on the account page, shown once, and stored hashed (SHA-256). It acts as its
owner, with the role and the firewall scope the owner has at the time of each call, so it can never do more than
the account. Sent as "Authorization: Bearer pfa_...". Failed attempts are throttled per address.

    GET  /api/v1/me
    GET  /api/v1/firewalls                      firewalls the token owner may see, with their score
    GET  /api/v1/firewalls/<name>               summary and active findings of the latest analysis
    GET  /api/v1/firewalls/<name>/analyses      stored analyses (id, date, score)
    POST /api/v1/firewalls/<name>/analyse       analyse an API firewall now (role operator or admin)
    POST /api/v1/uploads                        send a configuration file (multipart "file"; operator / admin,
                                                not for a user limited to some firewalls)
    GET  /api/v1/runs/<id>                      status of an analysis run
"""

import functools
import hashlib
import secrets
from datetime import date

from flask import Blueprint, abort, current_app, g, jsonify, request
from werkzeug.exceptions import HTTPException

from pyfrc2g_web import access, security

PREFIX = "pfa_"
MAX_TOKENS_PER_USER = 10
EXPIRY_CHOICES = (("30", "30 days"), ("90", "90 days"), ("365", "1 year"), ("0", "Never"))
MAX_FINDINGS = 1000

bp = Blueprint("api", __name__, url_prefix="/api/v1")


def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def new_token():
    """Return (token to show once, its hash, its display prefix)."""
    token = PREFIX + secrets.token_urlsafe(32)
    return token, hash_token(token), token[:8]


def db():
    return current_app.db


@bp.errorhandler(HTTPException)
def _json_error(error):
    return jsonify(error=error.description or error.name), error.code


@bp.after_request
def _no_store(response):
    response.headers["Cache-Control"] = "no-store"
    return response


def _authenticate():
    """Set g.user from the bearer token or abort with 401 / 429."""
    header = request.headers.get("Authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else ""
    key = f"api:{request.remote_addr or '?'}"
    if current_app.throttle.blocked(key):
        abort(429, "Too many failed attempts: try again later.")
    row = db().api_token(hash_token(token)) if token.startswith(PREFIX) else None
    user = db().user(user_id=row["user_id"]) if row else None
    expired = bool(row and row["expires"] and row["expires"] < date.today().isoformat())
    if user and user["password_hash"] == "!oidc" and not _signed_in_recently(user):
        expired = True  # The identity provider is the only judge of an SSO account: it has to keep signing in.
    if not row or not user or user["role"] not in security.ROLES or expired or user.get("must_change"):
        current_app.throttle.fail(key)
        abort(401, "Invalid, expired or revoked token.")
    g.user, g.session_token, g.api_token = user, None, row
    if (row["last_used"] or "")[:16] != _now()[:16]:  # At most one write a minute.
        db().touch_api_token(row["id"])


def _signed_in_recently(user):
    """True if an SSO user signed in during the last PYFRC2G_OIDC_TOKEN_IDLE_DAYS (30): an account revoked at the
    identity provider can no longer sign in, so its tokens die with it instead of living until they expire."""
    from datetime import datetime, timedelta

    try:
        last = datetime.strptime(user.get("last_login") or "", "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return False
    return datetime.now() - last < timedelta(days=current_app.config.get("OIDC_TOKEN_IDLE_DAYS", 30))


def _now():
    from pyfrc2g_web.db import now

    return now()


def token_required(permission=None):
    """Decorator: valid bearer token, and the permission if given (403 otherwise)."""
    def decorator(view):
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            _authenticate()
            if permission and not security.can(permission):
                abort(403, "Your role does not allow this.")
            return view(*args, **kwargs)
        return wrapped
    return decorator


def _summary(gw):
    keys = ("name", "kind", "gateway_type", "site", "tags", "description", "owner", "score", "level", "rules",
            "findings", "critical", "updated")
    return {key: gw.get(key) for key in keys}


def _gateway(name):
    return access.require_gateway(name)  # 404 also outside the scope of the owner.


@bp.route("/me")
@token_required()
def me():
    return jsonify(username=g.user["username"], role=g.user["role"], scope=access.user_scope(),
                   token={"name": g.api_token["name"], "expires": g.api_token["expires"]})


@bp.route("/firewalls")
@token_required()
def firewalls():
    return jsonify(firewalls=[_summary(gw) for gw in access.visible_gateways(db())])


@bp.route("/firewalls/<name>")
@token_required()
def firewall(name):
    from pyfrc2g_web.routes import _latest_data

    gw = _gateway(name)
    data = _latest_data(gw)
    result = _summary(gw)
    if data:
        result["generated"] = data.get("generated")
        result["severities"] = data.get("severities") or {}
        result["accepted_risks"] = len(data.get("accepted") or [])
        result["findings_list"] = [{k: f.get(k) for k in ("SEVERITY", "CHECK", "GATEWAY", "RULE ORDER", "RULE ID",
                                                           "RULE", "DETAIL")}
                                  for f in (data.get("audit") or [])[:MAX_FINDINGS]]
    return jsonify(result)


@bp.route("/firewalls/<name>/analyses")
@token_required()
def analyses(name):
    gw = _gateway(name)
    return jsonify(analyses=[{k: a[k] for k in ("id", "created", "score", "level")} for a in db().analyses(gw["id"])])


@bp.route("/firewalls/<name>/analyse", methods=["POST"])
@token_required("analyse")
def analyse(name):
    gw = _gateway(name)
    firewall = db().firewall(gw["firewall_id"]) if gw.get("kind") == "api" and gw.get("firewall_id") else None
    if firewall is None:
        abort(400, "Only a firewall read through its API can be analysed on demand.")
    if current_app.runner is None:
        abort(503, "The analysis worker is not running.")
    run_id = current_app.runner.submit("api", f"API analysis of {gw['name']}",
                                       [{"kind": "api", "firewall_id": firewall["id"]}], g.user["id"])
    db().add_event(g.user["username"], "analysis requested (API)", gw["name"])
    return jsonify(run=run_id), 202


@bp.route("/uploads", methods=["POST"])
@token_required("analyse")
def upload():
    from pyfrc2g.inputs import FORMATS

    from pyfrc2g_web import jobs
    from pyfrc2g_web.routes import _upload_hints

    if access.is_restricted():
        abort(403, "A user limited to some firewalls cannot add new ones.")
    file = request.files.get("file")
    fmt = request.form.get("format", "auto")
    if fmt not in FORMATS:
        abort(400, "Unknown format.")
    content = file.read() if file and file.filename else b""
    if not content:
        abort(400, "Send the configuration as a multipart field named 'file'.")
    if current_app.runner is None:
        abort(503, "The analysis worker is not running.")
    filename, content = jobs.slim_upload(file.filename, content)
    hints, problem = _upload_hints(request.form)
    if problem:
        abort(400, problem)
    upload_id = db().add_upload(g.user["id"], filename, fmt, content)
    db().add_event(g.user["username"], "upload (API)", f"{filename} ({len(content)} bytes)")
    run_id = current_app.runner.submit("upload", f"Analysis of {hints.get('name') or filename}",
                                       [{"kind": "upload", "upload_id": upload_id, **hints}], g.user["id"])
    return jsonify(run=run_id), 202


@bp.route("/runs/<int:run_id>")
@token_required()
def run(run_id):
    item = db().run(run_id)
    if item is None:
        abort(404, "Unknown run.")
    if not access.run_visible(db(), item):
        abort(404, "Unknown run.")
    keys = ("id", "kind", "label", "status", "queued", "started", "finished", "exit_code", "gateways")
    return jsonify({k: item.get(k) for k in keys})
