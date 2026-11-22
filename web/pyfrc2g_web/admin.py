"""
Administration pages: API firewalls, settings, CISO Assistant, users, event log, sessions,
notifications, backup, policies and accepted risks. Most require the admin role (see each
route's permission). Secrets are never sent back to the browser: an empty secret field keeps
the stored value.
"""

import json
import os
import re
import sqlite3

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    url_for,
)

from pyfrc2g_web import access, security
from pyfrc2g_web.fwopts import ports
from pyfrc2g_web.security import admin_required, permission_required

bp = Blueprint("admin", __name__, url_prefix="/admin")

FIREWALL_TYPES = (("pfsense", "pfSense (REST API v2)"), ("opnsense", "OPNsense"), ("nfsensei", "nfSensei"))
SECRET_FIELDS = ("token", "key", "secret")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")


def db():
    return current_app.db


# ---------------------------------------------------------------------------
# Firewalls
# ---------------------------------------------------------------------------

@bp.route("/firewalls")
@admin_required
def firewalls():
    """List the API firewalls."""
    from pyfrc2g_web import fwopts

    items = db().firewalls()
    gateways = {gw["firewall_id"]: gw for gw in db().gateways() if gw["firewall_id"]}
    return render_template("admin/firewalls.html", firewalls=items, gateways=gateways,
                           options={f["id"]: fwopts.options(f) for f in items},
                           schedule=db().settings().get("schedule"))


def _firewall_form(existing=None):
    """Validate the firewall form. Returns (name, type, enabled, config, errors)."""
    from pyfrc2g_web import fwopts

    form = request.form
    name = form.get("name", "").strip()
    gateway_type = form.get("type", "")
    errors = []
    if not _NAME.match(name):
        errors.append("Name: letters, digits, '.', '_' or '-' (64 characters max).")
    if gateway_type not in dict(FIREWALL_TYPES):
        errors.append("Unknown firewall type.")
    url = form.get("url", "").strip().rstrip("/")
    if not re.match(r"^https?://[^\s/]+", url):
        errors.append("URL must start with https:// (or http://).")
    old = (existing or {}).get("config", {})
    old_options = fwopts.options(existing) if existing else dict(fwopts.DEFAULTS)
    config = {
        "url": url,
        "verify_ssl": form.get("verify_ssl") == "1",
        "ca_pem": form.get("ca_pem", "").strip() or ("" if form.get("ca_clear") else old.get("ca_pem", "")),
    }
    for field in SECRET_FIELDS:
        value = form.get(field, "").strip()
        config[field] = value or old.get(field, "")
    config.update(fwopts.parse_form(form, old_options, errors))
    if config["ca_pem"] and "BEGIN CERTIFICATE" not in config["ca_pem"]:
        errors.append("CA certificate must be in PEM format (-----BEGIN CERTIFICATE-----).")
    if gateway_type in ("pfsense", "nfsensei") and not config["token"]:
        errors.append(f"{'pfSense' if gateway_type == 'pfsense' else 'nfSensei'} needs an API key.")
    if gateway_type == "opnsense" and not (config["key"] and config["secret"]):
        errors.append("OPNsense needs an API key and secret.")
    return name, gateway_type, form.get("enabled") == "1", config, errors


def _firewall_view(existing):
    """Values shown by the firewall form (secrets replaced by 'stored' flags)."""
    from pyfrc2g_web import fwopts

    if not existing:
        return None
    conf = existing["config"]
    view = fwopts.options(existing)
    view.update(id=existing.get("id"), name=existing["name"], type=existing["type"],
                enabled=existing["enabled"], url=conf.get("url", ""), verify_ssl=conf.get("verify_ssl"),
                has_ca=bool(conf.get("ca_pem")), has={field: bool(conf.get(field)) for field in SECRET_FIELDS})
    detected = {i["id"]: i["name"] for i in view["detected_interfaces"]}
    view["extra_interfaces"] = [i for i in view["interfaces"] if i not in detected]
    return view


def _gateway_of(firewall_id):
    """Return the gateway analysed from this API firewall, if any."""
    return next((gw for gw in db().gateways() if gw["firewall_id"] == firewall_id), None)


@bp.route("/firewalls/new", methods=["GET", "POST"])
@bp.route("/firewalls/<int:firewall_id>", methods=["GET", "POST"])
@admin_required
def firewall(firewall_id=None):
    """Add or edit an API firewall, optionally testing the connection or starting an analysis."""
    existing = db().firewall(firewall_id) if firewall_id else None
    if firewall_id and existing is None:
        abort(404)
    test = None
    if request.method == "POST":
        name, gateway_type, enabled, config, errors = _firewall_form(existing)
        duplicate = next((f for f in db().firewalls() if f["name"] == name and f["id"] != firewall_id), None)
        if duplicate:
            errors.append(f"A firewall named {name} already exists.")
        if not errors:
            saved = db().save_firewall(firewall_id, name, gateway_type, enabled, config)
            gateway = _gateway_of(saved)
            if gateway:  # The evidence / folder ids of the firewall are also the ones of its analyses.
                db().set_gateway_evidence(gateway["id"], config["ciso_evidence_id"], config["ciso_folder_id"])
            db().add_event(g.user["username"], "firewall updated" if firewall_id else "firewall added", name)
            if request.form.get("analyse") == "1" and enabled:
                flash(f"Firewall {name} saved (credentials encrypted).", "ok")
                run_id = current_app.runner.submit("manual", f"API analysis of {name}",
                                                   [{"kind": "api", "firewall_id": saved, "force": True}],
                                                   g.user["id"])
                return redirect(url_for("main.run", run_id=run_id))
            if request.form.get("test") != "1":
                flash(f"Firewall {name} saved (credentials encrypted).", "ok")
                return redirect(url_for("admin.firewalls"))
            from pyfrc2g_web.jobs import test_firewall

            stored = db().firewall(saved)
            ok, lines, detected = test_firewall(stored, db().settings(), os.path.join(current_app.data_dir, "tmp"))
            if detected:
                stored["config"]["detected_interfaces"] = detected
                db().save_firewall(saved, stored["name"], stored["type"], stored["enabled"], stored["config"])
            db().add_event(g.user["username"], "firewall connection test", f"{name}: {'ok' if ok else 'failed'}")
            test = {"ok": ok, "lines": lines}
            existing = db().firewall(saved)
            firewall_id = saved
        else:
            for error in errors:
                flash(error, "error")
            existing = {"id": firewall_id, "name": name, "type": gateway_type, "enabled": enabled, "config": config}
    return render_template("admin/firewall_form.html", fw=_firewall_view(existing), types=FIREWALL_TYPES,
                           test=test, settings=db().settings())


@bp.route("/firewalls/<int:firewall_id>/delete", methods=["POST"])
@admin_required
def delete_firewall(firewall_id):
    """Delete an API firewall; its stored analyses are kept."""
    existing = db().firewall(firewall_id)
    if existing is None:
        abort(404)
    db().delete_firewall(firewall_id)
    db().add_event(g.user["username"], "firewall deleted", existing["name"])
    flash(f"Firewall {existing['name']} deleted (its analyses are kept).", "ok")
    return redirect(url_for("admin.firewalls"))


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

@bp.route("/settings", methods=["GET", "POST"])
@admin_required
def settings():
    """Global settings: schedule, retention, analysis thresholds and compliance policy."""
    from pyfrc2g.analysis.policy import PolicyError, parse_policy
    from pyfrc2g.config import parse_duration

    values = db().settings()
    if request.method == "POST":
        form, errors = request.form, []
        schedule = form.get("schedule", "").strip()
        if schedule:
            try:
                parse_duration(schedule)
            except ValueError as e:
                errors.append(f"Schedule: {e}")
        try:
            retention = max(1, min(500, int(form.get("retention", "30"))))
            unused_days = max(1, int(form.get("unused_days", "30")))
            parallel_fetch = max(1, min(16, int(form.get("parallel_fetch", "4"))))
        except ValueError:
            errors.append("Retention, unused days and parallel readings must be numbers.")
            retention, unused_days = values["retention"], values["unused_days"]
            parallel_fetch = values["parallel_fetch"]
        policy = form.get("policy", "")
        if policy.strip():
            try:
                count = len(parse_policy(policy))
            except PolicyError as e:
                errors.append(f"Compliance policy: {e}")
        new = {
            "schedule": schedule, "retention": retention, "unused_days": unused_days,
            "parallel_fetch": parallel_fetch,
            "wan_interfaces": [i.strip() for i in form.get("wan_interfaces", "").split(",") if i.strip()] or ["wan"],
            "admin_ports": ports(form.get("admin_ports", ""), "Administration ports", errors),
            "sensitive_ports": ports(form.get("sensitive_ports", ""), "Sensitive ports", errors),
            "verify_ssl": form.get("verify_ssl") == "1", "policy": policy,
            "automatic_rules": form.get("automatic_rules") == "1",
        }
        if errors:
            for error in errors:
                flash(error, "error")
            values.update(new)
        else:
            db().save_settings(new)
            db().add_event(g.user["username"], "settings updated")
            message = "Settings saved."
            if policy.strip():
                message += f" Compliance policy: {count} rule(s)."
            flash(message, "ok")
            return redirect(url_for("admin.settings"))
    return render_template("admin/settings.html", s=values)


@bp.route("/settings/policy-example")
@admin_required
def policy_example():
    """Commented example compliance policy (copy of PyFRC2G examples/policy.example.yml)."""
    import os

    from flask import Response

    candidates = [os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "policy.example.yml")]
    path = next((p for p in candidates if os.path.isfile(p)), None)
    if path is None:
        abort(404)
    with open(path, encoding="utf-8") as f:
        return Response(f.read(), mimetype="text/plain")


# ---------------------------------------------------------------------------
# CISO Assistant
# ---------------------------------------------------------------------------

_ID = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
CISO_FIELDS = ("ciso_url", "ciso_folder_id", "ciso_evidence_id", "ciso_changes_evidence_id", "ciso_observation")


def _ciso_form(current):
    """Validate the CISO Assistant form. Returns (values, errors)."""
    form, errors = request.form, []
    values = {key: form.get(key, "").strip() for key in CISO_FIELDS}
    values["ciso_url"] = values["ciso_url"].rstrip("/")
    values["ciso_enabled"] = form.get("ciso_enabled") == "1"
    values["ciso_auto"] = form.get("ciso_auto") == "1"
    values["ciso_verify_ssl"] = form.get("ciso_verify_ssl") == "1"
    values["ciso_changes"] = form.get("ciso_changes") == "1"
    values["ciso_site_folders"] = {}
    for line in form.get("ciso_site_folders", "").splitlines():
        if not line.strip():
            continue
        site, sep, folder = (part.strip() for part in line.partition("="))
        if not sep or not site or len(site) > 64 or not _ID.match(folder):
            errors.append(f"Folder per site: '{line.strip()}' is not 'site=folder id'.")
        else:
            values["ciso_site_folders"][site] = folder
    values["ciso_token"] = form.get("ciso_token", "").strip() or current.get("ciso_token", "")
    pem = form.get("ciso_ca_pem", "").strip()
    values["ciso_ca_pem"] = pem or ("" if form.get("ciso_ca_clear") else current.get("ciso_ca_pem", ""))
    if values["ciso_url"] and not re.match(r"^https?://[^\s/]+", values["ciso_url"]):
        errors.append("URL must start with https:// (or http://).")
    for key, label in (("ciso_folder_id", "Folder id"), ("ciso_evidence_id", "Default evidence id"),
                       ("ciso_changes_evidence_id", "Change report evidence id")):
        if values[key] and not _ID.match(values[key]):
            errors.append(f"{label}: letters, digits, '-', '_', '.' or ':' only.")
    if values["ciso_ca_pem"] and "BEGIN CERTIFICATE" not in values["ciso_ca_pem"]:
        errors.append("CA certificate must be in PEM format (-----BEGIN CERTIFICATE-----).")
    if values["ciso_enabled"] and not (values["ciso_url"] and values["ciso_token"] and values["ciso_folder_id"]):
        errors.append("To enable CISO Assistant, fill in the URL, the API token and the folder id.")
    return values, errors


def _ciso_view(values):
    """Values shown by the CISO Assistant form (secrets replaced by flags)."""
    view = {key: values.get(key, "") for key in CISO_FIELDS}
    view.update(site_folders="\n".join(f"{site}={folder}" for site, folder in
                                       (values.get("ciso_site_folders") or {}).items()),
                changes=values.get("ciso_changes"), enabled=values.get("ciso_enabled"), auto=values.get("ciso_auto"),
                verify_ssl=values.get("ciso_verify_ssl", True), has_token=bool(values.get("ciso_token")),
                has_ca=bool(values.get("ciso_ca_pem")))
    return view


@bp.route("/ciso", methods=["GET", "POST"])
@admin_required
def ciso():
    """CISO Assistant integration settings, with an optional connection test."""
    from pyfrc2g_web import ciso as ciso_client

    current = db().settings()
    if request.method == "POST":
        values, errors = _ciso_form(current)
        if errors:
            for error in errors:
                flash(error, "error")
            return render_template("admin/ciso.html", c=_ciso_view(dict(current, **values)),
                                   uploads=db().ciso_uploads(limit=30), default_note=ciso_client.DEFAULT_OBSERVATION)
        db().save_settings(values)
        db().add_event(g.user["username"], "CISO Assistant settings updated",
                       "enabled" if values["ciso_enabled"] else "disabled")
        flash("CISO Assistant settings saved (token encrypted).", "ok")
        if request.form.get("test") == "1":
            ok, message = ciso_client.test_connection(db().settings(), os.path.join(current_app.data_dir, "tmp"))
            flash(message, "ok" if ok else "error")
        return redirect(url_for("admin.ciso"))
    return render_template("admin/ciso.html", c=_ciso_view(current), uploads=db().ciso_uploads(limit=30),
                           default_note=ciso_client.DEFAULT_OBSERVATION)


# ---------------------------------------------------------------------------
# Users and events
# ---------------------------------------------------------------------------

@bp.route("/users", methods=["GET", "POST"])
@admin_required
def users():
    """List local and SSO users (GET) or create a local user (POST)."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        role = request.form.get("role", "viewer")
        password = request.form.get("password", "")
        problem = security.password_problem(password)
        if not _NAME.match(username):
            flash("User name: letters, digits, '.', '_' or '-'.", "error")
        elif role not in security.ROLES:
            flash("Unknown role.", "error")
        elif problem:
            flash(problem, "error")
        elif db().user(username=username):
            flash(f"User {username} already exists.", "error")
        else:
            try:
                scope = access.parse_scope_text(request.form.get("scope", "")) if role != "admin" else None
            except access.ScopeError as e:
                flash(str(e), "error")
                return redirect(url_for("admin.users"))
            user_id = db().create_user(username, security.hash_password(password), role)
            db().update_user(user_id, scope=scope)
            db().add_event(g.user["username"], "user created", f"{username} ({role}; {access.describe(scope)})")
            flash(f"User {username} created.", "ok")
        return redirect(url_for("admin.users"))
    users_list = db().users()
    for u in users_list:
        u["scope_view"] = access.scope_text(access.parse_scope(u["scope"])) if u["role"] != "admin" else ""
        u["restricted"] = u["role"] != "admin" and bool(u["scope"])
        u["sessions"] = len(db().sessions(u["id"]))
    return render_template("admin/users.html", users=users_list, roles=security.ROLES, role_help=security.ROLE_HELP,
                           group_scopes=access.group_scopes_text(db().settings().get("group_scopes")))


@bp.route("/users/group-scopes", methods=["POST"])
@admin_required
def group_scopes():
    """Mapping identity-provider groups -> firewalls (sites, tags, names) for the SSO users."""
    try:
        rules = access.parse_group_scopes(request.form.get("group_scopes", ""))
    except access.ScopeError as e:
        flash(str(e), "error")
    else:
        db().save_settings({"group_scopes": rules})
        db().add_event(g.user["username"], "group scopes saved", f"{len(rules)} rule(s)")
        flash(f"{len(rules)} group scope rule(s) saved: they apply at the next sign-in of each SSO user.", "ok")
    return redirect(url_for("admin.users"))


@bp.route("/users/<int:user_id>", methods=["POST"])
@admin_required
def update_user(user_id):
    """Delete a user or change their role, scope or password (action field)."""
    user = db().user(user_id=user_id)
    if user is None:
        abort(404)
    action = request.form.get("action")
    if action == "delete":
        if user_id == g.user["id"]:
            flash("You cannot delete your own account.", "error")
        elif user["role"] == "admin" and db().count_users("admin") <= 1:
            flash("The last administrator cannot be deleted.", "error")
        else:
            db().delete_user(user_id)
            db().add_event(g.user["username"], "user deleted", user["username"])
            flash(f"User {user['username']} deleted.", "ok")
    elif action == "role":
        role = request.form.get("role")
        if role not in security.ROLES:
            abort(400)
        if user["role"] == "admin" and role != "admin" and db().count_users("admin") <= 1:
            flash("At least one administrator is required.", "error")
        else:
            db().update_user(user_id, role=role)
            db().add_event(g.user["username"], "role changed", f"{user['username']}: {user['role']} -> {role}")
            flash(f"{user['username']} is now {role}.", "ok")
    elif action == "scope":
        try:
            scope = access.parse_scope_text(request.form.get("scope", ""))
        except access.ScopeError as e:
            flash(str(e), "error")
        else:
            db().update_user(user_id, scope=scope)
            db().add_event(g.user["username"], "scope changed", f"{user['username']}: {access.describe(scope)}")
            flash(f"Scope of {user['username']}: {access.describe(scope)}.", "ok")
    elif action == "password":
        password = request.form.get("password", "")
        problem = security.password_problem(password)
        if user["password_hash"] == "!oidc":
            flash(f"{user['username']} signs in through the identity provider: no local password.", "error")
        elif problem:
            flash(problem, "error")
        else:
            db().update_user(user_id, password_hash=security.hash_password(password))
            db().add_event(g.user["username"], "password reset", user["username"])
            flash(f"Password of {user['username']} changed (their sessions are signed out).", "ok")
    return redirect(url_for("admin.users"))


@bp.route("/events")
@permission_required("audit")
def events():
    """Show the event log."""
    return render_template("admin/events.html", events=db().events(), export=current_app.db.on_event is not None)


@bp.route("/events.<fmt>")
@permission_required("audit")
def events_export(fmt):
    """Download of the event log (JSON lines or CSV), for archiving or a SIEM that pulls files."""
    import csv
    import io
    import json

    from flask import Response

    if fmt not in ("json", "csv"):
        abort(404)
    rows = db().events(limit=min(request.args.get("limit", 5000, type=int), 50000))
    fields = ("time", "username", "action", "detail")
    if fmt == "json":
        body, mime = "\n".join(json.dumps({k: r[k] for k in fields}, ensure_ascii=False) for r in rows), \
            "application/x-ndjson"
    else:
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(fields)
        for r in rows:
            # Prevent spreadsheet formula injection: prefix cells starting with = + - @ with a quote.
            writer.writerow(["'" + str(r[k]) if str(r[k]).startswith(("=", "+", "-", "@")) else r[k]
                             for k in fields])
        body, mime = out.getvalue(), "text/csv"
    db().add_event(g.user["username"], "event log exported", fmt)
    response = Response(body, mimetype=mime)
    extension = "csv" if fmt == "csv" else "jsonl"
    response.headers["Content-Disposition"] = f'attachment; filename="pyfrc2g-events.{extension}"'
    return response


# ---------------------------------------------------------------------------
# Active sessions
# ---------------------------------------------------------------------------

@bp.route("/sessions", methods=["GET", "POST"])
@admin_required
def sessions():
    """List active sessions and revoke one (token) or all of a user (user_id)."""
    if request.method == "POST":
        token, user_id = request.form.get("token"), request.form.get("user_id", type=int)
        if token:
            target = next((s for s in db().sessions() if s["token"] == token), None)
            if target and db().delete_sessions(token=token):
                db().add_event(g.user["username"], "session revoked", f"{target['username']} from {target['address']}")
                flash(f"Session of {target['username']} revoked.", "ok")
        elif user_id is not None:
            user = db().user(user_id=user_id)
            count = db().delete_sessions(user_id=user_id, except_token=g.session_token)
            if user:
                db().add_event(g.user["username"], "sessions revoked", f"{user['username']}: {count}")
                flash(f"{count} session(s) of {user['username']} revoked.", "ok")
        return redirect(url_for("admin.sessions"))
    return render_template("admin/sessions.html", sessions=db().sessions(), current=g.session_token,
                           limit=current_app.config.get("MAX_SESSIONS", 0))


# ---------------------------------------------------------------------------
# Notifications and scheduled reports
# ---------------------------------------------------------------------------

_LABEL = re.compile(r"^\w[\w .:-]{0,59}$", re.UNICODE)


def _add_channel(notifier, form):
    """Validate the form and create a notification channel. Raises NotifyError."""
    from pyfrc2g_web import notify

    cfg = notifier.cfg
    name, kind = form.get("name", "").strip(), form.get("kind", "")
    if not _LABEL.match(name):
        raise notify.NotifyError("Name: 1 to 60 letters, digits, spaces, '.', ':' or '-'.")
    if kind not in dict(notify.KINDS):
        raise notify.NotifyError("Unknown kind of channel.")
    events = [e for e in form.getlist("events") if e in dict(notify.EVENTS)]
    if not events:
        raise notify.NotifyError("Choose at least one event.")
    if kind == "email":
        if cfg["smtp"] is None:
            raise notify.NotifyError("No mail server configured (PYFRC2G_SMTP_HOST).")
        target = json.dumps(notify.parse_recipients(form.get("target"), cfg))
    else:
        target = notify.check_url(kind, form.get("target"), cfg)
    secret = form.get("secret", "")[:200] if kind == "webhook" else ""
    try:
        scope = access.parse_scope_text(form.get("scope"))
    except access.ScopeError as e:
        raise notify.NotifyError(str(e)) from e
    detail = "full" if form.get("detail") == "full" else "minimal"
    try:
        return db().add_channel(name, kind, target, secret, events, detail, scope, g.user["username"]), name, kind
    except sqlite3.IntegrityError as e:
        raise notify.NotifyError("A channel has this name.") from e


def _add_schedule(notifier, form):
    """Validate the form and create a scheduled e-mail report. Raises NotifyError."""
    from pyfrc2g_web import notify

    name = form.get("name", "").strip()
    if not _LABEL.match(name):
        raise notify.NotifyError("Name: 1 to 60 letters, digits, spaces, '.', ':' or '-'.")
    if notifier.cfg["smtp"] is None:
        raise notify.NotifyError("No mail server configured (PYFRC2G_SMTP_HOST).")
    fmt, frequency = form.get("format", ""), form.get("frequency", "")
    if fmt not in ("pdf", "xlsx") or frequency not in dict(notify.FREQUENCIES):
        raise notify.NotifyError("Choose a format and a frequency.")
    weekday, monthday, hour = (form.get("weekday", type=int, default=0), form.get("monthday", type=int, default=1),
                               form.get("hour", type=int, default=7))
    if not (0 <= weekday <= 6 and 1 <= monthday <= 28 and 0 <= hour <= 23):
        raise notify.NotifyError("Invalid day or hour (day of the month: 1 to 28).")
    site, tag = notify.clean(form.get("site"), 64), notify.clean(form.get("tag"), 64)
    recipients = notify.parse_recipients(form.get("recipients"), notifier.cfg)
    try:
        return db().add_schedule(name, fmt, frequency, weekday, monthday, hour, recipients, site, tag,
                                 g.user["username"]), name
    except sqlite3.IntegrityError as e:
        raise notify.NotifyError("A schedule has this name.") from e


@bp.route("/notifications", methods=["GET", "POST"])
@admin_required
def notifications():
    """Notification channels, drift threshold and scheduled reports (action field selects the operation)."""
    from pyfrc2g_web import notify

    notifier = db().notifier
    user = g.user["username"]
    if request.method == "POST":
        form, action = request.form, request.form.get("action", "")
        channel_id, schedule_id = form.get("channel_id", type=int), form.get("schedule_id", type=int)
        channel = db().channel(channel_id) if channel_id else None
        schedule = db().schedule(schedule_id) if schedule_id else None
        try:
            if action == "add_channel":
                _, name, kind = _add_channel(notifier, form)
                db().add_event(user, "notification channel added", f"{name} ({kind})")
                flash(f"Channel {name} added. Use Test to check it.", "ok")
            elif action == "drift":
                value = form.get("notify_drift", type=int, default=10)
                if not 0 <= value <= 100:
                    raise notify.NotifyError("Threshold between 0 (never) and 100 points.")
                db().save_settings({"notify_drift": value})
                db().add_event(user, "notification threshold changed", f"{value} points")
                flash("Threshold saved.", "ok")
            elif action == "add_schedule":
                _, name = _add_schedule(notifier, form)
                db().add_event(user, "report schedule added", name)
                flash(f"Schedule {name} added.", "ok")
            elif channel and action in ("channel_toggle", "channel_delete", "channel_test"):
                if action == "channel_delete":
                    db().delete_channel(channel["id"])
                elif action == "channel_toggle":
                    db().set_channel_enabled(channel["id"], not channel["enabled"])
                else:
                    notify.test_message(notifier, channel)
                    flash("Test queued: the result is in the event log.", "ok")
                db().add_event(user, f"notification channel {action.split('_')[1]}", channel["name"])
            elif schedule and action in ("schedule_toggle", "schedule_delete", "schedule_send"):
                if action == "schedule_delete":
                    db().delete_schedule(schedule["id"])
                elif action == "schedule_toggle":
                    db().set_schedule_enabled(schedule["id"], not schedule["enabled"])
                elif notify.send_report(db(), notifier, schedule, "manual"):
                    flash("Report queued: the result is in the event log.", "ok")
                else:
                    flash("The report could not be built (see the event log).", "error")
                db().add_event(user, f"report schedule {action.split('_')[1]}", schedule["name"])
            else:
                abort(400)
        except notify.NotifyError as e:
            flash(str(e), "error")
        return redirect(url_for("admin.notifications"))
    channels = db().channels()
    for channel in channels:
        channel["shown"] = notify.describe_target(channel)
    schedules = db().schedules()
    for schedule in schedules:
        schedule["when"] = notify.describe_schedule(schedule)
    return render_template("admin/notifications.html", channels=channels, schedules=schedules, cfg=notifier.cfg,
                           kinds=notify.KINDS, events=notify.EVENTS,
                           event_labels=dict(notify.EVENTS), frequencies=notify.FREQUENCIES,
                           drift=db().settings().get("notify_drift"))


# ---------------------------------------------------------------------------
# Backup and key rotation
# ---------------------------------------------------------------------------

@bp.route("/backup", methods=["GET", "POST"])
@admin_required
def backup():
    """Download an encrypted backup or re-encrypt stored values with the current key."""
    from pyfrc2g_web import backup as backups

    action = request.form.get("action") if request.method == "POST" else None
    if action == "download":
        passphrase = request.form.get("passphrase", "")
        if passphrase != request.form.get("confirm", ""):
            flash("The passphrases do not match.", "error")
        else:
            try:
                path = backups.make_backup(db(), os.path.join(current_app.data_dir, "tmp"), passphrase)
            except backups.BackupError as e:
                flash(str(e), "error")
            else:
                return _send_and_delete(path)
    elif action == "rotate":
        status = backups.rotation_status(db())
        if not status["old"]:
            flash("Nothing to re-encrypt: every value already uses the current key.", "ok")
        else:
            count = backups.rotate(db())
            db().add_event(g.user["username"], "key rotation", f"{count} value(s) re-encrypted")
            flash(f"{count} value(s) re-encrypted with the current key. You can now remove "
                  "PYFRC2G_SECRET_KEY_OLD and restart.", "ok")
        return redirect(url_for("admin.backup"))
    return render_template("admin/backup.html", status=backups.rotation_status(db()),
                           old_key=bool(os.environ.get("PYFRC2G_SECRET_KEY_OLD", "").strip()),
                           min_length=backups.MIN_PASSPHRASE)


def _send_and_delete(path):
    """Stream the file to the client, then delete it."""
    from datetime import datetime

    from flask import Response

    def stream():
        try:
            with open(path, "rb") as f:
                while chunk := f.read(1024 * 1024):
                    yield chunk
        finally:
            os.unlink(path)

    db().add_event(g.user["username"], "backup downloaded", f"{os.path.getsize(path)} bytes")
    response = Response(stream(), mimetype="application/octet-stream")
    response.headers["Content-Disposition"] = f'attachment; filename="pyfrc2g-{datetime.now():%Y%m%d-%H%M}.bak"'
    response.headers["Content-Length"] = str(os.path.getsize(path))
    return response


# ---------------------------------------------------------------------------
# Compliance policies per site / tag
# ---------------------------------------------------------------------------

_SCOPE_NAME = re.compile(r"^[\w .:-]{1,64}$", re.UNICODE)


def _scope_choices():
    """Sites and tags already used by the firewalls (suggestions)."""
    from pyfrc2g_web import ciso

    sites, tags = set(), set()
    for gw in db().gateways():
        opts = ciso.options_of(db(), gw)
        if opts["site"]:
            sites.add(opts["site"])
        tags.update(opts["tags"])
    return sorted(sites), sorted(tags)


@bp.route("/policies", methods=["GET", "POST"])
@admin_required
def policies():
    """Manage compliance policies scoped to a site or a tag."""
    from pyfrc2g.analysis.policy import PolicyError, parse_policy

    items = list(db().settings().get("scoped_policies") or [])
    if request.method == "POST":
        form = request.form
        index = form.get("index", type=int)
        if form.get("action") == "delete":
            if index is not None and 0 <= index < len(items):
                removed = items.pop(index)
                db().save_settings({"scoped_policies": items})
                db().add_event(g.user["username"], "scoped policy deleted", f"{removed['kind']} {removed['name']}")
                flash("Policy deleted.", "ok")
            return redirect(url_for("admin.policies"))
        kind, name, text = form.get("kind", ""), form.get("name", "").strip(), form.get("policy", "")
        error = None
        if kind not in ("site", "tag"):
            error = "Choose site or tag."
        elif not _SCOPE_NAME.match(name):
            error = "Name: letters, digits, spaces, '.', ':', '_' or '-' (64 characters max)."
        elif not text.strip():
            error = "Paste a policy."
        else:
            try:
                count = len(parse_policy(text))
            except PolicyError as e:
                error = f"Policy: {e}"
        if error:
            flash(error, "error")
        else:
            entry = {"kind": kind, "name": name, "policy": text}
            if index is not None and 0 <= index < len(items):
                items[index] = entry
            else:
                items.append(entry)
            db().save_settings({"scoped_policies": items})
            db().add_event(g.user["username"], "scoped policy saved", f"{kind} {name}")
            flash(f"Policy for {kind} {name} saved: {count} rule(s).", "ok")
            return redirect(url_for("admin.policies"))
    sites, tags = _scope_choices()
    return render_template("admin/policies.html", items=items, sites=sites, tags=tags)


# ---------------------------------------------------------------------------
# Accepted risks
# ---------------------------------------------------------------------------

@bp.route("/exceptions")
@permission_required("audit")
def exceptions():
    """List accepted risks with their approval status and upcoming expirations."""
    from datetime import date

    from pyfrc2g_web import exceptions as accepted

    items = db().exceptions()
    days = current_app.config.get("RISK_REMINDER_DAYS", 14)
    soon = {e["id"]: left for e, left in accepted.expiring(items, days)}
    return render_template("admin/exceptions.html", items=items, today=date.today().isoformat(), soon=soon,
                           days=days, four_eyes=current_app.config.get("RISK_FOUR_EYES"))


@bp.route("/exceptions/<int:exception_id>/decide", methods=["POST"])
@permission_required("approve_risk")
def decide_exception(exception_id):
    """Approve or reject a proposed accepted risk. With four eyes the proposer cannot approve their own."""
    from pyfrc2g_web import exceptions as accepted

    item = next((e for e in db().exceptions() if e["id"] == exception_id), None)
    if item is None or item["status"] != "pending":
        abort(404)
    approve = request.form.get("decision") == "approve"
    if approve and item["username"] == g.user["username"] and current_app.config.get("RISK_FOUR_EYES"):
        flash("Four eyes: another administrator must approve a risk you proposed.", "error")
        return redirect(url_for("admin.exceptions"))
    db().decide_exception(exception_id, approve, g.user["username"])
    db().add_event(g.user["username"], "risk approved" if approve else "risk rejected",
                   f"{item['check_name']} on {item['gateway'] or 'all firewalls'} (proposed by {item['username']})")
    if not approve:
        flash("Proposal rejected.", "ok")
        return redirect(url_for("admin.exceptions"))
    names = None if not item["gateway"] else {item["gateway"]}
    accepted.refresh(db(), names)
    run_id = accepted.regenerate(current_app, db(), names, g.user["id"])
    flash("Risk approved: the finding no longer counts."
          + (" The PDF, HTML and Excel reports are being regenerated." if run_id else ""), "ok")
    return redirect(url_for("main.run", run_id=run_id) if run_id else url_for("admin.exceptions"))


@bp.route("/exceptions/<int:exception_id>/delete", methods=["POST"])
@permission_required("approve_risk")
def delete_exception(exception_id):
    """Remove an accepted risk so the finding counts again."""
    from pyfrc2g_web import exceptions as accepted

    item = next((e for e in db().exceptions() if e["id"] == exception_id), None)
    if item is None:
        abort(404)
    db().delete_exception(exception_id)
    accepted.refresh(db(), None if not item["gateway"] else {item["gateway"]})
    db().add_event(g.user["username"], "accepted risk removed", f"{item['check_name']} {item['gateway'] or '(all)'}")
    run_id = accepted.regenerate(current_app, db(), None if not item["gateway"] else {item["gateway"]},
                                 g.user["id"])
    flash("Accepted risk removed: the finding counts again."
          + (" The PDF, HTML and Excel reports are being regenerated." if run_id else ""), "ok")
    return redirect(url_for("main.run", run_id=run_id) if run_id else url_for("admin.exceptions"))
