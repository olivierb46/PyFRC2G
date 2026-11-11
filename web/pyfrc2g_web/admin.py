"""
Administration pages (role admin): API firewalls, settings (schedule, audit, compliance
policy), users, event log. Secrets are never sent back to the browser: an empty secret field
keeps the stored value.
"""

import os
import re

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

from pyfrc2g_web import security
from pyfrc2g_web.fwopts import ports
from pyfrc2g_web.security import admin_required

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
    return next((gw for gw in db().gateways() if gw["firewall_id"] == firewall_id), None)


@bp.route("/firewalls/new", methods=["GET", "POST"])
@bp.route("/firewalls/<int:firewall_id>", methods=["GET", "POST"])
@admin_required
def firewall(firewall_id=None):
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
            db().create_user(username, security.hash_password(password), role)
            db().add_event(g.user["username"], "user created", f"{username} ({role})")
            flash(f"User {username} created.", "ok")
        return redirect(url_for("admin.users"))
    return render_template("admin/users.html", users=db().users(), roles=security.ROLES)


@bp.route("/users/<int:user_id>", methods=["POST"])
@admin_required
def update_user(user_id):
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
            db().add_event(g.user["username"], "role changed", f"{user['username']}: {role}")
            flash(f"{user['username']} is now {role}.", "ok")
    elif action == "password":
        password = request.form.get("password", "")
        problem = security.password_problem(password)
        if problem:
            flash(problem, "error")
        else:
            db().update_user(user_id, password_hash=security.hash_password(password))
            db().add_event(g.user["username"], "password reset", user["username"])
            flash(f"Password of {user['username']} changed (their sessions are signed out).", "ok")
    return redirect(url_for("admin.users"))


@bp.route("/events")
@admin_required
def events():
    return render_template("admin/events.html", events=db().events())


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
@admin_required
def exceptions():
    from datetime import date

    return render_template("admin/exceptions.html", items=db().exceptions(), today=date.today().isoformat())


@bp.route("/exceptions/<int:exception_id>/delete", methods=["POST"])
@admin_required
def delete_exception(exception_id):
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
