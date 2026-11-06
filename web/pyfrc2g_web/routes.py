"""
Main pages: sign-in, dashboard, firewall details (rules, audit, changes, NAT, matrix, usage,
graphs, reports, history), uploads, runs, account.
"""

import logging

from flask import (
    Blueprint,
    Response,
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
from pyfrc2g_web.security import admin_required, login_required

bp = Blueprint("main", __name__)

TABS = (("overview", "Overview"), ("rules", "Rules"), ("audit", "Audit"), ("changes", "Changes"),
        ("nat", "NAT"), ("matrix", "Zone matrix"), ("usage", "Rule usage"), ("graphs", "Graphs"),
        ("files", "Reports & files"), ("history", "History"))
REPORT_SUFFIXES = (("_REPORT.html", "Interactive report", "html"), ("_FLOW_MATRIX.pdf", "PDF report", "pdf"),
                   ("_FLOW_MATRIX.xlsx", "Excel workbook", "xlsx"))


def db():
    return current_app.db


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user is not None:
        return redirect(url_for("main.dashboard"))
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        address = request.remote_addr or "?"
        throttle = current_app.throttle
        if throttle.blocked(address, f"user:{username}"):
            error = "Too many failed attempts: try again in 10 minutes."
        else:
            user = db().user(username=username)
            if security.check_password(user, request.form.get("password", "")):
                throttle.reset(address, f"user:{username}")
                security.login_user(user)
                db().touch_login(user["id"])
                db().add_event(username, "sign-in", address)
                return redirect(security.safe_next(request.args.get("next")))
            throttle.fail(address, f"user:{username}")
            db().add_event(username or "?", "failed sign-in", address)
            logging.warning(f"web: failed sign-in for {username!r} from {address}")
            error = "Invalid user name or password."
    return render_template("login.html", error=error, no_users=db().count_users() == 0)


@bp.route("/logout", methods=["POST"])
def logout():
    from flask import session

    if g.user:
        db().add_event(g.user["username"], "sign-out")
    session.clear()
    return redirect(url_for("main.login"))


@bp.route("/health")
def health():
    return Response("ok", mimetype="text/plain")


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@bp.route("/")
@login_required
def dashboard():
    from pyfrc2g_web import fwopts

    firewalls = db().firewalls()
    labels = {f["id"]: fwopts.options(f) for f in firewalls}
    gateways = db().gateways()
    for gw in gateways:
        opts = labels.get(gw["firewall_id"]) or {}
        gw.update(site=opts.get("site", ""), tags=opts.get("tags", []), description=opts.get("description", ""))
    sites = sorted({gw["site"] for gw in gateways if gw["site"]})
    tags = sorted({tag for gw in gateways for tag in gw["tags"]})
    site, tag = request.args.get("site", ""), request.args.get("tag", "")
    if site:
        gateways = [gw for gw in gateways if gw["site"] == site]
    if tag:
        gateways = [gw for gw in gateways if tag in gw["tags"]]
    for gw in gateways:
        gw["history"] = db().score_history(gw["id"])
    runs = db().runs(limit=8)
    scheduler = current_app.scheduler
    next_run = scheduler.next_run() if scheduler else None
    kpis = {
        "gateways": len(gateways),
        "rules": sum(gw["rules"] or 0 for gw in gateways),
        "findings": sum(gw["findings"] or 0 for gw in gateways),
        "critical": sum(gw["critical"] or 0 for gw in gateways),
        "average": round(sum(gw["score"] or 0 for gw in gateways) / len(gateways)) if gateways else None,
        "api": len([f for f in firewalls if f["enabled"]]),
    }
    return render_template("dashboard.html", gateways=gateways, runs=runs, kpis=kpis, next_run=next_run,
                           schedule=db().settings().get("schedule"), sites=sites, tags=tags,
                           site=site, tag=tag)


# ---------------------------------------------------------------------------
# Firewall (gateway) details
# ---------------------------------------------------------------------------

def _gateway_or_404(name):
    gateway = next((gw for gw in db().gateways() if gw["name"] == name), None)
    if gateway is None:
        abort(404)
    return gateway


def _selected_analysis(gateway):
    analyses = db().analyses(gateway["id"])
    if not analyses:
        return analyses, None
    wanted = request.args.get("analysis", type=int)
    chosen = next((a for a in analyses if a["id"] == wanted), analyses[0])
    return analyses, db().analysis(chosen["id"])


def _classify(artifacts, gateway_name):
    groups = {"reports": [], "interfaces": [], "csv": [], "graphs": [], "other": []}
    for item in artifacts:
        name = item["name"]
        report = next((label for suffix, label, _ in REPORT_SUFFIXES if name == f"{gateway_name}{suffix}"), None)
        if report:
            groups["reports"].append(dict(item, label=report))
        elif name.startswith("graphs/"):
            groups["graphs"].append(dict(item, label=name[len("graphs/"):-len(".svg")].replace("_", " ")))
        elif name.endswith("_FLOW_MATRIX.pdf"):
            groups["interfaces"].append(dict(item, label=name[len(gateway_name) + 1:-len("_FLOW_MATRIX.pdf")]))
        elif name.endswith(".csv"):
            groups["csv"].append(item)
        else:
            groups["other"].append(item)
    groups["graphs"].sort(key=lambda item: (item["name"] != "graphs/zones.svg", item["name"].lower()))
    return groups


@bp.route("/firewalls/<name>")
@login_required
def gateway(name):
    gw = _gateway_or_404(name)
    tab = request.args.get("tab", "overview")
    if tab not in dict(TABS):
        tab = "overview"
    analyses, analysis = _selected_analysis(gw)
    artifacts = _classify(db().artifacts(analysis["id"]), gw["name"]) if analysis else None
    from pyfrc2g_web import ciso

    settings = db().settings()
    ciso_info = {"configured": ciso.configured(settings), "auto": settings.get("ciso_auto"),
                 "evidence": ciso.evidence_for(settings, gw), "own": gw.get("ciso_evidence_id") or "",
                 "uploads": db().ciso_uploads(gateway=gw["name"], limit=20)}
    return render_template("gateway.html", gw=gw, tab=tab, tabs=TABS, analyses=analyses, analysis=analysis,
                           ciso=ciso_info,
                           data=analysis["data"] if analysis else None, artifacts=artifacts,
                           history=db().score_history(gw["id"], 60),
                           runs=db().runs(limit=20, gateway=gw["name"]))


@bp.route("/firewalls/<name>/files/<int:analysis_id>/<path:filename>")
@login_required
def artifact(name, analysis_id, filename):
    gw = _gateway_or_404(name)
    if not any(a["id"] == analysis_id for a in db().analyses(gw["id"])):
        abort(404)
    item = db().artifact(analysis_id, filename)
    if item is None:
        abort(404)
    mime = item["mime"] or "application/octet-stream"
    inline = mime in ("text/html", "application/pdf", "image/svg+xml", "text/csv") and not request.args.get("download")
    response = Response(item["content"], mimetype=mime)
    basename = filename.rsplit("/", 1)[-1].replace('"', "")
    response.headers["Content-Disposition"] = f'{"inline" if inline else "attachment"}; filename="{basename}"'
    if mime == "text/html":
        response.headers["Content-Security-Policy"] = security.REPORT_CSP
    elif mime == "image/svg+xml":
        response.headers["Content-Security-Policy"] = security.SVG_CSP
    elif mime == "text/csv" and inline:
        response.mimetype = "text/plain"
    return response


@bp.route("/firewalls/<name>/ciso", methods=["POST"])
@admin_required
def send_to_ciso(name):
    """Queue the upload of the PDF report of an analysis to CISO Assistant."""
    from pyfrc2g_web import ciso

    gw = _gateway_or_404(name)
    analysis_id = request.form.get("analysis_id", type=int)
    if not any(a["id"] == analysis_id for a in db().analyses(gw["id"])):
        abort(404)
    settings = db().settings()
    if not ciso.configured(settings):
        flash("CISO Assistant is not configured: Administration > CISO Assistant.", "error")
        return redirect(url_for("main.gateway", name=name, tab="files"))
    if not ciso.evidence_for(settings, gw):
        flash("No evidence id for this firewall: set one below or a default one in Administration > CISO Assistant.",
              "error")
        return redirect(url_for("main.gateway", name=name, tab="files"))
    run_id = current_app.runner.submit("ciso", f"CISO Assistant upload of {name} (analysis #{analysis_id})",
                                       [{"kind": "ciso", "analysis_id": analysis_id, "gateway": name,
                                         "username": g.user["username"]}], g.user["id"])
    return redirect(url_for("main.run", run_id=run_id))


@bp.route("/firewalls/<name>/ciso-evidence", methods=["POST"])
@admin_required
def ciso_evidence(name):
    import re

    gw = _gateway_or_404(name)
    evidence = request.form.get("evidence_id", "").strip()
    if evidence and not re.match(r"^[A-Za-z0-9._:-]{1,64}$", evidence):
        flash("Evidence id: letters, digits, '-', '_', '.' or ':' only.", "error")
    else:
        db().set_gateway_evidence(gw["id"], evidence)
        firewall = db().firewall(gw["firewall_id"]) if gw.get("firewall_id") else None
        if firewall:  # API firewall: its settings hold the evidence used by the next analyses.
            firewall["config"]["ciso_evidence_id"] = evidence
            db().save_firewall(firewall["id"], firewall["name"], firewall["type"], firewall["enabled"],
                               firewall["config"])
        db().add_event(g.user["username"], "CISO Assistant evidence set", f"{name}: {evidence or '(default)'}")
        flash(f"CISO Assistant evidence of {name}: {evidence or 'default one'}.", "ok")
    return redirect(url_for("main.gateway", name=name, tab="files"))


@bp.route("/firewalls/<name>/delete", methods=["POST"])
@admin_required
def delete_gateway(name):
    gw = _gateway_or_404(name)
    db().delete_gateway(gw["id"])
    db().add_event(g.user["username"], "firewall data deleted", name)
    flash(f"All analyses of {name} were deleted.", "ok")
    return redirect(url_for("main.dashboard"))


# ---------------------------------------------------------------------------
# Uploads and runs
# ---------------------------------------------------------------------------

@bp.route("/uploads", methods=["GET", "POST"])
@login_required
def uploads():
    from pyfrc2g.inputs import FORMATS

    if request.method == "POST":
        if g.user["role"] != "admin":
            abort(403)
        file = request.files.get("file")
        fmt = request.form.get("format", "auto")
        if fmt not in FORMATS:
            abort(400, "Unknown format.")
        if not file or not file.filename:
            flash("Choose a file to analyse.", "error")
            return redirect(url_for("main.uploads"))
        content = file.read()
        if not content:
            flash("The file is empty.", "error")
            return redirect(url_for("main.uploads"))
        upload_id = db().add_upload(g.user["id"], file.filename, fmt, content)
        db().add_event(g.user["username"], "upload", f"{file.filename} ({len(content)} bytes)")
        run_id = current_app.runner.submit("upload", f"Analysis of {file.filename}",
                                           [{"kind": "upload", "upload_id": upload_id}], g.user["id"])
        return redirect(url_for("main.run", run_id=run_id))
    return render_template("uploads.html", uploads=db().uploads(), formats=FORMATS)


@bp.route("/uploads/<int:upload_id>/analyse", methods=["POST"])
@admin_required
def reanalyse_upload(upload_id):
    upload = db().upload(upload_id)
    if upload is None:
        abort(404)
    run_id = current_app.runner.submit("upload", f"Analysis of {upload['filename']}",
                                       [{"kind": "upload", "upload_id": upload_id}], g.user["id"])
    return redirect(url_for("main.run", run_id=run_id))


@bp.route("/analyse", methods=["POST"])
@admin_required
def analyse():
    firewall_id = request.form.get("firewall_id", type=int)
    firewalls = [f for f in db().firewalls() if f["enabled"] and (firewall_id is None or f["id"] == firewall_id)]
    if not firewalls:
        flash("No enabled firewall to analyse: add one in Administration > Firewalls.", "error")
        return redirect(request.referrer or url_for("main.dashboard"))
    force = request.form.get("force") == "1"
    label = firewalls[0]["name"] if len(firewalls) == 1 else f"{len(firewalls)} firewalls"
    run_id = current_app.runner.submit("manual", f"API analysis of {label}",
                                       [{"kind": "api", "firewall_id": f["id"], "force": force} for f in firewalls],
                                       g.user["id"])
    db().add_event(g.user["username"], "analysis started", label)
    return redirect(url_for("main.run", run_id=run_id))


@bp.route("/runs")
@login_required
def runs():
    return render_template("runs.html", runs=db().runs(limit=200))


@bp.route("/runs/<int:run_id>")
@login_required
def run(run_id):
    item = db().run(run_id)
    if item is None:
        abort(404)
    return render_template("run.html", run=item, active=item["status"] in ("queued", "running"))


# ---------------------------------------------------------------------------
# Account
# ---------------------------------------------------------------------------

@bp.route("/account", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "POST":
        current = request.form.get("current", "")
        new = request.form.get("new", "")
        if not security.check_password(g.user, current):
            flash("Current password is wrong.", "error")
        elif new != request.form.get("confirm", ""):
            flash("The new passwords do not match.", "error")
        elif security.password_problem(new):
            flash(security.password_problem(new), "error")
        else:
            db().update_user(g.user["id"], password_hash=security.hash_password(new))
            db().add_event(g.user["username"], "password changed")
            security.login_user(db().user(user_id=g.user["id"]))  # Keep this session valid.
            flash("Password changed. Other sessions were signed out.", "ok")
            return redirect(url_for("main.account"))
    return render_template("account.html")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

def register_error_handlers(app):
    messages = {400: "Bad request", 403: "Access denied", 404: "Page not found",
                413: "File too large", 500: "Internal error"}

    def handler(error):
        code = getattr(error, "code", 500) or 500
        if code == 500:
            logging.exception("web: internal error")
        description = getattr(error, "description", "") if code != 500 else ""
        return render_template("error.html", code=code, title=messages.get(code, "Error"),
                               description=description), code

    for code in messages:
        app.register_error_handler(code, handler)
