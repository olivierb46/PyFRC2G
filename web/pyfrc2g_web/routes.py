"""
Main pages: sign-in, dashboard, firewall details (rules, audit, changes, NAT, matrix, usage,
graphs, reports, history), uploads, runs, trends, comparison, help, account.
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

from pyfrc2g_web import access, security
from pyfrc2g_web.security import admin_required, login_required, permission_required

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
    """Sign in with a local account (throttled per address and per user name)."""
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
    sso_url = None
    if "pyfrc2g_oidc" in current_app.extensions:
        from pyfrc2g_web.oidc import sso_login_url

        sso_url = sso_login_url(request.args.get("next"))
    return render_template("login.html", error=error, no_users=db().count_users() == 0, sso_url=sso_url)


@bp.route("/logout", methods=["POST"])
def logout():
    from flask import session

    if g.user:
        db().add_event(g.user["username"], "sign-out")
    session.clear()
    return redirect(url_for("main.login"))


@bp.route("/health")
def health():
    """Liveness probe for load balancers and containers."""
    return Response("ok", mimetype="text/plain")


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

def _visible_runs(limit, gateway=None):
    """Runs the user may see: all of them, or (scoped user) those of visible firewalls and their own."""
    if not access.is_restricted():
        return db().runs(limit=limit, gateway=gateway)
    names, user_id = access.visible_names(db()), g.user["id"]
    return db().runs(limit=limit, gateway=gateway,
                     accept=lambda r: bool(set(r["gateways"]) & names) or r.get("user_id") == user_id)


def _filtered_gateways():
    """Gateways (with site, tags, description) matching the site / tag filters of the query string."""
    firewalls = db().firewalls()
    gateways = access.visible_gateways(db())  # Only the firewalls the user may see.
    sites = sorted({gw["site"] for gw in gateways if gw["site"]})
    tags = sorted({tag for gw in gateways for tag in gw["tags"]})
    site, tag = request.args.get("site", ""), request.args.get("tag", "")
    if site:
        gateways = [gw for gw in gateways if gw["site"] == site]
    if tag:
        gateways = [gw for gw in gateways if tag in gw["tags"]]
    return firewalls, gateways, sites, tags, site, tag


@bp.route("/")
@login_required
def dashboard():
    firewalls, gateways, sites, tags, site, tag = _filtered_gateways()
    for gw in gateways:
        gw["history"] = db().score_history(gw["id"])
    runs = _visible_runs(8)
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
    return access.require_gateway(name)  # Also 404 for a firewall outside the user scope.


def _selected_analysis(gateway):
    """Return (all analyses, the one selected by ?analysis=, defaulting to the latest)."""
    analyses = db().analyses(gateway["id"])
    if not analyses:
        return analyses, None
    wanted = request.args.get("analysis", type=int)
    chosen = next((a for a in analyses if a["id"] == wanted), analyses[0])
    return analyses, db().analysis(chosen["id"])


def _classify(artifacts, gateway_name):
    """Group the stored files of an analysis by kind for the Reports & files tab."""
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
    """Firewall page: one tab per view of the selected analysis."""
    gw = _gateway_or_404(name)
    tab = request.args.get("tab", "overview")
    if tab not in dict(TABS):
        tab = "overview"
    analyses, analysis = _selected_analysis(gw)
    if analysis:  # Expired accepted risks count again as soon as they expire.
        from pyfrc2g_web import exceptions as accepted

        accepted.apply(analysis["data"], db().exceptions(), gw["name"])
    artifacts = _classify(db().artifacts(analysis["id"]), gw["name"]) if analysis else None
    from pyfrc2g_web import ciso

    settings = db().settings()
    opts = ciso.options_of(db(), gw)
    ciso_info = {"configured": ciso.configured(settings), "auto": settings.get("ciso_auto"),
                 "evidence": ciso.evidence_for(settings, gw), "own": gw.get("ciso_evidence_id") or "",
                 "folder": ciso.folder_for(settings, gw, opts["site"]), "own_folder": gw.get("ciso_folder_id") or "",
                 "folder_origin": ciso.folder_origin(settings, gw, opts["site"]), "site": opts["site"],
                 "changes": ciso.changes_evidence_for(settings, opts),
                 "uploads": db().ciso_uploads(gateway=gw["name"], limit=20)}
    return render_template("gateway.html", gw=gw, tab=tab, tabs=TABS, analyses=analyses, analysis=analysis,
                           ciso=ciso_info,
                           data=analysis["data"] if analysis else None, artifacts=artifacts,
                           history=db().score_history(gw["id"], 60),
                           runs=_visible_runs(20, gw["name"]))


@bp.route("/firewalls/<name>/files/<int:analysis_id>/<path:filename>")
@login_required
def artifact(name, analysis_id, filename):
    """Serve a stored file of an analysis, inline or as a download, with a restrictive CSP for HTML and SVG."""
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


@bp.route("/firewalls/<name>/accept", methods=["POST"])
@permission_required("propose_risk")
def accept_finding(name):
    """
    Accept a finding of the Audit tab (justification, owner, optional expiry). An administrator's
    acceptance applies at once; an operator's is a proposal waiting for an administrator's decision
    (and with PYFRC2G_RISK_FOUR_EYES=1 an administrator's too, to be approved by another one).
    """
    import re
    from datetime import date

    from pyfrc2g_web import exceptions as accepted

    gw = _gateway_or_404(name)
    analysis = db().analysis(request.form.get("analysis_id", type=int) or 0)
    if analysis is None or analysis["gateway_id"] != gw["id"]:
        abort(404)
    data = accepted.apply(analysis["data"], db().exceptions(), gw["name"])
    index = request.form.get("finding", type=int)
    if index is None or not 0 <= index < len(data["audit"]):
        flash("Choose the finding to accept.", "error")
        return redirect(url_for("main.gateway", name=name, tab="audit"))
    finding = data["audit"][index]
    reason = request.form.get("reason", "").strip()
    owner = request.form.get("owner", "").strip()[:64]
    expires = request.form.get("expires", "").strip()
    if not reason or len(reason) > 500:
        flash("Give the justification (500 characters max).", "error")
    elif expires and (not re.match(r"^\d{4}-\d{2}-\d{2}$", expires) or expires < date.today().isoformat()):
        flash("Expiry: a future date (YYYY-MM-DD), or empty for no expiry.", "error")
    else:
        scope = request.form.get("scope", "rule")
        everywhere = request.form.get("where") == "all"
        if everywhere and access.is_restricted():
            abort(403)  # A scoped user cannot decide for firewalls outside the scope.
        key = accepted.rule_key(finding) if scope == "rule" else ""
        approve_now = security.can("approve_risk") and not current_app.config.get("RISK_FOUR_EYES")
        db().add_exception(None if everywhere else name, finding["CHECK"], key, reason, owner, expires,
                           g.user["username"], approver=g.user["username"] if approve_now else None)
        if not approve_now:
            db().add_event(g.user["username"], "risk proposed",
                           f"{finding['CHECK']} on {'all firewalls' if everywhere else name}")
            flash("Acceptance proposed: it counts once an administrator approves it "
                  "(Administration > Accepted risks).", "ok")
            return redirect(url_for("main.gateway", name=name, tab="audit"))
        accepted.refresh(db(), None if everywhere else {name})
        db().add_event(g.user["username"], "risk accepted",
                       f"{finding['CHECK']} on {'all firewalls' if everywhere else name}")
        run_id = accepted.regenerate(current_app, db(), None if everywhere else {name}, g.user["id"])
        flash("Risk accepted: the finding no longer counts in the score."
              + (" The PDF, HTML and Excel reports are being regenerated." if run_id else ""), "ok")
        if run_id:
            return redirect(url_for("main.run", run_id=run_id))
    return redirect(url_for("main.gateway", name=name, tab="audit"))


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
    """Set the CISO Assistant evidence and folder ids of a firewall."""
    import re

    gw = _gateway_or_404(name)
    evidence = request.form.get("evidence_id", "").strip()
    folder = request.form.get("folder_id", "").strip()
    if any(value and not re.match(r"^[A-Za-z0-9._:-]{1,64}$", value) for value in (evidence, folder)):
        flash("Evidence and folder ids: letters, digits, '-', '_', '.' or ':' only.", "error")
    else:
        firewall = db().firewall(gw["firewall_id"]) if gw.get("firewall_id") else None
        if firewall:  # API firewall: its settings hold the ids used by the next analyses.
            firewall["config"].update(ciso_evidence_id=evidence, ciso_folder_id=folder)
            db().save_firewall(firewall["id"], firewall["name"], firewall["type"], firewall["enabled"],
                               firewall["config"])
            db().set_gateway_evidence(gw["id"], evidence, folder)
        elif gw.get("options") is not None:  # Configuration file with its own settings.
            db().set_gateway_options(gw["id"], dict(gw["options"], ciso_evidence_id=evidence,
                                                    ciso_folder_id=folder))
        else:
            db().set_gateway_evidence(gw["id"], evidence, folder)
        db().add_event(g.user["username"], "CISO Assistant evidence set",
                       f"{name}: evidence {evidence or '(default)'}, folder {folder or '(default)'}")
        flash(f"CISO Assistant of {name}: evidence {evidence or 'default'}, folder {folder or 'default'}.", "ok")
    return redirect(url_for("main.gateway", name=name, tab="files"))


@bp.route("/firewalls/<name>/settings", methods=["GET", "POST"])
@admin_required
def gateway_settings(name):
    """Own settings of a gateway analysed from a configuration file (backup)."""
    from pyfrc2g_web import fwopts

    gw = _gateway_or_404(name)
    if gw["kind"] != "upload":
        if gw.get("firewall_id"):
            return redirect(url_for("admin.firewall", firewall_id=gw["firewall_id"]))
        abort(404)
    old = fwopts.options({"config": gw.get("options") or {}})
    errors = []
    if request.method == "POST":
        values = fwopts.parse_form(request.form, old, errors, backup=True)
        if not errors:
            db().set_gateway_options(gw["id"], values)
            db().add_event(g.user["username"], "gateway settings updated", name)
            if request.form.get("analyse") == "1" and gw.get("upload_id"):
                flash(f"Settings of {name} saved.", "ok")
                run_id = current_app.runner.submit("upload", f"Analysis of {name}",
                                                   [{"kind": "upload", "upload_id": gw["upload_id"]}], g.user["id"])
                return redirect(url_for("main.run", run_id=run_id))
            flash(f"Settings of {name} saved: they apply to the next analysis of its configuration file.", "ok")
            return redirect(url_for("main.gateway", name=name))
        for error in errors:
            flash(error, "error")
        old = dict(old, **{k: v for k, v in values.items()})
    return render_template("gateway_settings.html", gw=gw, o=old, settings=db().settings())


@bp.route("/firewalls/<name>/delete", methods=["POST"])
@admin_required
def delete_gateway(name):
    """Delete a firewall with all its stored analyses."""
    gw = _gateway_or_404(name)
    db().delete_gateway(gw["id"])
    db().add_event(g.user["username"], "firewall data deleted", name)
    flash(f"All analyses of {name} were deleted.", "ok")
    return redirect(url_for("main.dashboard"))


# ---------------------------------------------------------------------------
# Uploads and runs
# ---------------------------------------------------------------------------

def _upload_hints(form):
    """Name, site and CISO Assistant ids given with an uploaded file -> ({key: value}, error)."""
    import re

    hints = {key: form.get(key, "").strip() for key in ("name", "site", "ciso_folder_id", "ciso_evidence_id")}
    if hints["name"] and not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$", hints["name"]):
        return {}, "Firewall name: letters, digits, '.', '_' or '-' (64 characters max)."
    if len(hints["site"]) > 64:
        return {}, "Site: 64 characters max."
    for key in ("ciso_folder_id", "ciso_evidence_id"):
        if hints[key] and not re.match(r"^[A-Za-z0-9._:-]{1,64}$", hints[key]):
            return {}, "CISO Assistant ids: letters, digits, '-', '_', '.' or ':' only."
    return {key: value for key, value in hints.items() if value}, None


@bp.route("/uploads", methods=["GET", "POST"])
@login_required
def uploads():
    """List uploaded configuration files (GET) or upload one and queue its analysis (POST)."""
    from pyfrc2g.inputs import FORMATS

    if request.method == "POST":
        if not security.can("analyse") or access.is_restricted():
            abort(403)  # A file may create a firewall outside the scope of a scoped user.
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
        from pyfrc2g_web import jobs

        filename, content = jobs.slim_upload(file.filename, content)
        hints, problem = _upload_hints(request.form)
        if problem:
            flash(problem, "error")
            return redirect(url_for("main.uploads"))
        upload_id = db().add_upload(g.user["id"], filename, fmt, content)
        db().add_event(g.user["username"], "upload", f"{filename} ({len(content)} bytes)"
                       + (f", extracted from {file.filename}" if filename != file.filename else ""))
        run_id = current_app.runner.submit("upload", f"Analysis of {hints.get('name') or filename}",
                                           [{"kind": "upload", "upload_id": upload_id, **hints}], g.user["id"])
        return redirect(url_for("main.run", run_id=run_id))
    from pyfrc2g_web import ciso

    settings = db().settings()
    items = db().uploads()
    if access.is_restricted():
        allowed = {gw["upload_id"] for gw in access.visible_gateways(db()) if gw.get("upload_id")}
        items = [u for u in items if u["id"] in allowed]
    return render_template("uploads.html", uploads=items, formats=FORMATS,
                           sites=sorted(settings.get("ciso_site_folders") or {}), ciso=ciso.configured(settings))


@bp.route("/uploads/<int:upload_id>/analyse", methods=["POST"])
@permission_required("analyse")
def reanalyse_upload(upload_id):
    """Queue a new analysis of a stored upload."""
    upload = db().upload(upload_id)
    if upload is None:
        abort(404)
    if access.is_restricted() and not any(gw.get("upload_id") == upload_id
                                          for gw in access.visible_gateways(db())):
        abort(404)
    run_id = current_app.runner.submit("upload", f"Analysis of {upload['filename']}",
                                       [{"kind": "upload", "upload_id": upload_id}], g.user["id"])
    return redirect(url_for("main.run", run_id=run_id))


@bp.route("/analyse", methods=["POST"])
@permission_required("analyse")
def analyse():
    """Queue an API analysis of one enabled firewall, or of all of them."""
    firewall_id = request.form.get("firewall_id", type=int)
    allowed = {gw["firewall_id"] for gw in access.visible_gateways(db()) if gw.get("firewall_id")} \
        if access.is_restricted() else None
    firewalls = [f for f in db().firewalls() if f["enabled"] and (firewall_id is None or f["id"] == firewall_id)
                 and (allowed is None or f["id"] in allowed)]
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


# ---------------------------------------------------------------------------
# Trends over time
# ---------------------------------------------------------------------------

@bp.route("/trends")
@login_required
def trends():
    """Risk score, findings and permissive rules of each firewall over its stored analyses."""
    limit = request.args.get("last", 60, type=int)
    limit = limit if limit in (10, 30, 60, 120) else 60
    wanted = request.args.get("firewall", "")
    gateways = access.visible_gateways(db())
    names = [gw["name"] for gw in gateways]
    items = []
    for gw in gateways:
        if wanted and gw["name"] != wanted:
            continue
        points = db().trend(gw["id"], limit)
        if not points:
            continue
        first, last = points[0], points[-1]
        delta = {key: (last[key] - first[key]) if first.get(key) is not None and last.get(key) is not None else None
                 for key in ("score", "findings", "permissive")}
        for point in points:  # Serious findings = critical + high.
            known = point["findings"] is not None
            point["serious"] = (point["critical"] or 0) + (point["high"] or 0) if known else None
        items.append({"gw": gw, "points": points, "delta": delta, "last": last})
    return render_template("trends.html", items=items, names=names, wanted=wanted, limit=limit)


# ---------------------------------------------------------------------------
# Comparison of two analyses
# ---------------------------------------------------------------------------

def _compare_side(value):
    """'firewall|analysis id' (or 'firewall' = latest analysis) -> (gateway, analysis) or (None, None)."""
    name, _, analysis_id = (value or "").partition("|")
    gw = next((x for x in access.visible_gateways(db()) if x["name"] == name), None)
    if gw is None:
        return None, None
    analyses = db().analyses(gw["id"])
    wanted = int(analysis_id) if analysis_id.isdigit() else None
    chosen = next((a for a in analyses if a["id"] == wanted), analyses[0] if analyses else None)
    return gw, (db().analysis(chosen["id"]) if chosen else None)


def _finding_keys(data):
    """Index the audit findings by (check, rule)."""
    return {(f["CHECK"], f["RULE"]): f for f in data.get("audit") or []}


@bp.route("/compare")
@login_required
def compare():
    """Show the differences between two analyses (rules, NAT, findings)."""
    from pyfrc2g.analysis.compare import compare_nat, compare_rules

    from pyfrc2g_web import exceptions as accepted

    choices = []
    for gw in access.visible_gateways(db()):
        choices.append({"name": gw["name"], "analyses": db().analyses(gw["id"])})
    gw_a, analysis_a = _compare_side(request.args.get("a"))
    gw_b, analysis_b = _compare_side(request.args.get("b"))
    result = None
    if analysis_a and analysis_b:
        exceptions = db().exceptions()
        a, b = (accepted.apply(x["data"], exceptions, gw["name"]) for x, gw in
                ((analysis_a, gw_a), (analysis_b, gw_b)))
        diff = compare_rules(a.get("rules") or [], b.get("rules") or []) + \
            compare_nat(a.get("nat") or [], b.get("nat") or [])
        keys_a, keys_b = _finding_keys(a), _finding_keys(b)
        findings = [dict(f, DIFFERENCE="ONLY IN A") for k, f in keys_a.items() if k not in keys_b] + \
                   [dict(f, DIFFERENCE="ONLY IN B") for k, f in keys_b.items() if k not in keys_a]
        counts = {}
        for item in diff:
            counts[item["DIFFERENCE"]] = counts.get(item["DIFFERENCE"], 0) + 1
        result = {"a": a, "b": b, "diff": diff, "findings": findings, "counts": counts,
                  "label_a": f"{gw_a['name']} #{analysis_a['id']}", "label_b": f"{gw_b['name']} #{analysis_b['id']}"}
    return render_template("compare.html", choices=choices, result=result,
                           a=f"{gw_a['name']}|{analysis_a['id']}" if analysis_a else request.args.get("a", ""),
                           b=f"{gw_b['name']}|{analysis_b['id']}" if analysis_b else request.args.get("b", ""))


# ---------------------------------------------------------------------------
# Export of the dashboard (Excel / PDF)
# ---------------------------------------------------------------------------

@bp.route("/export.<fmt>")
@login_required
def export(fmt):
    """Download the dashboard (same site / tag filters) as an Excel or PDF report."""
    from datetime import datetime

    from pyfrc2g_web import exports

    if fmt not in ("xlsx", "pdf"):
        abort(404)
    _, gateways, _, _, site, tag = _filtered_gateways()
    items = exports.collect(db(), gateways)
    scope = " · ".join(part for part in (f"site {site}" if site else "", f"tag {tag}" if tag else "") if part)
    content, mime = exports.build(fmt, items, scope or "all firewalls")
    db().add_event(g.user["username"], "export", f"{fmt} {scope or 'all firewalls'}")
    response = Response(content, mimetype=mime)
    response.headers["Content-Disposition"] = (
        f'attachment; filename="pyfrc2g-report-{datetime.now():%Y%m%d}.{fmt}"')
    return response


# ---------------------------------------------------------------------------
# Documentation (HOW_IT_WORKS.md of the repository, copied to docs/)
# ---------------------------------------------------------------------------

def _render_doc():
    """(html, table of contents) of docs/how-it-works.md. Relative links (repository files) become code."""
    import os
    import re

    import markdown

    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "docs", "how-it-works.md")
    with open(path, encoding="utf-8") as f:
        text = f.read()
    md = markdown.Markdown(extensions=["tables", "fenced_code", "toc"], extension_configs={"toc": {"toc_depth": "2"}})
    html = md.convert(text)
    html = re.sub(r'<a href="(?!https?://|#)[^"]*">(.*?)</a>', r"\1", html)
    html = html.replace("<table>", '<div class="table-wrap"><table>').replace("</table>", "</table></div>")
    toc = [{"id": t["id"], "name": t["name"]} for top in md.toc_tokens for t in top["children"]]
    return html, toc


@bp.route("/help")
@login_required
def help_page():
    html, toc = _render_doc()
    return render_template("help.html", doc=html, toc=toc)


@bp.route("/runs")
@login_required
def runs():
    return render_template("runs.html", runs=_visible_runs(200))


@bp.route("/runs/<int:run_id>")
@login_required
def run(run_id):
    """Progress and log of a run."""
    item = db().run(run_id)
    if item is None:
        abort(404)
    if access.is_restricted() and not (set(item["gateways"]) & access.visible_names(db())
                                       or item.get("user_id") == g.user["id"]):
        abort(404)
    return render_template("run.html", run=item, active=item["status"] in ("queued", "running"))


# ---------------------------------------------------------------------------
# Account
# ---------------------------------------------------------------------------

@bp.route("/account", methods=["GET", "POST"])
@login_required
def account():
    """Change the own password (local accounts only)."""
    from pyfrc2g_web.oidc import is_sso_user

    sso = is_sso_user(g.user)  # Managed by the identity provider: no local password.
    if request.method == "POST" and not sso:
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
    return render_template("account.html", sso=sso, scope_text=access.describe(access.user_scope()))


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

def register_error_handlers(app):
    """Render error.html for the common HTTP errors."""
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
