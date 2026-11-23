"""
Notifications and scheduled reports.

* Alerts: after each analysis, the new findings and the drift of the risk score compared with the
  previous analysis of the same firewall are sent to the channels (email, signed JSON webhook,
  Slack, Teams) that subscribed to them.
* Scheduled reports: the PDF or Excel export of the dashboard is e-mailed periodically.

Configuration of the mail server and of the safety rules, in the environment (no secret in the
database); the channels and the schedules are edited in Administration > Notifications.

    PYFRC2G_SMTP_HOST / _PORT          mail server (port default 587)
    PYFRC2G_SMTP_SECURITY              "starttls" (default), "ssl", or "none" (loopback servers only)
    PYFRC2G_SMTP_USER / _PASSWORD      optional authentication
    PYFRC2G_SMTP_FROM                  sender address (required with the host)
    PYFRC2G_BASE_URL                   public URL of this application (links in the messages)
    PYFRC2G_MAIL_ALLOWED_DOMAINS       comma separated: recipients are limited to these domains
    PYFRC2G_NOTIFY_WEBHOOK_HOSTS       comma separated: extra host suffixes accepted for Slack / Teams
    PYFRC2G_NOTIFY_ALLOW_PRIVATE       1: webhooks may target private / loopback addresses (default: refused)

Safety rules: TLS with certificate verification for mail and webhooks (no redirect followed); Slack and
Teams URLs must belong to the vendors' domains; a generic webhook may not resolve to a private,
loopback or link-local address (SSRF), checked again at each delivery; webhook URLs and recipients
are encrypted in the database and never displayed again; header injection is impossible (addresses are
validated, subjects are cleaned); the content of the alerts is *minimal* (counts only) unless the channel
asks for the details; everything sent or failed is written to the event log (without the URL).
"""

import functools
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import queue
import re
import smtplib
import socket
import ssl
import threading
import time
from datetime import date, datetime, timedelta
from datetime import time as dtime
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from urllib.parse import urlparse

from pyfrc2g.analysis.exceptions import rule_key

from pyfrc2g_web.db import is_permissive

LOG = logging.getLogger("pyfrc2g.notify")

KINDS = (("email", "Email"), ("webhook", "Webhook (signed JSON)"), ("slack", "Slack"), ("teams", "Microsoft Teams"))
EVENTS = (("critical", "New critical finding"), ("high", "New high finding"),
          ("drift", "Risk score rise"), ("permissive", "New permissive rule (any)"),
          ("failed", "Analysis failed"), ("stale", "Analysis too old"),
          ("window", "Change outside the maintenance window"))
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SLACK_HOSTS = ("hooks.slack.com",)
TEAMS_SUFFIXES = (".webhook.office.com", ".logic.azure.com", ".powerplatform.com", ".office.com")
MAX_FINDINGS = 10
MAX_RECIPIENTS = 20
_EMAIL = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f\u0085\u2028\u2029]")


class NotifyError(ValueError):
    """Invalid configuration entered by the administrator (the message is shown to them)."""


class NotifyConfigError(Exception):
    """Invalid environment configuration (the application refuses to start)."""


# ---------------------------------------------------------------------------
# Environment configuration
# ---------------------------------------------------------------------------

def _csv(value):
    return [item.strip().lower() for item in (value or "").split(",") if item.strip()]


def _flag(value):
    return str(value or "").lower() in ("1", "true", "yes")


def _loopback(host):
    try:
        return ipaddress.ip_address(host).is_loopback or host == "localhost"
    except ValueError:
        return host == "localhost"


def settings_from_env(env=None):
    env = os.environ if env is None else env
    host = env.get("PYFRC2G_SMTP_HOST", "").strip()
    smtp = None
    if host:
        security = env.get("PYFRC2G_SMTP_SECURITY", "starttls").strip().lower() or "starttls"
        if security not in ("starttls", "ssl", "none"):
            raise NotifyConfigError("PYFRC2G_SMTP_SECURITY must be starttls, ssl or none.")
        if security == "none" and not _loopback(host):
            raise NotifyConfigError("PYFRC2G_SMTP_SECURITY=none is only accepted for a server on this machine "
                                    "(mail and credentials would cross the network in clear text).")
        sender = env.get("PYFRC2G_SMTP_FROM", "").strip()
        if not _EMAIL.match(sender):
            raise NotifyConfigError("PYFRC2G_SMTP_FROM must be a valid sender address.")
        try:
            port = int(env.get("PYFRC2G_SMTP_PORT", "") or (465 if security == "ssl" else 587))
        except ValueError as e:
            raise NotifyConfigError("PYFRC2G_SMTP_PORT must be a number.") from e
        smtp = {"host": host, "port": port, "security": security, "from": sender,
                "user": env.get("PYFRC2G_SMTP_USER", "").strip(), "password": env.get("PYFRC2G_SMTP_PASSWORD", "")}
        if smtp["password"] and not smtp["user"]:
            raise NotifyConfigError("PYFRC2G_SMTP_PASSWORD needs PYFRC2G_SMTP_USER.")
    base_url = env.get("PYFRC2G_BASE_URL", "").strip().rstrip("/")
    if base_url and urlparse(base_url).scheme not in ("http", "https"):
        raise NotifyConfigError("PYFRC2G_BASE_URL must be an http(s) URL.")
    return {"smtp": smtp, "base_url": base_url, "allowed_domains": _csv(env.get("PYFRC2G_MAIL_ALLOWED_DOMAINS")),
            "extra_hosts": _csv(env.get("PYFRC2G_NOTIFY_WEBHOOK_HOSTS")),
            "allow_private": _flag(env.get("PYFRC2G_NOTIFY_ALLOW_PRIVATE"))}


# ---------------------------------------------------------------------------
# Validation of what the administrator enters
# ---------------------------------------------------------------------------

def parse_recipients(text, cfg):
    """Return the list of addresses in a comma / semicolon / whitespace separated text. Raise NotifyError."""
    addresses = []
    for item in re.split(r"[,;\s]+", text or ""):
        if not item:
            continue
        if not _EMAIL.match(item):
            raise NotifyError(f"Invalid email address: {item[:60]!r}.")
        domain = item.rsplit("@", 1)[1].lower()
        allowed = cfg["allowed_domains"]
        if allowed and domain not in allowed and not any(domain.endswith("." + d) for d in allowed):
            raise NotifyError(f"{item}: domain not allowed (PYFRC2G_MAIL_ALLOWED_DOMAINS).")
        if item.lower() not in [a.lower() for a in addresses]:
            addresses.append(item)
    if not addresses:
        raise NotifyError("At least one recipient is required.")
    if len(addresses) > MAX_RECIPIENTS:
        raise NotifyError(f"At most {MAX_RECIPIENTS} recipients.")
    return addresses


def _check_host(host, allow_private):
    """Refuse a host resolving to a non-public address (SSRF)."""
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError as e:
        raise NotifyError(f"Cannot resolve {host}.") from e
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if not ip.is_global and not allow_private:
            raise NotifyError(f"{host} points to a private or local address (PYFRC2G_NOTIFY_ALLOW_PRIVATE=1 to "
                              "allow it).")


def check_url(kind, url, cfg):
    """Return the validated URL of a webhook / Slack / Teams channel. Raise NotifyError."""
    url = (url or "").strip()
    parts = urlparse(url)
    host = (parts.hostname or "").lower()
    plain_ok = cfg["allow_private"] and kind == "webhook"
    if parts.scheme != "https" and not (plain_ok and parts.scheme == "http"):
        raise NotifyError("The URL must start with https://.")
    if not host or parts.username or parts.password or len(url) > 2000:
        raise NotifyError("Invalid URL.")
    if kind == "slack" and not (host in SLACK_HOSTS or host in cfg["extra_hosts"]
                                or any(host.endswith(s) for s in cfg["extra_hosts"] if s.startswith("."))):
        raise NotifyError("A Slack webhook is on hooks.slack.com.")
    if kind == "teams" and not (any(host.endswith(s) for s in TEAMS_SUFFIXES)
                                or any(host.endswith(s) for s in cfg["extra_hosts"] if s.startswith("."))
                                or host in cfg["extra_hosts"]):
        raise NotifyError("A Teams webhook is on webhook.office.com, logic.azure.com or powerplatform.com "
                          "(other hosts: PYFRC2G_NOTIFY_WEBHOOK_HOSTS).")
    _check_host(host, cfg["allow_private"])
    return url


def describe_target(channel):
    """What the page may show of a channel target: the host or the recipients, never the URL path."""
    if channel["kind"] == "email":
        return ", ".join(json.loads(channel["target"]))
    return (urlparse(channel["target"]).hostname or "?") + "/…"


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def _keys(findings):
    return {(f.get("CHECK", ""), rule_key(f)) for f in findings}


def detect(previous, data, drift=10):
    """
    Compare an analysis with the previous one of the same firewall. Return an alert dict, or None
    when there is no previous analysis (baseline) or nothing noteworthy is new.
    `drift` is the score rise that triggers the "drift" event (0 disables it).
    """
    if previous is None:
        return None
    before = _keys(previous.get("audit") or [])
    new = [f for f in data.get("audit") or [] if (f.get("CHECK", ""), rule_key(f)) not in before]
    new.sort(key=lambda f: SEVERITY_RANK.get(f.get("SEVERITY"), 9))
    score_after = (data.get("risk") or {}).get("score")
    score_before = (previous.get("risk") or {}).get("score")
    delta = score_after - score_before if None not in (score_after, score_before) else 0
    events = []
    if any(f.get("SEVERITY") == "CRITICAL" for f in new):
        events.append("critical")
    if any(f.get("SEVERITY") == "HIGH" for f in new):
        events.append("high")
    if drift and delta >= drift:
        events.append("drift")
    if any(is_permissive(f) for f in new):
        events.append("permissive")
    if not events:
        return None
    return {"firewall": data.get("gateway", ""), "events": events, "score_before": score_before,
            "score_after": score_after, "delta": delta,
            "counts": {"critical": sum(f.get("SEVERITY") == "CRITICAL" for f in new),
                       "high": sum(f.get("SEVERITY") == "HIGH" for f in new),
                       "permissive": sum(is_permissive(f) for f in new)},
            "findings": [{"severity": f.get("SEVERITY", ""), "check": f.get("CHECK", ""), "rule": rule_key(f),
                          "detail": f.get("DETAIL", "")} for f in new[:MAX_FINDINGS]]}


def wanted(channel, alert):
    """Return the part of the alert matching the channel's events and scope, or None."""
    events = [e for e in alert["events"] if e in channel["events"]]
    if not events:
        return None
    scope = channel.get("scope")
    if scope and not (alert["firewall"] in scope.get("firewalls", [])
                      or alert.get("site") and alert["site"] in scope.get("sites", [])
                      or set(alert.get("tags") or []) & set(scope.get("tags", []))):
        return None
    return {**alert, "events": events}


# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------

def clean(text, limit=160):
    """Replace control and line-break characters, then truncate (header injection, log forging)."""
    text = _CONTROL.sub(" ", str(text or "")).strip()
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _label(code):
    return dict(EVENTS).get(code, code)


def alert_text(alert, detail, base_url=""):
    """Return (subject, text lines) of an alert; with detail=False only the counts are included."""
    name = clean(alert["firewall"], 80)
    labels = ", ".join(_label(e) for e in alert["events"])
    subject = clean(f"[PyFRC2G] {name}: {labels}", 150)
    lines = [f"Firewall: {name}", f"Events: {labels}"]
    if alert.get("score_after") is not None:
        before = "?" if alert.get("score_before") is None else alert["score_before"]
        lines.append(f"Risk score: {before} -> {alert['score_after']}")
    if alert.get("note"):
        lines.append(clean(alert["note"], 120))
    counts = alert.get("counts") or {}
    if counts:
        lines.append(f"New findings: {counts.get('critical', 0)} critical, {counts.get('high', 0)} high, "
                     f"{counts.get('permissive', 0)} permissive")
    if detail:
        for f in alert.get("findings") or []:
            rule = f" (rule {clean(f['rule'], 60)})" if f.get("rule") else ""
            lines.append(f"- {clean(f['severity'], 10)} {clean(f['check'], 60)}{rule}: {clean(f['detail'], 140)}")
    if base_url and alert["firewall"]:
        lines.append(f"{base_url}/firewalls/{alert['firewall']}")
    return subject, lines


def _escape_slack(text):
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _escape_teams(text):
    return re.sub(r"([\\`*_{}\[\]()#+!|~<>])", r"\\\1", text)


def webhook_payload(kind, subject, lines, alert=None):
    """Return the JSON body for this kind of channel (Slack, Teams adaptive card, or generic)."""
    if kind == "slack":
        return {"text": "\n".join([f"*{_escape_slack(subject)}*"] + [_escape_slack(x) for x in lines])}
    if kind == "teams":
        body = [{"type": "TextBlock", "text": _escape_teams(subject), "weight": "Bolder", "wrap": True}]
        body += [{"type": "TextBlock", "text": _escape_teams(x), "wrap": True, "spacing": "None"} for x in lines]
        return {"type": "message", "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None,
            "content": {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
                        "version": "1.4", "body": body}}]}
    return {"app": "pyfrc2g-web", "host": socket.gethostname(), "time": datetime.now().isoformat(timespec="seconds"),
            "subject": subject, "lines": lines, **({"alert": alert} if alert else {})}


# ---------------------------------------------------------------------------
# Delivery
# ---------------------------------------------------------------------------

def send_mail(cfg, recipients, subject, body, attachments=()):
    """Send an e-mail; attachments are (filename, MIME type, bytes) tuples."""
    smtp = cfg["smtp"]
    if smtp is None:
        raise NotifyError("No mail server configured (PYFRC2G_SMTP_HOST).")
    message = EmailMessage()
    message["From"] = smtp["from"]
    message["To"] = ", ".join(recipients)  # Validated addresses only: no header injection.
    message["Subject"] = clean(subject, 200)
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid(domain=smtp["from"].rsplit("@", 1)[1])
    message.set_content(body)
    for name, mime, content in attachments:
        maintype, _, subtype = mime.partition("/")
        message.add_attachment(content, maintype=maintype, subtype=subtype, filename=name)
    context = ssl.create_default_context()  # Verifies the certificate and the host name.
    if smtp["security"] == "ssl":
        client = smtplib.SMTP_SSL(smtp["host"], smtp["port"], timeout=20, context=context)
    else:
        client = smtplib.SMTP(smtp["host"], smtp["port"], timeout=20)
    with client:
        if smtp["security"] == "starttls":
            client.starttls(context=context)
        if smtp["user"]:
            client.login(smtp["user"], smtp["password"])
        client.send_message(message)


def post_webhook(cfg, channel, payload):
    """POST the payload to the channel URL (HMAC-signed for generic webhooks); no redirect is followed."""
    import requests

    # Checked again: DNS may have changed since the channel was saved.
    _check_host(urlparse(channel["target"]).hostname or "", cfg["allow_private"])
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    headers = {"Content-Type": "application/json", "User-Agent": "pyfrc2g-web"}
    if channel["kind"] == "webhook" and channel.get("secret"):
        headers["X-PyFRC2G-Signature"] = "sha256=" + hmac.new(channel["secret"].encode(), body,
                                                              hashlib.sha256).hexdigest()
    requests.post(channel["target"], data=body, headers=headers, timeout=10,
                  allow_redirects=False).raise_for_status()


def deliver(cfg, channel, job):
    """Send one job {'subject', 'lines', 'alert', 'attachments'} to one channel; raise on failure."""
    if channel["kind"] == "email":
        send_mail(cfg, json.loads(channel["target"]), job["subject"], "\n".join(job["lines"]),
                  job.get("attachments") or ())
    else:
        post_webhook(cfg, channel, webhook_payload(channel["kind"], job["subject"], job["lines"], job.get("alert")))


class Notifier:
    """Send messages from a worker thread (bounded queue, 3 attempts) so that an analysis is never slowed down."""

    def __init__(self, db, cfg, start=True, sender=None):
        self.db, self.cfg = db, cfg
        self.sender = sender or deliver
        self.queue = queue.Queue(maxsize=200)
        if start:
            threading.Thread(target=self._worker, name="pyfrc2g-notify", daemon=True).start()

    def submit(self, channel, job, what):
        try:
            self.queue.put_nowait((channel, job, what))
        except queue.Full:
            LOG.warning("notification queue full: message dropped")

    def process(self, item, pause=1.0):
        channel, job, what = item
        for attempt in range(3):
            try:
                self.sender(self.cfg, channel, job)
                self.db.add_event("system", "notification sent", f"{channel['name']}: {what}")
                return True
            except Exception as e:
                if attempt == 2:  # Log the class name only: library messages may contain the URL.
                    self.db.add_event("system", "notification failed",
                                      f"{channel['name']}: {what} ({e.__class__.__name__})")
                    LOG.warning(f"notification to {channel['name']} failed: {e.__class__.__name__}")
                else:
                    time.sleep(pause * 2 ** attempt)
        return False

    def _worker(self):
        while True:
            try:
                self.process(self.queue.get())
            except Exception:
                LOG.exception("notification worker")

    # ------------------------------------------------------------------ alerts

    def alert(self, alert, labels=None):
        """Queue an alert for every enabled channel interested in it. Return the number of channels."""
        alert = {**alert, **(labels or {})}
        sent = 0
        for channel in self.db.channels(enabled_only=True):
            part = wanted(channel, alert)
            if part is None:
                continue
            subject, lines = alert_text(part, channel["detail"] == "full", self.cfg["base_url"])
            self.submit(channel, {"subject": subject, "lines": lines,
                                  "alert": {k: part[k] for k in ("firewall", "events", "score_before", "score_after",
                                                                 "counts") if k in part}
                                  | ({"findings": part["findings"]} if channel["detail"] == "full" else {})},
                        ",".join(part["events"]))
            sent += 1
        return sent

    def failure(self, name, reason, labels=None):
        alert = {"firewall": name, "events": ["failed"], "score_before": None, "score_after": None,
                 "counts": {}, "findings": [{"severity": "", "check": "ANALYSIS FAILED", "rule": "",
                                              "detail": reason}]}
        return self.alert(alert, labels)


def check_stale(db, now=None):
    """Alert once per firewall whose last analysis is older than the threshold. Return the alerts queued.

    Only API firewalls count: a configuration file is analysed when somebody uploads it.
    """
    from pyfrc2g_web import access
    from pyfrc2g_web.metrics import timestamp

    notifier = getattr(db, "notifier", None)
    hours = int(db.settings().get("notify_stale_hours") or 0)
    if notifier is None or hours <= 0:
        return 0
    now = now or time.time()
    enabled = {f["id"] for f in db.firewalls() if f["enabled"]}
    sent = 0
    for gw in access.labelled_gateways(db):
        when = timestamp(gw.get("updated"))
        if gw["firewall_id"] not in enabled or when is None or now - when < hours * 3600:
            continue
        key = f"stale:{gw['name']}"
        if db.get_meta(key) == gw["updated"]:
            continue  # Already announced for this last analysis; a new analysis re-arms it.
        db.set_meta(key, gw["updated"])
        age = int((now - when) // 3600)
        db.add_event("system", "analysis stale", f"{gw['name']}: last analysis {gw['updated']} ({age} h)")
        alert = {"firewall": gw["name"], "events": ["stale"], "score_before": None, "score_after": gw.get("score"),
                 "counts": {}, "note": f"Last analysis: {gw['updated']} ({age} h ago)", "findings": []}
        sent += notifier.alert(alert, {"site": gw["site"], "tags": gw["tags"]})
    return sent


def check_window(db, host, data, text, labels=None, moment=None):
    """Alert when the analysis found rule changes outside the maintenance windows. Return the channels reached."""
    from pyfrc2g_web import windows

    changes = data.get("changes") or []
    if not changes or not (text or "").strip():
        return 0
    try:
        allowed = windows.parse(text)
    except windows.WindowError:
        return 0
    if windows.contains(allowed, moment or datetime.now()):
        return 0
    db.add_event("system", "change outside window", f"{host}: {len(changes)} rule change(s)")
    notifier = getattr(db, "notifier", None)
    if notifier is None:
        return 0
    findings = [{"severity": c.get("CHANGE", ""), "check": "", "rule": rule_key(c), "detail": c.get("DETAIL", "")}
                for c in changes[:MAX_FINDINGS]]
    alert = {"firewall": host, "events": ["window"], "score_before": None,
             "score_after": (data.get("risk") or {}).get("score"), "counts": {},
             "note": f"{len(changes)} rule change(s) detected outside the maintenance window", "findings": findings}
    return notifier.alert(alert, labels)


def analysis_alert(db, previous, data, host, labels=None):
    """Queue the alerts after the runner stored an analysis. Return the channel count; never raises."""
    notifier = getattr(db, "notifier", None)
    if notifier is None or previous is None:
        return 0
    try:
        alert = detect(previous, data, int(db.settings().get("notify_drift") or 0))
        return notifier.alert(alert, labels) if alert else 0
    except Exception:
        LOG.exception("notification detection")
        return 0


def test_message(notifier, channel):
    """Queue a harmless test message (no firewall data)."""
    subject = "[PyFRC2G] Test notification"
    lines = ["This is a test of the notification channel.", "If you read it, the channel works."]
    notifier.submit(channel, {"subject": subject, "lines": lines}, "test")


# ---------------------------------------------------------------------------
# Scheduled reports
# ---------------------------------------------------------------------------

_MONTH_NAMES = {n: i for i, n in enumerate(("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct",
                                              "nov", "dec"), 1)}
_DAY_NAMES = {n: i for i, n in enumerate(("sun", "mon", "tue", "wed", "thu", "fri", "sat"))}
_MACROS = {"@hourly": "0 * * * *", "@daily": "0 0 * * *", "@midnight": "0 0 * * *", "@weekly": "0 0 * * 0",
           "@monthly": "0 0 1 * *", "@yearly": "0 0 1 1 *", "@annually": "0 0 1 1 *"}
CRON_EXAMPLES = (("0 7 * * *", "Every day at 07:00"), ("0 7 * * 1", "Every Monday at 07:00"),
                 ("0 7 * * 1-5", "Weekdays at 07:00"), ("0 8 1 * *", "The 1st of each month at 08:00"),
                 ("30 6 1,15 * *", "The 1st and the 15th at 06:30"), ("0 7 */2 * *", "Every other day at 07:00"))
MIN_INTERVAL = 3600  # A report is at most hourly.


def _cron_field(text, low, high, names=None):
    """Set of the values of one cron field: lists, ranges, steps (*/5, 1-10/2) and month / day names."""
    def number(item):
        item = item.lower()
        if names and item in names:
            return names[item]
        if not (item.isascii() and item.isdigit()):
            raise NotifyError(f"Schedule: {item!r} is not a valid value.")
        return int(item)

    values = set()
    for part in text.split(","):
        part, slash, step_text = part.partition("/")
        step = number(step_text) if slash else 1
        if step < 1:
            raise NotifyError("Schedule: a step must be at least 1.")
        if part == "*":
            start, end = low, high
        elif "-" in part:
            first, last = part.split("-", 1)
            start, end = number(first), number(last)
        else:
            start = number(part)
            end = high if slash else start
        if not low <= start <= end <= high:
            raise NotifyError(f"Schedule: {part!r} is out of range ({low}-{high}).")
        values.update(range(start, end + 1, step))
    return values


@functools.lru_cache(maxsize=64)
def parse_cron(text):
    """Parse a 5-field cron expression (minute hour day-of-month month day-of-week) or an @macro.

    Returns a dict of value sets; raises NotifyError. Day of week: 0 or 7 = Sunday.
    """
    text = _MACROS.get((text or "").strip().lower(), (text or "").strip().lower())
    fields = text.split()
    if len(fields) != 5 or len(text) > 100:
        raise NotifyError("Schedule: five fields are expected (minute hour day-of-month month day-of-week), "
                          "e.g. 0 7 * * 1.")
    minute, hour, dom, month, dow = fields
    days = {d % 7 for d in _cron_field(dow, 0, 7, _DAY_NAMES)}
    return {"minutes": sorted(_cron_field(minute, 0, 59)), "hours": sorted(_cron_field(hour, 0, 23)),
            "doms": _cron_field(dom, 1, 31), "months": _cron_field(month, 1, 12, _MONTH_NAMES), "dows": days,
            # As in cron: when both day fields are restricted, a day matches if either one does.
            "dom_any": dom.startswith("*"), "dow_any": dow.startswith("*")}


def _day_matches(cron, day):
    if day.month not in cron["months"]:
        return False
    dom_ok, dow_ok = day.day in cron["doms"], day.isoweekday() % 7 in cron["dows"]
    return (dom_ok and dow_ok) if cron["dom_any"] or cron["dow_any"] else (dom_ok or dow_ok)


def last_slot(text, moment):
    """The most recent instant matching the cron expression, not after `moment` (None if none within 4 years)."""
    cron = parse_cron(text)
    for back in range(366 * 4 + 1):
        day = moment.date() - timedelta(days=back)
        if _day_matches(cron, day):
            for hour in reversed(cron["hours"]):
                for minute in reversed(cron["minutes"]):
                    slot = datetime.combine(day, dtime(hour, minute))
                    if slot <= moment:
                        return slot
    return None


def next_slot(text, moment):
    """The first instant matching the cron expression, after `moment` (None if none within 4 years)."""
    cron = parse_cron(text)
    for ahead in range(366 * 4 + 1):
        day = moment.date() + timedelta(days=ahead)
        if _day_matches(cron, day):
            for hour in cron["hours"]:
                for minute in cron["minutes"]:
                    slot = datetime.combine(day, dtime(hour, minute))
                    if slot > moment:
                        return slot
    return None


def check_cron(text, moment=None):
    """Validate a schedule entered by the administrator and return it cleaned. Raises NotifyError."""
    text = (text or "").strip()
    parse_cron(text)
    slot, gaps = next_slot(text, moment or datetime.now()), []
    for _ in range(6):
        following = slot and next_slot(text, slot)
        if not following:
            break
        gaps.append((following - slot).total_seconds())
        slot = following
    if slot is None:
        raise NotifyError("Schedule: this expression never matches a date.")
    if gaps and min(gaps) < MIN_INTERVAL:
        raise NotifyError("Schedule: a report is sent at most once an hour.")
    return text


def is_due(schedule, moment=None):
    """True when a scheduled slot has passed since the report was last sent."""
    moment = moment or datetime.now()
    if not schedule["enabled"] or not schedule.get("cron"):
        return False
    slot = last_slot(schedule["cron"], moment)
    if slot is None:
        return False
    try:
        last = datetime.strptime(schedule["last_sent"], "%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return True
    return last < slot


def describe_schedule(schedule, moment=None):
    """Next run of a schedule, e.g. '2026-11-30 07:00' (or '-' when disabled or invalid)."""
    try:
        slot = next_slot(schedule["cron"], moment or datetime.now()) if schedule["enabled"] else None
    except (NotifyError, KeyError, TypeError):
        slot = None
    return slot.strftime("%Y-%m-%d %H:%M") if slot else "-"


def _score_on(history, day):
    """Score of the last analysis made on or before `day` ('YYYY-MM-DD'), else of the oldest one."""
    earlier = [h["score"] for h in history if h["date"][:10] <= day]
    return earlier[-1] if earlier else (history[0]["score"] if history else None)


def digest_lines(db, gateways, today=None, days=7):
    """Return the lines of the summary e-mail: score changes, stale firewalls, expiring risks, rules to review."""
    from pyfrc2g_web import exceptions, review
    from pyfrc2g_web.metrics import timestamp

    today = today or date.today()
    since = (today - timedelta(days=days)).isoformat()
    scored = [gw for gw in gateways if gw.get("score") is not None]
    lines = [f"Firewalls: {len(gateways)}, average risk score "
             f"{round(sum(gw['score'] for gw in scored) / len(scored)) if scored else '-'}, "
             f"{sum(gw.get('critical') or 0 for gw in gateways)} critical finding(s)", ""]
    moves = []
    for gw in scored:
        before = _score_on(db.score_history(gw["id"], 60), since)
        if before is not None and gw["score"] != before:
            moves.append((gw["score"] - before, gw))
    worse = sorted((m for m in moves if m[0] > 0), key=lambda m: -m[0])[:10]
    better = sorted((m for m in moves if m[0] < 0), key=lambda m: m[0])[:5]
    for title, items in ((f"Risk score up over {days} days", worse), (f"Risk score down over {days} days", better)):
        if items:
            lines.append(title + ":")
            lines += [f"  {clean(gw['name'], 60)}: {gw['score']} ({delta:+d}), {gw.get('critical') or 0} critical"
                      for delta, gw in items]
            lines.append("")
    hours = int(db.settings().get("notify_stale_hours") or 0)
    if hours:
        enabled = {f["id"] for f in db.firewalls() if f["enabled"]}
        stale = [gw for gw in gateways if gw["firewall_id"] in enabled and timestamp(gw.get("updated"))
                 and time.time() - timestamp(gw["updated"]) > hours * 3600]
        if stale:
            lines.append(f"Not analysed for more than {hours} h:")
            lines += [f"  {clean(gw['name'], 60)} (last analysis {gw['updated']})" for gw in stale[:10]]
            lines.append("")
    soon = exceptions.expiring(db.exceptions(), 14, today)
    if soon:
        lines.append("Accepted risks expiring within 14 days:")
        lines += [f"  {clean(e['check_name'], 40)} on {clean(e.get('gateway') or 'all firewalls', 40)}: "
                  f"{e['expires']} ({left} day(s))" for e, left in soon[:10]]
        lines.append("")
    months = int(db.settings().get("review_months") or 0)
    if months:
        due = []
        for gw in gateways:
            analyses = db.analyses(gw["id"])
            if analyses:
                stats = review.counts(review.rows(db.analysis(analyses[0]["id"])["data"],
                                                  db.rule_notes(gw["name"]), months, today))
                if stats["never"] + stats["overdue"]:
                    due.append((gw["name"], stats["overdue"], stats["never"]))
        if due:
            lines.append(f"Rules to review (every {months} months):")
            lines += [f"  {clean(name, 60)}: {overdue} overdue, {never} never reviewed"
                      for name, overdue, never in due[:10]]
            lines.append("")
    if len(lines) <= 2:
        lines.append("Nothing to report this week.")
    return lines[:80]


def report_job(db, schedule, cfg, today=None):
    """Build the job (subject, lines, attachment) of a scheduled report: the dashboard export filtered by site / tag."""
    from pyfrc2g_web import access, exports

    gateways = access.labelled_gateways(db)
    if schedule["site"]:
        gateways = [gw for gw in gateways if gw["site"] == schedule["site"]]
    if schedule["tag"]:
        gateways = [gw for gw in gateways if schedule["tag"] in gw["tags"]]
    scope = " · ".join(p for p in (f"site {schedule['site']}" if schedule["site"] else "",
                                   f"tag {schedule['tag']}" if schedule["tag"] else "") if p) or "all firewalls"
    today = today or date.today()
    if schedule["format"] == "digest":  # Summary in the body of the e-mail, no attachment.
        lines = [f"Summary: {clean(schedule['name'], 80)} ({clean(scope, 80)})", ""] + digest_lines(db, gateways, today)
        if cfg["base_url"]:
            lines.append(cfg["base_url"])
        return {"subject": clean(f"[PyFRC2G] Summary {schedule['name']} - {today:%Y-%m-%d}", 150), "lines": lines}
    content, mime = exports.build(schedule["format"], exports.collect(db, gateways), scope)
    name = f"pyfrc2g-report-{today:%Y%m%d}.{schedule['format']}"
    lines = [f"Scheduled report: {clean(schedule['name'], 80)}", f"Scope: {clean(scope, 80)}",
             f"Firewalls: {len(gateways)}"]
    if cfg["base_url"]:
        lines.append(cfg["base_url"])
    return {"subject": clean(f"[PyFRC2G] Report {schedule['name']} - {today:%Y-%m-%d}", 150), "lines": lines,
            "attachments": [(name, mime, content)]}


def send_report(db, notifier, schedule, now_label="scheduled"):
    """Queue the report of a schedule. Return False when it could not be built."""
    channel = {"name": f"report:{schedule['name']}", "kind": "email", "target": json.dumps(schedule["recipients"])}
    try:
        job = report_job(db, schedule, notifier.cfg)
    except Exception as e:
        LOG.exception("report build")
        db.add_event("system", "report failed", f"{schedule['name']} ({e.__class__.__name__})")
        return False
    notifier.submit(channel, job, f"{now_label} report {schedule['name']}")
    return True


def run_reports(db, moment=None):
    """Queue the reports that are due (meant to be called every minute). Return their number."""
    notifier = getattr(db, "notifier", None)
    if notifier is None or notifier.cfg["smtp"] is None:
        return 0
    count = 0
    for schedule in db.schedules():
        if is_due(schedule, moment):
            db.mark_schedule_sent(schedule["id"])  # Mark first: a failing report must not be retried every minute.
            count += send_report(db, notifier, schedule)
    return count


def install(db, env=None, start=True):
    """Create the application notifier (db.notifier). Raise NotifyConfigError on a bad environment."""
    cfg = settings_from_env(env)
    db.notifier = Notifier(db, cfg, start=start)
    if cfg["smtp"]:
        LOG.info(f"mail notifications through {cfg['smtp']['host']}:{cfg['smtp']['port']} ({cfg['smtp']['security']})")
    return db.notifier
