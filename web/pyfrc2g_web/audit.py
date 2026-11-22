"""
Export of the audit events (sign-ins, role changes, deletions, accepted risks...) to a SIEM, as one
JSON object per event: syslog (UDP / TCP / unix socket) and / or an HTTP webhook. The event log of
the database stays the reference; an unreachable collector never blocks the application.

    PYFRC2G_AUDIT_SYSLOG          udp://host:514, tcp://host:514 or unix:///dev/log
    PYFRC2G_AUDIT_WEBHOOK         https://collector.example.com/events (POST, JSON)
    PYFRC2G_AUDIT_WEBHOOK_SECRET  optional: HMAC-SHA256 of the body in the X-PyFRC2G-Signature header
    PYFRC2G_AUDIT_WEBHOOK_TOKEN   optional: "Authorization: Bearer <token>"

JSON: {"app": "pyfrc2g-web", "host", "time", "username", "action", "detail"}
"""

import hashlib
import hmac
import json
import logging
import os
import queue
import socket
import threading
from logging.handlers import SysLogHandler
from urllib.parse import urlparse

LOG = logging.getLogger("pyfrc2g.audit")


class AuditConfigError(Exception):
    pass


def settings_from_env(env=None):
    """Return the audit export settings from the environment, or None when no target is configured."""
    env = os.environ if env is None else env
    syslog = env.get("PYFRC2G_AUDIT_SYSLOG", "").strip()
    webhook = env.get("PYFRC2G_AUDIT_WEBHOOK", "").strip()
    if not syslog and not webhook:
        return None
    if webhook and not webhook.startswith(("https://", "http://")):
        raise AuditConfigError("PYFRC2G_AUDIT_WEBHOOK must be an http(s) URL.")
    if webhook.startswith("http://") and urlparse(webhook).hostname not in ("localhost", "127.0.0.1", "::1"):
        LOG.warning("Audit webhook over plain HTTP: events are readable on the network; use https://")
    return {"syslog": syslog or None, "webhook": webhook or None,
            "secret": env.get("PYFRC2G_AUDIT_WEBHOOK_SECRET", ""), "token": env.get("PYFRC2G_AUDIT_WEBHOOK_TOKEN", "")}


def _syslog_handler(target):
    url = urlparse(target)
    if url.scheme == "unix":
        return SysLogHandler(address=url.path)
    if url.scheme in ("udp", "tcp") and url.hostname and url.port:
        kind = socket.SOCK_DGRAM if url.scheme == "udp" else socket.SOCK_STREAM
        return SysLogHandler(address=(url.hostname, url.port), socktype=kind)
    raise AuditConfigError("PYFRC2G_AUDIT_SYSLOG must look like udp://host:514, tcp://host:514 or unix:///dev/log")


def to_json(record):
    """Serialise an event as compact JSON, adding the application name and host."""
    return json.dumps({"app": "pyfrc2g-web", "host": socket.gethostname(), **record}, ensure_ascii=False,
                      separators=(",", ":"))


class Sink:
    """Callable that sends each event record; webhook posts go through a bounded queue and a worker thread."""

    def __init__(self, settings, post=None):
        self.settings = settings
        self.syslog = None
        if settings["syslog"]:
            self.syslog = logging.getLogger("pyfrc2g.audit.syslog")
            self.syslog.propagate = False
            self.syslog.setLevel(logging.INFO)
            handler = _syslog_handler(settings["syslog"])
            handler.ident = "pyfrc2g-web: "
            handler.append_nul = False
            self.syslog.addHandler(handler)
        self.queue = None
        self._post = post or self._http_post
        if settings["webhook"]:
            self.queue = queue.Queue(maxsize=1000)
            threading.Thread(target=self._worker, name="pyfrc2g-audit", daemon=True).start()

    def __call__(self, record):
        body = to_json(record)
        if self.syslog:
            self.syslog.info(body)  # Logging handlers swallow network errors (handleError).
        if self.queue is not None:
            try:
                self.queue.put_nowait(body)
            except queue.Full:
                LOG.warning("audit webhook queue full: event dropped")

    def _http_post(self, body):
        import requests

        headers = {"Content-Type": "application/json"}
        if self.settings["token"]:
            headers["Authorization"] = f"Bearer {self.settings['token']}"
        if self.settings["secret"]:
            headers["X-PyFRC2G-Signature"] = "sha256=" + hmac.new(
                self.settings["secret"].encode(), body.encode(), hashlib.sha256).hexdigest()
        requests.post(self.settings["webhook"], data=body.encode(), headers=headers, timeout=5,
                      allow_redirects=False).raise_for_status()

    def _worker(self):
        while True:
            body = self.queue.get()
            for attempt in range(3):
                try:
                    self._post(body)
                    break
                except Exception as e:
                    if attempt == 2:
                        LOG.warning(f"audit webhook failed, event dropped: {e.__class__.__name__}")
                    else:
                        threading.Event().wait(2 ** attempt)


def install(db, env=None):
    """Hook the sinks configured in the environment to the database events; return the sink, or None if unconfigured."""
    settings = settings_from_env(env)
    if settings is None:
        return None
    sink = Sink(settings)
    db.on_event = sink
    LOG.info("audit events exported to " + ", ".join(
        x for x in (settings["syslog"] and "syslog", settings["webhook"] and "webhook") if x))
    return sink
