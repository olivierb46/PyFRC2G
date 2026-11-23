"""
SQLite storage of the web application. Columns ending with "_enc" are encrypted with the
application key (see crypto.py); the others hold non-sensitive metadata (names, dates,
scores) used for listing and sorting.
"""

import contextlib
import hashlib
import json
import logging
import os
import sqlite3
import threading
import time
from datetime import datetime

from pyfrc2g_web.crypto import Cipher

SCHEMA_VERSION = 1
SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT, value_enc BLOB);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
    role TEXT NOT NULL, created TEXT, last_login TEXT);  -- roles are validated by the application
CREATE TABLE IF NOT EXISTS firewalls (
    id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, type TEXT NOT NULL, enabled INTEGER NOT NULL,
    config_enc BLOB NOT NULL, created TEXT, updated TEXT);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value_enc BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS uploads (
    id INTEGER PRIMARY KEY, created TEXT, user_id INTEGER, format TEXT, size INTEGER,
    filename_enc BLOB, content_enc BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS gateways (
    id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, kind TEXT, firewall_id INTEGER,
    upload_id INTEGER, gateway_type TEXT, updated TEXT, score INTEGER, level TEXT,
    rules INTEGER, findings INTEGER, critical INTEGER, state_enc BLOB);
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY, kind TEXT, label TEXT, status TEXT, user_id INTEGER, queued TEXT,
    started TEXT, finished TEXT, exit_code INTEGER, gateways TEXT, log_enc BLOB);
CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY, gateway_id INTEGER NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
    run_id INTEGER, created TEXT, score INTEGER, level TEXT, fingerprint TEXT, data_enc BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS artifacts (
    id INTEGER PRIMARY KEY, analysis_id INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    name TEXT NOT NULL, mime TEXT, size INTEGER, content_enc BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS artifacts_analysis ON artifacts(analysis_id, name);
CREATE INDEX IF NOT EXISTS analyses_gateway ON analyses(gateway_id, created);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY, time TEXT, username TEXT, action TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS ciso_uploads (
    id INTEGER PRIMARY KEY, analysis_id INTEGER, gateway TEXT, time TEXT, evidence_id TEXT,
    ok INTEGER, username TEXT, message_enc BLOB);
CREATE TABLE IF NOT EXISTS exceptions (
    id INTEGER PRIMARY KEY, gateway TEXT, check_name TEXT NOT NULL, rule_key TEXT, reason_enc BLOB,
    owner TEXT, expires TEXT, created TEXT, username TEXT);
CREATE INDEX IF NOT EXISTS ciso_uploads_gateway ON ciso_uploads(gateway, id);
CREATE TABLE IF NOT EXISTS user_sessions (
    token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created TEXT, last_seen TEXT, address TEXT, agent TEXT);
CREATE INDEX IF NOT EXISTS user_sessions_user ON user_sessions(user_id);
CREATE TABLE IF NOT EXISTS notification_channels (
    id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, kind TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
    target_enc BLOB NOT NULL, secret_enc BLOB, events TEXT, detail TEXT, scope TEXT, created TEXT, username TEXT);
CREATE TABLE IF NOT EXISTS report_schedules (
    id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, format TEXT, cron TEXT,
    recipients_enc BLOB NOT NULL, site TEXT, tag TEXT,
    enabled INTEGER NOT NULL DEFAULT 1, last_sent TEXT, created TEXT, username TEXT);
CREATE TABLE IF NOT EXISTS rule_notes (
    id INTEGER PRIMARY KEY, gateway TEXT NOT NULL, rule_key TEXT NOT NULL, owner TEXT, ticket TEXT,
    comment_enc BLOB, reviewed TEXT, reviewer TEXT, updated TEXT, username TEXT, UNIQUE (gateway, rule_key));
CREATE TABLE IF NOT EXISTS api_tokens (
    id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, name TEXT NOT NULL, prefix TEXT,
    token_hash TEXT UNIQUE NOT NULL, created TEXT, last_used TEXT, expires TEXT);
CREATE INDEX IF NOT EXISTS api_tokens_user ON api_tokens(user_id);
"""
# users table of the first releases: role restricted to ('admin', 'viewer') by a CHECK constraint.
USERS_V2 = ("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, "
            "password_hash TEXT NOT NULL, role TEXT NOT NULL, created TEXT, last_login TEXT)")
# Columns update_run() may write (the names are interpolated into the SQL).
RUN_COLUMNS = frozenset({"kind", "label", "status", "user_id", "queued", "started", "finished",
                         "exit_code", "gateways", "log_enc"})
# Columns added after the first release: (table, column, definition).
MIGRATIONS = (("gateways", "ciso_evidence_id", "TEXT"), ("gateways", "ciso_folder_id", "TEXT"),
              ("gateways", "options_enc", "BLOB"),
              # Firewall scope of a user: JSON {"sites": [], "tags": [], "firewalls": []}, NULL = all.
              ("users", "scope", "TEXT"),
              # Accepted risks: approval workflow (existing rows stay approved).
              ("exceptions", "status", "TEXT NOT NULL DEFAULT 'approved'"),
              ("exceptions", "approver", "TEXT"), ("exceptions", "decided", "TEXT"),
              # Figures of each analysis for the trends (filled by backfill_analysis_stats for old rows).
              ("analyses", "rules", "INTEGER"), ("analyses", "findings", "INTEGER"),
              ("analyses", "critical", "INTEGER"), ("analyses", "high", "INTEGER"),
              ("analyses", "permissive", "INTEGER"),
              # Scheduled reports: cron expression (replaces the frequency / weekday / hour of the first drafts).
              ("report_schedules", "cron", "TEXT"),
              # 1 = the user must choose a new password before anything else (first sign-in, admin reset).
              ("users", "must_change", "INTEGER NOT NULL DEFAULT 0"),
              # Two-factor authentication (see mfa.py): secret and hashed recovery codes are encrypted.
              ("users", "totp_enabled", "INTEGER NOT NULL DEFAULT 0"), ("users", "totp_secret_enc", "BLOB"),
              ("users", "totp_last", "INTEGER"), ("users", "recovery_enc", "BLOB"))

DEFAULT_SETTINGS = {
    "schedule": "",
    "retention": 30,
    # API firewalls read in parallel during one run (analyses and reports stay sequential).
    "parallel_fetch": 4,
    "wan_interfaces": ["wan"],
    "admin_ports": [22, 23, 80, 443, 161, 3389, 5900, 8080, 8443, 10443],
    "sensitive_ports": [135, 139, 445, 1433, 1521, 2049, 3306, 5432, 6379, 9200, 11211, 27017],
    "unused_days": 30,
    "verify_ssl": True,
    "policy": "",
    # Rules generated by the firewall itself (OPNsense automatic rules) kept in the analyses.
    "automatic_rules": True,
    # CISO Assistant (token encrypted like every setting, never sent back to the browser).
    "ciso_enabled": False,
    "ciso_url": "",
    "ciso_token": "",
    "ciso_folder_id": "",
    "ciso_evidence_id": "",
    "ciso_verify_ssl": True,
    "ciso_ca_pem": "",
    "ciso_auto": False,
    "ciso_observation": "",
    # CISO Assistant: folder (domain) per site, and the change report sent as a second evidence.
    "ciso_site_folders": {},
    "ciso_changes": False,
    "ciso_changes_evidence_id": "",
    # Compliance policies applied on top of the global one: [{"kind": "site"|"tag", "name", "policy"}].
    "scoped_policies": [],
    # Notifications: a risk score rise of at least this many points is a "drift" (see notify.py).
    "notify_drift": 10,
    # Frameworks added by the administrators on the Compliance page (see frameworks.py).
    "custom_frameworks": "",
    # Rules not reviewed for this many months are "overdue" in the rule review page (0 = no review).
    "review_months": 12,
    # Maintenance windows (see windows.py) applying to the firewalls without their own; empty = no control.
    "change_windows": "",
    # ... and an API firewall not analysed for this many hours raises "analysis too old" (0 = never).
    "notify_stale_hours": 48,
}


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


PERMISSIVE_CHECK = "ANY_ANY"  # Engine check: pass rule from any source to any destination.
STATS_VERSION = "2"  # Bump to recompute the stored figures of the analyses (see backfill_analysis_stats).


def is_permissive(finding):
    """True for the finding of an any -> any rule (exact check name: policy ids may contain "ANY")."""
    return (finding.get("CHECK") or "") == PERMISSIVE_CHECK


def analysis_stats(data):
    """Return (rules, findings, critical, high, permissive) of an analysis."""
    audit = data.get("audit") or []
    severities = data.get("severities") or {}
    return (len(data.get("rules") or []), len(audit), severities.get("CRITICAL", 0), severities.get("HIGH", 0),
            sum(1 for f in audit if is_permissive(f)))


class Database:
    """Data access layer; one connection is reused per thread (opening one is slow on NFS)."""

    on_event = None  # Optional callable(dict) called with each audit event (syslog / webhook, see audit.py).

    def __init__(self, path, data_dir):
        self.path = path
        self._local = threading.local()
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with self._conn() as c:
            c.executescript(SCHEMA)
            c.execute("PRAGMA journal_mode=WAL")
            users_sql = c.execute("SELECT sql FROM sqlite_master WHERE name='users'").fetchone()[0]
            if "CHECK" in users_sql:  # Rebuild a legacy users table whose CHECK forbids the operator / auditor roles.
                c.execute("ALTER TABLE users RENAME TO users_old")
                c.execute(USERS_V2)
                c.execute("INSERT INTO users (id, username, password_hash, role, created, last_login) "
                          "SELECT id, username, password_hash, role, created, last_login FROM users_old")
                c.execute("DROP TABLE users_old")
            for table, column, definition in MIGRATIONS:
                if column not in [r[1] for r in c.execute(f"PRAGMA table_info({table})")]:
                    c.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
            columns = [r[1] for r in c.execute("PRAGMA table_info(report_schedules)")]
            if "frequency" in columns:  # Schedules of version 1.2: frequency / weekday / hour become a cron expression.
                c.execute("UPDATE report_schedules SET cron = CASE frequency "
                          "WHEN 'daily' THEN '0 ' || hour || ' * * *' "
                          "WHEN 'weekly' THEN '0 ' || hour || ' * * ' || ((weekday + 1) % 7) "
                          "WHEN 'monthly' THEN '0 ' || hour || ' ' || monthday || ' * *' END "
                          "WHERE cron IS NULL AND frequency IN ('daily', 'weekly', 'monthly')")
            salt = c.execute("SELECT value FROM meta WHERE key='salt'").fetchone()
            if salt is None:
                c.execute("INSERT INTO meta (key, value) VALUES ('salt', ?)", (os.urandom(16).hex(),))
                c.execute("INSERT INTO meta (key, value) VALUES ('schema', ?)", (str(SCHEMA_VERSION),))
            salt = c.execute("SELECT value FROM meta WHERE key='salt'").fetchone()[0]
        self.cipher = Cipher.load(data_dir, bytes.fromhex(salt))
        with self._conn() as c:
            check = c.execute("SELECT value_enc FROM meta WHERE key='check'").fetchone()
            if check is None:
                c.execute("INSERT INTO meta (key, value_enc) VALUES ('check', ?)", (self.cipher.check_token(),))
            else:
                self.cipher.verify(check[0])
        self._keep_previous_tls_default()
        for name in (path, f"{path}-wal", f"{path}-shm"):  # WAL files hold clear metadata too.
            with contextlib.suppress(OSError):
                os.chmod(name, 0o600)

    def _conn(self):
        if getattr(self._local, "conn", None) is None:
            conn = sqlite3.connect(self.path, timeout=30)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            self._local.conn, self._local.depth, self._local.failed = conn, 0, False
        return _Transaction(self._local)

    # ------------------------------------------------------------------ meta / events

    def _keep_previous_tls_default(self):
        """Version 1.3 verifies TLS certificates by default. An existing installation that never saved this
        setting keeps what it had (not verified) instead of suddenly failing to reach its firewalls."""
        if self.get_meta("tls_default_checked"):
            return
        with self._conn() as c:
            existing = c.execute("SELECT COUNT(*) FROM firewalls").fetchone()[0] > 0
            stored = c.execute("SELECT 1 FROM settings WHERE key='verify_ssl'").fetchone() is not None
        if existing and not stored:
            self.save_settings({"verify_ssl": False})
            self.add_event("system", "tls default kept off",
                           "TLS verification was off before the upgrade: turn it on in Settings when possible")
        self.set_meta("tls_default_checked", "1")

    def get_meta(self, key, default=None):
        with self._conn() as c:
            row = c.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else default

    def set_meta(self, key, value):
        with self._conn() as c:
            c.execute("INSERT INTO meta (key, value) VALUES (?, ?) "
                      "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    def add_event(self, username, action, detail=""):
        record = {"time": now(), "username": username or "-", "action": action, "detail": detail}
        with self._conn() as c:
            c.execute("INSERT INTO events (time, username, action, detail) VALUES (?, ?, ?, ?)",
                      (record["time"], record["username"], action, detail))
        if self.on_event:
            try:
                self.on_event(record)
            except Exception:  # An unreachable SIEM must never break the application.
                logging.exception("audit export failed")

    def events(self, limit=300):
        with self._conn() as c:
            return [dict(r) for r in c.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))]

    # ------------------------------------------------------------------ users

    def count_users(self, role=None):
        with self._conn() as c:
            if role:
                return c.execute("SELECT COUNT(*) FROM users WHERE role=?", (role,)).fetchone()[0]
            return c.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    def user(self, user_id=None, username=None):
        with self._conn() as c:
            if user_id is not None:
                row = c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
            else:
                row = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return dict(row) if row else None

    def users(self):
        with self._conn() as c:
            return [dict(r) for r in c.execute("SELECT id, username, role, scope, created, last_login, totp_enabled "
                                               "FROM users "
                                               "ORDER BY username")]

    def create_user(self, username, password_hash, role, must_change=False):
        with self._conn() as c:
            cur = c.execute("INSERT INTO users (username, password_hash, role, created, must_change) "
                            "VALUES (?, ?, ?, ?, ?)", (username, password_hash, role, now(), int(must_change)))
            return cur.lastrowid

    def update_user(self, user_id, role=None, password_hash=None, scope=False, must_change=None):
        """scope: dict (restriction), None (all firewalls) or False (unchanged).

        A new password clears must_change unless must_change=True (password chosen by someone else).
        """
        with self._conn() as c:
            if role:
                c.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))
            if password_hash:
                c.execute("UPDATE users SET password_hash=?, must_change=? WHERE id=?",
                          (password_hash, int(bool(must_change)), user_id))
            if scope is not False:
                c.execute("UPDATE users SET scope=? WHERE id=?", (json.dumps(scope) if scope else None, user_id))

    # ------------------------------------------------------------------ two-factor authentication

    def mfa(self, user_id):
        """Return {'enabled', 'secret', 'last', 'recovery': [hashes]} of a user."""
        with self._conn() as c:
            row = c.execute("SELECT totp_enabled, totp_secret_enc, totp_last, recovery_enc FROM users WHERE id=?",
                            (user_id,)).fetchone()
        if row is None:
            return {"enabled": False, "secret": None, "last": 0, "recovery": []}
        return {"enabled": bool(row["totp_enabled"]),
                "secret": self.cipher.decrypt(row["totp_secret_enc"]).decode() if row["totp_secret_enc"] else None,
                "last": row["totp_last"] or 0,
                "recovery": self.cipher.decrypt_json(row["recovery_enc"], []) if row["recovery_enc"] else []}

    def begin_totp(self, user_id, secret):
        """Store a not yet confirmed secret (the second factor is not active until it is confirmed)."""
        with self._conn() as c:
            c.execute("UPDATE users SET totp_secret_enc=?, totp_enabled=0, totp_last=0, recovery_enc=NULL WHERE id=?",
                      (self.cipher.encrypt(secret), user_id))

    def enable_totp(self, user_id, step, recovery_hashes):
        with self._conn() as c:
            c.execute("UPDATE users SET totp_enabled=1, totp_last=?, recovery_enc=? WHERE id=?",
                      (step, self.cipher.encrypt_json(recovery_hashes), user_id))

    def set_recovery(self, user_id, recovery_hashes):
        with self._conn() as c:
            c.execute("UPDATE users SET recovery_enc=? WHERE id=?",
                      (self.cipher.encrypt_json(recovery_hashes), user_id))

    def use_totp_step(self, user_id, step):
        """Remember the last accepted time step: a code cannot be used twice. False if it was already used."""
        with self._conn() as c:
            return c.execute("UPDATE users SET totp_last=? WHERE id=? AND COALESCE(totp_last, 0) < ?",
                             (step, user_id, step)).rowcount > 0

    def disable_totp(self, user_id):
        with self._conn() as c:
            c.execute("UPDATE users SET totp_enabled=0, totp_secret_enc=NULL, totp_last=NULL, recovery_enc=NULL "
                      "WHERE id=?", (user_id,))

    def delete_user(self, user_id):
        with self._conn() as c:
            c.execute("DELETE FROM users WHERE id=?", (user_id,))
            c.execute("DELETE FROM user_sessions WHERE user_id=?", (user_id,))
            c.execute("DELETE FROM api_tokens WHERE user_id=?", (user_id,))

    # ------------------------------------------------------------------ sign-in sessions

    def add_session(self, token, user_id, address, agent, max_age, limit=0):
        """Register a session; expired ones are dropped and, with a limit, the oldest ones are revoked."""
        cutoff = datetime.fromtimestamp(time.time() - max_age).strftime("%Y-%m-%d %H:%M:%S")
        with self._conn() as c:
            c.execute("DELETE FROM user_sessions WHERE last_seen < ?", (cutoff,))
            c.execute("INSERT INTO user_sessions (token, user_id, created, last_seen, address, agent) "
                      "VALUES (?, ?, ?, ?, ?, ?)", (token, user_id, now(), now(), address, (agent or "")[:200]))
            if limit:
                c.execute("DELETE FROM user_sessions WHERE user_id=? AND token NOT IN (SELECT token FROM "
                          "user_sessions WHERE user_id=? ORDER BY created DESC, rowid DESC LIMIT ?)",
                          (user_id, user_id, limit))

    def session_alive(self, token, touch_after=60, max_age=None):
        """True if the session was not revoked and is not older than max_age seconds (absolute limit).

        last_seen is refreshed at most every touch_after seconds.
        """
        with self._conn() as c:
            row = c.execute("SELECT last_seen, created FROM user_sessions WHERE token=?", (token,)).fetchone()
            if row is None:
                return False
            try:
                too_old = max_age and time.time() - datetime.strptime(row[1], "%Y-%m-%d %H:%M:%S").timestamp() > max_age
            except (TypeError, ValueError):
                too_old = False
            if too_old:  # A cookie refreshed again and again does not live for ever.
                c.execute("DELETE FROM user_sessions WHERE token=?", (token,))
                return False
            try:
                age = time.time() - datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S").timestamp()
            except (TypeError, ValueError):
                age = touch_after
            if age >= touch_after:
                c.execute("UPDATE user_sessions SET last_seen=? WHERE token=?", (now(), token))
        return True

    @staticmethod
    def session_ref(token):
        """Public reference of a session (the token itself is a credential and is never listed)."""
        return hashlib.sha256(("session:" + str(token)).encode()).hexdigest()[:20]

    def session_created(self, token):
        with self._conn() as c:
            row = c.execute("SELECT created FROM user_sessions WHERE token=?", (token,)).fetchone()
        return row[0] if row else None

    def sessions(self, user_id=None):
        """Sessions with a `ref` (opaque identifier) and no token."""
        query = ("SELECT s.token, s.user_id, s.created, s.last_seen, s.address, s.agent, u.username "
                 "FROM user_sessions s LEFT JOIN users u ON u.id = s.user_id")
        with self._conn() as c:
            if user_id is not None:
                rows = c.execute(query + " WHERE s.user_id=? ORDER BY s.last_seen DESC", (user_id,))
            else:
                rows = c.execute(query + " ORDER BY s.last_seen DESC")
            result = [dict(r) for r in rows]
        for item in result:
            item["ref"] = self.session_ref(item.pop("token"))
        return result

    def token_of_ref(self, ref):
        """The token of a session reference, or None (only used to revoke it)."""
        with self._conn() as c:
            tokens = [r[0] for r in c.execute("SELECT token FROM user_sessions")]
        return next((t for t in tokens if self.session_ref(t) == ref), None)

    def delete_sessions(self, token=None, user_id=None, except_token=None):
        """Revoke one session (token), or every session of a user (except_token kept). Returns the count."""
        with self._conn() as c:
            if token is not None:
                cur = c.execute("DELETE FROM user_sessions WHERE token=?", (token,))
            else:
                cur = c.execute("DELETE FROM user_sessions WHERE user_id=? AND token IS NOT ?",
                                (user_id, except_token))
            return cur.rowcount

    def touch_login(self, user_id):
        with self._conn() as c:
            c.execute("UPDATE users SET last_login=? WHERE id=?", (now(), user_id))

    # ------------------------------------------------------------------ firewalls

    def firewalls(self):
        """Firewalls with their decrypted configuration."""
        with self._conn() as c:
            rows = [dict(r) for r in c.execute("SELECT * FROM firewalls ORDER BY name")]
        for row in rows:
            row["config"] = self.cipher.decrypt_json(row.pop("config_enc"), {})
        return rows

    def firewall(self, firewall_id):
        return next((f for f in self.firewalls() if f["id"] == firewall_id), None)

    def save_firewall(self, firewall_id, name, gateway_type, enabled, config):
        with self._conn() as c:
            if firewall_id is None:
                cur = c.execute("INSERT INTO firewalls (name, type, enabled, config_enc, created, updated) "
                                "VALUES (?, ?, ?, ?, ?, ?)", (name, gateway_type, int(enabled),
                                                              self.cipher.encrypt_json(config), now(), now()))
                return cur.lastrowid
            c.execute("UPDATE firewalls SET name=?, type=?, enabled=?, config_enc=?, updated=? WHERE id=?",
                      (name, gateway_type, int(enabled), self.cipher.encrypt_json(config), now(), firewall_id))
            return firewall_id

    def delete_firewall(self, firewall_id):
        with self._conn() as c:
            c.execute("DELETE FROM firewalls WHERE id=?", (firewall_id,))

    # ------------------------------------------------------------------ settings

    def settings(self):
        values = dict(DEFAULT_SETTINGS)
        with self._conn() as c:
            for row in c.execute("SELECT key, value_enc FROM settings"):
                values[row["key"]] = self.cipher.decrypt_json(row["value_enc"])
        return values

    def save_settings(self, values):
        with self._conn() as c:
            for key, value in values.items():
                c.execute("INSERT INTO settings (key, value_enc) VALUES (?, ?) "
                          "ON CONFLICT(key) DO UPDATE SET value_enc=excluded.value_enc",
                          (key, self.cipher.encrypt_json(value)))

    # ------------------------------------------------------------------ notifications

    def _channel(self, row):
        channel = dict(row)
        channel["target"] = self.cipher.decrypt(channel.pop("target_enc")).decode()
        secret = channel.pop("secret_enc")
        channel["secret"] = self.cipher.decrypt(secret).decode() if secret else ""
        channel["events"] = [e for e in (channel["events"] or "").split(",") if e]
        channel["scope"] = json.loads(channel["scope"]) if channel["scope"] else None
        return channel

    def channels(self, enabled_only=False):
        with self._conn() as c:
            rows = c.execute("SELECT * FROM notification_channels " + ("WHERE enabled=1 " if enabled_only else "")
                             + "ORDER BY name").fetchall()
        return [self._channel(r) for r in rows]

    def channel(self, channel_id):
        with self._conn() as c:
            row = c.execute("SELECT * FROM notification_channels WHERE id=?", (channel_id,)).fetchone()
        return self._channel(row) if row else None

    def add_channel(self, name, kind, target, secret, events, detail, scope, username):
        with self._conn() as c:
            return c.execute(
                "INSERT INTO notification_channels (name, kind, target_enc, secret_enc, events, detail, scope, "
                "created, username) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (name, kind, self.cipher.encrypt(target), self.cipher.encrypt(secret) if secret else None,
                 ",".join(events), detail, json.dumps(scope) if scope else None, now(), username)).lastrowid

    def set_channel_enabled(self, channel_id, enabled):
        with self._conn() as c:
            c.execute("UPDATE notification_channels SET enabled=? WHERE id=?", (int(enabled), channel_id))

    def delete_channel(self, channel_id):
        with self._conn() as c:
            c.execute("DELETE FROM notification_channels WHERE id=?", (channel_id,))

    def _schedule(self, row):
        schedule = dict(row)
        schedule["recipients"] = json.loads(self.cipher.decrypt(schedule.pop("recipients_enc")).decode())
        return schedule

    def schedules(self):
        with self._conn() as c:
            rows = c.execute("SELECT * FROM report_schedules ORDER BY name").fetchall()
        return [self._schedule(r) for r in rows]

    def schedule(self, schedule_id):
        with self._conn() as c:
            row = c.execute("SELECT * FROM report_schedules WHERE id=?", (schedule_id,)).fetchone()
        return self._schedule(row) if row else None

    def add_schedule(self, name, fmt, cron, recipients, site, tag, username):
        with self._conn() as c:  # last_sent = now: only the next slot sends, never a past one.
            return c.execute(
                "INSERT INTO report_schedules (name, format, cron, recipients_enc, site, tag, last_sent, created, "
                "username) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (name, fmt, cron, self.cipher.encrypt(json.dumps(recipients)), site, tag, now(), now(),
                 username)).lastrowid

    def set_schedule_enabled(self, schedule_id, enabled):
        with self._conn() as c:
            c.execute("UPDATE report_schedules SET enabled=? WHERE id=?", (int(enabled), schedule_id))

    def mark_schedule_sent(self, schedule_id, when=None):
        with self._conn() as c:
            c.execute("UPDATE report_schedules SET last_sent=? WHERE id=?", (when or now(), schedule_id))

    def delete_schedule(self, schedule_id):
        with self._conn() as c:
            c.execute("DELETE FROM report_schedules WHERE id=?", (schedule_id,))

    # ------------------------------------------------------------------ rule notes (owner, ticket, review)

    def rule_notes(self, gateway):
        """Return {rule_key: note} of a firewall."""
        with self._conn() as c:
            rows = c.execute("SELECT * FROM rule_notes WHERE gateway=?", (gateway,)).fetchall()
        notes = {}
        for row in rows:
            note = dict(row)
            blob = note.pop("comment_enc")
            note["comment"] = self.cipher.decrypt(blob).decode() if blob else ""
            notes[note["rule_key"]] = note
        return notes

    def save_rule_notes(self, gateway, rule_keys, username, owner=None, ticket=None, comment=None, reviewed=False):
        """Set the given fields (None = unchanged) on rules, and stamp today's date when `reviewed`."""
        today = now()[:10]
        with self._conn() as c:
            for key in rule_keys:
                c.execute("INSERT INTO rule_notes (gateway, rule_key) VALUES (?, ?) "
                          "ON CONFLICT(gateway, rule_key) DO NOTHING", (gateway, key))
                if owner is not None:
                    c.execute("UPDATE rule_notes SET owner=? WHERE gateway=? AND rule_key=?", (owner, gateway, key))
                if ticket is not None:
                    c.execute("UPDATE rule_notes SET ticket=? WHERE gateway=? AND rule_key=?", (ticket, gateway, key))
                if comment is not None:
                    c.execute("UPDATE rule_notes SET comment_enc=? WHERE gateway=? AND rule_key=?",
                              (self.cipher.encrypt(comment) if comment else None, gateway, key))
                if reviewed:
                    c.execute("UPDATE rule_notes SET reviewed=?, reviewer=? WHERE gateway=? AND rule_key=?",
                              (today, username, gateway, key))
                c.execute("UPDATE rule_notes SET updated=?, username=? WHERE gateway=? AND rule_key=?",
                          (now(), username, gateway, key))

    # ------------------------------------------------------------------ API tokens

    def add_api_token(self, user_id, name, token_hash, prefix, expires):
        with self._conn() as c:
            return c.execute("INSERT INTO api_tokens (user_id, name, prefix, token_hash, created, expires) "
                             "VALUES (?, ?, ?, ?, ?, ?)", (user_id, name, prefix, token_hash, now(), expires)).lastrowid

    def api_token(self, token_hash):
        """Return the token row (with its user) for a hash, or None."""
        with self._conn() as c:
            row = c.execute("SELECT * FROM api_tokens WHERE token_hash=?", (token_hash,)).fetchone()
        return dict(row) if row else None

    def touch_api_token(self, token_id):
        with self._conn() as c:
            c.execute("UPDATE api_tokens SET last_used=? WHERE id=?", (now(), token_id))

    def api_tokens(self, user_id=None):
        query = ("SELECT t.id, t.user_id, t.name, t.prefix, t.created, t.last_used, t.expires, u.username "
                 "FROM api_tokens t LEFT JOIN users u ON u.id = t.user_id")
        with self._conn() as c:
            rows = (c.execute(query + " WHERE t.user_id=? ORDER BY t.id", (user_id,)) if user_id is not None
                    else c.execute(query + " ORDER BY u.username, t.id")).fetchall()
        return [dict(r) for r in rows]

    def delete_user_api_tokens(self, user_id):
        """Revoke every API token of a user (after a change of credentials). Return how many."""
        with self._conn() as c:
            return c.execute("DELETE FROM api_tokens WHERE user_id=?", (user_id,)).rowcount

    def delete_api_token(self, token_id, user_id=None):
        """Delete a token (only if it belongs to user_id when given). Return True if one was deleted."""
        with self._conn() as c:
            if user_id is None:
                return c.execute("DELETE FROM api_tokens WHERE id=?", (token_id,)).rowcount > 0
            return c.execute("DELETE FROM api_tokens WHERE id=? AND user_id=?", (token_id, user_id)).rowcount > 0

    # ------------------------------------------------------------------ uploads

    def add_upload(self, user_id, filename, fmt, content):
        with self._conn() as c:
            cur = c.execute("INSERT INTO uploads (created, user_id, format, size, filename_enc, content_enc) "
                            "VALUES (?, ?, ?, ?, ?, ?)", (now(), user_id, fmt, len(content),
                                                          self.cipher.encrypt(filename), self.cipher.encrypt(content)))
            return cur.lastrowid

    def upload(self, upload_id):
        with self._conn() as c:
            row = c.execute("SELECT * FROM uploads WHERE id=?", (upload_id,)).fetchone()
        if row is None:
            return None
        row = dict(row)
        row["filename"] = self.cipher.decrypt_text(row.pop("filename_enc"))
        row["content"] = self.cipher.decrypt(row.pop("content_enc"))
        return row

    def uploads(self, limit=100):
        with self._conn() as c:
            rows = [dict(r) for r in c.execute(
                "SELECT u.id, u.created, u.format, u.size, u.filename_enc, us.username FROM uploads u "
                "LEFT JOIN users us ON us.id = u.user_id ORDER BY u.id DESC LIMIT ?", (limit,))]
        for row in rows:
            row["filename"] = self.cipher.decrypt_text(row.pop("filename_enc"))
        return rows

    # ------------------------------------------------------------------ gateways

    def gateways(self):
        with self._conn() as c:
            rows = [dict(r) for r in c.execute("SELECT id, name, kind, firewall_id, upload_id, gateway_type, "
                                               "updated, score, level, rules, findings, critical, "
                                               "ciso_evidence_id, ciso_folder_id, options_enc "
                                               "FROM gateways ORDER BY name")]
        for row in rows:
            blob = row.pop("options_enc")
            row["options"] = self.cipher.decrypt_json(blob, None) if blob else None
        return rows

    def gateway(self, name):
        with self._conn() as c:
            row = c.execute("SELECT * FROM gateways WHERE name=?", (name,)).fetchone()
        if row is None:
            return None
        row = dict(row)
        row["state"] = self.cipher.decrypt_json(row.pop("state_enc"), {})
        row["options"] = self.cipher.decrypt_json(row.pop("options_enc"), None) if row.get("options_enc") else None
        return row

    def save_gateway(self, name, kind, gateway_type, state, firewall_id=None, upload_id=None, summary=None):
        """Create or update a gateway (its state files are encrypted)."""
        summary = summary or {}
        with self._conn() as c:
            existing = c.execute("SELECT id FROM gateways WHERE name=?", (name,)).fetchone()
            values = (kind, firewall_id, upload_id, gateway_type, now(), self.cipher.encrypt_json(state))
            if existing is None:
                cur = c.execute("INSERT INTO gateways (name, kind, firewall_id, upload_id, gateway_type, updated, "
                                "state_enc) VALUES (?, ?, ?, ?, ?, ?, ?)", (name, *values))
                gateway_id = cur.lastrowid
            else:
                gateway_id = existing[0]
                c.execute("UPDATE gateways SET kind=?, firewall_id=?, upload_id=?, gateway_type=?, updated=?, "
                          "state_enc=? WHERE id=?", (*values, gateway_id))
            if summary:
                c.execute("UPDATE gateways SET score=?, level=?, rules=?, findings=?, critical=? WHERE id=?",
                          (summary.get("score"), summary.get("level"), summary.get("rules"),
                           summary.get("findings"), summary.get("critical"), gateway_id))
        return gateway_id

    def set_gateway_evidence(self, gateway_id, evidence_id, folder_id=None):
        with self._conn() as c:
            c.execute("UPDATE gateways SET ciso_evidence_id=?, ciso_folder_id=? WHERE id=?",
                      (evidence_id or None, folder_id or None, gateway_id))

    def set_gateway_options(self, gateway_id, options):
        """Own settings of a gateway analysed from a configuration file (encrypted)."""
        with self._conn() as c:
            c.execute("UPDATE gateways SET options_enc=?, ciso_evidence_id=?, ciso_folder_id=? WHERE id=?",
                      (self.cipher.encrypt_json(options), options.get("ciso_evidence_id") or None,
                       options.get("ciso_folder_id") or None, gateway_id))

    # ------------------------------------------------------------------ CISO Assistant uploads

    def add_ciso_upload(self, analysis_id, gateway, evidence_id, ok, message, username):
        with self._conn() as c:
            c.execute("INSERT INTO ciso_uploads (analysis_id, gateway, time, evidence_id, ok, username, "
                      "message_enc) VALUES (?, ?, ?, ?, ?, ?, ?)",
                      (analysis_id, gateway, now(), evidence_id, int(bool(ok)), username,
                       self.cipher.encrypt(message)))

    def ciso_uploads(self, gateway=None, limit=50):
        query = "SELECT * FROM ciso_uploads"
        params = []
        if gateway is not None:
            query += " WHERE gateway=?"
            params.append(gateway)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._conn() as c:
            rows = [dict(r) for r in c.execute(query, params)]
        for row in rows:
            row["message"] = self.cipher.decrypt_text(row.pop("message_enc"))
        return rows

    def delete_gateway(self, gateway_id):
        with self._conn() as c:
            c.execute("DELETE FROM gateways WHERE id=?", (gateway_id,))

    # ------------------------------------------------------------------ analyses / artifacts

    def add_analysis(self, gateway_id, run_id, data, artifacts):
        """Store an analysis (data dict) and its files [(name, mime, bytes)]."""
        risk = data.get("risk") or {}
        stats = analysis_stats(data)
        with self._conn() as c:
            cur = c.execute("INSERT INTO analyses (gateway_id, run_id, created, score, level, fingerprint, data_enc, "
                            "rules, findings, critical, high, permissive) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            (gateway_id, run_id, now(), risk.get("score"), risk.get("level"),
                             data.get("fingerprint"), self.cipher.encrypt_json(data), *stats))
            analysis_id = cur.lastrowid
            c.executemany("INSERT INTO artifacts (analysis_id, name, mime, size, content_enc) VALUES (?, ?, ?, ?, ?)",
                          [(analysis_id, name, mime, len(content), self.cipher.encrypt(content))
                           for name, mime, content in artifacts])
        return analysis_id

    def analyses(self, gateway_id):
        with self._conn() as c:
            return [dict(r) for r in c.execute("SELECT id, run_id, created, score, level, fingerprint FROM analyses "
                                               "WHERE gateway_id=? ORDER BY id DESC", (gateway_id,))]

    def score_history(self, gateway_id, limit=30):
        """[{"date", "score"}] of the last analyses, oldest first (clear columns, no decryption)."""
        with self._conn() as c:
            rows = c.execute("SELECT created, score FROM analyses WHERE gateway_id=? AND score IS NOT NULL "
                             "ORDER BY id DESC LIMIT ?", (gateway_id, limit)).fetchall()
        return [{"date": r["created"], "score": r["score"]} for r in reversed(rows)]

    def analysis(self, analysis_id):
        with self._conn() as c:
            row = c.execute("SELECT * FROM analyses WHERE id=?", (analysis_id,)).fetchone()
        if row is None:
            return None
        row = dict(row)
        row["data"] = self.cipher.decrypt_json(row.pop("data_enc"), {})
        return row

    def artifacts(self, analysis_id):
        with self._conn() as c:
            return [dict(r) for r in c.execute("SELECT id, name, mime, size FROM artifacts WHERE analysis_id=? "
                                               "ORDER BY name", (analysis_id,))]

    def artifact(self, analysis_id, name):
        with self._conn() as c:
            row = c.execute("SELECT name, mime, content_enc FROM artifacts WHERE analysis_id=? AND name=?",
                            (analysis_id, name)).fetchone()
        if row is None:
            return None
        return {"name": row["name"], "mime": row["mime"], "content": self.cipher.decrypt(row["content_enc"])}

    def update_analysis_data(self, analysis_id, data):
        """Replace the data of a stored analysis (accepted risks re-evaluated)."""
        risk = data.get("risk") or {}
        with self._conn() as c:
            c.execute("UPDATE analyses SET score=?, level=?, data_enc=?, rules=?, findings=?, critical=?, high=?, "
                      "permissive=? WHERE id=?",
                      (risk.get("score"), risk.get("level"), self.cipher.encrypt_json(data), *analysis_stats(data),
                       analysis_id))

    def trend(self, gateway_id, limit=120):
        """Figures of the last analyses of a firewall, oldest first (clear columns, no decryption)."""
        with self._conn() as c:
            rows = c.execute("SELECT id, created, score, rules, findings, critical, high, permissive FROM analyses "
                             "WHERE gateway_id=? ORDER BY id DESC LIMIT ?", (gateway_id, limit)).fetchall()
        return [dict(r) for r in reversed(rows)]

    def backfill_analysis_stats(self):
        """Compute the figures of the analyses stored before the trends existed, or with an older definition
        of "permissive" (all of them once, when STATS_VERSION changes). Returns the number of rows."""
        stale = self.get_meta("stats_version") != STATS_VERSION
        with self._conn() as c:
            ids = [r[0] for r in c.execute("SELECT id FROM analyses" + ("" if stale else " WHERE findings IS NULL"))]
        for analysis_id in ids:
            with self._conn() as c:
                row = c.execute("SELECT data_enc FROM analyses WHERE id=?", (analysis_id,)).fetchone()
                if row is None:
                    continue
                data = self.cipher.decrypt_json(row[0], {})
                c.execute("UPDATE analyses SET rules=?, findings=?, critical=?, high=?, permissive=? WHERE id=?",
                          (*analysis_stats(data), analysis_id))
        self.set_meta("stats_version", STATS_VERSION)
        return len(ids)

    def update_gateway_summary(self, gateway_id, summary):
        with self._conn() as c:
            c.execute("UPDATE gateways SET score=?, level=?, rules=?, findings=?, critical=? WHERE id=?",
                      (summary.get("score"), summary.get("level"), summary.get("rules"),
                       summary.get("findings"), summary.get("critical"), gateway_id))

    # ------------------------------------------------------------------ accepted risks

    def exceptions(self, status=None):
        with self._conn() as c:
            if status:
                rows = [dict(r) for r in c.execute("SELECT * FROM exceptions WHERE status=? ORDER BY id DESC",
                                                   (status,))]
            else:
                rows = [dict(r) for r in c.execute("SELECT * FROM exceptions ORDER BY id DESC")]
        for row in rows:
            row["reason"] = self.cipher.decrypt_json(row.pop("reason_enc"), "") if row.get("reason_enc") else ""
        return rows

    def add_exception(self, gateway, check, rule_key, reason, owner, expires, username, approver=None):
        """Accepted risk. With an approver it is approved at once, otherwise it waits for a decision."""
        with self._conn() as c:
            cur = c.execute("INSERT INTO exceptions (gateway, check_name, rule_key, reason_enc, owner, expires, "
                            "created, username, status, approver, decided) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            (gateway or None, check, rule_key or None, self.cipher.encrypt_json(reason),
                             owner, expires or None, now(), username, "approved" if approver else "pending",
                             approver, now() if approver else None))
            return cur.lastrowid

    def decide_exception(self, exception_id, approve, approver):
        with self._conn() as c:
            c.execute("UPDATE exceptions SET status=?, approver=?, decided=? WHERE id=? AND status='pending'",
                      ("approved" if approve else "rejected", approver, now(), exception_id))

    def delete_exception(self, exception_id):
        with self._conn() as c:
            c.execute("DELETE FROM exceptions WHERE id=?", (exception_id,))

    def prune_analyses(self, gateway_id, keep):
        """Keep the `keep` most recent analyses of a gateway (artifacts are deleted in cascade)."""
        with self._conn() as c:
            c.execute("DELETE FROM analyses WHERE gateway_id=? AND id NOT IN "
                      "(SELECT id FROM analyses WHERE gateway_id=? ORDER BY id DESC LIMIT ?)",
                      (gateway_id, gateway_id, max(1, int(keep))))

    # ------------------------------------------------------------------ runs

    def new_run(self, kind, label, user_id=None):
        with self._conn() as c:
            cur = c.execute("INSERT INTO runs (kind, label, status, user_id, queued, gateways) "
                            "VALUES (?, ?, 'queued', ?, ?, '[]')", (kind, label, user_id, now()))
            return cur.lastrowid

    def update_run(self, run_id, **fields):
        if "log" in fields:
            fields["log_enc"] = self.cipher.encrypt("\n".join(fields.pop("log")[-500:]))
        if "gateways" in fields:
            fields["gateways"] = json.dumps(fields["gateways"])
        unknown = set(fields) - RUN_COLUMNS
        if unknown:
            raise ValueError(f"Unknown run column(s): {sorted(unknown)}")
        columns = ", ".join(f"{key}=?" for key in fields)  # Whitelisted names only.
        with self._conn() as c:
            c.execute(f"UPDATE runs SET {columns} WHERE id=?", (*fields.values(), run_id))  # noqa: S608

    def _run_row(self, row, with_log=False):
        row = dict(row)
        log = row.pop("log_enc", None)
        row["gateways"] = json.loads(row.get("gateways") or "[]")
        if with_log:
            row["log"] = self.cipher.decrypt_text(log).splitlines() if log else []
        return row

    def run(self, run_id):
        with self._conn() as c:
            row = c.execute("SELECT r.*, u.username FROM runs r LEFT JOIN users u ON u.id = r.user_id "
                            "WHERE r.id=?", (run_id,)).fetchone()
        return self._run_row(row, with_log=True) if row else None

    def runs(self, limit=100, gateway=None, accept=None, scan=5000):
        """Return the latest runs, newest first, that involve `gateway` and satisfy accept(run).

        Reads by batches until `limit` runs match, looking at `scan` runs at most.
        """
        found, last_id, batch = [], None, max(limit * 3, 50)
        looked = 0
        while len(found) < limit and looked < scan:
            with self._conn() as c:
                rows = c.execute("SELECT r.*, u.username FROM runs r LEFT JOIN users u ON u.id = r.user_id "
                                 "WHERE (? IS NULL OR r.id < ?) ORDER BY r.id DESC LIMIT ?",
                                 (last_id, last_id, batch)).fetchall()
            if not rows:
                break
            looked += len(rows)
            last_id = rows[-1]["id"]
            for row in rows:
                run = self._run_row(row)
                if (not gateway or gateway in run["gateways"]) and (accept is None or accept(run)):
                    found.append(run)
                    if len(found) == limit:
                        break
        return found

    def fail_unfinished_runs(self):
        """Mark runs left 'queued' / 'running' by a stopped server as failed."""
        with self._conn() as c:
            c.execute("UPDATE runs SET status='failed', finished=? WHERE status IN ('queued', 'running')", (now(),))


class _Transaction:
    """One transaction per outermost block; the connection is dropped after an sqlite error."""

    def __init__(self, local):
        self.local = local

    def __enter__(self):
        self.local.depth += 1
        return self.local.conn

    def __exit__(self, exc_type, exc, tb):
        self.local.depth -= 1
        if exc_type is not None:
            self.local.failed = True  # an error in a nested block rolls back the whole transaction
        if self.local.depth:
            return False
        failed, self.local.failed = self.local.failed, False
        conn = self.local.conn
        broken = exc_type is not None and issubclass(exc_type, sqlite3.Error)
        try:
            if not failed:
                conn.commit()
            else:
                conn.rollback()
        except sqlite3.Error:
            broken = True
            raise
        finally:
            if broken:
                self.local.conn = None
                with contextlib.suppress(sqlite3.Error):
                    conn.close()
        return False
