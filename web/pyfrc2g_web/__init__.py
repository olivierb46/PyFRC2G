"""
PyFRC2G-Web: Flask web application for PyFRC2G (firewall dashboard, analyses with charts and
graphs, firewall API configuration, configuration file uploads, users).

Analyses are run by the PyFRC2G engine (package pyfrc2g); everything is stored in an SQLite
database whose sensitive content is encrypted (see crypto.py and db.py).

    export PYFRC2G_SECRET_KEY=...             # encryption key (Fernet key or passphrase)
    pyfrc2g-web --create-admin admin          # first administrator (password prompted)
    pyfrc2g-web                               # http://127.0.0.1:8080
"""

import logging
import os
import sys
from datetime import timedelta

__version__ = "1.3.0"
MIN_ENGINE_VERSION = (2, 3, 0)
ENGINE_URL = "git+https://github.com/olivierb46/PyFRC2G.git@v2.3.0#subdirectory=engine"

WEB_PACKAGES = (("flask", "flask"), ("cryptography", "cryptography"))


def check_engine():
    """Return None if a compatible PyFRC2G engine is installed, else an error message."""
    try:
        import pyfrc2g
    except ImportError:
        return ("The PyFRC2G engine is not installed: pip install ./engine (from the repository root) "
                f"or pip install \"pyfrc2g @ {ENGINE_URL}\"")
    version = tuple(int(p) for p in pyfrc2g.__version__.split(".")[:3] if p.isdigit())
    if version < MIN_ENGINE_VERSION:
        return (f"PyFRC2G {pyfrc2g.__version__} is too old: version "
                f"{'.'.join(map(str, MIN_ENGINE_VERSION))} or later is required ({ENGINE_URL})")
    return None


def engine_version():
    import pyfrc2g

    return pyfrc2g.__version__
DB_FILE = "pyfrc2g.db"


def check_web_dependencies():
    """Return None if the web packages are importable, else an install hint."""
    import importlib

    missing = []
    for module, package in WEB_PACKAGES:
        try:
            importlib.import_module(module)
        except ImportError:
            missing.append(package)
    if missing:
        return (f"Missing package(s) for the web application: {', '.join(missing)}.\n"
                f"Install with: pip install {' '.join(missing)} waitress")
    return None


def open_database(data_dir):
    from pyfrc2g_web.db import Database

    os.makedirs(data_dir, mode=0o700, exist_ok=True)
    return Database(os.path.join(data_dir, DB_FILE), data_dir)


def create_app(data_dir=None, start_workers=True):
    """Build the Flask application; start_workers=False skips the job runner, scheduler and backfill."""
    from flask import Flask
    from pyfrc2g import __version__ as engine_version
    from werkzeug.middleware.proxy_fix import ProxyFix

    from pyfrc2g_web import access, audit, charts, filters, notify, oidc, redisutil, security
    from pyfrc2g_web.admin import bp as admin_bp
    from pyfrc2g_web.api import bp as api_bp
    from pyfrc2g_web.jobs import Runner, Scheduler
    from pyfrc2g_web.routes import bp as main_bp
    from pyfrc2g_web.routes import register_error_handlers

    data_dir = os.path.abspath(data_dir or os.environ.get("PYFRC2G_DATA_DIR", "pyfrc2g-data"))
    app = Flask(__name__)
    app.db = open_database(data_dir)
    app.data_dir = data_dir
    redis_settings = redisutil.settings_from_env()  # May raise RedisConfigError.
    redis_client = redisutil.connect(redis_settings) if redis_settings else None
    app.redis = redis_client
    app.throttle = security.Throttle(redis_client)  # Shared by the instances when Redis is configured.
    audit.install(app.db)  # Forward events to syslog / webhook (PYFRC2G_AUDIT_*).
    notify.install(app.db, start=start_workers)  # Alerts and scheduled reports by e-mail (PYFRC2G_SMTP_*).
    app.runner = app.scheduler = None
    if start_workers:
        app.runner = Runner(app.db, os.path.join(data_dir, "tmp"))
        reminder_days = max(1, int(os.environ.get("PYFRC2G_RISK_REMINDER_DAYS", "14") or 14))
        app.scheduler = Scheduler(app.db, app.runner, reminder_days)

    max_upload = int(os.environ.get("PYFRC2G_WEB_MAX_UPLOAD_MB", "50"))
    app.config.update(
        SECRET_KEY=app.db.cipher.session_secret,
        SESSION_COOKIE_NAME="pyfrc2g_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("PYFRC2G_WEB_SECURE_COOKIES", "").lower() in ("1", "true", "yes"),
        PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
        MAX_SESSIONS=max(0, int(os.environ.get("PYFRC2G_MAX_SESSIONS", "0") or 0)),  # per user, 0 = no limit
        OIDC_TOKEN_IDLE_DAYS=max(1, int(os.environ.get("PYFRC2G_OIDC_TOKEN_IDLE_DAYS", "30") or 30)),
        OIDC_REVALIDATE_MINUTES=max(5, int(os.environ.get("PYFRC2G_OIDC_REVALIDATE_MINUTES", "60") or 60)),
        RISK_FOUR_EYES=os.environ.get("PYFRC2G_RISK_FOUR_EYES", "").lower() in ("1", "true", "yes"),
        RISK_REMINDER_DAYS=max(1, int(os.environ.get("PYFRC2G_RISK_REMINDER_DAYS", "14") or 14)),
        MAX_CONTENT_LENGTH=max_upload * 1024 * 1024,
    )
    if os.environ.get("PYFRC2G_WEB_PROXY", "").lower() in ("1", "true", "yes"):
        # Behind a reverse proxy: trust X-Forwarded-For / -Proto from one hop.
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    oidc_settings = oidc.settings_from_env()  # Raises OidcConfigError if incomplete.
    if oidc_settings:
        oidc.init_app(app, data_dir, oidc_settings, redis_client)  # Server-side sessions + /oidc/* routes.

    app.before_request(security.load_user)
    app.before_request(security.require_password_change)
    app.before_request(security.check_csrf)
    app.after_request(security.security_headers)
    app.jinja_env.globals.update(csrf_token=security.csrf_token, charts=charts, version=__version__,
                                 engine_version=engine_version, can=security.can,
                                 is_restricted=access.is_restricted)
    filters.register(app)
    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(api_bp)
    register_error_handlers(app)
    _bootstrap_admin(app.db)
    if start_workers:  # Compute trend figures for analyses stored by an older version.
        import threading

        threading.Thread(target=_backfill, args=(app.db,), name="pyfrc2g-backfill", daemon=True).start()
    return app


def _backfill(db):
    try:
        count = db.backfill_analysis_stats()
        if count:
            logging.info(f"Trends: figures computed for {count} stored analysis(es)")
    except Exception:
        logging.exception("Trends: backfill failed")


def _bootstrap_admin(db):
    """First administrator from PYFRC2G_ADMIN_USER / PYFRC2G_ADMIN_PASSWORD (empty database only)."""
    from pyfrc2g_web.security import hash_password, password_problem

    username = os.environ.get("PYFRC2G_ADMIN_USER", "").strip()
    password = os.environ.get("PYFRC2G_ADMIN_PASSWORD", "")
    if db.count_users() or not username:
        return
    problem = password_problem(password)
    if problem:
        logging.error(f"PYFRC2G_ADMIN_PASSWORD rejected: {problem}")
        return
    # The password sits in a file: the administrator has to choose another one at the first sign-in.
    db.create_user(username, hash_password(password), "admin", must_change=True)
    db.add_event("system", "user created", f"{username} (admin, from environment)")
    logging.info(f"Administrator {username} created from the environment")


def create_admin(data_dir, username):
    """pyfrc2g-web --create-admin NAME: create (or reset the password of) an administrator."""
    import getpass

    from pyfrc2g_web.security import hash_password, password_problem

    error = check_engine() or check_web_dependencies()
    if error:
        print(error, file=sys.stderr)
        return 1
    db = open_database(data_dir)
    password = os.environ.get("PYFRC2G_ADMIN_PASSWORD") or getpass.getpass(f"Password for {username}: ")
    if not os.environ.get("PYFRC2G_ADMIN_PASSWORD") and getpass.getpass("Confirm: ") != password:
        print("Passwords do not match.", file=sys.stderr)
        return 2
    problem = password_problem(password)
    if problem:
        print(problem, file=sys.stderr)
        return 2
    user = db.user(username=username)
    if user:
        db.update_user(user["id"], role="admin", password_hash=hash_password(password))
        db.add_event("cli", "password reset", f"{username} (admin)")
        print(f"Administrator {username} updated.")
    else:
        db.create_user(username, hash_password(password), "admin")
        db.add_event("cli", "user created", f"{username} (admin)")
        print(f"Administrator {username} created.")
    return 0


def serve(args):
    """Start the web application (blocking). Returns an exit code."""
    from pyfrc2g.cli import check_dependencies
    from pyfrc2g.config import parse_duration

    from pyfrc2g_web.audit import AuditConfigError
    from pyfrc2g_web.crypto import CryptoKeyError
    from pyfrc2g_web.notify import NotifyConfigError
    from pyfrc2g_web.oidc import OidcConfigError
    from pyfrc2g_web.redisutil import RedisConfigError

    for error in (check_dependencies()[1], check_web_dependencies()):
        if error:
            print(error, file=sys.stderr)
            return 1
    try:
        app = create_app(args.data_dir)
    except (CryptoKeyError, OidcConfigError, RedisConfigError, AuditConfigError, NotifyConfigError) as e:
        logging.error(str(e))
        return 2
    if args.every:
        try:
            parse_duration(args.every)
        except ValueError as e:
            logging.error(str(e))
            return 2
        app.db.save_settings({"schedule": args.every})
    if not app.db.count_users():
        logging.warning("No user yet: create an administrator with  pyfrc2g-web --create-admin NAME  "
                        f"--data-dir {args.data_dir}  (or PYFRC2G_ADMIN_USER / PYFRC2G_ADMIN_PASSWORD)")
    logging.info(f"PyFRC2G-Web {__version__} (engine {engine_version()}) on http://{args.host}:{args.port} "
                 f"(data: {app.data_dir})")
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        logging.info("Reachable from the network: put a TLS reverse proxy in front of it "
                     "(PYFRC2G_WEB_PROXY=1, PYFRC2G_WEB_SECURE_COOKIES=1)")
    try:
        from waitress import serve as waitress_serve
    except ImportError:
        logging.warning("waitress not installed: using the Flask development server (pip install waitress)")
        app.run(host=args.host, port=args.port, threaded=True, use_reloader=False)
        return 0
    try:
        waitress_serve(app, host=args.host, port=args.port, threads=8, ident="PyFRC2G")
    except KeyboardInterrupt:
        logging.info("Web application stopped")
    return 0
