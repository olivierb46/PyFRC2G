"""
Command line interface: arguments, settings (.env, environment, CLI overrides) and the loop
over firewalls / configuration files. The processing itself lives in pipeline.py.
"""

import argparse
import logging
import os
import sys
import traceback

# Heavy imports (requests, graphviz, reportlab, pypdf, openpyxl) are done lazily in run().
# Import name -> pip package name.
REQUIRED_PACKAGES = {"requests": "requests", "graphviz": "graphviz", "reportlab": "reportlab",
                     "pypdf": "pypdf", "openpyxl": "openpyxl", "yaml": "pyyaml", "defusedxml": "defusedxml"}

EPILOG = """
Examples:
  # Fetch rules from API (configure pyfrc2g/config.py or .env first; FIREWALLS for several)
  pyfrc2g
  pyfrc2g --api --force --verify-ssl

  # Read rules from one or several backup files (format detected automatically)
  pyfrc2g --backup config-backup.xml
  pyfrc2g --backup fw1.xml fortigate.conf iptables-save.txt --output-dir /srv/audit

  # Only some interfaces / IPv6 rules, zones view only, raster PDF
  pyfrc2g --backup config.xml --interfaces lan,opt1 --ip-version 6 --view zones --raster

  # Compliance policy, unused rules (pfctl -vvsr output)
  pyfrc2g --backup config.xml --policy policy.yml --hits pfctl-vvsr.txt

  # Compare two firewalls (e.g. CARP primary / secondary)
  pyfrc2g --compare fw1.xml fw2.xml
"""


def check_dependencies():
    """
    Verify that required dependencies are installed.

    Returns:
        tuple: (ok, error_message); error_message contains an "Install with: ..." line.
    """
    import importlib

    missing = []
    for module, package in REQUIRED_PACKAGES.items():
        try:
            importlib.import_module(module)
        except ImportError:
            missing.append(package)
    if missing:
        return False, (
            f"Missing required package(s): {', '.join(missing)}.\n"
            f"Install with: pip install -r requirements.txt   or   pip install {' '.join(missing)}"
        )
    return True, None


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

def apply_settings(args):
    """Load .env / environment variables, then CLI options, into the configuration module."""
    from pyfrc2g import config as cfg

    env_file = getattr(args, "env_file", None)
    if env_file and not os.path.isfile(env_file):
        logging.error(f".env file not found: {env_file}")
        return False
    count = cfg.load_env_file(env_file or ".env")
    if count:
        logging.info(f"Loaded {count} variable(s) from {env_file or '.env'}")
    try:
        applied = cfg.apply_environment()
    except (OSError, ValueError, ImportError) as e:
        logging.error(f"Invalid environment configuration: {e}")
        return False
    if applied:
        logging.debug(f"Configuration overridden by environment: {', '.join(applied)}")
    if getattr(args, "ca_bundle", None):
        if not os.path.isfile(args.ca_bundle):
            logging.error(f"CA bundle not found: {args.ca_bundle}")
            return False
        cfg.CA_BUNDLE = args.ca_bundle
        cfg.VERIFY_SSL = True
    if getattr(args, "verify_ssl", False):
        cfg.VERIFY_SSL = True
    if getattr(args, "unused_days", None) is not None:
        cfg.UNUSED_DAYS = args.unused_days
    if getattr(args, "policy", None):
        cfg.POLICY_FILE = args.policy
    return True


def load_exceptions_file(args):
    """Load the accepted risks file into args.exceptions. Returns False on error."""
    from pyfrc2g.analysis.exceptions import ExceptionsError, load_exceptions

    args.exceptions = None
    path = getattr(args, "exceptions_file", None)
    if not path:
        return True
    try:
        args.exceptions = load_exceptions(path)
    except (OSError, ExceptionsError) as e:
        logging.error(f"Cannot load accepted risks {path}: {e}")
        return False
    return True


def load_policies(args):
    """Load the compliance policy file into args.policies. Returns False on error."""
    from pyfrc2g import config as cfg
    from pyfrc2g.analysis.policy import PolicyError, load_policy

    args.policies = None
    if not cfg.POLICY_FILE:
        return True
    try:
        args.policies = load_policy(cfg.POLICY_FILE)
    except (OSError, PolicyError) as e:
        logging.error(f"Cannot load compliance policy {cfg.POLICY_FILE}: {e}")
        return False
    return True


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

def load_job(job, args, from_backup, gateway_name=None):
    """Load one firewall. Returns (loaded or None, exit code when loading did not happen)."""
    from pyfrc2g.config_checker import check_target
    from pyfrc2g.pipeline import load_api, load_backup_file

    if from_backup:
        return load_backup_file(job, args, gateway_name), 1
    if not getattr(args, "skip_config_check", False):
        errors = check_target(job)
        if errors:
            for msg in errors:
                logging.error(f"  - {msg}")
            logging.error("Configuration is missing or invalid: edit pyfrc2g/config.py "
                          "or the .env file (or use --backup FILE).")
            return None, 2
    return load_api(job, args, gateway_name), 1


def run(args):
    """Process every firewall (API) or configuration file. Returns the highest exit code."""
    ok, err = check_dependencies()
    if not ok:
        print(err, file=sys.stderr)
        return 1
    if not apply_settings(args) or not load_policies(args) or not load_exceptions_file(args):
        return 2

    from graphviz import ExecutableNotFound

    from pyfrc2g.config import api_targets
    from pyfrc2g.pipeline import process_firewall, run_compare

    if getattr(args, "compare", None):
        return run_compare(args)

    backups = list(getattr(args, "backup", None) or [])
    jobs = backups or api_targets()
    gateway_name = getattr(args, "gateway_name", None)
    if len(jobs) > 1:
        if gateway_name:
            logging.warning("--gateway-name ignored: several firewalls/backups are processed")
            gateway_name = None
        if getattr(args, "hits", None):
            logging.warning("--hits applies to a single firewall: use 'hits' in FIREWALLS instead")
            args.hits = None

    workers = max(1, int(getattr(args, "workers", 1) or 1))
    preloaded = {}
    if not backups and len(jobs) > 1 and workers > 1:
        # Reading the firewall APIs (network bound) in parallel; analyses and reports stay sequential.
        from pyfrc2g.utils import load_in_parallel

        logging.info(f"Reading {len(jobs)} firewall(s) with {min(workers, len(jobs))} parallel worker(s)")
        results = load_in_parallel([(j.get("name") or j.get("url") or "firewall", j) for j in jobs],
                                   lambda job: load_job(job, args, False, None), workers)
        preloaded = dict(enumerate(results))

    exit_code = 0
    for index, job in enumerate(jobs):
        label = job if backups else (job.get("name") or job.get("url") or "firewall")
        if len(jobs) > 1:
            logging.info(f"===== {label} =====")
        try:
            if index in preloaded:
                if isinstance(preloaded[index], Exception):
                    raise preloaded[index]
                loaded, failure_code = preloaded[index]
            else:
                loaded, failure_code = load_job(job, args, bool(backups), gateway_name)
            if loaded is None:
                exit_code = max(exit_code, failure_code)
                continue
            exit_code = max(exit_code, process_firewall(loaded, args, from_backup=bool(backups)))
        except ExecutableNotFound:
            logging.error("Graphviz 'dot' executable not found: install Graphviz "
                          "(apt install graphviz / dnf install graphviz / brew install graphviz)")
            return 1
        except Exception as e:
            logging.error(f"[{label}] failed: {e}")
            logging.debug(traceback.format_exc())
            exit_code = max(exit_code, 1)
    return exit_code


def parse_args(argv=None):
    """Parse command-line arguments."""
    from pyfrc2g.inputs import FORMATS

    parser = argparse.ArgumentParser(
        description="PyFRC2G - Convert firewall rules to flow diagrams, audit and reports "
                    "(pfSense, OPNsense, FortiGate, iptables, nftables, Stormshield)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG,
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--api", "-a", action="store_true",
                      help="Fetch rules from firewall API (default if no mode; configure pyfrc2g/config.py)")
    mode.add_argument("--backup", "-b", metavar="FILE", nargs="+",
                      help="Read rules from one or several configuration files (see --format)")
    mode.add_argument("--compare", metavar="FILE", nargs=2,
                      help="Compare the rules, aliases and NAT of two configuration files")
    parser.add_argument("--format", choices=FORMATS, default="auto",
                        help="Format of --backup / --compare files (default: auto-detect)")
    parser.add_argument("--gateway-name", "-g", metavar="NAME",
                        help="Gateway display name (single firewall/backup only)")
    parser.add_argument("--output-dir", "-o", metavar="DIR", default="results",
                        help="Base output directory (default: results); files go to DIR/<gateway>/")
    parser.add_argument("--force", "-f", action="store_true",
                        help="Regenerate outputs even if no rule changed since the previous run")
    parser.add_argument("--interfaces", "-i", metavar="LIST",
                        help="Comma-separated interfaces to process (e.g. lan,opt1); floating rules are kept")
    parser.add_argument("--ip-version", choices=("4", "6"),
                        help="Only rules that apply to IPv4 (4) or IPv6 (6)")
    parser.add_argument("--view", choices=("all", "rules", "zones"), default="all",
                        help="Graphs to include: rules (per-rule flows), zones (network view) or all")
    parser.add_argument("--raster", action="store_true",
                        help="Render graphs as PNG on A4 pages instead of vector PDF")
    parser.add_argument("--no-excel", action="store_true", help="Do not write the Excel workbook")
    parser.add_argument("--no-nat", action="store_true", help="Do not include NAT rules")
    parser.add_argument("--workers", type=int, default=4, metavar="N",
                        help="API mode with several firewalls: read up to N firewalls in parallel (default 4; "
                             "1 = one after the other). Analyses and reports are always sequential")
    parser.add_argument("--no-automatic-rules", action="store_true",
                        help="Leave out the rules generated by the firewall itself (OPNsense automatic rules: "
                             "default deny, anti-lockout, DHCP, bogons...), e.g. to compare API and backup")

    audit = parser.add_argument_group("audit")
    audit.add_argument("--policy", metavar="FILE",
                       help="Compliance policy file (YAML or JSON), see README")
    audit.add_argument("--exceptions", metavar="FILE", dest="exceptions_file",
                       help="Accepted risks file (YAML or JSON): justified findings left out of the audit "
                            "and of the risk score, listed apart in the reports")
    audit.add_argument("--hits", metavar="FILE",
                       help="Rule hit counters: 'pfctl -vvsr' output file, or 'api' (pfSense REST API "
                            "command prompt); OPNsense counters are read from the API automatically")
    audit.add_argument("--no-hits", action="store_true", help="Do not read rule hit counters")
    audit.add_argument("--unused-days", type=int, metavar="N",
                       help="Report rules without traffic for N days (default: UNUSED_DAYS = 30)")

    schedule = parser.add_argument_group("scheduling")
    schedule.add_argument("--every", metavar="DURATION", default=os.environ.get("PYFRC2G_SCHEDULE") or None,
                          help="Run again every DURATION (300, 30m, 6h, 1d) until stopped (env PYFRC2G_SCHEDULE)")

    settings = parser.add_argument_group("settings")
    settings.add_argument("--env-file", metavar="FILE",
                          help="Load PYFRC2G_* variables and secrets from this file (default: ./.env)")
    settings.add_argument("--verify-ssl", action="store_true",
                          help="Verify the firewall / CISO Assistant TLS certificates")
    settings.add_argument("--ca-bundle", metavar="FILE",
                          help="CA certificates (PEM) used to verify TLS certificates (implies --verify-ssl)")
    parser.add_argument("--debug", "-d", action="store_true", help="Enable debug logging")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output (same as --debug)")
    parser.add_argument("--skip-config-check", action="store_true",
                        help="Skip configuration check before running (API mode only)")
    parser.add_argument("--check-deps", action="store_true",
                        help="Check that required packages are installed, then exit (0=OK, 1=missing deps)")
    return parser.parse_args(argv)


def _preload_env_file(argv):
    """Load .env (or --env-file) before parsing: some option defaults come from PYFRC2G_* variables."""
    from pyfrc2g.config import load_env_file

    path = ".env"
    for index, arg in enumerate(argv):
        if arg == "--env-file" and index + 1 < len(argv):
            path = argv[index + 1]
        elif arg.startswith("--env-file="):
            path = arg.split("=", 1)[1]
    load_env_file(path)


def _stop_on_sigterm():
    """docker stop sends SIGTERM, ignored by a PID 1 without handler: stop like Ctrl+C instead."""
    import signal

    def handler(signum, frame):
        raise KeyboardInterrupt

    try:
        signal.signal(signal.SIGTERM, handler)
    except (ValueError, AttributeError):  # Not in the main thread / platform without SIGTERM.
        pass


def main(argv=None):
    """
    Entry point for the pyfrc2g console script.

    Args:
        argv: Optional list of arguments (default: sys.argv[1:]).

    Returns:
        int: Exit code (0 on success).
    """
    _preload_env_file(sys.argv[1:] if argv is None else argv)
    args = parse_args(argv)
    if args.check_deps:
        ok, err = check_dependencies()
        if ok:
            print(f"All required packages are installed ({', '.join(REQUIRED_PACKAGES.values())}).")
            return 0
        print(err, file=sys.stderr)
        return 1
    logging.basicConfig(
        level=logging.DEBUG if (args.debug or args.verbose) else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    _stop_on_sigterm()
    if args.every:
        return run_every(args)
    return run(args) or 0


def run_every(args):
    """Scheduled mode without portal: run, sleep DURATION, run again... until interrupted."""
    import time

    from pyfrc2g.config import parse_duration

    try:
        interval = parse_duration(args.every)
    except ValueError as e:
        logging.error(str(e))
        return 2
    try:
        while True:
            code = run(args) or 0
            logging.info(f"Run finished (exit code {code}); next run in {args.every}")
            time.sleep(interval)
    except KeyboardInterrupt:
        logging.info("Scheduled mode stopped")
        return 0
