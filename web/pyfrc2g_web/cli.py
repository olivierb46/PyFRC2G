"""
Command line of PyFRC2G-Web.

    pyfrc2g-web [--host 0.0.0.0] [--port 8080] [--data-dir DIR] [--every 6h]
    pyfrc2g-web --create-admin NAME
"""

import argparse
import logging
import os
import signal
import sys


def _preload_env_file(argv):
    """Load .env (or --env-file) before parsing: option defaults come from PYFRC2G_* variables."""
    from pyfrc2g.config import load_env_file

    path = ".env"
    for index, arg in enumerate(argv):
        if arg == "--env-file" and index + 1 < len(argv):
            path = argv[index + 1]
        elif arg.startswith("--env-file="):
            path = arg.split("=", 1)[1]
    load_env_file(path)


def parse_args(argv=None):
    from pyfrc2g_web import __version__

    parser = argparse.ArgumentParser(
        prog="pyfrc2g-web",
        description="PyFRC2G-Web - web application for the PyFRC2G firewall analysis engine",
    )
    parser.add_argument("--host", default=os.environ.get("PYFRC2G_WEB_HOST", "127.0.0.1"),
                        help="Listening address (default 127.0.0.1; 0.0.0.0 in Docker)")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PYFRC2G_WEB_PORT", "8080")),
                        help="Port (default 8080)")
    parser.add_argument("--data-dir", metavar="DIR", default=os.environ.get("PYFRC2G_DATA_DIR", "pyfrc2g-data"),
                        help="Data directory holding the encrypted database (default pyfrc2g-data)")
    parser.add_argument("--every", metavar="DURATION", default=os.environ.get("PYFRC2G_SCHEDULE") or None,
                        help="Schedule of the API analysis (30m, 6h, 1d); also editable in Settings")
    parser.add_argument("--create-admin", metavar="USER",
                        help="Create an administrator (password prompted, or PYFRC2G_ADMIN_PASSWORD), "
                             "or reset their password, then exit")
    parser.add_argument("--env-file", metavar="FILE", help="Load variables from this file (default: ./.env)")
    parser.add_argument("--debug", action="store_true", help="Debug logging")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser.parse_args(argv)


def main(argv=None):
    from pyfrc2g_web import check_engine, create_admin, serve

    error = check_engine()
    if error:
        print(error, file=sys.stderr)
        return 1
    _preload_env_file(sys.argv[1:] if argv is None else argv)
    args = parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                        datefmt="%Y-%m-%d %H:%M:%S")

    def stop(signum, frame):
        raise KeyboardInterrupt  # docker stop: SIGTERM, ignored by a PID 1 without handler.

    signal.signal(signal.SIGTERM, stop)
    if args.create_admin:
        return create_admin(args.data_dir, args.create_admin)
    return serve(args)


if __name__ == "__main__":
    sys.exit(main())
