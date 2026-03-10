#!/usr/bin/env python3
"""
Compatibility launcher for PyFRC2G.
Run the installed package entry point when executed as script (e.g. python pyfrc2g.py).
"""

import sys

from pyfrc2g.main import main, check_dependencies

if __name__ == "__main__":
    argv = sys.argv[1:]
    # For any run except -h/--help, verify dependencies first and show "Install with ..." if missing.
    if argv and argv[0] not in ("-h", "--help"):
        ok, err = check_dependencies()
        if not ok:
            print(err, file=sys.stderr)
            sys.exit(1)
    sys.exit(main())
