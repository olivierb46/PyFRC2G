#!/usr/bin/env python3
"""
Compatibility launcher for PyFRC2G.
Run the package entry point when executed as script (e.g. python pyfrc2g.py).
Dependencies are checked by main() before any heavy import.
"""

import sys

from pyfrc2g.main import main

if __name__ == "__main__":
    sys.exit(main())
