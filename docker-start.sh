#!/bin/sh
set -e
echo "▶ Running PyFRC2G..."
python pyfrc2g.py
echo "▶ Starting nginx..."
exec nginx -g "daemon off;"
