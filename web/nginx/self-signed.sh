#!/bin/sh
# Make a self-signed certificate for a test (browsers will warn). For a real deployment put a certificate from
# your CA (or Let's Encrypt) in nginx/certs/fullchain.pem and privkey.pem instead.
#   ./nginx/self-signed.sh pyfrc2g.example.com
set -eu
name="${1:-localhost}"
dir="$(dirname "$0")/certs"
mkdir -p "$dir"
openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 365 \
    -keyout "$dir/privkey.pem" -out "$dir/fullchain.pem" \
    -subj "/CN=$name" -addext "subjectAltName=DNS:$name"
# The nginx user of the container (not the owner of the files) has to read them.
chmod 644 "$dir/fullchain.pem" "$dir/privkey.pem"
echo "Certificate for $name written in $dir (valid 365 days)."
