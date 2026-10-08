#!/usr/bin/env bash
# Test unvr-state (live state + Protect API proxy) against a fake console,
# inside a built image. No UniFi hardware, no tunnel.
#
#   scripts/state-test.sh ghcr.io/brezio/unvr-relay:dev
set -euo pipefail

IMAGE="${1:?usage: state-test.sh <image>}"
DIR="$(cd "$(dirname "$0")" && pwd)"
CERTS="$(mktemp -d)"
trap 'rm -rf "$CERTS"' EXIT

# Throwaway certificate for the fake console (the real one is self-signed too).
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=console.test \
  -keyout "$CERTS/key.pem" -out "$CERTS/cert.pem" >/dev/null 2>&1
# The container runs as uid 10001. mktemp -d is 0700 and owned by the runner,
# which Docker Desktop ignores but Linux enforces (CI failed exactly here).
chmod 755 "$CERTS"
chmod 644 "$CERTS"/*.pem

docker run --rm \
  -v "$DIR/state_test.py:/t/state_test.py:ro" \
  -v "$CERTS:/certs:ro" \
  --entrypoint /usr/bin/python3 \
  "$IMAGE" /t/state_test.py
