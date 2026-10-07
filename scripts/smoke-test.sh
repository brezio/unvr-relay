#!/usr/bin/env bash
# Smoke-test a built image with a synthetic stream: no UniFi, no tunnel.
# Proves the gate admits signed playback and refuses everything else.
#
#   scripts/smoke-test.sh ghcr.io/brezio/unvr-relay:dev
set -euo pipefail

IMAGE="${1:?usage: smoke-test.sh <image>}"
NAME="unvr-relay-smoke-$$"
PORT="${SMOKE_PORT:-18089}"
SECRET="smoke$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
B="http://127.0.0.1:${PORT}"
fail=0

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker run -d --name "$NAME" -p "127.0.0.1:${PORT}:8080" \
  -e STREAM_SECRET="$SECRET" \
  -e RELAY_STREAMS='test=ffmpeg:virtual?video&size=640x480#video=h264' \
  "$IMAGE" >/dev/null

for _ in $(seq 1 30); do
  curl -fs "$B/healthz" >/dev/null 2>&1 && break
  sleep 1
done

sign() { docker exec -e STREAM_SECRET="$SECRET" "$NAME" unvr-sign "$1" "${2:-600}" "$B" | sed -n "s/^${3:-Still frame}: *//p" | sed 's/.*?//'; }
code() { curl -s -o /dev/null -m "${2:-15}" -w '%{http_code}' "$1"; }
check() {
  local what="$1" want="$2" got="$3"
  if [[ "$got" == "$want" ]]; then echo "ok    $what -> $got"; else echo "FAIL  $what -> $got (want $want)"; fail=1; fi
}

GOOD="$(sign test)"
check "healthz"                       200 "$(code "$B/healthz")"
check "signed frame.jpeg"             200 "$(code "$B/api/frame.jpeg?$GOOD" 30)"
check "signed frame is a JPEG"        image/jpeg "$(curl -s -m 30 -o /dev/null -w '%{content_type}' "$B/api/frame.jpeg?$GOOD")"
check "signed stream.m3u8"            200 "$(code "$B/api/stream.m3u8?$GOOD" 30)"
check "unsigned"                      403 "$(code "$B/api/frame.jpeg?src=test")"
check "signature moved to other src"  403 "$(code "$B/api/frame.jpeg?${GOOD/src=test/src=other}")"
check "expired"                       410 "$(code "$B/api/frame.jpeg?$(sign test -10)")"
check "non-name src"                  400 "$(code "$B/api/frame.jpeg?src=exec:id&exp=1&sig=x")"
check "go2rtc admin path"             404 "$(code "$B/api/streams")"
check "root"                          404 "$(code "$B/")"
check "websocket upgrade (signed)"    101 "$(curl -s -m 4 -o /dev/null -w '%{http_code}' -N \
  -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' \
  -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' "$B/api/ws?$GOOD" || true)"
check "runs as non-root"              10001 "$(docker exec "$NAME" id -u)"
check "go2rtc API not on 0.0.0.0"     closed "$(docker exec "$NAME" sh -c 'wget -q -T 2 -O /dev/null http://$(hostname -i):1984/api 2>/dev/null && echo open || echo closed')"

if [[ $fail -ne 0 ]]; then
  echo "--- container logs"; docker logs "$NAME" 2>&1 | tail -40
  exit 1
fi
echo "smoke test passed"
