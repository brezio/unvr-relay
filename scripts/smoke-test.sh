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
  -e 'RELAY_STREAMS=test=ffmpeg:virtual?video&size=640x480#video=h264;withaudio=exec:ffmpeg -hide_banner -re -f lavfi -i testsrc=size=320x240:rate=10 -f lavfi -i sine=frequency=440:sample_rate=48000 -c:v libx264 -preset ultrafast -tune zerolatency -c:a aac -f rtsp {output};videoonly=rtsp://127.0.0.1:8554/withaudio#media=video' \
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
check "no-store on stream responses"  no-store "$(curl -s -m 8 -o /dev/null -D - "$B/api/frame.jpeg?$GOOD" | tr -d '\r' | sed -n 's/^[Cc]ache-[Cc]ontrol: //p')"
check "no-store on Safari redirect"   "301 no-store" "$(curl -s -m 8 -o /dev/null -D - -A 'Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15' "$B/api/stream.mp4?$GOOD" | tr -d '\r' | awk 'NR==1{c=$2} tolower($1)=="cache-control:"{v=$2} END{print c, v}')"
check "websocket upgrade (signed)"    101 "$(curl -s -m 4 -o /dev/null -w '%{http_code}' -N \
  -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' \
  -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' "$B/api/ws?$GOOD" || true)"
check "runs as non-root"              10001 "$(docker exec "$NAME" id -u)"

# RELAY_AUDIO=false (the default) relies on go2rtc's "#media=video" source
# filter. Prove the filter still drops audio, against a control that has it --
# a go2rtc upgrade that broke this would silently put coop audio back online.
#
# The stream never ends, so curl always exits 28 (timeout) after -m. Capture
# the header first and test it separately: piping curl into grep under
# pipefail reports "no" no matter what the stream contains.
has_audio() {
  local t
  t="$(curl -s -m 8 -o /dev/null -w '%{content_type}' "$B/api/stream.mp4?$(sign "$1")${2:-}" || true)"
  [[ -z "$t" ]] && { echo "no-response"; return; }
  [[ "$t" == *mp4a* ]] && echo yes || echo no
}
check "control source carries audio"  yes "$(has_audio withaudio)"
check "#media=video drops audio"      no  "$(has_audio videoonly)"
check "viewer cannot ask audio back"  no  "$(has_audio videoonly '&audio=aac&mp4=all')"
check "go2rtc API not on 0.0.0.0"     closed "$(docker exec "$NAME" sh -c 'wget -q -T 2 -O /dev/null http://$(hostname -i):1984/api 2>/dev/null && echo open || echo closed')"

if [[ $fail -ne 0 ]]; then
  echo "--- container logs"; docker logs "$NAME" 2>&1 | tail -40
  exit 1
fi
echo "smoke test passed"
