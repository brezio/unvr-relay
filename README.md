# unvr-relay

Watch UniFi Protect cameras in a browser, from anywhere, behind short-lived
signed links. One container:

```
camera -> Protect RTSPS (LAN) -> go2rtc -> nginx signed-URL gate -> cloudflared (optional) -> browser
```

- **go2rtc** pulls a camera's RTSPS stream only while someone is watching,
  and serves it as MP4, HLS or MSE-over-WebSocket. Its API listens on loopback only.
- **nginx** on `:8080` is the only listener. It forwards a playback request
  only if the request carries a valid signature.
- **cloudflared** (bundled) runs when `TUNNEL_TOKEN` is set, so nothing needs
  opening on your router.
- At start-up the container asks the **Protect Integration API** for each
  camera's RTSPS URL, enabling RTSPS output on the camera if it is off.

Images: `ghcr.io/brezio/unvr-relay` for `linux/amd64` and `linux/arm64`, built
by [`.github/workflows/build.yml`](.github/workflows/build.yml) and
smoke-tested before every push.

> **Status: not production.** Not yet deployed against real cameras.

## Run

Run it on a machine on the **same LAN as the UniFi console**: the RTSPS
stream comes from the console's local address.

```bash
cp .env.example .env     # fill it in; see comments
docker compose up -d
docker compose logs -f   # lists each camera, tokens redacted
```

Test with a signed link:

```bash
docker exec unvr-relay unvr-sign <stream> 600 https://cams.example.com
```

Open the MP4 link in Chrome or Firefox, or the HLS link in Safari.

### Configuration

| Variable | Required | Meaning |
| --- | --- | --- |
| `STREAM_SECRET` | yes | Signing key shared with whatever mints links. At least 32 chars of `[A-Za-z0-9_-]` |
| `UNIFI_API_KEY` | with cameras | Site Manager API key (admin-scoped) |
| `UNIFI_HOST_ID` | with cameras | From `GET api.ui.com/v1/hosts`. Keep the `:<digits>` suffix |
| `RELAY_CAMERAS` | one of these two | `<cameraId>:<name>,...` |
| `RELAY_STREAMS` | one of these two | Extra go2rtc sources: `<name>=<source>;...` |
| `RTSPS_QUALITY` | | `high` / `medium` (default) / `low` |
| `UNIFI_ENABLE_RTSPS` | | `true` (default) turns RTSPS on in Protect if it is off |
| `RTSPS_HOST` | | Override the console address in RTSPS URLs |
| `RELAY_AUDIO` | | **Off by default.** `true` relays camera audio. Off means go2rtc pulls only the video track, so audio never leaves the console, whatever a link asks for. Applies to `RELAY_CAMERAS`; `RELAY_STREAMS` are passed verbatim |
| `TUNNEL_TOKEN` | | Run the bundled cloudflared. Public hostname service: `http://localhost:8080` |

## Signed links

```
/api/<endpoint>?src=<stream>&exp=<unix seconds>&sig=<base64url(md5("<exp><stream> <secret>"))>
```

This is nginx's `secure_link` scheme. `sig` is unpadded base64url. The
endpoints are `stream.mp4`, `stream.m3u8` (HLS), `frame.jpeg` and `ws` (MSE).

Node, for a server that mints links for its own users:

```js
import { createHash } from "node:crypto";
const exp = Math.floor(Date.now() / 1000) + 600;
const sig = createHash("md5").update(`${exp}${stream} ${process.env.STREAM_SECRET}`).digest("base64url");
const url = `https://cams.example.com/api/stream.mp4?src=${stream}&exp=${exp}&sig=${sig}`;
```

- The signature covers the stream name, so a link for one camera cannot be
  edited into another. It also cannot be edited into a go2rtc source such as
  `exec:...`, which is the real danger of exposing go2rtc: its API can create
  streams that run commands. A *validly signed* non-name `src` is refused too.
- `exp` only gates *starting* playback. A stream that is already open keeps
  going after `exp` passes.
- MD5 is what `secure_link` supports. With a 256-bit secret, the attacks that
  matter (forging a link, or recovering the key) are not practical.

## Live device state and the Protect API proxy

Optional. With `UNIFI_LOCAL_HOST` + `UNIFI_LOCAL_API_KEY` set, a fourth
process, **unvr-state** (`rootfs/usr/local/lib/unvr-relay/state.py`), talks to
the console's **local** Protect Integration API -- never api.ui.com, so none of
it counts against the cloud connector's rate limit -- and serves two routes
through the same nginx and tunnel:

| Route | For | Auth |
| --- | --- | --- |
| `GET /api/state` (WebSocket) | browsers | `?exp=&sig=` token + `Origin` in `STATE_ORIGINS` |
| `/api/protect/<path>` | the dashboard **server** | per-request HMAC headers |

**How state stays current.** It reads every device in `RELAY_DEVICES` at
start, on every reconnect and every 30 s, and holds Protect's
`/v1/subscribe/devices` stream open in between. Observed on Protect 7.2.105:
the stream carries every device on the console, updates are partial (changed
fields only), and the same update can arrive twice about 2 s apart. So
updates are filtered to the allowlist, deep-merged into the last full read,
and de-duplicated; a relay output change reaches browsers within about 2 s.

**`/api/state` protocol.** Server to browser only; anything a browser sends is
ignored.

```
{"type":"snapshot","live":true,"at":<ms>,"devices":[{kind,id,present,...},...]}
{"type":"device","device":{kind,id,present,...}}
{"type":"health","live":false,"at":<ms>}          every 10 s, and on change
```

`live` is false while the upstream stream is down or no full read has
succeeded for 90 s. A client must stop trusting the feed then, not keep
showing the last state. Devices carry only the fields a dashboard reads
(outputs, inputs, connection state, signal quality, light on/forced/mode,
sensor stats and battery); MAC, GUID and everything else stay on the LAN.

**Tokens.**

```
state:  sig = base64url(HMAC-SHA256(STREAM_SECRET, "unvr-state:v1:<exp>"))
api:    X-Relay-Exp: <exp>   X-Relay-Sig: base64url(HMAC-SHA256(STREAM_SECRET,
          "unvr-api:v1\n<METHOD>\n<path>\n<exp>\n<sha256 hex of body>"))
```

A state token may live at most 1 h, and the socket is closed with code 4001
when it expires, so the page reconnects with a fresh one and a rotated secret
takes effect within one token lifetime. An API signature is valid for 60 s
and covers the body, so it cannot be moved to another call. Both are
HMAC-SHA256 with their own prefixes, so neither can be turned into a video
link (MD5, different message) or into each other.

**What the proxy allows.** Only these calls, only on ids in `RELAY_DEVICES`:

| Method | Path | Body |
| --- | --- | --- |
| GET | `/meta/info`, `/relays`, `/relays/<id>` | |
| POST | `/relays/<id>/outputs/<n>/activate` | `{"state":"on"\|"off"[,"pulseDuration":ms]}` -- an explicit state, never a toggle |
| GET, PATCH | `/lights/<id>` | PATCH: exactly `{"isLightForceEnabled":bool}` |
| GET | `/sensors/<id>`, `/cameras/<id>/snapshot` | |

`GET /relays` is filtered to the allowlisted relays and JSON responses are
trimmed like the state feed. Query strings are refused. A failure of the relay
itself (console unreachable) is a 502 with `X-Relay-Error: 1`; the console's
own errors pass through unmarked, so a caller can tell "fall back to the
cloud" from "the console said no".

**Not covered:** the console's certificate is self-signed and not verified
unless `UNIFI_LOCAL_CERT_SHA256` pins it. On a LAN you trust that is a small
risk, but it is the API key on the wire.

## Security

| Layer | What it does |
| --- | --- |
| nginx gate | Rejects unsigned (403), expired (410) and non-name (400) requests. Everything else is 404 |
| go2rtc | `allow_paths` restricts the API to playback endpoints. API and RTSP are on loopback. WebRTC is off |
| audio | Off unless `RELAY_AUDIO=true`. The camera's audio track is never pulled (`#media=video`). CI checks the filter against a control that has audio |
| container | Runs as uid 10001. The example compose adds `read_only`, `cap_drop: ALL` and `no-new-privileges` |

`scripts/smoke-test.sh` checks the gate, the uid and loopback binding against a
synthetic stream. `scripts/state-test.sh` checks unvr-state's auth, filtering,
merging and proxy allowlist against a fake console. CI runs both before
pushing.

## Gotchas

- **`rtsp: listen: ""` breaks go2rtc.** It disables the whole RTSP module,
  which go2rtc needs to pull sources (`streams: exec: rtsp module disabled`).
  So RTSP listens on `127.0.0.1:8554` instead.
- **No WebRTC.** WebRTC media is UDP and does not cross a Cloudflare Tunnel.
  MSE over WebSocket (about 1 s latency) and MP4 do cross it. HLS works too,
  but lags several seconds.
- **RTSPS tokens rotate** if RTSPS is disabled and re-enabled in Protect.
  Restart the container to pick up the new URLs.
- **If one process dies, the container exits.** That covers nginx, go2rtc,
  cloudflared and unvr-state, and lets the restart policy bring the whole
  relay back. A bad `RELAY_DEVICES` or missing `STATE_ORIGINS` therefore stops
  video too -- deliberately: it fails at start, loudly, not silently later.
- **Two pythons in the image.** go2rtc's base image puts its own python 3.13
  first on `PATH`; Alpine's `py3-aiohttp` is installed for `/usr/bin/python3`
  only. unvr-state is started with the latter explicitly.

## Development

```bash
docker build -t unvr-relay:dev .
scripts/smoke-test.sh unvr-relay:dev
scripts/state-test.sh unvr-relay:dev
```
