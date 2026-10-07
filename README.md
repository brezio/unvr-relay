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

## Security

| Layer | What it does |
| --- | --- |
| nginx gate | Rejects unsigned (403), expired (410) and non-name (400) requests. Everything else is 404 |
| go2rtc | `allow_paths` restricts the API to playback endpoints. API and RTSP are on loopback. WebRTC is off |
| container | Runs as uid 10001. The example compose adds `read_only`, `cap_drop: ALL` and `no-new-privileges` |

`scripts/smoke-test.sh` checks the gate, the uid and loopback binding against a
synthetic stream. CI runs it before pushing.

## Gotchas

- **`rtsp: listen: ""` breaks go2rtc.** It disables the whole RTSP module,
  which go2rtc needs to pull sources (`streams: exec: rtsp module disabled`).
  So RTSP listens on `127.0.0.1:8554` instead.
- **No WebRTC.** WebRTC media is UDP and does not cross a Cloudflare Tunnel.
  MSE over WebSocket (about 1 s latency) and MP4 do cross it. HLS works too,
  but lags several seconds.
- **RTSPS tokens rotate** if RTSPS is disabled and re-enabled in Protect.
  Restart the container to pick up the new URLs.
- **If one process dies, the container exits.** That covers nginx, go2rtc and
  cloudflared, and lets the restart policy bring the whole relay back.

## Development

```bash
docker build -t unvr-relay:dev .
scripts/smoke-test.sh unvr-relay:dev
```
