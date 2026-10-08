#!/usr/bin/env python3
"""
unvr-state: live device state and a narrow Protect API proxy, from the LAN.

Listens on 127.0.0.1:8090 behind nginx (never directly reachable):

  /state     WebSocket for BROWSERS. Read-only. Pushes the current state of the
             allowlisted devices (RELAY_DEVICES), then every change.
  /protect/  HTTP proxy for the dashboard SERVER. Forwards a fixed set of
             Protect Integration API calls, scoped to allowlisted devices.

Upstream it talks to the console's LOCAL Protect Integration API
(UNIFI_LOCAL_HOST + UNIFI_LOCAL_API_KEY), never api.ui.com, so none of this
counts against the cloud connector's rate limit:

  - GET the allowlisted devices at start, on every reconnect, and every
    RESYNC_S seconds as a backstop for anything the stream misses.
  - Hold /v1/subscribe/devices open and apply each update as it arrives.

Observed against Protect 7.2.105 on 2026-10-08:
  - The stream carries EVERY device on the console, so it is filtered here
    and the raw stream is never forwarded.
  - Updates are PARTIAL (only the changed fields), so they are merged into the
    last full read.
  - The same update can arrive twice ~2s apart. Every message is a SET of
    state, never a flip, so duplicates are harmless.

Security:
  - /state needs ?exp=&sig= minted by the dashboard with STREAM_SECRET
    (HMAC-SHA256, domain-separated from the video links' MD5 scheme so neither
    can be turned into the other), an Origin in STATE_ORIGINS, and is closed
    when the token expires, so a revoked secret takes effect within one TTL.
  - /protect/ needs a per-request HMAC over method, path, expiry and body, and
    only allows the exact calls the dashboard makes, on allowlisted ids, with
    validated bodies. Responses are trimmed to the fields the dashboard reads.
  - The API key never leaves this process.
"""

import asyncio
import base64
import hashlib
import hmac
import json
import os
import re
import sys
import time

from aiohttp import ClientSession, ClientTimeout, Fingerprint, TCPConnector, WSMsgType, web

LISTEN = ("127.0.0.1", 8090)
RESYNC_S = 30
HEARTBEAT_S = 10
# Upstream is "live" while the stream is open and a full read succeeded this
# recently. Past it, browsers are told to stop trusting this feed.
STALE_AFTER_S = 3 * RESYNC_S
MAX_CLIENTS = 100
STATE_TOKEN_MAX_S = 3600
API_SIG_MAX_S = 60

ID_OK = re.compile(r"^[A-Za-z0-9_-]+$")
KINDS = {"relay": "relays", "light": "lights", "sensor": "sensors", "camera": "cameras"}
STATEFUL = ("relay", "light", "sensor")


def log(msg):
    print(f"unvr-relay: state: {msg}", flush=True)


def die(msg):
    print(f"unvr-relay: state: config: {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


def env(name, default=""):
    return (os.environ.get(name) or default).strip()


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def mac(secret, message):
    return b64url(hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest())


# ---------------------------------------------------------------- config


class Config:
    def __init__(self):
        self.host = env("UNIFI_LOCAL_HOST")
        self.key = env("UNIFI_LOCAL_API_KEY")
        self.secret = env("STREAM_SECRET")
        if not self.host or not self.key:
            die("UNIFI_LOCAL_HOST and UNIFI_LOCAL_API_KEY are required")
        if len(self.secret) < 32:
            die("STREAM_SECRET must be at least 32 characters")

        # RELAY_DEVICES=relay:<id>,relay:<id>,light:<id>,sensor:<id>,camera:<id>
        self.devices = {}
        for entry in [s.strip() for s in env("RELAY_DEVICES").split(",") if s.strip()]:
            kind, _, dev_id = (p.strip() for p in entry.partition(":"))
            if kind not in KINDS:
                die(f'RELAY_DEVICES entry "{entry}": kind must be one of {", ".join(KINDS)}')
            if not ID_OK.match(dev_id):
                die(f'RELAY_DEVICES entry "{entry}": bad id')
            self.devices[dev_id] = kind
        # Cameras the relay already streams may also be snapshotted.
        for entry in [s.strip() for s in env("RELAY_CAMERAS").split(",") if s.strip()]:
            cam_id = entry.partition(":")[0].strip()
            if ID_OK.match(cam_id):
                self.devices.setdefault(cam_id, "camera")
        if not any(k in STATEFUL for k in self.devices.values()):
            die("RELAY_DEVICES lists no relay, light or sensor")

        self.origins = {o.strip().rstrip("/") for o in env("STATE_ORIGINS").split(",") if o.strip()}
        if not self.origins:
            die("STATE_ORIGINS is required (the dashboard origins allowed to open /state)")

        fp = env("UNIFI_LOCAL_CERT_SHA256").replace(":", "").lower()
        if fp and not re.match(r"^[0-9a-f]{64}$", fp):
            die("UNIFI_LOCAL_CERT_SHA256 must be a SHA-256 fingerprint (64 hex digits)")
        self.fingerprint = bytes.fromhex(fp) if fp else None

    def ids(self, kind):
        return [i for i, k in self.devices.items() if k == kind]


# ---------------------------------------------------------------- shaping

# Only what the dashboard reads. Everything else stays on the LAN.
FIELDS = {
    "relay": ("id", "modelKey", "name", "state", "outputs", "inputs", "wirelessConnectionState"),
    "light": ("id", "modelKey", "name", "state", "isLightOn", "isLightForceEnabled", "lightModeSettings"),
    "sensor": ("id", "modelKey", "name", "state", "stats", "batteryStatus"),
}


def sanitize(kind, raw):
    out = {k: raw[k] for k in FIELDS[kind] if k in raw}
    if kind == "relay":
        out["outputs"] = [{"id": o.get("id"), "state": o.get("state")} for o in out.get("outputs") or []]
        out["inputs"] = [
            {"id": i.get("id"), "name": i.get("name"), "state": i.get("state")} for i in out.get("inputs") or []
        ]
        sig = (out.get("wirelessConnectionState") or {}).get("signalState") or {}
        out["wirelessConnectionState"] = {"signalState": {"signalQuality": sig.get("signalQuality")}}
    elif kind == "light":
        out["lightModeSettings"] = {"mode": (out.get("lightModeSettings") or {}).get("mode")}
    elif kind == "sensor":
        b = out.get("batteryStatus") or {}
        out["batteryStatus"] = {"percentage": b.get("percentage"), "isLow": b.get("isLow")}
    return out


def merge(base, patch):
    """Deep-merge a partial update. Lists (outputs, inputs) are replaced whole."""
    out = dict(base)
    for k, v in patch.items():
        out[k] = merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


# ---------------------------------------------------------------- state hub


class Hub:
    def __init__(self, cfg):
        self.cfg = cfg
        self.raw = {}  # id -> merged raw device
        self.present = {}  # id -> adopted on the console
        self.sent = {}  # id -> last broadcast payload, to drop duplicate updates
        self.clients = set()
        self.ws_up = False
        self.last_sync_ok = 0.0

    def live(self):
        return self.ws_up and time.time() - self.last_sync_ok < STALE_AFTER_S

    def health(self):
        return {"type": "health", "live": self.live(), "at": int(time.time() * 1000)}

    def device(self, dev_id):
        kind = self.cfg.devices[dev_id]
        body = sanitize(kind, self.raw.get(dev_id, {"id": dev_id}))
        return {"kind": kind, "id": dev_id, "present": self.present.get(dev_id, False), **body}

    def snapshot(self):
        ids = [i for i, k in self.cfg.devices.items() if k in STATEFUL]
        return {**self.health(), "type": "snapshot", "devices": [self.device(i) for i in ids]}

    async def put(self, dev_id, raw=None, patch=None, present=True):
        if raw is not None:
            self.raw[dev_id] = raw
        if patch is not None:
            self.raw[dev_id] = merge(self.raw.get(dev_id, {}), patch)
        self.present[dev_id] = present
        msg = {"type": "device", "device": self.device(dev_id)}
        if self.sent.get(dev_id) == msg:
            return
        self.sent[dev_id] = msg
        await self.broadcast(msg)

    async def broadcast(self, msg):
        if not self.clients:
            return
        data = json.dumps(msg)
        for ws in list(self.clients):
            try:
                await ws.send_str(data)
            except Exception:
                self.clients.discard(ws)


# ---------------------------------------------------------------- upstream


class Upstream:
    def __init__(self, cfg, hub):
        self.cfg, self.hub = cfg, hub
        self.base = f"https://{cfg.host}/proxy/protect/integration/v1"
        self.wss = f"wss://{cfg.host}/proxy/protect/integration/v1/subscribe/devices"
        self.session = None

    def open(self):
        """Create the HTTP session. Must run inside the event loop."""
        # The console serves a self-signed certificate. Pin it when a
        # fingerprint is configured; otherwise skip verification (LAN only).
        ssl = Fingerprint(self.cfg.fingerprint) if self.cfg.fingerprint else False
        self.session = ClientSession(
            connector=TCPConnector(ssl=ssl, limit=8),
            headers={"X-API-KEY": self.cfg.key},
            timeout=ClientTimeout(total=10),
        )
        if not self.cfg.fingerprint:
            log("console certificate NOT pinned (set UNIFI_LOCAL_CERT_SHA256 to pin it)")

    async def request(self, method, path, body=None):
        async with self.session.request(
            method, self.base + path, data=body, headers={"Content-Type": "application/json"} if body else None
        ) as res:
            return res.status, res.headers.get("Content-Type", ""), await res.read()

    async def get_json(self, path):
        status, _, body = await self.request("GET", path)
        if status != 200:
            raise RuntimeError(f"GET {path} -> {status}")
        return json.loads(body)

    async def resync(self):
        """Full read of every allowlisted device. Missing relays are reported absent."""
        relays = self.cfg.ids("relay")
        if relays:
            seen = {r["id"]: r for r in await self.get_json("/relays") if r.get("id") in relays}
            for rid in relays:
                await self.hub.put(rid, raw=seen.get(rid, {"id": rid}), present=rid in seen)
        for kind in ("light", "sensor"):
            for dev_id in self.cfg.ids(kind):
                status, _, body = await self.request("GET", f"/{KINDS[kind]}/{dev_id}")
                if status == 404:
                    await self.hub.put(dev_id, raw={"id": dev_id}, present=False)
                elif status != 200:
                    raise RuntimeError(f"GET /{KINDS[kind]}/{dev_id} -> {status}")
                else:
                    await self.hub.put(dev_id, raw=json.loads(body), present=True)
        self.hub.last_sync_ok = time.time()

    async def resync_loop(self):
        while True:
            try:
                await self.resync()
            except Exception as e:
                log(f"resync failed: {e}")
            await asyncio.sleep(RESYNC_S)

    async def stream_loop(self):
        backoff = 1
        while True:
            try:
                async with self.session.ws_connect(self.wss, heartbeat=30, timeout=ClientTimeout(total=None)) as ws:
                    self.hub.ws_up = True
                    backoff = 1
                    log("subscribed to device updates")
                    # Anything that changed while we were disconnected.
                    try:
                        await self.resync()
                    except Exception as e:
                        log(f"resync after connect failed: {e}")
                    await self.hub.broadcast(self.hub.health())
                    async for msg in ws:
                        if msg.type == WSMsgType.TEXT:
                            await self.apply(msg.data)
                        elif msg.type in (WSMsgType.ERROR, WSMsgType.CLOSED):
                            break
            except Exception as e:
                log(f"device stream error: {type(e).__name__}: {e}")
            if self.hub.ws_up:
                self.hub.ws_up = False
                await self.hub.broadcast(self.hub.health())
                log("device stream closed")
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30)

    async def apply(self, data):
        try:
            msg = json.loads(data)
        except ValueError:
            return
        item = msg.get("item") if isinstance(msg, dict) else None
        if not isinstance(item, dict):
            return
        dev_id = item.get("id")
        if self.cfg.devices.get(dev_id) not in STATEFUL:
            return  # not ours: never stored, never forwarded
        if msg.get("type") == "remove":
            await self.hub.put(dev_id, present=False)
        elif msg.get("type") in ("add", "update"):
            await self.hub.put(dev_id, patch=item, present=True)


# ---------------------------------------------------------------- /state


def check_state_token(cfg, exp, sig):
    try:
        exp_i = int(exp)
    except (TypeError, ValueError):
        return "bad token"
    now = int(time.time())
    if exp_i <= now:
        return "token expired"
    if exp_i > now + STATE_TOKEN_MAX_S:
        return "token lifetime too long"
    if not sig or not hmac.compare_digest(sig, mac(cfg.secret, f"unvr-state:v1:{exp_i}")):
        return "bad token"
    return None


async def state_handler(request):
    cfg, hub = request.app["cfg"], request.app["hub"]
    origin = (request.headers.get("Origin") or "").rstrip("/")
    if origin not in cfg.origins:
        return web.Response(status=403, text="origin not allowed\n")
    problem = check_state_token(cfg, request.query.get("exp"), request.query.get("sig"))
    if problem:
        return web.Response(status=410 if problem == "token expired" else 403, text=problem + "\n")
    if len(hub.clients) >= MAX_CLIENTS:
        return web.Response(status=503, text="too many viewers\n")

    ws = web.WebSocketResponse(heartbeat=25, max_msg_size=1024)
    await ws.prepare(request)
    await ws.send_str(json.dumps(hub.snapshot()))
    hub.clients.add(ws)

    # Close when the token lapses; the page reconnects with a fresh one.
    async def expire():
        await asyncio.sleep(max(0, int(request.query["exp"]) - time.time()))
        await ws.close(code=4001, message=b"token expired")

    expiry = asyncio.create_task(expire())
    try:
        async for _ in ws:
            pass  # read-only: anything a browser sends is ignored
    finally:
        expiry.cancel()
        hub.clients.discard(ws)
    return ws


# ---------------------------------------------------------------- /protect


def _id(kind):
    return lambda cfg, v: cfg.devices.get(v) == kind


# (method, path regex, id checks per group, body validator)
def _activate_body(b):
    return (
        isinstance(b, dict)
        and set(b) <= {"state", "pulseDuration"}
        and b.get("state") in ("on", "off")
        and (b.get("pulseDuration") is None or (isinstance(b["pulseDuration"], int) and 0 < b["pulseDuration"] <= 60000))
    )


def _light_body(b):
    return isinstance(b, dict) and set(b) == {"isLightForceEnabled"} and isinstance(b["isLightForceEnabled"], bool)


ROUTES = [
    ("GET", re.compile(r"^/meta/info$"), [], None),
    ("GET", re.compile(r"^/relays$"), [], None),
    ("GET", re.compile(r"^/relays/([A-Za-z0-9_-]+)$"), [_id("relay")], None),
    ("POST", re.compile(r"^/relays/([A-Za-z0-9_-]+)/outputs/(\d{1,2})/activate$"), [_id("relay"), None], _activate_body),
    ("GET", re.compile(r"^/lights/([A-Za-z0-9_-]+)$"), [_id("light")], None),
    ("PATCH", re.compile(r"^/lights/([A-Za-z0-9_-]+)$"), [_id("light")], _light_body),
    ("GET", re.compile(r"^/sensors/([A-Za-z0-9_-]+)$"), [_id("sensor")], None),
    ("GET", re.compile(r"^/cameras/([A-Za-z0-9_-]+)/snapshot$"), [_id("camera")], None),
]


def match_route(cfg, method, path):
    for m, rx, checks, validator in ROUTES:
        if m != method:
            continue
        hit = rx.match(path)
        if hit and all(c is None or c(cfg, g) for c, g in zip(checks, hit.groups())):
            return validator, True
    return None, False


def relay_error(status, text):
    # X-Relay-Error marks a failure of the relay itself, as opposed to the
    # console's own answer, so the dashboard knows when to fall back.
    return web.Response(status=status, text=text + "\n", headers={"X-Relay-Error": "1"})


async def protect_handler(request):
    cfg, upstream = request.app["cfg"], request.app["upstream"]
    method = request.method
    path = "/" + request.match_info["tail"]
    if request.query_string:
        return web.Response(status=400, text="query strings are not accepted\n")

    body = await request.content.read(4097)
    if len(body) > 4096:
        return web.Response(status=413, text="body too large\n")

    # Authenticate before revealing anything about the allowlist.
    exp, sig = request.headers.get("X-Relay-Exp", ""), request.headers.get("X-Relay-Sig", "")
    try:
        exp_i = int(exp)
    except ValueError:
        return web.Response(status=401, text="unauthorized\n")
    now = int(time.time())
    expected = mac(cfg.secret, f"unvr-api:v1\n{method}\n{path}\n{exp_i}\n{hashlib.sha256(body).hexdigest()}")
    if not (now - 5 <= exp_i <= now + API_SIG_MAX_S) or not hmac.compare_digest(sig, expected):
        return web.Response(status=401, text="unauthorized\n")

    validator, allowed = match_route(cfg, method, path)
    if not allowed:
        return web.Response(status=403, text="not allowed\n")
    if validator:
        try:
            parsed = json.loads(body or b"null")
        except ValueError:
            parsed = None
        if not validator(parsed):
            return web.Response(status=400, text="body not allowed\n")

    try:
        status, ctype, data = await upstream.request(method, path, body or None)
    except Exception as e:
        return relay_error(502, f"console unreachable: {type(e).__name__}")

    if ctype.startswith("application/json") and status == 200:
        data = trim_response(cfg, path, data)
    return web.Response(status=status, body=data, headers={"Content-Type": ctype or "application/octet-stream"})


def trim_response(cfg, path, data):
    try:
        doc = json.loads(data)
    except ValueError:
        return data
    if path == "/relays" and isinstance(doc, list):
        doc = [sanitize("relay", r) for r in doc if cfg.devices.get(r.get("id")) == "relay"]
    elif isinstance(doc, dict) and cfg.devices.get(doc.get("id")) in STATEFUL:
        doc = sanitize(cfg.devices[doc["id"]], doc)
    return json.dumps(doc).encode()


# ---------------------------------------------------------------- main


async def background(app):
    upstream = app["upstream"]
    hub = app["hub"]
    upstream.open()

    async def heartbeat():
        while True:
            await asyncio.sleep(HEARTBEAT_S)
            await hub.broadcast(hub.health())

    tasks = [asyncio.create_task(t) for t in (upstream.stream_loop(), upstream.resync_loop(), heartbeat())]
    yield
    for t in tasks:
        t.cancel()
    await upstream.session.close()


def main():
    cfg = Config()
    hub = Hub(cfg)
    app = web.Application(client_max_size=8192)
    app["cfg"], app["hub"] = cfg, hub
    app["upstream"] = Upstream(cfg, hub)
    app.router.add_get("/state", state_handler)
    app.router.add_route("*", "/protect/{tail:.+}", protect_handler)
    app.cleanup_ctx.append(background)
    counts = {k: len(cfg.ids(k)) for k in KINDS}
    log(f"devices: {counts}; origins: {', '.join(sorted(cfg.origins))}")
    web.run_app(app, host=LISTEN[0], port=LISTEN[1], print=None, access_log=None)


if __name__ == "__main__":
    main()
