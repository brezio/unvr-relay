#!/usr/bin/env python3
"""
Tests for unvr-state (rootfs/usr/local/lib/unvr-relay/state.py) against a fake
Protect console. Runs inside the image, under Alpine's python (the one with
aiohttp):

  scripts/state-test.sh unvr-relay:dev

The fake console serves the Integration API over TLS with a throwaway
certificate, plus /subscribe/devices, which the test drives by hand.
"""

import asyncio
import base64
import hashlib
import hmac
import json
import os
import ssl
import subprocess
import sys
import time

from aiohttp import ClientSession, WSMsgType, web

SECRET = "t" * 40
ORIGIN = "https://dash.test"
R1, R2, FOREIGN = "relay1aaaa", "relay2bbbb", "relayFOREIGN"
LIGHT, SENSOR, CAMERA = "light1cccc", "sensor1dddd", "cam1eeee"
STATE = "http://127.0.0.1:8090"

failures = 0


def check(what, ok, detail=""):
    global failures
    print(f"{'ok  ' if ok else 'FAIL'}  {what}{'' if ok else f'  ({detail})'}", flush=True)
    if not ok:
        failures += 1


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def mac(message):
    return b64url(hmac.new(SECRET.encode(), message.encode(), hashlib.sha256).digest())


def state_url(exp=None):
    exp = exp if exp is not None else int(time.time()) + 600
    return f"{STATE}/state?exp={exp}&sig={mac(f'unvr-state:v1:{exp}')}"


def api_headers(method, path, body=b"", exp=None):
    exp = exp if exp is not None else int(time.time()) + 30
    sig = mac(f"unvr-api:v1\n{method}\n{path}\n{exp}\n{hashlib.sha256(body).hexdigest()}")
    return {"X-Relay-Exp": str(exp), "X-Relay-Sig": sig, "Content-Type": "application/json"}


# ------------------------------------------------------------ fake console


def relay(rid, outputs=("off", "off"), state="CONNECTED"):
    return {
        "id": rid, "modelKey": "relay", "name": rid, "state": state, "mac": "SECRETMAC", "guid": "g",
        "outputs": [{"id": i, "state": s, "rebootState": "off"} for i, s in enumerate(outputs)],
        "inputs": [{"id": 0, "name": None, "state": None, "actionTrigger": "x"}],
        "wirelessConnectionState": {"signalState": {"signalQuality": 90, "signalStrength": -40}, "bridge": "b"},
    }


class Console:
    def __init__(self):
        self.relays = [relay(R1, ("on", "off")), relay(R2, ("on", "off")), relay(FOREIGN)]
        self.light = {"id": LIGHT, "modelKey": "light", "name": "Coop Light", "state": "CONNECTED",
                      "isLightOn": False, "isLightForceEnabled": False, "lightModeSettings": {"mode": "off", "x": 1},
                      "mac": "SECRETMAC"}
        self.sensor = {"id": SENSOR, "modelKey": "sensor", "name": "Coop Sensor", "state": "CONNECTED",
                       "stats": {"temperature": {"value": 17.0}}, "batteryStatus": {"percentage": 90, "isLow": False}}
        self.subscribers = set()
        self.writes = []
        self.keys = []

    async def push(self, msg):
        for ws in list(self.subscribers):
            await ws.send_str(json.dumps(msg))

    async def kick(self):
        for ws in list(self.subscribers):
            await ws.close()

    def app(self):
        base = "/proxy/protect/integration/v1"
        app = web.Application()

        async def relays(req):
            self.keys.append(req.headers.get("X-API-KEY"))
            return web.json_response(self.relays)

        async def light(req):
            if req.method == "PATCH":
                self.writes.append(("PATCH", req.path, await req.json()))
            return web.json_response(self.light)

        async def sensor(req):
            return web.json_response(self.sensor)

        async def activate(req):
            self.writes.append(("POST", req.path, await req.json()))
            return web.Response(status=204)

        async def snap(req):
            return web.Response(body=b"\xff\xd8JPEG", content_type="image/jpeg")

        async def subscribe(req):
            ws = web.WebSocketResponse()
            await ws.prepare(req)
            self.subscribers.add(ws)
            async for _ in ws:
                pass
            self.subscribers.discard(ws)
            return ws

        app.router.add_get(base + "/relays", relays)
        app.router.add_get(base + "/relays/{id}", relays)
        app.router.add_post(base + "/relays/{id}/outputs/{n}/activate", activate)
        app.router.add_route("*", base + f"/lights/{LIGHT}", light)
        app.router.add_get(base + f"/sensors/{SENSOR}", sensor)
        app.router.add_get(base + f"/cameras/{CAMERA}/snapshot", snap)
        app.router.add_get(base + "/subscribe/devices", subscribe)
        return app


# ------------------------------------------------------------ helpers


async def recv(ws, timeout=3.0):
    """Next non-health message, or None on timeout."""
    end = time.time() + timeout
    while time.time() < end:
        try:
            msg = await asyncio.wait_for(ws.receive(), end - time.time())
        except asyncio.TimeoutError:
            return None
        if msg.type != WSMsgType.TEXT:
            return msg
        data = json.loads(msg.data)
        if data.get("type") != "health":
            return data
    return None


async def wait_health(ws, live, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            msg = await asyncio.wait_for(ws.receive(), end - time.time())
        except asyncio.TimeoutError:
            return False
        if msg.type == WSMsgType.TEXT and json.loads(msg.data).get("type") in ("health", "snapshot"):
            if json.loads(msg.data).get("live") is live:
                return True
    return False


# ------------------------------------------------------------ tests


async def main():
    console = Console()
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain("/certs/cert.pem", "/certs/key.pem")
    runner = web.AppRunner(console.app())
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", 8443, ssl_context=ctx).start()

    env = dict(os.environ,
               UNIFI_LOCAL_HOST="127.0.0.1:8443", UNIFI_LOCAL_API_KEY="local-key", STREAM_SECRET=SECRET,
               STATE_ORIGINS=f"{ORIGIN},http://localhost:3501",
               RELAY_DEVICES=f"relay:{R1},relay:{R2},light:{LIGHT},sensor:{SENSOR},camera:{CAMERA}")
    proc = subprocess.Popen(["/usr/bin/python3", "/usr/local/lib/unvr-relay/state.py"], env=env)

    try:
        async with ClientSession() as http:
            for _ in range(50):
                try:
                    async with http.get(f"{STATE}/state") as r:
                        break
                except Exception:
                    await asyncio.sleep(0.2)
            await asyncio.sleep(1.5)  # first resync + subscribe

            # --- /state auth
            async def status_of(url, headers):
                async with http.get(url, headers={"Upgrade": "websocket", "Connection": "Upgrade",
                                                  "Sec-WebSocket-Version": "13", "Sec-WebSocket-Key": "dGVzdA==",
                                                  **headers}) as r:
                    return r.status

            check("state: no Origin -> 403", await status_of(state_url(), {}) == 403)
            check("state: wrong Origin -> 403", await status_of(state_url(), {"Origin": "https://evil.test"}) == 403)
            check("state: no token -> 403", await status_of(f"{STATE}/state", {"Origin": ORIGIN}) == 403)
            check("state: forged sig -> 403",
                  await status_of(f"{STATE}/state?exp={int(time.time()) + 60}&sig=AAAA", {"Origin": ORIGIN}) == 403)
            check("state: expired -> 410", await status_of(state_url(int(time.time()) - 1), {"Origin": ORIGIN}) == 410)
            check("state: lifetime > 1h -> 403",
                  await status_of(state_url(int(time.time()) + 7200), {"Origin": ORIGIN}) == 403)
            vid = int(time.time()) + 600
            video_sig = b64url(hashlib.md5(f"{vid}coop {SECRET}".encode()).digest())
            check("state: video-link signature rejected",
                  await status_of(f"{STATE}/state?exp={vid}&sig={video_sig}", {"Origin": ORIGIN}) == 403)

            # --- /state snapshot + filtering
            ws = await http.ws_connect(state_url(), headers={"Origin": ORIGIN})
            snap = await recv(ws)
            ids = sorted(d["id"] for d in snap["devices"]) if snap else []
            check("snapshot lists exactly the allowlisted stateful devices", ids == sorted([R1, R2, LIGHT, SENSOR]), ids)
            check("snapshot reports live", snap and snap.get("live") is True, snap and snap.get("live"))
            raw = json.dumps(snap)
            check("foreign relay never sent", FOREIGN not in raw)
            check("mac/guid/rebootState trimmed", "SECRETMAC" not in raw and "guid" not in raw and "rebootState" not in raw)
            r1 = next((d for d in snap["devices"] if d["id"] == R1), {})
            check("relay outputs present", r1.get("outputs") == [{"id": 0, "state": "on"}, {"id": 1, "state": "off"}], r1)

            # --- updates
            await console.push({"type": "update", "item": {"id": FOREIGN, "modelKey": "relay", "outputs": []}})
            check("foreign update not forwarded", await recv(ws, 1.0) is None)

            await console.push({"type": "update", "item": {"id": R1, "modelKey": "relay",
                                                           "outputs": [{"id": 0, "state": "off"}, {"id": 1, "state": "on"}]}})
            m = await recv(ws)
            dev = (m or {}).get("device", {})
            check("partial relay update forwarded",
                  dev.get("id") == R1 and dev.get("outputs") == [{"id": 0, "state": "off"}, {"id": 1, "state": "on"}], m)
            check("partial update keeps unchanged fields", dev.get("state") == "CONNECTED" and dev.get("name") == R1, dev)

            await console.push({"type": "update", "item": {"id": R1, "modelKey": "relay",
                                                           "outputs": [{"id": 0, "state": "off"}, {"id": 1, "state": "on"}]}})
            check("duplicate update suppressed", await recv(ws, 1.0) is None)

            await console.push({"type": "update", "item": {"id": SENSOR, "stats": {"humidity": {"value": 70}}}})
            dev = ((await recv(ws)) or {}).get("device", {})
            check("nested stats deep-merged", dev.get("stats", {}).get("temperature", {}).get("value") == 17.0
                  and dev.get("stats", {}).get("humidity", {}).get("value") == 70, dev.get("stats"))

            await console.push({"type": "remove", "item": {"id": R2, "modelKey": "relay"}})
            dev = ((await recv(ws)) or {}).get("device", {})
            check("remove -> present false", dev.get("id") == R2 and dev.get("present") is False, dev)

            ws.send_str = ws.send_str  # browsers may send; must be ignored
            await ws.send_str("please write something")
            check("browser messages ignored (socket stays open)", not ws.closed)

            # --- health on upstream drop
            await console.kick()
            check("upstream drop -> health live:false", await wait_health(ws, False))
            check("upstream back -> health live:true", await wait_health(ws, True, 8.0))
            await ws.close()

            # --- token expiry closes the socket
            ws2 = await http.ws_connect(state_url(int(time.time()) + 2), headers={"Origin": ORIGIN})
            end = time.time() + 6
            closed = None
            while time.time() < end:
                msg = await ws2.receive(timeout=6)
                if msg.type in (WSMsgType.CLOSE, WSMsgType.CLOSED, WSMsgType.CLOSING):
                    closed = ws2.close_code
                    break
            check("socket closed at token expiry with 4001", closed == 4001, closed)

            # --- /protect
            async def api(method, path, body=b"", headers=None, signed=True):
                h = api_headers(method, path, body) if signed else {}
                h.update(headers or {})
                async with http.request(method, f"{STATE}/protect{path}", data=body or None, headers=h) as r:
                    return r.status, r.headers.get("X-Relay-Error"), await r.read()

            st, _, _ = await api("GET", "/relays", signed=False)
            check("api: unsigned -> 401", st == 401, st)
            st, _, _ = await api("GET", "/relays", headers={"X-Relay-Sig": "AAAA"})
            check("api: bad sig -> 401", st == 401, st)
            st, _, _ = await api("GET", "/relays", headers=api_headers("GET", "/relays", exp=int(time.time()) - 30))
            check("api: expired sig -> 401", st == 401, st)
            st, _, _ = await api("GET", "/relays", headers=api_headers("GET", "/meta/info"))
            check("api: sig for another path -> 401", st == 401, st)

            st, _, body = await api("GET", "/relays")
            doc = json.loads(body) if st == 200 else []
            check("api: GET /relays only allowlisted", st == 200 and sorted(r["id"] for r in doc) == [R1, R2], (st, body[:120]))
            check("api: GET /relays trimmed", b"SECRETMAC" not in body)
            st, _, _ = await api("GET", f"/relays/{FOREIGN}")
            check("api: foreign relay -> 403", st == 403, st)
            st, _, _ = await api("DELETE", f"/relays/{R1}")
            check("api: unlisted method -> 403", st == 403, st)
            st, _, _ = await api("GET", "/cameras/otherCam/snapshot")
            check("api: unlisted camera -> 403", st == 403, st)
            st, _, body = await api("GET", f"/cameras/{CAMERA}/snapshot")
            check("api: allowlisted snapshot passes", st == 200 and body.startswith(b"\xff\xd8"), st)

            good = json.dumps({"state": "on"}).encode()
            st, _, _ = await api("POST", f"/relays/{R1}/outputs/0/activate", good)
            check("api: explicit activate passes", st == 204 and console.writes[-1][2] == {"state": "on"}, (st, console.writes[-1:]))
            n = len(console.writes)
            st, _, _ = await api("POST", f"/relays/{R1}/outputs/0/activate", b"{}")
            check("api: activate without state (a toggle) -> 400", st == 400 and len(console.writes) == n, st)
            st, _, _ = await api("POST", f"/relays/{FOREIGN}/outputs/0/activate", good)
            check("api: activate foreign relay -> 403", st == 403 and len(console.writes) == n, st)
            st, _, _ = await api("PATCH", f"/lights/{LIGHT}", json.dumps({"isLightForceEnabled": True, "name": "x"}).encode())
            check("api: light patch with extra field -> 400", st == 400 and len(console.writes) == n, st)
            st, _, body = await api("PATCH", f"/lights/{LIGHT}", json.dumps({"isLightForceEnabled": True}).encode())
            check("api: light patch passes, response trimmed", st == 200 and b"SECRETMAC" not in body
                  and json.loads(body).get("lightModeSettings") == {"mode": "off"}, (st, body[:120]))
            async with http.get(f"{STATE}/protect/relays?x=1", headers=api_headers("GET", "/relays?x=1")) as r:
                check("api: query string -> 400", r.status == 400, r.status)
            check("console only ever saw the local key", set(console.keys) == {"local-key"}, set(console.keys))

            # --- console unreachable -> marked relay error
            await runner.cleanup()
            st, relay_err, _ = await api("GET", "/relays")
            check("api: console down -> 502 + X-Relay-Error", st == 502 and relay_err == "1", (st, relay_err))
    finally:
        proc.terminate()
        proc.wait(5)

    print("state test passed" if not failures else f"{failures} FAILED", flush=True)
    sys.exit(1 if failures else 0)


asyncio.run(main())
