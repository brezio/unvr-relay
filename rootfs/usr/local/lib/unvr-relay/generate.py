#!/usr/bin/env python3
"""
Render /config/go2rtc.yaml and /config/nginx.conf from the environment.

Runs once at container start, before anything listens. For each camera in
RELAY_CAMERAS it asks the UniFi Protect Integration API for the camera's
RTSPS URL, enabling RTSPS output on the camera first if it is off (unless
UNIFI_ENABLE_RTSPS=false).

RTSPS URLs carry a secret token: they are written to a 0600 file and never
logged.
"""

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

CONFIG_DIR = os.environ.get("RELAY_CONFIG_DIR", "/config")
LIB_DIR = os.path.dirname(os.path.abspath(__file__))
QUALITIES = ("high", "medium", "low")
NAME_OK = re.compile(r"^[a-z0-9_-]+$")
ID_OK = re.compile(r"^[A-Za-z0-9_-]+$")
FALSE = re.compile(r"^(0|false|no|off)$", re.I)


def die(msg):
    print(f"unvr-relay: config: {msg}", file=sys.stderr)
    sys.exit(1)


def log(msg):
    print(f"unvr-relay: config: {msg}", flush=True)


def env(name, default=""):
    return (os.environ.get(name) or default).strip()


class Protect:
    """Minimal Protect Integration API client over the UniFi cloud Connector."""

    def __init__(self, api_key, host_id):
        # HOST_ID must keep its ":<digits>" suffix -- the bare form 403s.
        self.base = (
            "https://api.ui.com/v1/connector/consoles/"
            + urllib.parse.quote(host_id, safe="")
            + "/proxy/protect/integration/v1"
        )
        self.key = api_key

    def call(self, path, method="GET", body=None):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(
            self.base + path,
            data=data,
            method=method,
            headers={"X-API-KEY": self.key, "Content-Type": "application/json"},
        )
        # Retry transient failures: on boot the network (or the console) may
        # not be up yet, and a 429 means UniFi is throttling the key.
        for attempt in range(6):
            try:
                with urllib.request.urlopen(req, timeout=20) as res:
                    return json.loads(res.read())
            except urllib.error.HTTPError as e:
                text = e.read().decode(errors="replace")[:200]
                if e.code in (429, 502, 503, 504) and attempt < 5:
                    time.sleep(2**attempt)
                    continue
                die(f"{method} {path} -> {e.code} {text}")
            except (urllib.error.URLError, TimeoutError) as e:
                if attempt < 5:
                    time.sleep(2**attempt)
                    continue
                die(f"{method} {path} -> {e}")


def protect_streams():
    spec = env("RELAY_CAMERAS")
    if not spec:
        return []
    for k in ("UNIFI_API_KEY", "UNIFI_HOST_ID"):
        if not env(k):
            die(f"{k} is required when RELAY_CAMERAS is set")

    quality = env("RTSPS_QUALITY", "medium")
    if quality not in QUALITIES:
        die(f"RTSPS_QUALITY must be one of {', '.join(QUALITIES)}")
    may_enable = not FALSE.match(env("UNIFI_ENABLE_RTSPS", "true"))
    host_override = env("RTSPS_HOST")
    api = Protect(env("UNIFI_API_KEY"), env("UNIFI_HOST_ID"))

    streams = []
    # RELAY_CAMERAS=<cameraId>:<streamName>,...
    for entry in [s.strip() for s in spec.split(",") if s.strip()]:
        cam_id, _, name = (p.strip() for p in entry.partition(":"))
        if not ID_OK.match(cam_id):
            die(f'bad camera id in "{entry}"')
        if not NAME_OK.match(name):
            die(f'stream name in "{entry}" must match {NAME_OK.pattern} (it appears in URLs)')

        urls = api.call(f"/cameras/{cam_id}/rtsps-stream")
        if not urls.get(quality):
            if not may_enable:
                die(f'camera {name}: RTSPS "{quality}" is off and UNIFI_ENABLE_RTSPS=false')
            log(f'{name}: enabling RTSPS "{quality}" on the camera')
            urls = api.call(f"/cameras/{cam_id}/rtsps-stream", "POST", {"qualities": [quality]})
            if not urls.get(quality):
                die(f'camera {name}: enable call returned no "{quality}" URL')

        # Protect hands out rtsps://<console>:7441/<token>?enableSrtp with a
        # self-signed cert. go2rtc's rtspx:// is RTSPS without certificate
        # verification; the SRTP flag is not wanted.
        u = urllib.parse.urlsplit(urls[quality])
        host = host_override or u.hostname
        port = u.port or 7441
        streams.append((name, f"rtspx://{host}:{port}{u.path}"))
        log(f"{name}: rtspx://{host}:{port}/<token redacted>")
    return streams


def static_streams():
    """RELAY_STREAMS=<name>=<go2rtc source>;... for non-Protect sources."""
    out = []
    for entry in [s.strip() for s in env("RELAY_STREAMS").split(";") if s.strip()]:
        name, sep, source = (p.strip() for p in entry.partition("="))
        if not sep or not source:
            die(f'bad RELAY_STREAMS entry "{entry}" (want name=source)')
        if not NAME_OK.match(name):
            die(f'stream name "{name}" must match {NAME_OK.pattern}')
        out.append((name, source))
        log(f"{name}: static source")
    return out


def write(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)


def main():
    secret = env("STREAM_SECRET")
    if len(secret) < 32:
        die("STREAM_SECRET must be at least 32 characters (openssl rand -hex 32)")
    if not re.match(r"^[A-Za-z0-9_-]+$", secret):
        die("STREAM_SECRET may only contain letters, digits, - and _ (it is embedded in nginx config)")

    streams = protect_streams() + static_streams()
    if not streams:
        die("nothing to relay: set RELAY_CAMERAS and/or RELAY_STREAMS")
    names = [n for n, _ in streams]
    if len(set(names)) != len(names):
        die(f"duplicate stream names: {names}")

    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with open(os.path.join(LIB_DIR, "go2rtc.yaml.tmpl")) as f:
        go2rtc = f.read().replace("@@STAMP@@", stamp).replace(
            "@@STREAMS@@", "\n".join(f"  {n}: {json.dumps(s)}" for n, s in streams)
        )
    with open(os.path.join(LIB_DIR, "nginx.conf.tmpl")) as f:
        nginx = f.read().replace("@@STREAM_SECRET@@", secret)

    write(os.path.join(CONFIG_DIR, "go2rtc.yaml"), go2rtc)
    write(os.path.join(CONFIG_DIR, "nginx.conf"), nginx)
    log(f"ready: {', '.join(names)}")


if __name__ == "__main__":
    main()
