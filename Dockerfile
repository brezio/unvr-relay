# unvr-relay: UniFi Protect RTSPS -> go2rtc -> signed-URL nginx gate -> (optional) Cloudflare Tunnel
#
# One container: go2rtc and its API on loopback, nginx as the only listener
# (8080), cloudflared bundled and started only when TUNNEL_TOKEN is set.

ARG GO2RTC_VERSION=1.9.14
ARG CLOUDFLARED_VERSION=2026.10.0

FROM cloudflare/cloudflared:${CLOUDFLARED_VERSION} AS cloudflared

FROM alexxit/go2rtc:${GO2RTC_VERSION}

# go2rtc's image is Alpine and already has python3, bash and tini.
# Alpine's nginx is built --with-http_secure_link_module (checked on 1.28.3).
RUN apk add --no-cache nginx \
 && addgroup -S -g 10001 relay \
 && adduser -S -D -H -u 10001 -G relay relay \
 && mkdir -p /config \
 && chown relay:relay /config

COPY --from=cloudflared /usr/local/bin/cloudflared /usr/local/bin/cloudflared
COPY rootfs/ /
RUN chmod 0755 /usr/local/bin/unvr-relay /usr/local/bin/unvr-sign

USER relay
WORKDIR /config
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/unvr-relay"]
