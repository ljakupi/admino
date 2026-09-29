# admino — Caddy TLS reverse proxy image (production profile, GH-156)
#
# The official Caddy image plus what entrypoint.sh needs to lock the proxy
# down before Caddy starts:
#   iptables, ip6tables — the egress whitelist (Let's Encrypt and the agent only)
#   su-exec             — drop from root to the unprivileged caddy user afterwards
#
# Pin to a specific patch release to prevent silent supply-chain changes.
# For maximum reproducibility, pin to a digest:
#   FROM caddy:2.11.4-alpine@sha256:<digest>
# Obtain the current digest with: docker inspect --format='{{index .RepoDigests 0}}' caddy:2.11.4-alpine
FROM caddy:2.11.4-alpine

# setcap -r: the upstream binary carries cap_net_bind_service as a file
# capability. Under `cap_drop: ALL` the kernel refuses to exec a binary whose
# file capabilities fall outside the bounding set, and Caddy doesn't need it:
# docker-compose.prod.yml sets net.ipv4.ip_unprivileged_port_start=0, so the
# unprivileged caddy user binds 80/443 without any capability.
# /data (certificates, ACME account) and /config are owned by caddy, so the
# named volumes mounted there start with that ownership.
RUN apk add --no-cache iptables ip6tables su-exec \
    && setcap -r /usr/bin/caddy \
    && addgroup -S -g 1000 caddy \
    && adduser -S -D -H -u 1000 -G caddy -s /sbin/nologin caddy \
    && chown -R caddy:caddy /data /config

# Root-owned and read-only for the caddy user: the proxy can't rewrite its own
# config or entrypoint (e.g. to turn on access logs or lift the egress rules on
# the next start).
COPY Caddyfile /etc/caddy/Caddyfile
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0444 /etc/caddy/Caddyfile \
    && chmod 0555 /entrypoint.sh

# The container starts as root ON PURPOSE: entrypoint.sh applies iptables
# (root + NET_ADMIN) and then drops to caddy with su-exec. Do NOT add `USER`.
ENTRYPOINT ["/entrypoint.sh"]
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
