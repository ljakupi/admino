#!/bin/sh
# entrypoint.sh — Caddy container entrypoint (production profile, GH-156)
#
# Responsibility: lock the proxy's egress down with iptables, then drop root and
# start Caddy as the unprivileged caddy user.
#
# Egress policy (OUTPUT chain, default DROP):
#   - loopback, and replies on established connections (the inbound 80/443
#     traffic and Caddy's connections to the agent);
#   - DNS: Docker's embedded resolver plus port 53, with the same DNS
#     tunnelling trade-off as the agent's entrypoint.sh (see docs/SECURITY.md);
#   - the agent on the proxy network (PROXY_NETWORK, TCP 8000 only);
#   - Let's Encrypt's ACME API (acme-v02.api.letsencrypt.org, TCP 443) for
#     certificate issuance and renewal — the proxy's only external destination;
#   - IPv6: only loopback and replies.
# Everything else is dropped. There is no development escape hatch: this image
# only runs in the production profile, so a missing NET_ADMIN capability, an
# unresolvable ACME host or an invalid input aborts the container.
#
# LIMITATION: the ACME host is resolved once at startup (as for the agent's
# whitelist). Let's Encrypt's API address is long-lived; if it ever changes,
# restart this container so renewals reach it again.
#
# Inputs:  ADMINO_DOMAIN   (required — the public hostname, e.g. admino.example.ch,
#                           or localhost for a local test with Caddy's internal CA)
#          PROXY_NETWORK   (required — the proxy network's CIDR, where the agent listens)
#          DOCKER_DNS_IP   (default: 127.0.0.11 — Docker's embedded resolver)
# Outputs: runs "$@" (the CMD) as the caddy user after the rules are applied.

set -eu

ACME_HOST="acme-v02.api.letsencrypt.org"
DOCKER_DNS_IP="${DOCKER_DNS_IP:-127.0.0.11}"
ADMINO_DOMAIN="${ADMINO_DOMAIN:-}"
PROXY_NETWORK="${PROXY_NETWORK:-}"

fail() {
    echo "[caddy-entrypoint] ERROR: $1 — aborting." >&2
    exit 1
}

# ADMINO_DOMAIN becomes the Caddyfile's site address: accept only localhost or
# a dotted hostname (the pattern the agent's entrypoint.sh uses for hosts), so
# no Caddyfile syntax can ride along in the value.
validate_domain() {
    if [ "${ADMINO_DOMAIN}" = "localhost" ]; then
        return 0
    fi
    if [ "${#ADMINO_DOMAIN}" -gt 253 ] \
        || ! printf '%s' "${ADMINO_DOMAIN}" | grep -qxE '[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}'; then
        fail "ADMINO_DOMAIN must be a hostname such as admino.example.ch (or localhost)"
    fi
}

validate_proxy_network() {
    if ! printf '%s' "${PROXY_NETWORK}" | grep -qxE '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}'; then
        fail "PROXY_NETWORK must be an IPv4 CIDR such as 172.31.0.0/24"
    fi
}

apply_iptables() {
    if ! iptables -L OUTPUT -n > /dev/null 2>&1; then
        fail "iptables unavailable or NET_ADMIN capability missing; the egress whitelist can't be applied"
    fi

    echo "[caddy-entrypoint] Applying egress whitelist via iptables..."
    # Default-deny BEFORE flushing, so the chain is never open (same ordering
    # as the agent's entrypoint.sh).
    iptables -P OUTPUT DROP
    iptables -F OUTPUT
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # DNS: the resolver itself on every port (Docker DNATs 127.0.0.11:53 to an
    # ephemeral port), plus port 53 for the resolver's upstream forwarding.
    iptables -A OUTPUT -d "${DOCKER_DNS_IP}" -j ACCEPT
    iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

    # The agent: port 8000 on the proxy network only (not postgres, not vllm).
    iptables -A OUTPUT -d "${PROXY_NETWORK}" -p tcp --dport 8000 -j ACCEPT

    # Let's Encrypt's ACME API, IPv4 only (IPv6 egress is locked down below).
    resolved="$(getent ahostsv4 "${ACME_HOST}" 2>/dev/null | awk '{print $1}' | sort -u || true)"
    if [ -z "${resolved}" ]; then
        fail "could not resolve ${ACME_HOST}"
    fi
    for ip in ${resolved}; do
        iptables -A OUTPUT -d "${ip}" -p tcp --dport 443 -j ACCEPT
    done
    echo "[caddy-entrypoint] Egress allowed to ${ACME_HOST} (port 443) and the agent (port 8000)."

    # IPv6: loopback and replies only. Fail closed when IPv6 is enabled but
    # can't be filtered, as the agent's entrypoint.sh does.
    if ip6tables -L OUTPUT -n > /dev/null 2>&1; then
        ip6tables -P OUTPUT DROP
        ip6tables -F OUTPUT
        ip6tables -A OUTPUT -o lo -j ACCEPT
        ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    elif [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo 1)" != "1" ]; then
        fail "ip6tables unavailable but IPv6 is enabled; IPv6 egress can't be locked down"
    fi
    echo "[caddy-entrypoint] Egress whitelist applied."
}

validate_domain
validate_proxy_network
apply_iptables

# Drop root: Caddy runs as caddy with no capabilities. Binding 80/443 needs
# none, because the compose file sets net.ipv4.ip_unprivileged_port_start=0 in
# the container's network namespace.
echo "[caddy-entrypoint] Dropping to caddy and starting Caddy."
exec su-exec caddy "$@"
