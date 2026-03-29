#!/bin/sh
# entrypoint.sh — Agent container entrypoint
#
# Responsibility: Apply iptables egress whitelist before starting the server.
#
# Security model:
#   - All outbound traffic is blocked by default (DROP policy on OUTPUT chain).
#   - Loopback (127.0.0.1) is always allowed (required for internal IPC).
#   - The internal Docker bridge network is allowed (Ollama communication).
#   - DNS (UDP/TCP port 53) to the Docker embedded DNS resolver is allowed
#     so that whitelisted hostnames can be resolved.
#   - Only whitelisted external destinations are opened by hostname. Docker's
#     embedded DNS resolves these names; iptables rules use the resolved IPs.
#   - All other egress is DROPped.
#
# Note on iptables availability:
#   iptables requires NET_ADMIN capability. In production the container is run
#   with --cap-add=NET_ADMIN. If the capability is absent (e.g., local dev
#   without Docker, or CI without privileges), the iptables block is skipped
#   with a warning so the image still works for development purposes.
#
# Inputs:  EGRESS_ALLOWED_HOSTS (space-separated, e.g. "googleapis.com newsapi.org")
#          DOCKER_DNS_IP          (default: 127.0.0.11 — Docker embedded resolver)
#          INTERNAL_NETWORK       (default: 172.16.0.0/12 — Docker bridge range)
# Outputs: Runs "$@" (the CMD) after rules are applied.

set -eu

DOCKER_DNS_IP="${DOCKER_DNS_IP:-127.0.0.11}"
INTERNAL_NETWORK="${INTERNAL_NETWORK:-172.16.0.0/12}"

apply_iptables() {
    # Verify iptables is available and we have the required capability
    if ! iptables -L OUTPUT -n > /dev/null 2>&1; then
        echo "[entrypoint] WARNING: iptables not available or NET_ADMIN capability missing." >&2
        echo "[entrypoint] WARNING: Egress whitelist NOT enforced. Do not run this in production." >&2
        return 0
    fi

    echo "[entrypoint] Applying egress whitelist via iptables..."

    # Flush existing OUTPUT rules to start clean
    iptables -F OUTPUT

    # Allow loopback
    iptables -A OUTPUT -o lo -j ACCEPT

    # Allow established/related connections (required for response traffic)
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Allow DNS queries to the Docker embedded DNS resolver only
    iptables -A OUTPUT -d "${DOCKER_DNS_IP}" -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -d "${DOCKER_DNS_IP}" -p tcp --dport 53 -j ACCEPT

    # Allow all traffic on the internal Docker bridge network (Ollama access)
    iptables -A OUTPUT -d "${INTERNAL_NETWORK}" -j ACCEPT

    # Allow egress to whitelisted external hosts (HTTPS only, port 443)
    # EGRESS_ALLOWED_HOSTS is space-separated and set from config.yaml egress.allowed_hosts
    # In the container this is populated via the EGRESS_ALLOWED_HOSTS env var.
    if [ -n "${EGRESS_ALLOWED_HOSTS:-}" ]; then
        for host in ${EGRESS_ALLOWED_HOSTS}; do
            # Strip leading wildcard (e.g. *.googleapis.com -> googleapis.com)
            clean_host="${host#\*.}"
            echo "[entrypoint] Whitelisting egress to: ${clean_host} (port 443)"
            # Resolve hostname to IP(s) and add rules for each
            resolved=$(getent hosts "${clean_host}" 2>/dev/null | awk '{print $1}' || true)
            if [ -n "$resolved" ]; then
                for ip in $resolved; do
                    iptables -A OUTPUT -d "${ip}" -p tcp --dport 443 -j ACCEPT
                done
            else
                echo "[entrypoint] WARNING: Could not resolve ${clean_host} — skipping." >&2
            fi
        done
    fi

    # Default policy: DROP all other outbound traffic
    iptables -P OUTPUT DROP

    echo "[entrypoint] Egress whitelist applied."
}

apply_iptables

echo "[entrypoint] Starting: $*"
exec "$@"
