#!/bin/bash
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
# Inputs:  EGRESS_ALLOWED_HOSTS      (space-separated, e.g. "googleapis.com newsapi.org")
#          DOCKER_DNS_IP             (default: 127.0.0.11 — Docker embedded resolver)
#          INTERNAL_NETWORK          (default: 172.16.0.0/12 — Docker bridge range)
#          REQUIRE_EGRESS_WHITELIST  (default: true — set to "false" only for local dev without Docker)
# Outputs: Runs "$@" (the CMD) after rules are applied.

set -euo pipefail

DOCKER_DNS_IP="${DOCKER_DNS_IP:-127.0.0.11}"
# Default covers Docker's full IPAM pool (172.16.0.0/12). User-defined bridge
# networks are assigned from this range (172.17.x, 172.18.x, etc.) so we must
# cover the full range to reliably reach Ollama regardless of subnet assignment.
# Override via INTERNAL_NETWORK if your Docker daemon uses a custom IPAM config
# (e.g. daemon.json "bip" or "default-address-pools"). Verify your Docker
# bridge CIDR with: docker network inspect admino-internal --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}'
INTERNAL_NETWORK="${INTERNAL_NETWORK:-172.16.0.0/12}"

# Sanitize EGRESS_ALLOWED_HOSTS: collapse newlines to spaces to prevent
# embedded newlines from bypassing the per-host character validation.
EGRESS_ALLOWED_HOSTS="$(printf '%s' "${EGRESS_ALLOWED_HOSTS:-}" | tr '\n' ' ')"

apply_iptables() {
    # Verify iptables is available and we have the required capability
    if ! iptables -L OUTPUT -n > /dev/null 2>&1; then
        echo "[entrypoint] WARNING: iptables not available or NET_ADMIN capability missing." >&2
        echo "[entrypoint] WARNING: Egress whitelist NOT enforced. Do not run this in production." >&2
        if [ "${REQUIRE_EGRESS_WHITELIST:-true}" = "true" ]; then
            echo "[entrypoint] ERROR: REQUIRE_EGRESS_WHITELIST=true but iptables unavailable — aborting." >&2
            exit 1
        fi
        return 0
    fi

    echo "[entrypoint] Applying egress whitelist via iptables..."

    # Set default-deny policy BEFORE flushing rules to eliminate the race
    # window. iptables -P persists across -F, so the chain is never open:
    #   1. -P OUTPUT DROP  → policy becomes DROP (existing rules still apply)
    #   2. -F OUTPUT       → rules removed, but DROP policy remains in effect
    iptables -P OUTPUT DROP
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
    #
    # IMPORTANT — wildcard entries (e.g. *.googleapis.com) do NOT expand to subdomains.
    # The '*.' prefix is stripped and only the apex domain is resolved. Each subdomain
    # you need to reach (e.g. oauth2.googleapis.com, accounts.google.com) must be listed
    # individually. Wildcard entries are accepted by the validator but provide no benefit
    # over listing the apex domain directly.
    #
    # LIMITATION — DNS resolution happens once at container startup. If a whitelisted
    # host's IPs change after startup (e.g. Google rotates IPs regularly), the iptables
    # rules become stale. This is acceptable for the laptop/home-server threat model.
    # For production VPS deployments, consider supplementing with a DNS-aware proxy.
    if [ -n "${EGRESS_ALLOWED_HOSTS:-}" ]; then
        for host in ${EGRESS_ALLOWED_HOSTS}; do
            # Validate host entry against safe character set before any shell use.
            # Allowed: alphanumeric, dots, hyphens, and a leading '*.' wildcard.
            if ! echo "${host}" | grep -qE '^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9.\-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}$'; then
                echo "[entrypoint] ERROR: Unsafe or malformed host entry in EGRESS_ALLOWED_HOSTS — aborting." >&2
                exit 1
            fi
            # Strip leading wildcard — resolves the apex only (see note above).
            clean_host="${host#\*.}"
            echo "[entrypoint] Whitelisting egress to: ${clean_host} (port 443)"
            # Resolve hostname to IP(s) and add rules for each.
            # Fail hard if a required host cannot be resolved — a silent skip
            # would leave the container running without its intended egress rules.
            resolved=$(getent hosts "${clean_host}" 2>/dev/null | awk '{print $1}' || true)
            if [ -n "$resolved" ]; then
                for ip in $resolved; do
                    iptables -A OUTPUT -d "${ip}" -p tcp --dport 443 -j ACCEPT
                done
            else
                echo "[entrypoint] ERROR: Could not resolve '${clean_host}' — aborting to prevent misconfigured egress." >&2
                exit 1
            fi
        done
    fi

    echo "[entrypoint] Egress whitelist applied."
}

apply_iptables

echo "[entrypoint] Starting: $*"
exec "$@"
