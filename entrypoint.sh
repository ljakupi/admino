#!/bin/bash
# entrypoint.sh — Agent container entrypoint
#
# Responsibility: Apply iptables egress whitelist before starting the server.
#
# Security model:
#   - All outbound traffic is blocked by default (DROP policy on OUTPUT chain).
#   - Loopback (127.0.0.1) is always allowed (required for internal IPC).
#   - The internal Docker bridge network is allowed (local LLM backend communication).
#   - DNS (UDP/TCP port 53) is allowed so whitelisted hostnames can be resolved.
#     Docker's embedded resolver forwards upstream from inside the container's
#     netns, so port 53 egress (not just the resolver IP) must be permitted or
#     resolution silently fails under the DROP policy.
#   - Only whitelisted external destinations are opened by hostname. Docker's
#     embedded DNS resolves these names (IPv4 only); iptables rules use the
#     resolved IPs.
#   - All other egress is DROPped.
#   - IPv6 egress is blocked entirely (ip6tables OUTPUT DROP; loopback and
#     established replies only). admino reaches every whitelisted host over IPv4,
#     so IPv6 stays fail-closed to prevent a silent whitelist bypass if IPv6 is
#     ever enabled on the Docker network. See apply_ip6tables_lockdown.
#
# Note on iptables availability:
#   iptables requires NET_ADMIN capability. In production the container is run
#   with --cap-add=NET_ADMIN. If the capability is absent (e.g., local dev
#   without Docker, or CI without privileges), the iptables block is skipped
#   with a warning so the image still works for development purposes.
#
# Inputs:  CONFIG_DIR                (default: config — directory containing config.yaml;
#                                     the egress whitelist is read from egress.allowed_hosts
#                                     there, the single source of truth. Same default as main.py.)
#          DOCKER_DNS_IP             (default: 127.0.0.11 — Docker embedded resolver)
#          INTERNAL_NETWORK          (default: 172.16.0.0/12 — Docker bridge range; covers
#                                     admino-internal (172.20.0.0/16) where postgres and
#                                     the vllm service live)
#          REQUIRE_EGRESS_WHITELIST  (default: true — set to "false" only for local dev without Docker)
# Outputs: Runs "$@" (the CMD) after rules are applied.

set -euo pipefail

DOCKER_DNS_IP="${DOCKER_DNS_IP:-127.0.0.11}"
CONFIG_FILE="${CONFIG_DIR:-config}/config.yaml"
# Default covers Docker's full IPAM pool (172.16.0.0/12). User-defined bridge
# networks are assigned from this range (172.17.x, 172.18.x, etc.) so we must
# cover the full range to reliably reach internal services regardless of subnet assignment.
# Override via INTERNAL_NETWORK if your Docker daemon uses a custom IPAM config
# (e.g. daemon.json "bip" or "default-address-pools"). Verify your Docker
# bridge CIDR with: docker network inspect admino-internal --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}'
INTERNAL_NETWORK="${INTERNAL_NETWORK:-172.16.0.0/12}"

# Read the egress whitelist from config.yaml (egress.allowed_hosts) — the
# single source of truth, also validated by Pydantic at app startup and
# checked against the LLM provider in main.py. The EGRESS_ALLOWED_HOSTS env
# var is intentionally NOT consulted: a second, hand-synced list already
# drifted once and silently broke provider egress.
# Fails hard (set -e) if the config file is missing or unparseable.
read_allowed_hosts() {
    python -c '
import sys
import yaml

with open(sys.argv[1]) as f:
    config = yaml.safe_load(f)
hosts = ((config or {}).get("egress") or {}).get("allowed_hosts") or []
# Mirror the Pydantic contract (EgressConfig): a list of strings, each at
# most 253 chars. Anything else (mapping, scalar, nested lists) fails closed
# here just as config.py would reject it at app startup.
if not isinstance(hosts, list) or not all(
    isinstance(h, str) and 0 < len(h) <= 253 for h in hosts
):
    sys.exit("egress.allowed_hosts must be a list of hostname strings (max 253 chars each)")
print(" ".join(hosts))
' "${CONFIG_FILE}"
}

# Lock down IPv6 egress entirely (defense-in-depth). admino reaches every
# whitelisted host over IPv4, and Docker disables IPv6 on the default bridge,
# so IPv6 egress is never needed. Blocking it fail-closed prevents a silent
# whitelist bypass if IPv6 is later enabled on the Docker network (or on an
# IPv6-capable VPS): the IPv4 OUTPUT DROP policy would not cover the v6 stack.
# Loopback and established/related replies stay open to mirror the IPv4 policy.
# Reaching a whitelisted host over IPv6 is intentionally unsupported; a future
# deployment that needs it would add per-host AAAA rules here.
apply_ip6tables_lockdown() {
    # Reaching here implies NET_ADMIN is present: apply_iptables aborts (or, in
    # dev mode, returns) before calling this when the capability is missing. So
    # a failing ip6tables query here is NOT a permission problem — the IPv6
    # netfilter tables are unavailable. That is only safe to skip if IPv6 is
    # genuinely disabled at the kernel level; if IPv6 is active but unfilterable,
    # traffic would bypass the egress whitelist, so we must fail closed instead.
    if ! ip6tables -L OUTPUT -n > /dev/null 2>&1; then
        # disable_ipv6=1 (or the sysctl absent → IPv6 compiled out of the
        # kernel) means no IPv6 egress is possible, so skipping is safe.
        v6_disabled="$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo 1)"
        if [ "${v6_disabled}" = "1" ]; then
            echo "[entrypoint] IPv6 disabled at kernel level — skipping ip6tables lockdown (no IPv6 egress possible)."
            return 0
        fi
        echo "[entrypoint] WARNING: ip6tables unavailable but IPv6 is enabled — egress whitelist does NOT cover IPv6." >&2
        if [ "${REQUIRE_EGRESS_WHITELIST:-true}" = "true" ]; then
            echo "[entrypoint] ERROR: REQUIRE_EGRESS_WHITELIST=true but IPv6 egress cannot be locked down — aborting." >&2
            exit 1
        fi
        return 0
    fi

    echo "[entrypoint] Locking down IPv6 egress (fail-closed)..."
    # Set default-deny BEFORE flushing to avoid an open race window (same
    # ordering rationale as the IPv4 OUTPUT chain below).
    ip6tables -P OUTPUT DROP
    ip6tables -F OUTPUT
    ip6tables -A OUTPUT -o lo -j ACCEPT
    # ESTABLISHED,RELATED mirrors the IPv4 OUTPUT policy for structural symmetry.
    # With no NEW IPv6 egress permitted it matches nothing today; it would carry
    # reply traffic only if a future change locks down IPv6 INPUT and allows a
    # specific inbound service. INPUT/FORWARD are intentionally left at their
    # defaults — this function's scope is egress (OUTPUT); inbound is already
    # constrained by the 127.0.0.1 host port publish and the server's IPv4 bind.
    # (Requires nf_conntrack; if the module is absent the rule fails and the
    # container aborts under `set -e` — a fail-closed outcome matching the IPv4
    # path.)
    ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    echo "[entrypoint] IPv6 egress locked down."
}

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

    # Allow DNS resolution. The app queries Docker's embedded resolver
    # (DOCKER_DNS_IP), which then FORWARDS to a real upstream nameserver from
    # inside the container's netns — that forwarded hop's destination is NOT
    # DOCKER_DNS_IP (it is the Docker Desktop gateway, or the host's resolvers
    # on Linux), so restricting to -d DOCKER_DNS_IP silently breaks resolution
    # under the DROP policy. Allow the resolver directly, plus port 53 egress so
    # the upstream forwarding works across Docker Desktop and Linux.
    #
    # DOCKER_DNS_IP is opened on all ports (not just 53) deliberately: on Linux,
    # Docker DNATs 127.0.0.11:53 to an ephemeral port before the filter chain,
    # so a --dport 53 match would miss it. This IP is Docker's internal resolver
    # (loopback-adjacent, not externally routable, no other service listening),
    # so the wider match is low risk.
    #
    # SECURITY TRADEOFF: allowing port 53 to any destination permits DNS
    # tunneling as an exfiltration channel. It is required here (the upstream
    # resolver IP is neither knowable nor portable) and matches issue #16's
    # "DNS resolution allowed (port 53 UDP/TCP)". Accepted for the
    # laptop/home-server threat model; bandwidth-limiting (e.g. hashlimit) is a
    # candidate follow-up hardening.
    iptables -A OUTPUT -d "${DOCKER_DNS_IP}" -j ACCEPT
    iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

    # Allow all traffic on the internal Docker bridge network.
    # This covers both postgres (5432) and the vllm service (8000) — both are
    # on the internal bridge (admino-internal, 172.20.0.0/16), which is within
    # INTERNAL_NETWORK (172.16.0.0/12). No separate per-service rule is needed.
    iptables -A OUTPUT -d "${INTERNAL_NETWORK}" -j ACCEPT

    # Allow egress to whitelisted external hosts (HTTPS only, port 443).
    # The list is read from config.yaml egress.allowed_hosts (see
    # read_allowed_hosts above). Sanitize by collapsing newlines to spaces to
    # prevent embedded newlines from bypassing the per-host validation.
    EGRESS_ALLOWED_HOSTS="$(read_allowed_hosts | tr '\n' ' ')"
    # Strip non-printable characters before logging: entries are not yet
    # validated here, and raw control chars from YAML could forge log lines.
    echo "[entrypoint] Egress whitelist from ${CONFIG_FILE}: $(printf '%s' "${EGRESS_ALLOWED_HOSTS:-<empty>}" | tr -cd '[:print:]')"
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
                echo "[entrypoint] ERROR: Unsafe or malformed host entry in config.yaml egress.allowed_hosts — aborting." >&2
                exit 1
            fi
            # Strip leading wildcard — resolves the apex only (see note above).
            clean_host="${host#\*.}"
            echo "[entrypoint] Whitelisting egress to: ${clean_host} (port 443)"
            # Resolve hostname to IPv4 address(es) and add a rule for each.
            # Use `getent ahostsv4` (NOT `getent hosts`, which may return an
            # AAAA/IPv6 address that iptables — an IPv4 tool — rejects, aborting
            # under `set -e`). IPv6 egress is blocked wholesale by
            # apply_ip6tables_lockdown, so IPv4 rules are all we need. ahostsv4
            # prints one line per socktype, so sort -u collapses duplicates.
            # Fail hard if a required host cannot be resolved — a silent skip
            # would leave the container running without its intended egress rules.
            resolved=$(getent ahostsv4 "${clean_host}" 2>/dev/null | awk '{print $1}' | sort -u || true)
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

    # Defense-in-depth: block all IPv6 egress now that the IPv4 whitelist is in
    # place (only reached when NET_ADMIN is present and iptables succeeded).
    apply_ip6tables_lockdown

    echo "[entrypoint] Egress whitelist applied."
}

apply_iptables

# Drop root privileges before running the application. The entrypoint runs as
# root so it can apply the iptables egress whitelist above; the app itself must
# not. gosu does a clean setuid to admino and exec's the command with no extra
# process, so the app becomes PID 1 with correct signal handling. If the
# container was started as a non-root user (e.g. a compose `user:` override)
# there is nothing to drop, so exec directly — iptables was already gated by
# REQUIRE_EGRESS_WHITELIST in that case.
if [ "$(id -u)" = "0" ]; then
    echo "[entrypoint] Dropping to admino and starting: $*"
    exec gosu admino "$@"
else
    echo "[entrypoint] Already non-root; starting: $*"
    exec "$@"
fi
