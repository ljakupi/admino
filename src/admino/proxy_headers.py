"""Trusted reverse proxy headers: the real client address and scheme (GH-156).

A pure ASGI middleware for running admino behind the TLS reverse proxy of the
production profile. When the TCP peer of an HTTP request is inside one of the
trusted proxy networks (``server.trusted_proxies``), the request's client
address comes from ``X-Forwarded-For`` and its scheme from
``X-Forwarded-Proto``; from any other peer both headers are ignored.

Inputs: the ASGI scope's ``client`` and headers, and the trusted networks.
Outputs: the scope passed on, with ``client`` and ``scheme`` resolved, so CORS,
the security headers, the CSRF check, the per-IP rate limits, the audit events
and the handlers all see the browser client.

Security notes:
- X-Forwarded-For is walked from the right: each proxy appends the address it
  received the request from, so the rightmost entry that isn't itself a
  trusted proxy is the client; entries further left were written by the client
  and never pick its address. When every entry is a trusted proxy, the
  leftmost one (the origin those proxies report) is the client.
- Fail closed: an entry on that walk that isn't an IP address keeps the peer
  as the client. The address is rebuilt from its packed bytes, which drops an
  IPv6 scope ID ('fe80::1%<any text>'), so no text rides along.
- X-Forwarded-Proto counts only as ``http`` or ``https``; any other value
  keeps the scheme. X-Forwarded-Host is never read: Host stays authoritative.
- Only ``http`` scopes are resolved (admino serves no websockets); lifespan
  and anything else pass through untouched.
- uvicorn's own ProxyHeadersMiddleware is off (``main.py``): it trusts
  127.0.0.1 by default and also accepts ws/wss as a scheme.
- Nothing from the headers is logged. Does not import from agent.py, llm*.py
  or server.py.
"""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING, Final

from starlette.datastructures import Headers

if TYPE_CHECKING:
    from collections.abc import Iterable

    from starlette.types import ASGIApp, Receive, Scope, Send

# The X-Forwarded-Proto values that may set the request scheme.
_FORWARDED_SCHEMES: Final = frozenset({"http", "https"})


class TrustedProxyHeadersMiddleware:
    """Resolves the client address and scheme of requests from a trusted proxy."""

    def __init__(self, app: ASGIApp, trusted_proxies: Iterable[str]) -> None:
        """Wrap ``app``; ``trusted_proxies`` are validated network strings (config)."""
        self._app = app
        self._networks = tuple(ipaddress.ip_network(entry) for entry in trusted_proxies)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Pass the request on, with the forwarded client and scheme when the peer is trusted."""
        client = scope.get("client") if scope["type"] == "http" else None
        if client is not None and self._is_trusted(client[0]):
            scope = self._resolved(scope)
        await self._app(scope, receive, send)

    def _is_trusted(self, host: str) -> bool:
        """Whether the peer ``host`` is an IP address inside a trusted proxy network."""
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return False
        return self._trusts(address)

    def _trusts(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        """Whether ``address`` is inside a trusted proxy network."""
        return any(address in network for network in self._networks)

    def _resolved(self, scope: Scope) -> Scope:
        """A copy of ``scope`` with the forwarded scheme and client applied."""
        headers = Headers(scope=scope)
        resolved = dict(scope)
        proto = headers.get("x-forwarded-proto", "").strip().lower()
        if proto in _FORWARDED_SCHEMES:
            resolved["scheme"] = proto
        client = self._forwarded_client(headers.getlist("x-forwarded-for"))
        if client is not None:
            resolved["client"] = (client, 0)
        return resolved

    def _forwarded_client(self, values: list[str]) -> str | None:
        """The client address in the X-Forwarded-For header lines, or None to keep the peer.

        No header, or an entry on the right-to-left walk that isn't an IP
        address (an empty one included), keeps the peer.
        """
        client: str | None = None
        for entry in reversed(",".join(values).split(",")):
            try:
                address = ipaddress.ip_address(ipaddress.ip_address(entry.strip()).packed)
            except ValueError:
                return None
            client = str(address)
            if not self._trusts(address):
                return client
        return client
