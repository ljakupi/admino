"""Shared helpers that log a caller in for the API tests (GH-149).

Every non-public route depends on ``server.require_session``, which resolves
the ``admino_session`` cookie to a ``sessions.AuthenticatedSession`` (carrying
an ``access.Principal``). API tests log a caller in with ``login``: it
overrides that dependency, so rate limiting, the ``chat.send`` role gate and
the handlers still run. ``resolved_session`` exercises the real dependency
instead: it patches ``admino.sessions.resolve_session`` (and
``admino.database.get_pool``) so a cookie resolves to the given session, or to
nothing.

Inputs: a member role or Super Admin, and optionally explicit IDs.
Outputs: ``Principal`` / ``AuthenticatedSession`` fixtures, a ``Cookie`` header,
and the dependency override.

Security notes:
- These Principals are test fixtures. The construction tripwire in
  tests/test_access.py only scans src/, where sessions.py is the one builder.
- The session token is a fixed, obviously fake value, never a real secret.
- ``admino.sessions`` is imported lazily, so a test module that uses these
  helpers still collects (and fails per test) before GH-149 is implemented.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING, Final, Literal
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

from admino import server
from admino.access import Principal

if TYPE_CHECKING:
    from collections.abc import Iterator

    from fastapi import FastAPI

    from admino.access import MemberRole
    from admino.sessions import AuthenticatedSession

SESSION_COOKIE_NAME: Final = "admino_session"
# A plausible secrets.token_urlsafe(32) value: 43 URL-safe characters.
TEST_SESSION_TOKEN: Final = "fake-session-token_for-tests-only_012345678"

TEST_ORG_ID: Final = UUID("0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0")
TEST_MEMBER_ID: Final = UUID("11111111-2222-4333-8444-555555555555")
TEST_SUPER_ADMIN_ID: Final = UUID("99999999-8888-4777-8666-555555555555")
TEST_SESSION_ID: Final = UUID("abcdefab-cdef-4abc-8def-abcdefabcdef")

UiLanguage = Literal["de", "fr", "en"]


def member_principal(
    role: MemberRole = "org_admin",
    *,
    user_id: UUID = TEST_MEMBER_ID,
    org_id: UUID = TEST_ORG_ID,
) -> Principal:
    """Return a member Principal of ``org_id`` with ``role``."""
    return Principal(user_id=user_id, kind="member", org_id=org_id, role=role)


def super_admin_principal(*, user_id: UUID = TEST_SUPER_ADMIN_ID) -> Principal:
    """Return a Super Admin Principal (no organization, no member role)."""
    return Principal(user_id=user_id, kind="super_admin")


def session_for(
    principal: Principal,
    *,
    session_id: UUID = TEST_SESSION_ID,
    ui_language: UiLanguage = "en",
) -> AuthenticatedSession:
    """Wrap ``principal`` in the AuthenticatedSession that require_session returns."""
    from admino.sessions import AuthenticatedSession

    return AuthenticatedSession(
        session_id=session_id,
        principal=principal,
        ui_language=ui_language,
        response_language=None,
    )


def member_session(
    role: MemberRole = "org_admin",
    *,
    user_id: UUID = TEST_MEMBER_ID,
    org_id: UUID = TEST_ORG_ID,
) -> AuthenticatedSession:
    """Return a logged-in member's session (default: an Org Admin)."""
    return session_for(member_principal(role, user_id=user_id, org_id=org_id))


def super_admin_session(*, user_id: UUID = TEST_SUPER_ADMIN_ID) -> AuthenticatedSession:
    """Return a logged-in Super Admin's session."""
    return session_for(super_admin_principal(user_id=user_id))


def login(app: FastAPI, session: AuthenticatedSession) -> AuthenticatedSession:
    """Log ``session`` in on ``app`` by overriding ``server.require_session``.

    Returns the session so a test can compare what the handlers received.
    """
    app.dependency_overrides[server.require_session] = lambda: session
    return session


def logout(app: FastAPI) -> None:
    """Remove the ``login`` override: requests are anonymous again."""
    app.dependency_overrides.pop(server.require_session, None)


def session_cookie(token: str = TEST_SESSION_TOKEN) -> dict[str, str]:
    """Return the request header that carries ``token`` as the session cookie."""
    return {"Cookie": f"{SESSION_COOKIE_NAME}={token}"}


@contextmanager
def resolved_session(session: AuthenticatedSession | None) -> Iterator[AsyncMock]:
    """Make any session cookie resolve to ``session`` (None: unknown/revoked/expired).

    Patches ``admino.sessions.resolve_session`` and ``admino.database.get_pool``
    (no real database). Yields the resolve mock so a test can check the token
    the server looked up.
    """
    resolve = AsyncMock(return_value=session)
    with (
        patch("admino.sessions.resolve_session", resolve),
        patch("admino.database.get_pool", MagicMock(return_value=MagicMock(name="pool"))),
    ):
        yield resolve
