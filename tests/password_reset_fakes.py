"""The in-memory database of the password reset tests (GH-151), re-exported.

The fake moved to tests/db_fakes.py when the session management tests (GH-152)
started to share it: it now models the sessions table after migration 0009
(per-row idle timeout, no ``revoked_at`` column: revoking deletes the row).
This module keeps the GH-151 test modules' imports working.

Security notes:
- Test infrastructure only: no real PostgreSQL, no network.
"""

from __future__ import annotations

from tests.db_fakes import (
    FAKE_LIFETIME,
    LINK_PREFIX,
    ORG_ID,
    PUBLIC_URL,
    TOKEN_RE,
    AuditWriteError,
    Call,
    FakeConnection,
    FakeDb,
    FakePool,
    fake_hash,
    norm,
    plain,
    sha256,
)

__all__ = [
    "FAKE_LIFETIME",
    "LINK_PREFIX",
    "ORG_ID",
    "PUBLIC_URL",
    "TOKEN_RE",
    "AuditWriteError",
    "Call",
    "FakeConnection",
    "FakeDb",
    "FakePool",
    "fake_hash",
    "norm",
    "plain",
    "sha256",
]
