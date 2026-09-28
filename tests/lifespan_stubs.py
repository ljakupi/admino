"""Stub for GH-154's org purge job in the server lifespan tests.

The lifespan helpers in test_audit_events, test_email_outbox,
test_session_management_api and test_critical_permissions_api replace every
background job with a fake, so each test runs only what it tests and no real
job touches their MagicMock pool. GH-154 adds
``admino.organizations.run_org_purge_job`` to the lifespan; the lifespan's own
org purge behavior is specified in tests/test_org_purge_lifespan.py.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import patch

if TYPE_CHECKING:
    import contextlib
    from collections.abc import Callable


def patch_org_purge_job(job: Callable[..., Any]) -> contextlib.AbstractContextManager[Any]:
    """Patch admino.organizations.run_org_purge_job with ``job``."""
    return patch("admino.organizations.run_org_purge_job", job)
