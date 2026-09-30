"""Stubs for the background jobs of the server lifespan tests (GH-154, GH-157).

The lifespan helpers in test_audit_events, test_email_outbox,
test_session_management_api, test_critical_permissions_api and
test_org_purge_lifespan replace every background job with a fake, so each
test runs only what it tests and no real job touches their MagicMock pool.

- GH-154 adds ``admino.organizations.run_org_purge_job`` to the lifespan; its
  own lifespan behavior is specified in tests/test_org_purge_lifespan.py.
- GH-157 adds ``admino.login_throttle.run_purge_job`` (the expired throttle
  rows); its lifespan behavior is specified in
  tests/test_session_management_api.py. Until ``admino.login_throttle``
  exists the stub patches nothing (a ``nullcontext``), so the unrelated
  lifespan tests keep running; once it exists the job must exist too (no
  ``create=True``).
- GH-159 drops the ``settings`` table: the lifespan recomputes the agent's
  tools gate with ``admino.scoped_settings.all_orgs_tools_gate`` (looked up at
  call time). ``patch_tools_gate`` stubs it; until ``admino.scoped_settings``
  exists it stubs the old reload (``admino.database.load_settings_from_db``)
  instead, so the unrelated lifespan tests keep running. The gate itself is
  specified in tests/test_settings_api.py.
"""

from __future__ import annotations

import contextlib
import importlib.util
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, patch

if TYPE_CHECKING:
    from collections.abc import Callable

_LOGIN_THROTTLE_MODULE = "admino.login_throttle"
_SCOPED_SETTINGS_MODULE = "admino.scoped_settings"
_TOOL_NAMES = (
    "gmail",
    "google_calendar",
    "google_drive",
    "outlook",
    "outlook_calendar",
    "onedrive",
    "memory",
)


def patch_org_purge_job(job: Callable[..., Any]) -> contextlib.AbstractContextManager[Any]:
    """Patch admino.organizations.run_org_purge_job with ``job``."""
    return patch("admino.organizations.run_org_purge_job", job)


def patch_login_throttle_purge_job(
    job: Callable[..., Any],
) -> contextlib.AbstractContextManager[Any]:
    """Patch admino.login_throttle.run_purge_job with ``job`` (GH-157).

    Before the module exists there is nothing to patch: a ``nullcontext``.
    """
    if importlib.util.find_spec(_LOGIN_THROTTLE_MODULE) is None:
        return contextlib.nullcontext()
    return patch(f"{_LOGIN_THROTTLE_MODULE}.run_purge_job", job)


def patch_tools_gate(gate: dict[str, bool] | None = None) -> contextlib.AbstractContextManager[Any]:
    """Stub the lifespan's tools-gate reload (GH-159) with a fixed gate (default: all on).

    Patches admino.scoped_settings.all_orgs_tools_gate; before that module exists,
    the pre-GH-159 reload (admino.database.load_settings_from_db) instead.
    """
    if importlib.util.find_spec(_SCOPED_SETTINGS_MODULE) is None:
        return patch("admino.database.load_settings_from_db", AsyncMock(return_value={}))
    value = gate if gate is not None else dict.fromkeys(_TOOL_NAMES, True)
    return patch(f"{_SCOPED_SETTINGS_MODULE}.all_orgs_tools_gate", AsyncMock(return_value=value))
