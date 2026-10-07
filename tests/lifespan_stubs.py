"""Stubs for the background jobs of the server lifespan tests (GH-154, GH-157, GH-187).

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
- GH-161 retired the lifespan's tools gate and its permission reload (each
  chat run reads its own org's policy), so there is nothing to stub for them.
- GH-187 adds two attachment tasks: ``admino.attachment_gc.run_gc_job`` (the
  orphan GC, now and then hourly) and the one-shot
  ``admino.attachment_processing.recover`` (files a restart left
  ``processing`` are queued again). Their lifespan behavior is specified in
  tests/test_attachments_lifespan.py. ``patch_attachment_jobs`` stubs both:
  until a module exists it patches nothing for it (like the login throttle
  stub), so the unrelated lifespan tests keep running before GH-187; once a
  module exists its function must exist too (no ``create=True``). Neither real
  task then runs a query on a test's pool or scans the real attachments root.
"""

from __future__ import annotations

import contextlib
import importlib.util
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, patch

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

_LOGIN_THROTTLE_MODULE = "admino.login_throttle"
_ATTACHMENT_GC_MODULE = "admino.attachment_gc"
_ATTACHMENT_PROCESSING_MODULE = "admino.attachment_processing"


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


@contextlib.contextmanager
def patch_attachment_jobs(
    gc_job: Callable[..., Any] | None = None,
    recover: Callable[..., Any] | None = None,
) -> Iterator[None]:
    """Patch admino.attachment_gc.run_gc_job with ``gc_job`` and
    admino.attachment_processing.recover with ``recover`` (GH-187).

    Each defaults to an ``AsyncMock`` that returns at once (``recover`` returns
    0, the number of files it queued). A module that doesn't exist yet is
    skipped (nothing to patch); once it exists, the patched function must exist.
    """
    with contextlib.ExitStack() as stack:
        if importlib.util.find_spec(_ATTACHMENT_GC_MODULE) is not None:
            stack.enter_context(
                patch(f"{_ATTACHMENT_GC_MODULE}.run_gc_job", gc_job or AsyncMock(return_value=None))
            )
        if importlib.util.find_spec(_ATTACHMENT_PROCESSING_MODULE) is not None:
            stack.enter_context(
                patch(
                    f"{_ATTACHMENT_PROCESSING_MODULE}.recover",
                    recover or AsyncMock(return_value=0),
                )
            )
        yield
