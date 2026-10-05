"""V1 model policy: data-residency guard and bounded retries around one LLM client.

This module is the V1 bridge until the LLM gateway of #174 (GH-174) replaces
it. It wraps the calls the agent makes to its one running ``LLMClient`` with
two rules (GH-242):

- Residency guard: when the requesting org's data residency is on, only a
  Swiss provider (``SWISS_PROVIDERS``: infomaniak, vllm) may be called.
  ``check_residency`` reads the client's ``provider`` attribute and fails
  closed: a client without one (or with anything but an exact str in the set)
  is blocked with ``residency_blocked_error()`` before any request is sent.
- Retries: a retryable ``LLMError`` (``timeout``, ``provider_unavailable``,
  ``rate_limited``) is retried up to ``max_retries`` times (0..5) on the SAME
  client with the SAME messages and tools objects: never another client,
  provider or model. Before each retry it sleeps the provider's Retry-After
  exactly (0..10 s), or ``backoff_delay(attempt)`` (capped exponential with
  jitter) when there is none; a Retry-After above 10 s means no retry at all.
  The last error is raised unchanged; any other error propagates at once.
  ``chat_stream`` retries only while nothing has reached the caller yet.
- Per-call output cap (GH-179): ``chat``'s keyword-only ``max_tokens`` is
  passed to ``client.chat`` on every attempt when it is an int (the chat-title
  call); when it is None the keyword is not passed at all, so clients without
  it keep working. The client validates it and applies
  ``min(max_tokens, configured cap)``.

Inputs: the client, the call's messages and tools, an optional per-call output
cap, the org's residency flag and the platform's retry limit. Outputs: the
client's ``LLMResponse`` (or its stream items), or the client's / the guard's
``LLMError``.

Security notes:
- Pure policy: imports only the standard library, ``admino.llm`` and
  ``admino.models`` (never the server, agent, database, settings or permission
  engine), and sees no user, org or account data, only the residency flag.
- Each retry logs one WARNING naming the error code, the attempt number and
  the delay: never the error's message or any provider text.
- ``_sleep`` and ``_random`` are module-level seams for tests; ``_random``
  draws from ``random.SystemRandom``.
"""

from __future__ import annotations

import asyncio
import logging
import random
from typing import TYPE_CHECKING, Any, Final, Protocol

from admino.llm import LLMError

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable

    from admino.llm import LLMClient, LLMResponse, LLMStreamDelta
    from admino.models import LLMMessage

logger = logging.getLogger(__name__)

SWISS_PROVIDERS: Final[frozenset[str]] = frozenset({"infomaniak", "vllm"})
MAX_RETRY_AFTER_S: Final = 10.0
BACKOFF_BASE_S: Final = 1.0
BACKOFF_CAP_S: Final = 8.0
MAX_RETRIES_LIMIT: Final = 5

_RESIDENCY_BLOCKED_MESSAGE: Final = (
    "Your organization's data residency policy allows only Swiss-hosted AI models, "
    "and the active model isn't one. Ask your administrator to choose a Swiss model."
)

# Test seams: replaced by tests, looked up at call time.
_sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
_random: Callable[[], float] = random.SystemRandom().random


class StreamingLLMClient(Protocol):
    """An LLM client that can stream a reply (``InfomaniakClient`` today)."""

    def chat_stream(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> AsyncIterator[LLMStreamDelta | LLMResponse]:
        """Stream answer deltas, then exactly one final LLMResponse."""
        ...


def residency_blocked_error() -> LLMError:
    """Return the ``residency_blocked`` error (user-facing, fixed message)."""
    return LLMError(_RESIDENCY_BLOCKED_MESSAGE, code="residency_blocked")


def check_residency(client: object, *, data_residency: bool) -> None:
    """Block a non-Swiss client when the org's data residency is on.

    Args:
        client: The LLM client about to be called; its ``provider`` attribute
            must be exactly one of ``SWISS_PROVIDERS`` under residency.
        data_residency: The requesting org's residency policy. False never blocks.

    Raises:
        LLMError: ``residency_blocked_error()`` when blocked (fail closed: a
            client without a str ``provider`` counts as non-Swiss).
    """
    if not data_residency:
        return
    provider = getattr(client, "provider", None)
    if not (isinstance(provider, str) and provider in SWISS_PROVIDERS):
        raise residency_blocked_error()


def backoff_delay(attempt: int) -> float:
    """Return the jittered, capped exponential delay before retry ``attempt`` (0-based)."""
    return min(BACKOFF_CAP_S, BACKOFF_BASE_S * 2.0**attempt) * (0.5 + 0.5 * _random())


def retry_delay(error: LLMError, attempt: int) -> float | None:
    """Return the seconds to wait before retrying ``error``, or None for no retry.

    None for a non-retryable error and for a Retry-After above
    ``MAX_RETRY_AFTER_S`` (fail at once); the Retry-After exactly when the
    provider sent one; else ``backoff_delay(attempt)``.
    """
    if not error.retryable:
        return None
    if error.retry_after_s is not None:
        return None if error.retry_after_s > MAX_RETRY_AFTER_S else error.retry_after_s
    return backoff_delay(attempt)


def _check_max_retries(max_retries: int) -> None:
    """Reject a retry limit outside 0..MAX_RETRIES_LIMIT."""
    if not 0 <= max_retries <= MAX_RETRIES_LIMIT:
        msg = f"max_retries must be between 0 and {MAX_RETRIES_LIMIT}"
        raise ValueError(msg)


async def _wait_before_retry(error: LLMError, attempt: int, max_retries: int) -> bool:
    """Sleep before retry ``attempt`` and return True, or return False for no retry."""
    if attempt >= max_retries:
        return False
    delay = retry_delay(error, attempt)
    if delay is None:
        return False
    logger.warning(
        "LLM call failed with code %s; retry %d in %.2f s", error.code, attempt + 1, delay
    )
    await _sleep(delay)
    return True


async def chat(
    client: LLMClient,
    messages: list[LLMMessage],
    tools: list[dict[str, Any]] | None = None,
    *,
    data_residency: bool,
    max_retries: int,
    max_tokens: int | None = None,
) -> LLMResponse:
    """Send one chat request through the residency guard and the retry policy.

    Args:
        client: The running LLM client (every retry uses it again).
        messages: The call's messages (the same object on every retry).
        tools: The call's tool definitions (the same object on every retry).
        data_residency: The requesting org's residency policy.
        max_retries: Retries of a retryable error (0..5).
        max_tokens: Per-call output cap (GH-179) passed to ``client.chat`` on
            every attempt; None calls ``client.chat(messages, tools=tools)``
            without the keyword, exactly as before.

    Returns:
        The client's response.

    Raises:
        ValueError: ``max_retries`` outside 0..5 (before any call).
        LLMError: ``residency_blocked`` (no call made), a non-retryable error,
            or the last retryable error once the retries are used up.
    """
    _check_max_retries(max_retries)
    check_residency(client, data_residency=data_residency)
    attempt = 0
    while True:
        try:
            if max_tokens is None:
                # No keyword at all: clients (and test fakes) without it keep working.
                return await client.chat(messages, tools=tools)
            return await client.chat(messages, tools=tools, max_tokens=max_tokens)
        except LLMError as exc:
            if not await _wait_before_retry(exc, attempt, max_retries):
                raise
        attempt += 1


async def chat_stream(
    client: StreamingLLMClient,
    messages: list[LLMMessage],
    tools: list[dict[str, Any]] | None = None,
    *,
    data_residency: bool,
    max_retries: int,
) -> AsyncIterator[LLMStreamDelta | LLMResponse]:
    """Stream one chat reply through the residency guard and the retry policy.

    A retryable error is retried like ``chat`` only while nothing has been
    yielded to the caller (also when opening the stream fails); once a delta
    or the final response went out, any error propagates unchanged.

    Args:
        client: The running streaming LLM client (every retry uses it again).
        messages: The call's messages (the same object on every retry).
        tools: The call's tool definitions (the same object on every retry).
        data_residency: The requesting org's residency policy.
        max_retries: Retries of a retryable error (0..5).

    Yields:
        The client's ``LLMStreamDelta`` items, then its final ``LLMResponse``.

    Raises:
        ValueError: ``max_retries`` outside 0..5 (before any call).
        LLMError: ``residency_blocked`` (nothing yielded, no call made), or
            the client's error as described above.
    """
    _check_max_retries(max_retries)
    check_residency(client, data_residency=data_residency)
    attempt = 0
    while True:
        yielded = False
        try:
            async for item in client.chat_stream(messages, tools):
                yielded = True
                yield item
            return
        except LLMError as exc:
            if yielded or not await _wait_before_retry(exc, attempt, max_retries):
                raise
        attempt += 1
