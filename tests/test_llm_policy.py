"""Tests for the V1 model policy (``admino.llm_policy``, GH-242 contract section 2).

The policy is the bridge that #174's gateway replaces. It wraps one LLM client
call with two rules:

- Residency guard: ``check_residency(client, data_residency=...)`` blocks every
  client whose ``provider`` attribute is not a str in ``SWISS_PROVIDERS``
  ({"infomaniak", "vllm"}) when the org's data residency is on. It fails closed:
  a client without a ``provider`` (or a non-str one) is blocked. A blocked call
  raises ``residency_blocked_error()`` (code ``residency_blocked``, user-facing)
  and never reaches the client (``chat`` and ``chat_stream``).
- Retries: ``chat`` retries a retryable ``LLMError`` (code ``timeout``,
  ``provider_unavailable`` or ``rate_limited``) up to ``max_retries`` times
  (0..5, else ValueError before any call) on the SAME client with the SAME
  messages and tools, sleeping ``retry_delay(error, attempt)`` before each
  retry: the provider's Retry-After exactly (0..10 s, no jitter), no retry at
  all above 10 s (D2), else ``backoff_delay(attempt)`` =
  ``min(8, 1 * 2**attempt) * (0.5 + 0.5 * _random())``. The last error is raised
  unchanged; non-retryable errors and non-LLMError exceptions propagate at once.
  Each retry logs one WARNING with the code, never message text.
- ``chat_stream`` retries like ``chat`` only while nothing has been yielded to
  the caller; once a delta (or the final LLMResponse) went out, any error
  propagates unchanged.

The module is imported inside the ``policy`` fixture so every test fails on its
own while the module doesn't exist. ``_sleep`` and ``_random`` are the test
seams: the ``sleeps`` fixture records every delay instead of sleeping.
"""

from __future__ import annotations

import ast
import asyncio
import inspect
import logging
import sys
from typing import TYPE_CHECKING, Any

import pytest

from admino.llm import LLMError, LLMResponse, LLMStreamDelta
from admino.models import LLMMessage

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Iterator
    from types import ModuleType

# A marker in error messages: it must never reach a log record.
_CANARY = "CANARY-9d41-provider-said-this"
_PROVIDERS = ("infomaniak", "vllm", "anthropic", "openai")
_SWISS = ("infomaniak", "vllm")
_NON_SWISS = ("anthropic", "openai")
_MISSING = object()

StreamItem = LLMStreamDelta | LLMResponse


# ---------------------------------------------------------------------------
# Error factories (built inside each test: LLMError's new keywords don't exist yet)
# ---------------------------------------------------------------------------


def _err(
    code: str,
    *,
    status: int | None = None,
    retry_after_s: float | None = None,
    message: str = "Fixed catalogue text.",
) -> LLMError:
    """A coded LLMError (a coded error is always user-facing)."""
    return LLMError(message, status, code=code, retry_after_s=retry_after_s)


_RETRYABLE: dict[str, Callable[[], LLMError]] = {
    "timeout": lambda: _err("timeout"),
    "provider_unavailable_connection": lambda: _err("provider_unavailable"),
    "provider_unavailable_5xx": lambda: _err("provider_unavailable", status=503),
    "rate_limited": lambda: _err("rate_limited", status=429),
}

# LLMErrors that must never be retried (retryable is decided by the code alone).
_NOT_RETRYABLE_LLM: dict[str, Callable[[], LLMError]] = {
    "not_configured": lambda: _err("not_configured", status=401),
    "missing_model": lambda: _err("missing_model", status=404),
    "context_too_long": lambda: _err("context_too_long", status=400),
    "residency_blocked": lambda: _err("residency_blocked"),
    "not_configured_with_retry_after": lambda: _err(
        "not_configured", status=403, retry_after_s=1.0
    ),
    "uncoded_user_facing": lambda: LLMError("Shown verbatim.", user_facing=True),
    "uncoded_internal_400": lambda: LLMError("Example API returned HTTP 400", 400),
    "uncoded_internal_503": lambda: LLMError("Example API returned HTTP 503", 503),
    "uncoded_429_with_retry_after": lambda: LLMError(
        "Example API returned HTTP 429",
        429,
        retry_after_s=1.0,
    ),
}

_NOT_RETRIED: dict[str, Callable[[], BaseException]] = {
    **_NOT_RETRYABLE_LLM,
    "value_error": lambda: ValueError("not an LLMError"),
    "runtime_error": lambda: RuntimeError("not an LLMError"),
}


# ---------------------------------------------------------------------------
# Fake clients
# ---------------------------------------------------------------------------


class ScriptedClient:
    """Stand-in LLM client: ``chat`` returns or raises the next scripted item.

    The last item repeats once the script runs out. Every call records the exact
    ``messages`` and ``tools`` objects it got. ``provider`` is set as an
    attribute unless it is ``_MISSING``.
    """

    def __init__(
        self, script: list[LLMResponse | BaseException], *, provider: object = "infomaniak"
    ) -> None:
        self._script = list(script)
        self.calls: list[tuple[object, object]] = []
        if provider is not _MISSING:
            self.provider = provider

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
    ) -> LLMResponse:
        self.calls.append((messages, tools))
        item = self._script[min(len(self.calls), len(self._script)) - 1]
        if isinstance(item, BaseException):
            raise item
        return item


class ScriptedStreamClient:
    """Stand-in streaming client: each ``chat_stream`` call plays the next script.

    A script is a list of items yielded in order (an exception item is raised at
    that point), or a bare exception, which ``chat_stream`` raises when called
    (the stream couldn't be opened). The last script repeats once they run out.
    Every call is recorded when it is made, with its exact arguments.
    """

    def __init__(
        self,
        scripts: list[list[StreamItem | BaseException] | BaseException],
        *,
        provider: object = "infomaniak",
    ) -> None:
        self._scripts = list(scripts)
        self.calls: list[tuple[object, object]] = []
        self.chat_calls = 0
        if provider is not _MISSING:
            self.provider = provider

    def chat_stream(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> AsyncIterator[StreamItem]:
        self.calls.append((messages, tools))
        script = self._scripts[min(len(self.calls), len(self._scripts)) - 1]
        if isinstance(script, BaseException):
            raise script
        return self._play(script)

    async def _play(self, script: list[StreamItem | BaseException]) -> AsyncIterator[StreamItem]:
        for item in script:
            if isinstance(item, BaseException):
                raise item
            yield item

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
    ) -> LLMResponse:
        self.chat_calls += 1
        msg = "chat_stream must not fall back to chat"
        raise AssertionError(msg)


async def _drain(stream: AsyncIterator[StreamItem], seen: list[StreamItem]) -> None:
    """Consume ``stream``, appending every item the caller receives to ``seen``."""
    async for item in stream:
        seen.append(item)


def _messages() -> list[LLMMessage]:
    return [
        LLMMessage(role="system", content="You have no tools available."),
        LLMMessage(role="user", content="hello"),
    ]


def _tools() -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": "echo.say",
                "description": "Echo text",
                "parameters": {"type": "object", "properties": {}},
            },
        }
    ]


def _ok(content: str = "ok") -> LLMResponse:
    return LLMResponse(content=content, tool_calls=[], model="m", done=True)


def _delta(content: str) -> LLMStreamDelta:
    return LLMStreamDelta(content=content)


def _sequence(values: list[float]) -> Callable[[], float]:
    """A ``_random`` stand-in returning ``values`` in order (one per backoff)."""
    it: Iterator[float] = iter(values)
    return lambda: next(it)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def policy() -> ModuleType:
    """The policy module, imported per test (so a missing module fails each test)."""
    from admino import llm_policy

    return llm_policy


@pytest.fixture()
def sleeps(policy: ModuleType, monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Record every ``_sleep`` delay instead of sleeping; ``_random`` returns 0.5."""
    slept: list[float] = []

    async def fake_sleep(delay: float) -> None:
        slept.append(delay)

    monkeypatch.setattr(policy, "_sleep", fake_sleep)
    monkeypatch.setattr(policy, "_random", lambda: 0.5)
    return slept


# ===========================================================================
# 1. Module surface
# ===========================================================================


class TestModuleSurface:
    """Constants, seams, docstring and import boundary."""

    def test_llm_policy_constants_match_contract(self, policy: ModuleType) -> None:
        assert sorted(policy.SWISS_PROVIDERS) == ["infomaniak", "vllm"]
        assert isinstance(policy.SWISS_PROVIDERS, frozenset)
        assert policy.MAX_RETRY_AFTER_S == 10.0
        assert policy.BACKOFF_BASE_S == 1.0
        assert policy.BACKOFF_CAP_S == 8.0
        assert policy.MAX_RETRIES_LIMIT == 5

    def test_llm_policy_default_sleep_seam_is_asyncio_sleep(self, policy: ModuleType) -> None:
        assert policy._sleep is asyncio.sleep

    def test_llm_policy_default_random_seam_returns_floats_in_unit_interval(
        self, policy: ModuleType
    ) -> None:
        values = [policy._random() for _ in range(200)]
        assert all(isinstance(v, float) and 0.0 <= v < 1.0 for v in values)
        assert len(set(values)) > 1

    def test_llm_policy_docstring_names_the_174_gateway(self, policy: ModuleType) -> None:
        doc = policy.__doc__ or ""
        assert "#174" in doc or "GH-174" in doc

    def test_llm_policy_imports_only_stdlib_llm_and_models(self, policy: ModuleType) -> None:
        """Never server, agent, database, scoped_settings, permissions or a third party."""
        tree = ast.parse(inspect.getsource(policy))
        imported: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if node.level:
                    module = f"admino.{module}" if module else "admino"
                if module == "admino":
                    imported.extend(f"admino.{alias.name}" for alias in node.names)
                else:
                    imported.append(module)
        assert imported, "expected at least one import"
        for name in imported:
            root = name.split(".")[0]
            if root == "admino":
                assert name in {"admino.llm", "admino.models"}, name
            else:
                assert root in sys.stdlib_module_names or root == "__future__", name
                assert root != "importlib", name


# ===========================================================================
# 2. Residency guard
# ===========================================================================


class TestResidencyGuard:
    """check_residency, residency_blocked_error and the guard in chat/chat_stream."""

    def test_llm_policy_residency_blocked_error_is_coded_user_facing_and_not_retryable(
        self, policy: ModuleType
    ) -> None:
        error = policy.residency_blocked_error()
        assert isinstance(error, LLMError)
        assert error.code == "residency_blocked"
        assert error.user_facing is True
        assert error.retryable is False
        assert error.message
        assert error.message == policy.residency_blocked_error().message

    @pytest.mark.parametrize("provider", _SWISS)
    def test_llm_policy_check_residency_swiss_provider_under_residency_passes(
        self, policy: ModuleType, provider: str
    ) -> None:
        client = ScriptedClient([_ok()], provider=provider)
        assert policy.check_residency(client, data_residency=True) is None

    @pytest.mark.parametrize("provider", _PROVIDERS)
    def test_llm_policy_check_residency_without_residency_never_raises(
        self, policy: ModuleType, provider: str
    ) -> None:
        client = ScriptedClient([_ok()], provider=provider)
        assert policy.check_residency(client, data_residency=False) is None

    @pytest.mark.parametrize("provider", _NON_SWISS)
    def test_llm_policy_check_residency_non_swiss_provider_under_residency_raises_blocked(
        self, policy: ModuleType, provider: str
    ) -> None:
        client = ScriptedClient([_ok()], provider=provider)
        with pytest.raises(LLMError) as excinfo:
            policy.check_residency(client, data_residency=True)
        assert excinfo.value.code == "residency_blocked"
        assert excinfo.value.user_facing is True
        assert excinfo.value.message == policy.residency_blocked_error().message

    @pytest.mark.parametrize(
        "provider",
        [_MISSING, None, 42, b"infomaniak", ["infomaniak"], "Infomaniak", " vllm", ""],
        ids=["missing", "none", "int", "bytes", "list", "case", "padded", "empty"],
    )
    def test_llm_policy_check_residency_missing_or_odd_provider_under_residency_is_blocked(
        self, policy: ModuleType, provider: object
    ) -> None:
        """Fail closed: only an exact str in SWISS_PROVIDERS passes under residency."""
        client = ScriptedClient([_ok()], provider=provider)
        with pytest.raises(LLMError) as excinfo:
            policy.check_residency(client, data_residency=True)
        assert excinfo.value.code == "residency_blocked"

    @pytest.mark.parametrize(
        "provider",
        [_MISSING, None, 42, b"infomaniak", ["infomaniak"], "Infomaniak", " vllm", ""],
        ids=["missing", "none", "int", "bytes", "list", "case", "padded", "empty"],
    )
    def test_llm_policy_check_residency_missing_or_odd_provider_without_residency_passes(
        self, policy: ModuleType, provider: object
    ) -> None:
        client = ScriptedClient([_ok()], provider=provider)
        assert policy.check_residency(client, data_residency=False) is None

    @pytest.mark.parametrize("provider", _NON_SWISS)
    async def test_llm_policy_chat_non_swiss_under_residency_raises_blocked_without_calling(
        self, policy: ModuleType, sleeps: list[float], provider: str
    ) -> None:
        client = ScriptedClient([_ok()], provider=provider)
        with pytest.raises(LLMError) as excinfo:
            await policy.chat(client, _messages(), _tools(), data_residency=True, max_retries=5)
        assert excinfo.value.code == "residency_blocked"
        assert excinfo.value.user_facing is True
        assert client.calls == []
        assert sleeps == []

    @pytest.mark.parametrize(
        ("provider", "data_residency"),
        [
            ("infomaniak", True),
            ("vllm", True),
            ("infomaniak", False),
            ("vllm", False),
            ("anthropic", False),
            ("openai", False),
        ],
    )
    async def test_llm_policy_chat_allowed_provider_returns_client_response(
        self, policy: ModuleType, sleeps: list[float], provider: str, data_residency: bool
    ) -> None:
        response = _ok("answer")
        client = ScriptedClient([response], provider=provider)
        result = await policy.chat(
            client, _messages(), _tools(), data_residency=data_residency, max_retries=2
        )
        assert result is response
        assert len(client.calls) == 1

    async def test_llm_policy_chat_client_without_provider_under_residency_never_called(
        self, policy: ModuleType, sleeps: list[float]
    ) -> None:
        client = ScriptedClient([_ok()], provider=_MISSING)
        with pytest.raises(LLMError) as excinfo:
            await policy.chat(client, _messages(), data_residency=True, max_retries=0)
        assert excinfo.value.code == "residency_blocked"
        assert client.calls == []

    async def test_llm_policy_chat_client_without_provider_without_residency_is_called(
        self, policy: ModuleType, sleeps: list[float]
    ) -> None:
        response = _ok()
        client = ScriptedClient([response], provider=_MISSING)
        result = await policy.chat(client, _messages(), data_residency=False, max_retries=0)
        assert result is response

    @pytest.mark.parametrize("provider", [*_NON_SWISS, _MISSING], ids=[*_NON_SWISS, "missing"])
    async def test_llm_policy_chat_stream_blocked_before_anything_is_yielded(
        self, policy: ModuleType, sleeps: list[float], provider: object
    ) -> None:
        client = ScriptedStreamClient([[_delta("leak"), _ok()]], provider=provider)
        seen: list[StreamItem] = []
        with pytest.raises(LLMError) as excinfo:
            await _drain(
                policy.chat_stream(client, _messages(), data_residency=True, max_retries=5),
                seen,
            )
        assert excinfo.value.code == "residency_blocked"
        assert seen == []
        assert client.calls == []
        assert client.chat_calls == 0


# ===========================================================================
# 3. Retries in chat()
# ===========================================================================


class TestChatRetries:
    """Retry counts, which errors are retried, and max_retries validation."""

    @pytest.mark.parametrize(("max_retries", "expected_calls"), [(0, 1), (2, 3), (5, 6)])
    async def test_llm_policy_chat_always_failing_transient_error_makes_one_plus_retries_calls(
        self,
        policy: ModuleType,
        sleeps: list[float],
        max_retries: int,
        expected_calls: int,
    ) -> None:
        errors = [_err("timeout") for _ in range(8)]
        client = ScriptedClient(list(errors))
        with pytest.raises(LLMError):
            await policy.chat(client, _messages(), data_residency=False, max_retries=max_retries)
        assert len(client.calls) == expected_calls
        assert len(sleeps) == max_retries

    @pytest.mark.parametrize("max_retries", [0, 2, 5])
    async def test_llm_policy_chat_exhausted_retries_raise_last_error_unchanged(
        self, policy: ModuleType, sleeps: list[float], max_retries: int
    ) -> None:
        errors = [_err("rate_limited", status=429, message=f"attempt {i}") for i in range(8)]
        client = ScriptedClient(list(errors))
        with pytest.raises(LLMError) as excinfo:
            await policy.chat(client, _messages(), data_residency=False, max_retries=max_retries)
        last = errors[max_retries]
        assert excinfo.value is last
        assert excinfo.value.code == "rate_limited"
        assert excinfo.value.message == f"attempt {max_retries}"

    async def test_llm_policy_chat_success_on_second_call_returns_that_response(
        self, policy: ModuleType, sleeps: list[float]
    ) -> None:
        response = _ok("second time lucky")
        client = ScriptedClient([_err("timeout"), response])
        result = await policy.chat(client, _messages(), data_residency=False, max_retries=2)
        assert result is response
        assert len(client.calls) == 2
        assert len(sleeps) == 1

    @pytest.mark.parametrize("make_error", list(_RETRYABLE.values()), ids=list(_RETRYABLE))
    async def test_llm_policy_chat_retryable_error_is_retried(
        self,
        policy: ModuleType,
        sleeps: list[float],
        make_error: Callable[[], LLMError],
    ) -> None:
        error = make_error()
        assert error.retryable is True
        response = _ok()
        client = ScriptedClient([error, response])
        result = await policy.chat(client, _messages(), data_residency=False, max_retries=1)
        assert result is response
        assert len(client.calls) == 2

    @pytest.mark.parametrize("make_error", list(_NOT_RETRIED.values()), ids=list(_NOT_RETRIED))
    async def test_llm_policy_chat_non_retryable_failure_propagates_after_one_call(
        self,
        policy: ModuleType,
        sleeps: list[float],
        make_error: Callable[[], BaseException],
    ) -> None:
        error = make_error()
        client = ScriptedClient([error, _ok()])
        with pytest.raises(type(error)) as excinfo:
            await policy.chat(client, _messages(), data_residency=False, max_retries=5)
        assert excinfo.value is error
        assert len(client.calls) == 1
        assert sleeps == []

    async def test_llm_policy_chat_non_retryable_error_after_a_retry_stops_retrying(
        self, policy: ModuleType, sleeps: list[float]
    ) -> None:
        final = _err("not_configured", status=401)
        client = ScriptedClient([_err("timeout"), final, _ok()])
        with pytest.raises(LLMError) as excinfo:
            await policy.chat(client, _messages(), data_residency=False, max_retries=4)
        assert excinfo.value is final
        assert len(client.calls) == 2

    @pytest.mark.parametrize("max_retries", [-1, 6, 100])
    async def test_llm_policy_chat_max_retries_out_of_range_raises_value_error_before_any_call(
        self, policy: ModuleType, sleeps: list[float], max_retries: int
    ) -> None:
        client = ScriptedClient([_ok()])
        with pytest.raises(ValueError):
            await policy.chat(client, _messages(), data_residency=False, max_retries=max_retries)
        assert client.calls == []

    @pytest.mark.parametrize("max_retries", [0, 1, 2, 3, 4, 5])
    async def test_llm_policy_chat_max_retries_in_range_is_accepted(
        self, policy: ModuleType, sleeps: list[float], max_retries: int
    ) -> None:
        response = _ok()
        client = ScriptedClient([response])
        result = await policy.chat(
            client, _messages(), data_residency=False, max_retries=max_retries
        )
        assert result is response


# ===========================================================================
# 4. Backoff
# ===========================================================================


class TestBackoff:
    """backoff_delay's formula, and the delays chat() actually sleeps."""

    @pytest.mark.parametrize("r", [0.0, 0.5, 0.999])
    @pytest.mark.parametrize("attempt", [0, 1, 2, 3, 4, 5])
    def test_llm_policy_backoff_delay_matches_capped_exponential_with_jitter(
        self, policy: ModuleType, monkeypatch: pytest.MonkeyPatch, r: float, attempt: int
    ) -> None:
        monkeypatch.setattr(policy, "_random", lambda: r)
        expected = min(8.0, 1.0 * 2**attempt) * (0.5 + 0.5 * r)
        assert policy.backoff_delay(attempt) == pytest.approx(expected)

    @pytest.mark.parametrize(
        ("attempt", "r", "expected"),
        [(0, 0.0, 0.5), (1, 0.5, 1.5), (3, 0.5, 6.0), (4, 0.0, 4.0), (5, 0.999, 7.996)],
    )
    def test_llm_policy_backoff_delay_literal_values(
        self,
        policy: ModuleType,
        monkeypatch: pytest.MonkeyPatch,
        attempt: int,
        r: float,
        expected: float,
    ) -> None:
        monkeypatch.setattr(policy, "_random", lambda: r)
        assert policy.backoff_delay(attempt) == pytest.approx(expected)

    async def test_llm_policy_chat_sleeps_backoff_delay_before_each_retry(
        self, policy: ModuleType, sleeps: list[float], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The first retry is attempt 0; each backoff draws one jitter value."""
        monkeypatch.setattr(policy, "_random", _sequence([0.0, 0.5, 0.999]))
        response = _ok()
        client = ScriptedClient([_err("timeout"), _err("timeout"), _err("timeout"), response])
        result = await policy.chat(client, _messages(), data_residency=False, max_retries=3)
        assert result is response
        assert sleeps == pytest.approx([0.5, 1.5, 3.998])

    async def test_llm_policy_chat_backoff_delays_grow_exponentially_then_cap(
        self, policy: ModuleType, sleeps: list[float], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(policy, "_random", lambda: 0.0)
        client = ScriptedClient([_err("provider_unavailable", status=502) for _ in range(6)])
        with pytest.raises(LLMError):
            await policy.chat(client, _messages(), data_residency=False, max_retries=5)
        assert sleeps == pytest.approx([0.5, 1.0, 2.0, 4.0, 4.0])

    async def test_llm_policy_chat_backoff_delays_never_exceed_cap(
        self, policy: ModuleType, sleeps: list[float], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(policy, "_random", lambda: 0.999)
        client = ScriptedClient([_err("timeout") for _ in range(6)])
        with pytest.raises(LLMError):
            await policy.chat(client, _messages(), data_residency=False, max_retries=5)
        assert len(sleeps) == 5
        assert all(delay <= 8.0 for delay in sleeps)
        assert sleeps[3] == pytest.approx(sleeps[4])
        assert sleeps[1] == pytest.approx(2 * sleeps[0])


# ===========================================================================
# 5. Retry-After
# ===========================================================================


class TestRetryAfter:
    """retry_delay and the provider's Retry-After (D2: above 10 s, no retry)."""

    @pytest.mark.parametrize(
        ("retry_after_s", "attempt", "expected"),
        [
            (3.0, 0, 3.0),
            (3.0, 4, 3.0),
            (0.0, 0, 0.0),
            (0.25, 2, 0.25),
            (10.0, 0, 10.0),
        ],
    )
    def test_llm_policy_retry_delay_uses_retry_after_exactly_without_jitter(
        self,
        policy: ModuleType,
        monkeypatch: pytest.MonkeyPatch,
        retry_after_s: float,
        attempt: int,
        expected: float,
    ) -> None:
        monkeypatch.setattr(policy, "_random", lambda: 0.37)
        error = _err("rate_limited", status=429, retry_after_s=retry_after_s)
        assert policy.retry_delay(error, attempt) == expected

    def test_llm_policy_retry_delay_uses_retry_after_for_unavailable_provider(
        self, policy: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(policy, "_random", lambda: 0.37)
        error = _err("provider_unavailable", status=503, retry_after_s=2.5)
        assert policy.retry_delay(error, 1) == 2.5

    @pytest.mark.parametrize("retry_after_s", [10.5, 10.001, 60.0, 3600.0])
    def test_llm_policy_retry_delay_retry_after_above_ten_seconds_returns_none(
        self, policy: ModuleType, retry_after_s: float
    ) -> None:
        error = _err("rate_limited", status=429, retry_after_s=retry_after_s)
        assert policy.retry_delay(error, 0) is None

    def test_llm_policy_retry_delay_without_retry_after_is_backoff(
        self, policy: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(policy, "_random", lambda: 0.5)
        assert policy.retry_delay(_err("timeout"), 2) == pytest.approx(3.0)
        assert policy.retry_delay(_err("timeout"), 2) == pytest.approx(policy.backoff_delay(2))

    @pytest.mark.parametrize(
        "make_error", list(_NOT_RETRYABLE_LLM.values()), ids=list(_NOT_RETRYABLE_LLM)
    )
    def test_llm_policy_retry_delay_non_retryable_error_returns_none(
        self, policy: ModuleType, make_error: Callable[[], LLMError]
    ) -> None:
        assert policy.retry_delay(make_error(), 0) is None

    @pytest.mark.parametrize("retry_after_s", [3.0, 0.0, 10.0])
    async def test_llm_policy_chat_sleeps_retry_after_and_retries(
        self, policy: ModuleType, sleeps: list[float], retry_after_s: float
    ) -> None:
        response = _ok()
        client = ScriptedClient(
            [_err("rate_limited", status=429, retry_after_s=retry_after_s), response]
        )
        result = await policy.chat(client, _messages(), data_residency=False, max_retries=2)
        assert result is response
        assert len(client.calls) == 2
        assert sleeps == [retry_after_s]

    @pytest.mark.parametrize("code", ["rate_limited", "provider_unavailable"])
    async def test_llm_policy_chat_retry_after_above_ten_seconds_fails_at_once(
        self, policy: ModuleType, sleeps: list[float], code: str
    ) -> None:
        error = _err(code, status=429 if code == "rate_limited" else 503, retry_after_s=10.5)
        client = ScriptedClient([error, _ok()])
        with pytest.raises(LLMError) as excinfo:
            await policy.chat(client, _messages(), data_residency=False, max_retries=5)
        assert excinfo.value is error
        assert len(client.calls) == 1
        assert sleeps == []

    async def test_llm_policy_chat_mixes_retry_after_and_backoff_by_attempt(
        self, policy: ModuleType, sleeps: list[float]
    ) -> None:
        """A Retry-After retry still counts as attempt 0; the next backoff is attempt 1."""
        response = _ok()
        client = ScriptedClient(
            [_err("rate_limited", status=429, retry_after_s=2.0), _err("timeout"), response]
        )
        result = await policy.chat(client, _messages(), data_residency=False, max_retries=2)
        assert result is response
        assert sleeps == pytest.approx([2.0, 1.5])


# ===========================================================================
# 6. Same client, same model, same request
# ===========================================================================


class TestSameRequest:
    """Every retry repeats the identical request on the same client."""

    async def test_llm_policy_chat_retries_send_identical_messages_and_tools_to_same_client(
        self, policy: ModuleType, sleeps: list[float]
    ) -> None:
        messages = _messages()
        tools = _tools()
        snapshot = (list(messages), [dict(t) for t in tools])
        client = ScriptedClient(
            [_err("timeout"), _err("rate_limited", status=429), _ok("from the same client")]
        )
        other = ScriptedClient([_ok("from another client")], provider="vllm")
        result = await policy.chat(client, messages, tools, data_residency=True, max_retries=2)
        assert result.content == "from the same client"
        assert len(client.calls) == 3
        assert all(m is messages and t is tools for m, t in client.calls)
        assert (list(messages), [dict(t) for t in tools]) == snapshot
        assert other.calls == []

    async def test_llm_policy_chat_without_tools_retries_with_tools_none(
        self, policy: ModuleType, sleeps: list[float]
    ) -> None:
        messages = _messages()
        client = ScriptedClient([_err("timeout"), _ok()])
        await policy.chat(client, messages, data_residency=False, max_retries=1)
        assert client.calls == [(messages, None), (messages, None)]


# ===========================================================================
# 7. Logging
# ===========================================================================


def _admino_warnings(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [
        r for r in caplog.records if r.levelno == logging.WARNING and r.name.startswith("admino")
    ]


class TestRetryLogging:
    """One WARNING per retry with the code; no message text anywhere in the log."""

    async def test_llm_policy_chat_logs_one_warning_per_retry_with_its_code(
        self, policy: ModuleType, sleeps: list[float], caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)
        client = ScriptedClient(
            [
                _err("timeout", message=_CANARY),
                _err("rate_limited", status=429, message=_CANARY),
                _ok(),
            ]
        )
        await policy.chat(client, _messages(), data_residency=False, max_retries=2)
        warnings = _admino_warnings(caplog)
        assert len(warnings) == 2
        assert "timeout" in warnings[0].getMessage()
        assert "rate_limited" in warnings[1].getMessage()

    async def test_llm_policy_chat_retry_logs_never_carry_message_text(
        self, policy: ModuleType, sleeps: list[float], caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)
        client = ScriptedClient(
            [_err("provider_unavailable", status=503, message=_CANARY) for _ in range(4)]
        )
        with pytest.raises(LLMError):
            await policy.chat(client, _messages(), data_residency=False, max_retries=3)
        assert len(_admino_warnings(caplog)) == 3
        assert _CANARY not in caplog.text
        for record in caplog.records:
            assert _CANARY not in record.getMessage()
            assert _CANARY not in repr(record.args)

    async def test_llm_policy_chat_stream_retry_logs_warning_without_message_text(
        self, policy: ModuleType, sleeps: list[float], caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)
        client = ScriptedStreamClient(
            [[_err("timeout", message=_CANARY)], [_delta("hi"), _ok("hi")]]
        )
        seen: list[StreamItem] = []
        await _drain(
            policy.chat_stream(client, _messages(), data_residency=False, max_retries=1), seen
        )
        warnings = _admino_warnings(caplog)
        assert len(warnings) == 1
        assert "timeout" in warnings[0].getMessage()
        assert _CANARY not in caplog.text


# ===========================================================================
# 8. Streams
# ===========================================================================


class TestChatStream:
    """chat_stream retries only before the first item reached the caller."""

    async def test_llm_policy_chat_stream_passes_items_through_in_order(
        self, policy: ModuleType, sleeps: list[float]
    ) -> None:
        first, second, final = _delta("he"), _delta("llo"), _ok("hello")
        client = ScriptedStreamClient([[first, second, final]])
        seen: list[StreamItem] = []
        await _drain(
            policy.chat_stream(client, _messages(), data_residency=True, max_retries=2), seen
        )
        assert seen == [first, second, final]
        assert seen[2] is final
        assert len(client.calls) == 1

    async def test_llm_policy_chat_stream_error_before_first_yield_is_retried(
        self, policy: ModuleType, sleeps: list[float]
    ) -> None:
        delta, final = _delta("hi"), _ok("hi")
        client = ScriptedStreamClient([[_err("timeout")], [delta, final]])
        seen: list[StreamItem] = []
        await _drain(
            policy.chat_stream(client, _messages(), data_residency=False, max_retries=1), seen
        )
        assert seen == [delta, final]
        assert len(client.calls) == 2
        assert sleeps == pytest.approx([0.75])

    async def test_llm_policy_chat_stream_error_opening_the_stream_is_retried(
        self, policy: ModuleType, sleeps: list[float]
    ) -> None:
        """``chat_stream(...)`` itself raises (nothing to iterate): still before any item."""
        delta, final = _delta("hi"), _ok("hi")
        client = ScriptedStreamClient([_err("provider_unavailable", status=503), [delta, final]])
        seen: list[StreamItem] = []
        await _drain(
            policy.chat_stream(client, _messages(), data_residency=False, max_retries=1), seen
        )
        assert seen == [delta, final]
        assert len(client.calls) == 2

    async def test_llm_policy_chat_stream_error_after_a_delta_propagates_without_retry(
        self, policy: ModuleType, sleeps: list[float]
    ) -> None:
        delta = _delta("partial")
        error = _err("timeout")
        client = ScriptedStreamClient([[delta, error], [_delta("again"), _ok("again")]])
        seen: list[StreamItem] = []
        with pytest.raises(LLMError) as excinfo:
            await _drain(
                policy.chat_stream(client, _messages(), data_residency=False, max_retries=3),
                seen,
            )
        assert excinfo.value is error
        assert seen == [delta]
        assert len(client.calls) == 1
        assert sleeps == []

    async def test_llm_policy_chat_stream_only_final_response_is_passed_through(
        self, policy: ModuleType, sleeps: list[float]
    ) -> None:
        final = _ok("no deltas")
        client = ScriptedStreamClient([[final]])
        seen: list[StreamItem] = []
        await _drain(
            policy.chat_stream(client, _messages(), data_residency=False, max_retries=2), seen
        )
        assert seen == [final]
        assert len(client.calls) == 1

    async def test_llm_policy_chat_stream_error_after_final_response_propagates_without_retry(
        self, policy: ModuleType, sleeps: list[float]
    ) -> None:
        final = _ok("done")
        error = _err("provider_unavailable")
        client = ScriptedStreamClient([[final, error], [_ok("again")]])
        seen: list[StreamItem] = []
        with pytest.raises(LLMError) as excinfo:
            await _drain(
                policy.chat_stream(client, _messages(), data_residency=False, max_retries=3),
                seen,
            )
        assert excinfo.value is error
        assert seen == [final]
        assert len(client.calls) == 1

    async def test_llm_policy_chat_stream_exhausted_retries_raise_last_error(
        self, policy: ModuleType, sleeps: list[float]
    ) -> None:
        errors = [_err("rate_limited", status=429) for _ in range(4)]
        client = ScriptedStreamClient([[e] for e in errors])
        seen: list[StreamItem] = []
        with pytest.raises(LLMError) as excinfo:
            await _drain(
                policy.chat_stream(client, _messages(), data_residency=False, max_retries=2),
                seen,
            )
        assert excinfo.value is errors[2]
        assert len(client.calls) == 3
        assert len(sleeps) == 2
        assert seen == []

    @pytest.mark.parametrize("make_error", list(_NOT_RETRIED.values()), ids=list(_NOT_RETRIED))
    async def test_llm_policy_chat_stream_non_retryable_error_before_first_yield_not_retried(
        self,
        policy: ModuleType,
        sleeps: list[float],
        make_error: Callable[[], BaseException],
    ) -> None:
        error = make_error()
        client = ScriptedStreamClient([[error], [_ok()]])
        seen: list[StreamItem] = []
        with pytest.raises(type(error)) as excinfo:
            await _drain(
                policy.chat_stream(client, _messages(), data_residency=False, max_retries=5),
                seen,
            )
        assert excinfo.value is error
        assert len(client.calls) == 1
        assert sleeps == []

    async def test_llm_policy_chat_stream_retry_after_above_ten_seconds_fails_at_once(
        self, policy: ModuleType, sleeps: list[float]
    ) -> None:
        error = _err("rate_limited", status=429, retry_after_s=10.5)
        client = ScriptedStreamClient([[error], [_ok()]])
        with pytest.raises(LLMError) as excinfo:
            await _drain(
                policy.chat_stream(client, _messages(), data_residency=False, max_retries=5),
                [],
            )
        assert excinfo.value is error
        assert len(client.calls) == 1
        assert sleeps == []

    async def test_llm_policy_chat_stream_retry_sleeps_retry_after(
        self, policy: ModuleType, sleeps: list[float]
    ) -> None:
        client = ScriptedStreamClient(
            [[_err("rate_limited", status=429, retry_after_s=4.0)], [_ok()]]
        )
        await _drain(
            policy.chat_stream(client, _messages(), data_residency=False, max_retries=1), []
        )
        assert sleeps == [4.0]

    async def test_llm_policy_chat_stream_retries_send_identical_messages_and_tools(
        self, policy: ModuleType, sleeps: list[float]
    ) -> None:
        messages = _messages()
        tools = _tools()
        client = ScriptedStreamClient([[_err("timeout")], [_err("timeout")], [_ok()]])
        await _drain(
            policy.chat_stream(client, messages, tools, data_residency=True, max_retries=2), []
        )
        assert len(client.calls) == 3
        assert all(m is messages and t is tools for m, t in client.calls)
        assert client.chat_calls == 0
