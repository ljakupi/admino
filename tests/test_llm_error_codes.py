"""Tests for GH-242 section 1: coded LLM errors and how each provider client maps SDK failures.

Spec (GH-242 contract section 1, #139 sections 1 and 5):
- ``admino.models.LLMErrorCode`` / ``LLM_ERROR_CODES``: the seven error codes.
- ``LLMError(..., code=..., retry_after_s=...)``: a coded error is always user-facing,
  ``retryable`` is True exactly for provider_unavailable / rate_limited / timeout, and an
  uncoded ``LLMError("x", user_facing=True)`` stays valid.
- The catalogue (``not_configured_error``, ``missing_model_error``,
  ``provider_status_error``) attaches the code. ``parse_retry_after`` reads the
  Retry-After headers. ``is_context_too_long`` classifies 400/413 failures.
- Every client (Infomaniak, vLLM, OpenAI, Anthropic) has a ``provider`` class attribute and
  maps SDK timeouts, connection errors and HTTP statuses to those codes. Text from a provider
  response (SDK message, body, error code string) never reaches ``LLMError.message``,
  ``str(err)`` or ``repr(err)``.

Not covered here (other GH-242 test files): identifiers in requests, SDK retries
(``max_retries=0``), the retry/residency policy, and the agent/HTTP wiring.

Mocking: the vLLM / OpenAI / Anthropic SDK ``create`` call is an ``AsyncMock`` that raises
real SDK exceptions built the way the SDKs build them (an ``httpx.Response`` with headers
and a JSON body). The Infomaniak client talks to an ``httpx.MockTransport`` fake installed
through its ``_new_http_client`` seam, so its SDK builds the exceptions itself. No real
network request is ever made.

The new names (``parse_retry_after``, ``is_context_too_long``, ``LLM_ERROR_CODES``, the new
``LLMError`` keywords and attributes) are looked up inside each test, so the file collects
and every test fails on its own before the implementation exists.
"""

from __future__ import annotations

import email.utils
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, get_args
from unittest.mock import AsyncMock, MagicMock

import anthropic
import httpx
import openai
import pytest

import admino.llm as llm_mod
import admino.llm_infomaniak as ik_mod
import admino.models as models_mod
from admino.config import LLMConfig
from admino.llm import LLMError, LLMStreamDelta
from admino.llm_anthropic import AnthropicClient
from admino.llm_infomaniak import InfomaniakClient
from admino.llm_openai import OpenAIClient
from admino.llm_vllm import VLLMClient
from admino.models import LLMMessage

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

# ---------------------------------------------------------------------------
# Constants and helpers
# ---------------------------------------------------------------------------

# Planted in every provider message / body: it must never reach an LLMError.
_CANARY = "CANARY-PROVIDER-TEXT-7f3a"
# Returned by getattr() while an attribute doesn't exist yet (keeps RED failures readable).
_MISSING = "<attribute missing>"

_ALL_CODES = frozenset(
    {
        "not_configured",
        "missing_model",
        "provider_unavailable",
        "rate_limited",
        "timeout",
        "residency_blocked",
        "context_too_long",
    }
)
_RETRYABLE_CODES = frozenset({"provider_unavailable", "rate_limited", "timeout"})

_NOW = datetime(2026, 10, 3, 12, 0, 0, tzinfo=UTC)

_IK_TOKEN = "ik-test-token-error-codes"
_IK_PRODUCT_ID = "7539"
_IK_MODEL = "Qwen/Qwen3.5-397B-A17B-FP8"
_OPENAI_URL = "https://api.openai.com/v1/chat/completions"
_VLLM_URL = "http://localhost:8000/v1/chat/completions"
_ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"

_MODEL_FIELDS = {
    "openai": "openai_model",
    "vllm": "vllm_model",
    "anthropic": "anthropic_model",
    "infomaniak": "infomaniak_model",
}


def _code(err: object) -> object:
    """The error's ``code`` attribute, or a sentinel while it doesn't exist."""
    return getattr(err, "code", _MISSING)


def _retry_after(err: object) -> object:
    """The error's ``retry_after_s`` attribute, or a sentinel while it doesn't exist."""
    return getattr(err, "retry_after_s", _MISSING)


def _msgs() -> list[LLMMessage]:
    """A minimal conversation."""
    return [LLMMessage(role="user", content="Hi")]


def _config(provider: str, **overrides: Any) -> LLMConfig:
    """A real LLMConfig for ``provider`` with a model set for every provider."""
    values: dict[str, Any] = {
        "provider": provider,
        "timeout_s": 5,
        "max_response_tokens": 1024,
        "openai_model": "gpt-4o",
        "anthropic_model": "claude-sonnet-4-6",
        "vllm_model": "local/test-model",
        "vllm_base_url": "http://localhost:8000/v1",
        "infomaniak_model": _IK_MODEL,
    }
    values.update(overrides)
    return LLMConfig(**values)


def _assert_no_text(err: LLMError, *texts: str) -> None:
    """Assert none of ``texts`` appears in the error's message, str() or repr()."""
    for text in texts:
        assert text not in err.message
        assert text not in str(err)
        assert text not in repr(err)


# ---------------------------------------------------------------------------
# Provider failures (one table drives every client)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Failure:
    """One provider failure and the code every client must turn it into.

    ``transport`` is "timeout" or "connection" for failures without an HTTP response;
    otherwise ``status`` is the HTTP status of the error response.
    """

    name: str
    status: int | None = None
    transport: str | None = None
    message: str = ""
    body_code: str | None = None
    headers: tuple[tuple[str, str], ...] = ()
    code: str | None = None
    retry_after_s: float | None = None


_TIMEOUT = _Failure("timeout", transport="timeout", code="timeout")
_CONNECTION = _Failure(
    "connection",
    transport="connection",
    message=f"connection refused {_CANARY}",
    code="provider_unavailable",
)
_AUTH_401 = _Failure(
    "401",
    401,
    message=f"Incorrect API key provided {_CANARY}",
    body_code="invalid_api_key",
    code="not_configured",
)
_AUTH_403 = _Failure("403", 403, message=f"Permission denied {_CANARY}", code="not_configured")
_NOT_FOUND = _Failure(
    "404",
    404,
    message=f"The model does not exist {_CANARY}",
    body_code="model_not_found",
    code="missing_model",
)
_RATE_LIMITED = _Failure(
    "429-retry-after",
    429,
    message=f"Rate limit reached {_CANARY}",
    body_code="rate_limit_exceeded",
    headers=(("retry-after", "3"),),
    code="rate_limited",
    retry_after_s=3.0,
)
_SERVER_500 = _Failure(
    "500", 500, message=f"Internal server error {_CANARY}", code="provider_unavailable"
)
_SERVER_503 = _Failure(
    "503-retry-after-ms",
    503,
    message=f"Service unavailable {_CANARY}",
    headers=(("retry-after-ms", "1500"),),
    code="provider_unavailable",
    retry_after_s=1.5,
)
_CONTEXT_CODE = _Failure(
    "400-context-length-code",
    400,
    message=f"Request rejected {_CANARY}",
    body_code="context_length_exceeded",
    code="context_too_long",
)
_CONTEXT_PROMPT = _Failure(
    "400-prompt-too-long",
    400,
    message=f"prompt is too long: 210000 tokens > 200000 maximum {_CANARY}",
    code="context_too_long",
)
_TOO_LARGE = _Failure(
    "413", 413, message=f"Request entity too large {_CANARY}", code="context_too_long"
)
_BAD_REQUEST = _Failure(
    "400-unrelated",
    400,
    message=f"Invalid value for temperature {_CANARY}",
    body_code="invalid_value",
    code=None,
)
_UNPROCESSABLE = _Failure("422", 422, message=f"Unprocessable entity {_CANARY}", code=None)
_OVERLOADED = _Failure(
    "529-overloaded",
    529,
    message=f"Overloaded {_CANARY}",
    headers=(("retry-after", "2"),),
    code="provider_unavailable",
    retry_after_s=2.0,
)

_COMMON_FAILURES = (
    _TIMEOUT,
    _CONNECTION,
    _AUTH_401,
    _AUTH_403,
    _NOT_FOUND,
    _RATE_LIMITED,
    _SERVER_500,
    _SERVER_503,
    _CONTEXT_PROMPT,
    _TOO_LARGE,
    _BAD_REQUEST,
    _UNPROCESSABLE,
)
# OpenAI-compatible providers send a body error code; Anthropic answers 529 when overloaded.
_FAILURES_BY_KIND: dict[str, tuple[_Failure, ...]] = {
    "openai": (*_COMMON_FAILURES, _CONTEXT_CODE),
    "vllm": (*_COMMON_FAILURES, _CONTEXT_CODE),
    "anthropic": (*_COMMON_FAILURES, _OVERLOADED),
    "infomaniak": (*_COMMON_FAILURES, _CONTEXT_CODE),
    "infomaniak-stream": (*_COMMON_FAILURES, _CONTEXT_CODE),
    # Product discovery (GET /1/ai, INFOMANIAK_PRODUCT_ID unset) maps like chat failures.
    "infomaniak-discovery": (
        _TIMEOUT,
        _CONNECTION,
        _AUTH_401,
        _AUTH_403,
        _RATE_LIMITED,
        _SERVER_500,
        _SERVER_503,
        _BAD_REQUEST,
        _UNPROCESSABLE,
    ),
}

_CLIENT_FAILURES = [
    pytest.param(kind, failure, id=f"{kind}-{failure.name}")
    for kind, failures in _FAILURES_BY_KIND.items()
    for failure in failures
]
_RETRY_AFTER_FAILURES = [
    pytest.param(kind, failure, id=f"{kind}-{failure.name}")
    for kind, failures in _FAILURES_BY_KIND.items()
    if kind != "infomaniak-discovery"
    for failure in failures
    if failure.status is not None and (failure.status == 429 or failure.status >= 500)
]


def _expected_code(kind: str, failure: _Failure) -> str | None:
    """The code ``kind`` must raise for ``failure``."""
    if kind == "vllm" and failure.status in (401, 403):
        return None  # vLLM has no key: 401/403 stay internal
    return failure.code


# ---------------------------------------------------------------------------
# SDK exception builders (mirror openai/anthropic ``_make_status_error``)
# ---------------------------------------------------------------------------

_OPENAI_STATUS_CLASSES: dict[int, type[openai.APIStatusError]] = {
    400: openai.BadRequestError,
    401: openai.AuthenticationError,
    403: openai.PermissionDeniedError,
    404: openai.NotFoundError,
    422: openai.UnprocessableEntityError,
    429: openai.RateLimitError,
}
_ANTHROPIC_STATUS_CLASSES: dict[int, type[anthropic.APIStatusError]] = {
    400: anthropic.BadRequestError,
    401: anthropic.AuthenticationError,
    403: anthropic.PermissionDeniedError,
    404: anthropic.NotFoundError,
    422: anthropic.UnprocessableEntityError,
    429: anthropic.RateLimitError,
}


def _openai_error_body(failure: _Failure) -> dict[str, Any]:
    """An OpenAI-style error body (also what vLLM and Infomaniak send)."""
    return {
        "error": {
            "message": failure.message,
            "type": "invalid_request_error",
            "param": None,
            "code": failure.body_code,
        }
    }


def _openai_exception(failure: _Failure, url: str) -> openai.APIError:
    """The exception the openai SDK raises for ``failure``."""
    request = httpx.Request("POST", url)
    if failure.transport == "timeout":
        return openai.APITimeoutError(request=request)
    if failure.transport == "connection":
        return openai.APIConnectionError(message=failure.message, request=request)
    assert failure.status is not None
    body = _openai_error_body(failure)
    response = httpx.Response(
        failure.status, headers=dict(failure.headers), json=body, request=request
    )
    fallback = openai.InternalServerError if failure.status >= 500 else openai.APIStatusError
    cls = _OPENAI_STATUS_CLASSES.get(failure.status, fallback)
    # The SDK passes the inner "error" object as ``body`` (that sets ``exc.code``).
    return cls(f"Error code: {failure.status} - {body}", response=response, body=body["error"])


def _anthropic_exception(failure: _Failure) -> anthropic.APIError:
    """The exception the anthropic SDK raises for ``failure``."""
    request = httpx.Request("POST", _ANTHROPIC_URL)
    if failure.transport == "timeout":
        return anthropic.APITimeoutError(request=request)
    if failure.transport == "connection":
        return anthropic.APIConnectionError(message=failure.message, request=request)
    assert failure.status is not None
    error_type = {
        413: "request_too_large",
        429: "rate_limit_error",
        529: "overloaded_error",
    }.get(failure.status, "api_error" if failure.status >= 500 else "invalid_request_error")
    body = {"type": "error", "error": {"type": error_type, "message": failure.message}}
    response = httpx.Response(
        failure.status, headers=dict(failure.headers), json=body, request=request
    )
    fallback = anthropic.InternalServerError if failure.status >= 500 else anthropic.APIStatusError
    cls = _ANTHROPIC_STATUS_CLASSES.get(failure.status, fallback)
    return cls(f"Error code: {failure.status} - {body}", response=response, body=body)


def _sdk_client(
    kind: str,
    monkeypatch: pytest.MonkeyPatch,
    *,
    with_key: bool = True,
    with_model: bool = True,
) -> tuple[Any, AsyncMock]:
    """A vLLM / OpenAI / Anthropic client whose SDK ``create`` call is an AsyncMock."""
    for env_var, value in (
        ("OPENAI_API_KEY", "sk-test-error-codes"),
        ("ANTHROPIC_API_KEY", "sk-ant-test-error-codes"),
    ):
        if with_key:
            monkeypatch.setenv(env_var, value)
        else:
            monkeypatch.delenv(env_var, raising=False)
    overrides: dict[str, Any] = {} if with_model else {_MODEL_FIELDS[kind]: None}
    config = _config(kind, **overrides)
    create = AsyncMock()
    sdk = MagicMock()
    sdk.close = AsyncMock()
    client: Any
    if kind == "openai":
        client = OpenAIClient(config)
        sdk.chat.completions.create = create
    elif kind == "vllm":
        client = VLLMClient(config)
        sdk.chat.completions.create = create
    else:
        client = AnthropicClient(config)
        sdk.messages.create = create
    client._client = sdk
    return client, create


def _sdk_exception(kind: str, failure: _Failure) -> Exception:
    """The SDK exception ``kind``'s client receives for ``failure``."""
    if kind == "anthropic":
        return _anthropic_exception(failure)
    return _openai_exception(failure, _OPENAI_URL if kind == "openai" else _VLLM_URL)


# ---------------------------------------------------------------------------
# Mocked Infomaniak server (httpx.MockTransport through ``_new_http_client``)
# ---------------------------------------------------------------------------


def _ik_discovery(*products: dict[str, Any]) -> Callable[[httpx.Request], httpx.Response]:
    """A discovery route answering with ``products``."""

    def route(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"result": "success", "data": list(products)})

    return route


def _ik_product(product_id: int) -> dict[str, Any]:
    """One discovery entry."""
    return {"product_id": product_id, "product_name": "p", "account_name": "a", "status": "ok"}


def _ik_failure_route(failure: _Failure) -> Callable[[httpx.Request], httpx.Response]:
    """A route that fails with ``failure`` (transport error or error status)."""

    def route(request: httpx.Request) -> httpx.Response:
        if failure.transport == "timeout":
            raise httpx.ReadTimeout(f"read timed out {_CANARY}", request=request)
        if failure.transport == "connection":
            raise httpx.ConnectError(failure.message, request=request)
        assert failure.status is not None
        return httpx.Response(
            failure.status, headers=dict(failure.headers), json=_openai_error_body(failure)
        )

    return route


class _FailingStream(httpx.AsyncByteStream):
    """An SSE body that sends one chunk, then breaks with ``error``."""

    def __init__(self, first: bytes, error: Exception) -> None:
        self._first = first
        self._error = error

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield self._first
        raise self._error


def _ik_failing_stream(
    exc_type: type[httpx.TransportError],
) -> Callable[[httpx.Request], httpx.Response]:
    """A chat route streaming one content delta ("Hel"), then failing with ``exc_type``."""
    chunk = {
        "id": "chatcmpl-stream",
        "object": "chat.completion.chunk",
        "created": 1_700_000_000,
        "model": _IK_MODEL,
        "choices": [{"index": 0, "delta": {"content": "Hel"}, "finish_reason": None}],
    }
    first = f"data: {json.dumps(chunk)}\n\n".encode()

    def route(request: httpx.Request) -> httpx.Response:
        error = exc_type(f"stream broke {_CANARY}", request=request)
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=_FailingStream(first, error),
        )

    return route


class _FakeInfomaniak:
    """A minimal Infomaniak server: product discovery and chat completions."""

    def __init__(self) -> None:
        self.discovery: Callable[[httpx.Request], httpx.Response] = _ik_discovery(
            _ik_product(int(_IK_PRODUCT_ID))
        )
        self.chat: Callable[[httpx.Request], httpx.Response] = _ik_failure_route(_SERVER_500)
        self.paths: list[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        """Route by path and record it."""
        request.read()
        self.paths.append(request.url.path)
        if request.url.path == "/1/ai":
            return self.discovery(request)
        if request.url.path.endswith("/chat/completions"):
            return self.chat(request)
        return httpx.Response(418, json={"error": "unexpected path"})

    def factory(self, *_args: Any, **_kwargs: Any) -> httpx.AsyncClient:
        """Drop-in replacement for ``_new_http_client`` (no real network)."""
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))


def _install_infomaniak(monkeypatch: pytest.MonkeyPatch) -> _FakeInfomaniak:
    """Configure token + product id and route every Infomaniak HTTP client to the fake."""
    monkeypatch.setenv("INFOMANIAK_API_TOKEN", _IK_TOKEN)
    monkeypatch.setenv("INFOMANIAK_PRODUCT_ID", _IK_PRODUCT_ID)
    fake = _FakeInfomaniak()
    monkeypatch.setattr(ik_mod, "_new_http_client", fake.factory)
    return fake


async def _infomaniak_error(client: InfomaniakClient, *, stream: bool = False) -> LLMError:
    """Run one chat (or drained chat_stream) that must fail; close the client."""
    try:
        with pytest.raises(LLMError) as exc_info:
            if stream:
                _ = [item async for item in client.chat_stream(_msgs())]
            else:
                await client.chat(_msgs())
    finally:
        await client.close()
    return exc_info.value


async def _raise_failure(kind: str, failure: _Failure, monkeypatch: pytest.MonkeyPatch) -> LLMError:
    """Drive ``kind``'s client into ``failure`` and return the LLMError it raises."""
    if kind.startswith("infomaniak"):
        fake = _install_infomaniak(monkeypatch)
        if kind == "infomaniak-discovery":
            monkeypatch.delenv("INFOMANIAK_PRODUCT_ID")
            fake.discovery = _ik_failure_route(failure)
        else:
            fake.chat = _ik_failure_route(failure)
        client = InfomaniakClient(_config("infomaniak"))
        return await _infomaniak_error(client, stream=kind == "infomaniak-stream")
    sdk_client, create = _sdk_client(kind, monkeypatch)
    create.side_effect = _sdk_exception(kind, failure)
    try:
        with pytest.raises(LLMError) as exc_info:
            await sdk_client.chat(_msgs())
    finally:
        await sdk_client.close()
    return exc_info.value


# ===========================================================================
# models.py: LLMErrorCode / LLM_ERROR_CODES
# ===========================================================================


class TestLLMErrorCodeCatalogue:
    """The seven codes live in admino.models."""

    def test_models_llm_error_codes_constant_is_frozenset_of_seven_codes(self) -> None:
        """LLM_ERROR_CODES is a frozenset of exactly the seven codes."""
        codes = models_mod.LLM_ERROR_CODES
        assert isinstance(codes, frozenset)
        assert codes == _ALL_CODES

    def test_models_llm_error_code_literal_lists_the_seven_codes(self) -> None:
        """LLMErrorCode is a Literal over exactly the seven codes."""
        alias = models_mod.LLMErrorCode
        literal = getattr(alias, "__value__", alias)
        assert set(get_args(literal)) == _ALL_CODES


# ===========================================================================
# LLMError attributes
# ===========================================================================


class TestLLMErrorAttributes:
    """``code`` and ``retry_after_s`` keywords, user-facing rule, ``retryable``."""

    def test_llm_error_coded_keeps_code_retry_after_and_status(self) -> None:
        """All attributes are stored as given."""
        err = LLMError("Acme is busy.", 429, code="rate_limited", retry_after_s=2.0)
        assert err.message == "Acme is busy."
        assert err.status_code == 429
        assert _code(err) == "rate_limited"
        assert _retry_after(err) == 2.0

    @pytest.mark.parametrize("code", sorted(_ALL_CODES))
    def test_llm_error_code_makes_error_user_facing(self, code: str) -> None:
        """A coded error is user-facing even without user_facing=True."""
        err = LLMError("Fixed text.", code=code)
        assert _code(err) == code
        assert err.user_facing is True

    def test_llm_error_code_overrides_user_facing_false(self) -> None:
        """code given => user_facing is True, even when user_facing=False is passed."""
        err = LLMError("Fixed text.", code="timeout", user_facing=False)
        assert _code(err) == "timeout"
        assert err.user_facing is True

    def test_llm_error_uncoded_user_facing_stays_valid(self) -> None:
        """LLMError("x", user_facing=True) without a code: code None, not retryable."""
        err = LLMError("Friendly text.", user_facing=True)
        assert err.user_facing is True
        assert _code(err) is None
        assert _retry_after(err) is None
        assert getattr(err, "retryable", _MISSING) is False

    def test_llm_error_defaults_are_uncoded_internal_not_retryable(self) -> None:
        """A bare LLMError (even with a 5xx status) has no code and isn't retryable."""
        err = LLMError("internal", 503)
        assert err.user_facing is False
        assert _code(err) is None
        assert _retry_after(err) is None
        assert getattr(err, "retryable", _MISSING) is False

    @pytest.mark.parametrize("code", sorted(_ALL_CODES))
    def test_llm_error_retryable_exactly_for_transient_codes(self, code: str) -> None:
        """retryable is True for provider_unavailable / rate_limited / timeout only."""
        err = LLMError("Fixed text.", code=code)
        assert getattr(err, "retryable", _MISSING) is (code in _RETRYABLE_CODES)


# ===========================================================================
# Catalogue helpers
# ===========================================================================


class TestCatalogueHelpers:
    """not_configured_error / missing_model_error / provider_status_error codes."""

    def test_not_configured_error_has_not_configured_code(self) -> None:
        """A missing credential is code not_configured, user-facing, not retryable."""
        err = llm_mod.not_configured_error("Acme", "ACME_API_KEY")
        assert _code(err) == "not_configured"
        assert err.user_facing is True
        assert getattr(err, "retryable", _MISSING) is False

    def test_missing_model_error_has_missing_model_code(self) -> None:
        """A missing model is code missing_model, user-facing, not retryable."""
        err = llm_mod.missing_model_error("Acme")
        assert _code(err) == "missing_model"
        assert err.user_facing is True
        assert getattr(err, "retryable", _MISSING) is False

    def test_provider_status_error_timed_out_is_timeout(self) -> None:
        """timed_out=True (no status) is code timeout, retryable."""
        err = llm_mod.provider_status_error("Acme", None, timed_out=True)
        assert _code(err) == "timeout"
        assert err.status_code is None
        assert err.user_facing is True
        assert getattr(err, "retryable", _MISSING) is True

    def test_provider_status_error_no_status_is_provider_unavailable(self) -> None:
        """A transport failure (status None) is code provider_unavailable."""
        err = llm_mod.provider_status_error("Acme", None)
        assert _code(err) == "provider_unavailable"
        assert err.status_code is None
        assert err.user_facing is True

    @pytest.mark.parametrize("status", [401, 403])
    def test_provider_status_error_auth_with_key_env_is_not_configured(self, status: int) -> None:
        """401/403 for a keyed provider is code not_configured, status kept."""
        err = llm_mod.provider_status_error("Acme", status, key_env="ACME_API_KEY")
        assert _code(err) == "not_configured"
        assert err.status_code == status
        assert err.user_facing is True

    @pytest.mark.parametrize("status", [401, 403])
    def test_provider_status_error_auth_without_key_env_is_internal(self, status: int) -> None:
        """401/403 for a keyless provider stays internal: code None, not user-facing."""
        err = llm_mod.provider_status_error("Acme", status)
        assert _code(err) is None
        assert err.user_facing is False
        assert err.status_code == status

    @pytest.mark.parametrize("key_env", [None, "ACME_API_KEY"])
    def test_provider_status_error_404_is_missing_model(self, key_env: str | None) -> None:
        """404 is code missing_model."""
        err = llm_mod.provider_status_error("Acme", 404, key_env=key_env)
        assert _code(err) == "missing_model"
        assert err.status_code == 404
        assert err.user_facing is True

    def test_provider_status_error_429_is_rate_limited_with_retry_after(self) -> None:
        """429 is code rate_limited and carries retry_after_s."""
        err = llm_mod.provider_status_error("Acme", 429, retry_after_s=2.5)
        assert _code(err) == "rate_limited"
        assert err.status_code == 429
        assert _retry_after(err) == 2.5
        assert err.user_facing is True

    def test_provider_status_error_429_without_retry_after_is_none(self) -> None:
        """429 without a Retry-After has retry_after_s None."""
        err = llm_mod.provider_status_error("Acme", 429)
        assert _code(err) == "rate_limited"
        assert _retry_after(err) is None

    @pytest.mark.parametrize("status", [500, 502, 503, 529])
    def test_provider_status_error_5xx_is_provider_unavailable_with_retry_after(
        self, status: int
    ) -> None:
        """5xx is code provider_unavailable and carries retry_after_s."""
        err = llm_mod.provider_status_error("Acme", status, retry_after_s=4.0)
        assert _code(err) == "provider_unavailable"
        assert err.status_code == status
        assert _retry_after(err) == 4.0
        assert err.user_facing is True

    def test_provider_status_error_zero_retry_after_is_kept(self) -> None:
        """retry_after_s=0.0 is a value ("retry now"), not a missing one."""
        err = llm_mod.provider_status_error("Acme", 503, retry_after_s=0.0)
        assert _retry_after(err) == 0.0

    @pytest.mark.parametrize("status", [400, 413])
    def test_provider_status_error_context_too_long_flag_on_400_or_413(self, status: int) -> None:
        """context_too_long=True with 400 or 413 is code context_too_long."""
        err = llm_mod.provider_status_error("Acme", status, context_too_long=True)
        assert _code(err) == "context_too_long"
        assert err.status_code == status
        assert err.user_facing is True
        assert getattr(err, "retryable", _MISSING) is False

    def test_provider_status_error_context_flag_ignored_for_other_status(self) -> None:
        """context_too_long=True with a 422 is still internal (code None)."""
        err = llm_mod.provider_status_error("Acme", 422, context_too_long=True)
        assert _code(err) is None
        assert err.user_facing is False

    @pytest.mark.parametrize("status", [400, 409, 413, 418, 422])
    def test_provider_status_error_other_status_is_internal_fixed_message(
        self, status: int
    ) -> None:
        """Other statuses: code None, not user-facing, the fixed status line as message."""
        err = llm_mod.provider_status_error("Acme", status, key_env="ACME_API_KEY")
        assert _code(err) is None
        assert err.user_facing is False
        assert err.status_code == status
        assert err.message == f"Acme API returned HTTP {status}"

    def test_provider_status_error_internal_message_used_for_uncoded(self) -> None:
        """internal_message replaces the status line for uncoded statuses."""
        err = llm_mod.provider_status_error("Acme", 400, internal_message="Acme discovery failed")
        assert _code(err) is None
        assert err.message == "Acme discovery failed"


# ===========================================================================
# parse_retry_after
# ===========================================================================


class TestParseRetryAfter:
    """Retry-After / retry-after-ms parsing (seconds, ms, HTTP-date)."""

    @pytest.mark.parametrize(
        ("value", "expected"),
        [("1500", 1.5), ("250", 0.25), ("0", 0.0), ("2500.0", 2.5)],
    )
    def test_parse_retry_after_ms_converted_to_seconds(self, value: str, expected: float) -> None:
        """retry-after-ms is milliseconds, returned as seconds."""
        result = llm_mod.parse_retry_after({"retry-after-ms": value})
        assert result == pytest.approx(expected)
        assert isinstance(result, float)

    def test_parse_retry_after_ms_wins_over_seconds(self) -> None:
        """retry-after-ms takes precedence over retry-after."""
        headers = {"retry-after": "10", "retry-after-ms": "250"}
        assert llm_mod.parse_retry_after(headers) == pytest.approx(0.25)

    @pytest.mark.parametrize(
        ("value", "expected"),
        [("3", 3.0), ("2.5", 2.5), ("0", 0.0), ("120", 120.0)],
    )
    def test_parse_retry_after_seconds(self, value: str, expected: float) -> None:
        """retry-after as int or float seconds (not capped here)."""
        result = llm_mod.parse_retry_after({"retry-after": value})
        assert result == pytest.approx(expected)
        assert isinstance(result, float)

    def test_parse_retry_after_http_date_in_future(self) -> None:
        """An HTTP-date 7 s after ``now`` is 7 s."""
        header = email.utils.format_datetime(_NOW + timedelta(seconds=7), usegmt=True)
        result = llm_mod.parse_retry_after({"retry-after": header}, now=_NOW)
        assert result == pytest.approx(7.0)

    def test_parse_retry_after_http_date_in_past_is_zero(self) -> None:
        """An HTTP-date before ``now`` is clamped to 0.0."""
        header = email.utils.format_datetime(_NOW - timedelta(seconds=30), usegmt=True)
        assert llm_mod.parse_retry_after({"retry-after": header}, now=_NOW) == 0.0

    def test_parse_retry_after_http_date_default_now(self) -> None:
        """Without ``now`` the current time is used (a 2015 date is in the past)."""
        headers = {"retry-after": "Wed, 21 Oct 2015 07:28:00 GMT"}
        assert llm_mod.parse_retry_after(headers) == 0.0

    @pytest.mark.parametrize(
        ("headers", "expected"),
        [
            pytest.param({"Retry-After": "3"}, 3.0, id="title-case-seconds"),
            pytest.param({"RETRY-AFTER-MS": "250"}, 0.25, id="upper-case-ms"),
            pytest.param({"Retry-After": "9", "Retry-After-Ms": "500"}, 0.5, id="mixed-ms-wins"),
            pytest.param(httpx.Headers({"Retry-After": "4"}), 4.0, id="httpx-headers"),
        ],
    )
    def test_parse_retry_after_header_names_case_insensitive(
        self, headers: Any, expected: float
    ) -> None:
        """Header names match case-insensitively, also in a plain dict."""
        assert llm_mod.parse_retry_after(headers) == pytest.approx(expected)

    @pytest.mark.parametrize(
        "headers",
        [
            pytest.param(None, id="none"),
            pytest.param({}, id="empty"),
            pytest.param({"x-ratelimit-reset": "3"}, id="unrelated-header"),
            pytest.param({"retry-after": "-1"}, id="negative"),
            pytest.param({"retry-after": "-0.5"}, id="negative-float"),
            pytest.param({"retry-after": "nan"}, id="nan"),
            pytest.param({"retry-after": "NaN"}, id="nan-mixed-case"),
            pytest.param({"retry-after": "inf"}, id="inf"),
            pytest.param({"retry-after": "-inf"}, id="minus-inf"),
            pytest.param({"retry-after": "Infinity"}, id="infinity"),
            pytest.param({"retry-after": "soon"}, id="garbage"),
            pytest.param({"retry-after": ""}, id="blank"),
            pytest.param({"retry-after-ms": "-5"}, id="ms-negative"),
            pytest.param({"retry-after-ms": "nan"}, id="ms-nan"),
            pytest.param({"retry-after-ms": "inf"}, id="ms-inf"),
            pytest.param({"retry-after-ms": "abc"}, id="ms-garbage"),
        ],
    )
    def test_parse_retry_after_unusable_is_none(self, headers: Any) -> None:
        """Missing, negative, NaN, infinite or garbage values give None."""
        assert llm_mod.parse_retry_after(headers, now=_NOW) is None


# ===========================================================================
# is_context_too_long
# ===========================================================================


class TestIsContextTooLong:
    """400/413 classification by status, body error code and message."""

    @pytest.mark.parametrize(
        ("status", "error_code", "message"),
        [
            pytest.param(413, None, None, id="413-no-detail"),
            pytest.param(413, "request_too_large", "Request entity too large", id="413-detail"),
            pytest.param(400, "context_length_exceeded", None, id="400-code-no-message"),
            pytest.param(400, "context_length_exceeded", "Request rejected", id="400-code"),
            pytest.param(400, None, "This request exceeds the context length", id="context-length"),
            pytest.param(400, None, "error: CONTEXT_LENGTH", id="context_length-upper"),
            pytest.param(400, "invalid_request_error", "Exceeds the Maximum Context", id="max-ctx"),
            pytest.param(400, None, "Context window exceeded", id="context-window"),
            pytest.param(400, None, "prompt is too long: 210000 tokens > 200000", id="prompt"),
            pytest.param(400, None, "Input is too long for requested model.", id="input"),
            pytest.param(400, None, "Too Many Tokens in the request", id="too-many-tokens"),
        ],
    )
    def test_is_context_too_long_true(
        self, status: int, error_code: str | None, message: str | None
    ) -> None:
        """413, 400 + context_length_exceeded, or 400 + a context phrase (any case)."""
        assert llm_mod.is_context_too_long(status, error_code, message) is True

    @pytest.mark.parametrize(
        ("status", "error_code", "message"),
        [
            pytest.param(400, None, None, id="400-no-detail"),
            pytest.param(400, "invalid_value", "Invalid value for temperature", id="400-other"),
            pytest.param(400, "invalid_request_error", "messages: field required", id="400-ant"),
            pytest.param(422, "context_length_exceeded", "prompt is too long", id="422"),
            pytest.param(500, None, "context length exceeded", id="500"),
            pytest.param(429, None, "too many tokens per minute", id="429"),
            pytest.param(404, "context_length_exceeded", None, id="404-code"),
            pytest.param(None, "context_length_exceeded", "prompt is too long", id="no-status"),
        ],
    )
    def test_is_context_too_long_false(
        self, status: int | None, error_code: str | None, message: str | None
    ) -> None:
        """Other statuses, or a 400 without a context code or phrase, are not context errors."""
        assert llm_mod.is_context_too_long(status, error_code, message) is False


# ===========================================================================
# Provider clients
# ===========================================================================


class TestClientProviderAttribute:
    """Each client class names its provider."""

    @pytest.mark.parametrize(
        ("cls", "provider"),
        [
            (InfomaniakClient, "infomaniak"),
            (VLLMClient, "vllm"),
            (OpenAIClient, "openai"),
            (AnthropicClient, "anthropic"),
        ],
        ids=["infomaniak", "vllm", "openai", "anthropic"],
    )
    def test_client_provider_class_attribute(self, cls: type[Any], provider: str) -> None:
        """The class attribute ``provider`` holds the provider name."""
        assert getattr(cls, "provider", _MISSING) == provider


class TestClientSdkFailureCodes:
    """SDK timeouts, connection errors and HTTP statuses map to the error codes."""

    @pytest.mark.parametrize(("kind", "failure"), _CLIENT_FAILURES)
    async def test_client_sdk_failure_maps_to_error_code(
        self, kind: str, failure: _Failure, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The raised LLMError has the mapped code, is user-facing iff coded, keeps the status."""
        err = await _raise_failure(kind, failure, monkeypatch)
        expected = _expected_code(kind, failure)
        assert _code(err) == expected
        assert err.user_facing is (expected is not None)
        assert err.status_code == failure.status

    @pytest.mark.parametrize(("kind", "failure"), _RETRY_AFTER_FAILURES)
    async def test_client_transient_status_carries_retry_after(
        self, kind: str, failure: _Failure, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """429/5xx carry retry_after_s from the response headers (None without one)."""
        err = await _raise_failure(kind, failure, monkeypatch)
        assert _retry_after(err) == failure.retry_after_s

    @pytest.mark.parametrize(("kind", "failure"), _CLIENT_FAILURES)
    async def test_client_error_never_carries_provider_text(
        self,
        kind: str,
        failure: _Failure,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Provider message, body and error code string never reach the LLMError."""
        caplog.set_level(logging.DEBUG)
        err = await _raise_failure(kind, failure, monkeypatch)
        _assert_no_text(err, _CANARY, *(t for t in (failure.body_code,) if t))
        if failure.transport is None:
            # The SDKs DEBUG-log transport exception text themselves; bodies never.
            assert _CANARY not in caplog.text
        code = _code(err)
        assert code is None or code in _ALL_CODES


class TestClientSetupCodes:
    """Missing key / model and Infomaniak setup problems are coded."""

    @pytest.mark.parametrize("kind", ["openai", "anthropic"])
    async def test_sdk_client_missing_key_is_not_configured(
        self, kind: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No API key: code not_configured, no SDK call."""
        client, create = _sdk_client(kind, monkeypatch, with_key=False)
        with pytest.raises(LLMError) as exc_info:
            await client.chat(_msgs())
        assert _code(exc_info.value) == "not_configured"
        assert exc_info.value.user_facing is True
        create.assert_not_awaited()

    @pytest.mark.parametrize("kind", ["openai", "vllm", "anthropic"])
    async def test_sdk_client_missing_model_is_missing_model(
        self, kind: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No model: code missing_model, no SDK call."""
        client, create = _sdk_client(kind, monkeypatch, with_model=False)
        with pytest.raises(LLMError) as exc_info:
            await client.chat(_msgs())
        assert _code(exc_info.value) == "missing_model"
        assert exc_info.value.user_facing is True
        create.assert_not_awaited()

    @pytest.mark.parametrize("stream", [False, True], ids=["chat", "stream"])
    async def test_infomaniak_missing_token_is_not_configured(
        self, stream: bool, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No INFOMANIAK_API_TOKEN: code not_configured, no request."""
        fake = _install_infomaniak(monkeypatch)
        monkeypatch.delenv("INFOMANIAK_API_TOKEN")
        err = await _infomaniak_error(InfomaniakClient(_config("infomaniak")), stream=stream)
        assert _code(err) == "not_configured"
        assert fake.paths == []

    async def test_infomaniak_missing_model_is_missing_model(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No infomaniak_model: code missing_model."""
        _install_infomaniak(monkeypatch)
        client = InfomaniakClient(_config("infomaniak", infomaniak_model=None))
        err = await _infomaniak_error(client)
        assert _code(err) == "missing_model"

    @pytest.mark.parametrize("bad_id", ["12/../x", "abc", "-5"])
    async def test_infomaniak_non_digit_product_id_is_not_configured(
        self, bad_id: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A non-digit INFOMANIAK_PRODUCT_ID: code not_configured, nothing product-scoped sent."""
        fake = _install_infomaniak(monkeypatch)
        monkeypatch.setenv("INFOMANIAK_PRODUCT_ID", bad_id)
        err = await _infomaniak_error(InfomaniakClient(_config("infomaniak")))
        assert _code(err) == "not_configured"
        assert err.user_facing is True
        assert [p for p in fake.paths if p.startswith("/2/")] == []

    @pytest.mark.parametrize(
        "products",
        [pytest.param((), id="no-product"), pytest.param((1, 2), id="several-products")],
    )
    async def test_infomaniak_discovery_product_problem_is_not_configured(
        self, products: tuple[int, ...], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Discovery finding no product or several products: code not_configured."""
        fake = _install_infomaniak(monkeypatch)
        monkeypatch.delenv("INFOMANIAK_PRODUCT_ID")
        fake.discovery = _ik_discovery(*(_ik_product(p) for p in products))
        err = await _infomaniak_error(InfomaniakClient(_config("infomaniak")))
        assert _code(err) == "not_configured"
        assert err.user_facing is True


class TestVLLMConnectionMessage:
    """vLLM keeps its local "starting or unavailable" text for connection errors."""

    async def test_vllm_connection_error_keeps_starting_message_with_code(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Connection error: code provider_unavailable, message says starting / unavailable."""
        err = await _raise_failure("vllm", _CONNECTION, monkeypatch)
        assert _code(err) == "provider_unavailable"
        assert "starting" in err.message.lower()
        assert "unavailable" in err.message.lower()


class TestInfomaniakMidStreamCodes:
    """A stream that breaks after a delta maps through the catalogue too."""

    @pytest.mark.parametrize(
        ("exc_type", "code"),
        [
            (httpx.ReadTimeout, "timeout"),
            (httpx.ReadError, "provider_unavailable"),
            (httpx.RemoteProtocolError, "provider_unavailable"),
        ],
        ids=["read-timeout", "read-error", "peer-closed"],
    )
    async def test_infomaniak_stream_failure_after_delta_maps_to_code(
        self,
        exc_type: type[httpx.TransportError],
        code: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Timeout mid-stream is timeout; other transport failures are provider_unavailable."""
        fake = _install_infomaniak(monkeypatch)
        fake.chat = _ik_failing_stream(exc_type)
        client = InfomaniakClient(_config("infomaniak"))
        received: list[Any] = []
        try:
            with pytest.raises(LLMError) as exc_info:
                async for item in client.chat_stream(_msgs()):
                    received.append(item)
        finally:
            await client.close()
        assert [i.content for i in received if isinstance(i, LLMStreamDelta)] == ["Hel"]
        err = exc_info.value
        assert _code(err) == code
        assert err.user_facing is True
        assert err.status_code is None
        _assert_no_text(err, _CANARY)
