"""Per-call output cap on the LLM clients and the model policy (GH-179 contract section 1).

The chat-title call of GH-179 asks the chat's model for a short title with a small
output limit (``chat_titles.TITLE_MAX_TOKENS``). That limit is a new keyword
``max_tokens: int | None = None`` on ``LLMClient.chat`` (the protocol in ``admino.llm``
and ``InfomaniakClient``, ``VLLMClient``, ``OpenAIClient``, ``AnthropicClient``) and on
``llm_policy.chat``:

- ``max_tokens=None`` (or omitted): the request is exactly today's, its cap is the
  configured ``max_response_tokens``.
- an int >= 1: the request's cap is ``min(max_tokens, configured cap)``. Infomaniak sends
  it as ``max_completion_tokens``, vLLM / OpenAI / Anthropic as ``max_tokens``. Nothing
  else in the request changes: Infomaniak keeps ``reasoning_effort: "none"`` (the #142
  reasoning-off mechanism) and ``stream: false``, there is no ``tools`` key without
  tools, and no identifier (``user``, ``safety_identifier``, ``prompt_cache_key``,
  ``metadata``, OpenAI organization / project headers) is ever sent.
- anything else (< 1, a bool, a str, a float): ``ValueError`` before any request.
- ``llm_policy.chat`` passes ``max_tokens`` to the client on every attempt (retries
  included) only when it isn't None, so clients and fakes without the keyword keep
  working; the ``max_retries`` check and the residency guard still run before any call.
- The agent's own LLM calls never pass ``max_tokens``.

How: each client is built from a real ``LLMConfig`` (configured cap 1024) and driven
against a fake wire: ``httpx.AsyncClient.send`` is replaced by a recorder that every SDK
request goes through, so the tests compare what would really be sent (method, URL,
headers, JSON body). No request leaves the process. The policy and agent tests use
recording stand-in clients.

Security notes: every key, token and identifier here is a fixed fake value; the OpenAI
account identifiers the SDK would read from the environment are canaries that must
never appear in a request.
"""

from __future__ import annotations

import inspect
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final
from uuid import UUID

import httpx
import pytest
from pydantic import BaseModel, Field

from admino import llm_policy
from admino.access import Principal
from admino.agent import Agent
from admino.config import LLMConfig
from admino.llm import LLMClient, LLMError, LLMResponse
from admino.llm_anthropic import AnthropicClient
from admino.llm_infomaniak import InfomaniakClient
from admino.llm_openai import OpenAIClient
from admino.llm_vllm import VLLMClient
from admino.models import AgentConfig, LLMMessage, ToolCall, ToolPolicy
from admino.permissions import PermissionsConfig, ToolPermissions
from admino.tools.registry import clear_registry, register_tool

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Generator

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROVIDERS: Final[tuple[str, ...]] = ("infomaniak", "vllm", "openai", "anthropic")

# The configured output cap (LLMConfig.max_response_tokens) of every client here.
_CAP: Final = 1024
_TITLE_CAP: Final = 40

_MODELS: Final[dict[str, str]] = {
    "infomaniak": "Qwen/Qwen3.5-397B-A17B-FP8",
    "vllm": "Qwen/Qwen3-4B-Instruct-2507",
    "openai": "gpt-4o",
    "anthropic": "claude-sonnet-4-6",
}
# The wire name of the output cap per provider.
_CAP_KEY: Final[dict[str, str]] = {
    "infomaniak": "max_completion_tokens",
    "vllm": "max_tokens",
    "openai": "max_tokens",
    "anthropic": "max_tokens",
}
_PRODUCT_ID: Final = "7539"

# OpenAI account identifiers the SDK would read from the environment.
_ORG_CANARY: Final = "org-CANARY-ORG-179"
_PROJECT_CANARY: Final = "proj-CANARY-PROJ-179"
_IDENTIFIER_BODY_KEYS: Final = frozenset(
    {"user", "metadata", "safety_identifier", "prompt_cache_key", "store"}
)
_ACCOUNT_HEADERS: Final = frozenset({"openai-organization", "openai-project"})

# A title-shaped conversation: one system prompt, one user message with the excerpt.
_TITLE_SYSTEM: Final = "Reply with a short title for this chat, nothing else."
_TITLE_USER: Final = "User:\nHow do I renew my Swiss passport?\n\nAssistant:\nYou can apply online."

_ECHO_TOOL: Final[dict[str, Any]] = {
    "type": "function",
    "function": {
        "name": "echo.say",
        "description": "Say a short text back",
        "parameters": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    },
}

# Not a valid per-call cap: ValueError before any request (contract section 1).
_INVALID_CAPS: Final[dict[str, object]] = {
    "zero": 0,
    "negative": -1,
    "bool_true": True,
    "str": "40",
    "float": 1.5,
}

# A keyword the caller did not pass (distinct from an explicit None).
_UNSET: Final = object()

_PRINCIPAL: Final = Principal(
    user_id=UUID("7e1e0179-4c0d-4e11-8a11-c0ffee000179"),
    kind="member",
    org_id=UUID("7e1e0179-4c0d-4e11-8a11-c0ffee000180"),
    role="editor",
)


def _title_messages() -> list[LLMMessage]:
    """A fresh title-shaped message list (system + user)."""
    return [
        LLMMessage(role="system", content=_TITLE_SYSTEM),
        LLMMessage(role="user", content=_TITLE_USER),
    ]


def _expected_body(provider: str, cap: int) -> dict[str, Any]:
    """The exact JSON body each provider sends for ``_title_messages()`` without tools."""
    openai_messages = [
        {"role": "system", "content": _TITLE_SYSTEM},
        {"role": "user", "content": _TITLE_USER},
    ]
    if provider == "infomaniak":
        return {
            "model": _MODELS[provider],
            "messages": openai_messages,
            "max_completion_tokens": cap,
            "reasoning_effort": "none",
            "stream": False,
        }
    if provider == "anthropic":
        return {
            "model": _MODELS[provider],
            "messages": [{"role": "user", "content": _TITLE_USER}],
            "max_tokens": cap,
            "system": _TITLE_SYSTEM,
        }
    return {"model": _MODELS[provider], "messages": openai_messages, "max_tokens": cap}


# ---------------------------------------------------------------------------
# The fake wire
# ---------------------------------------------------------------------------


def _openai_reply() -> dict[str, Any]:
    """An OpenAI-compatible ``chat.completion`` body with a short text answer."""
    return {
        "id": "chatcmpl-179",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": "wire-model",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "Swiss passport renewal"},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 12, "completion_tokens": 3, "total_tokens": 15},
    }


def _anthropic_reply() -> dict[str, Any]:
    """An Anthropic ``message`` body with a short text answer."""
    return {
        "id": "msg_179",
        "type": "message",
        "role": "assistant",
        "model": _MODELS["anthropic"],
        "content": [{"type": "text", "text": "Swiss passport renewal"}],
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 12, "output_tokens": 3},
    }


@dataclass(frozen=True)
class _Sent:
    """One recorded outgoing request."""

    method: str
    url: str
    headers: tuple[tuple[str, str], ...]
    body: bytes

    def json_body(self) -> dict[str, Any]:
        """The JSON request body."""
        payload = json.loads(self.body)
        assert isinstance(payload, dict)
        return payload

    def header_names(self) -> set[str]:
        """The lower-cased header names."""
        return {name.lower() for name, _ in self.headers}

    def comparable(self) -> tuple[str, str, dict[str, str]]:
        """Method, URL and headers, without the body-dependent content-length."""
        headers = {
            name.lower(): value for name, value in self.headers if name.lower() != "content-length"
        }
        return self.method, self.url, headers

    def everything(self) -> str:
        """URL, every header and the body, lower-cased, for canary scans."""
        parts = [
            self.method,
            self.url,
            *(f"{name}: {value}" for name, value in self.headers),
            self.body.decode("utf-8", errors="replace"),
        ]
        return "\n".join(parts).lower()


class _Wire:
    """Stands in for the network behind ``httpx.AsyncClient.send``: records and answers."""

    def __init__(self) -> None:
        self.sent: list[_Sent] = []

    def leaked(self, *needles: str) -> list[str]:
        """The needles (case-insensitive) found anywhere in any recorded request."""
        haystacks = [sent.everything() for sent in self.sent]
        return [needle for needle in needles if any(needle.lower() in h for h in haystacks)]

    async def send(self, request: httpx.Request) -> httpx.Response:
        """Record ``request`` and answer it with a canned reply of its wire format."""
        body = await request.aread()
        self.sent.append(
            _Sent(
                method=request.method,
                url=str(request.url),
                headers=tuple(request.headers.multi_items()),
                body=body,
            )
        )
        if request.url.path.endswith("/v1/messages"):
            return httpx.Response(200, json=_anthropic_reply(), request=request)
        if request.url.path.endswith("/chat/completions"):
            return httpx.Response(200, json=_openai_reply(), request=request)
        return httpx.Response(404, json={"error": "unexpected path"}, request=request)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _provider_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every provider configured; the OpenAI account identifiers set to canaries."""
    monkeypatch.setenv("INFOMANIAK_API_TOKEN", "ik-wire-token-179")
    monkeypatch.setenv("INFOMANIAK_PRODUCT_ID", _PRODUCT_ID)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-wire-179")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-wire-179")
    monkeypatch.setenv("OPENAI_ORG_ID", _ORG_CANARY)
    monkeypatch.setenv("OPENAI_PROJECT_ID", _PROJECT_CANARY)
    for name in ("OPENAI_BASE_URL", "ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _clean_registry() -> Generator[None, None, None]:
    """An empty, unfrozen tool registry before and after every test."""
    clear_registry()
    yield
    clear_registry()


@pytest.fixture()
def wire(monkeypatch: pytest.MonkeyPatch) -> _Wire:
    """Route every ``httpx.AsyncClient.send`` through the recording fake wire."""
    fake = _Wire()

    async def send(_client: httpx.AsyncClient, request: httpx.Request, **_: Any) -> httpx.Response:
        return await fake.send(request)

    monkeypatch.setattr(httpx.AsyncClient, "send", send)
    return fake


_CLIENT_CLASSES: Final[dict[str, Callable[[LLMConfig], Any]]] = {
    "infomaniak": InfomaniakClient,
    "vllm": VLLMClient,
    "openai": OpenAIClient,
    "anthropic": AnthropicClient,
}


def _config(provider: str) -> LLMConfig:
    """A real LLMConfig selecting ``provider`` (configured cap ``_CAP``)."""
    return LLMConfig(
        provider=provider,
        timeout_s=5,
        max_response_tokens=_CAP,
        infomaniak_model=_MODELS["infomaniak"],
        vllm_model=_MODELS["vllm"],
        vllm_base_url="http://vllm:8000/v1",
        openai_model=_MODELS["openai"],
        anthropic_model=_MODELS["anthropic"],
    )


@pytest.fixture(params=PROVIDERS)
async def provider_client(
    request: pytest.FixtureRequest, wire: _Wire
) -> AsyncIterator[tuple[str, Any]]:
    """``(provider, client)`` for each provider, talking to the fake wire; closed after."""
    provider: str = request.param
    client = _CLIENT_CLASSES[provider](_config(provider))
    yield provider, client
    await client.close()


async def _chat_request(wire: _Wire, client: Any, *args: Any, **kwargs: Any) -> _Sent:
    """Call ``client.chat(*args, **kwargs)`` and return the one request it sent."""
    before = len(wire.sent)
    await client.chat(*args, **kwargs)
    new = wire.sent[before:]
    assert len(new) == 1, f"expected exactly one request, got {len(new)}"
    return new[0]


# ===========================================================================
# 1. The clients: max_tokens=None is today's request
# ===========================================================================


class TestClientDefaultCap:
    """Without a per-call cap, the request is exactly today's."""

    async def test_llm_client_chat_max_tokens_omitted_or_none_sends_todays_request(
        self, provider_client: tuple[str, Any], wire: _Wire
    ) -> None:
        """Omitted and ``max_tokens=None`` both send the configured cap and nothing new."""
        provider, client = provider_client
        omitted = await _chat_request(wire, client, _title_messages())
        explicit_none = await _chat_request(wire, client, _title_messages(), max_tokens=None)
        assert omitted.json_body() == _expected_body(provider, _CAP)
        assert explicit_none.json_body() == omitted.json_body()
        assert explicit_none.comparable() == omitted.comparable()


# ===========================================================================
# 2. The clients: a per-call cap
# ===========================================================================


class TestClientPerCallCap:
    """An int ``max_tokens`` caps the output at ``min(max_tokens, configured cap)``."""

    @pytest.mark.parametrize("max_tokens", [_TITLE_CAP, 1], ids=["title_cap", "minimum"])
    async def test_llm_client_chat_max_tokens_below_configured_cap_is_sent(
        self, provider_client: tuple[str, Any], wire: _Wire, max_tokens: int
    ) -> None:
        """The provider's cap key carries the per-call cap; the rest is today's body."""
        provider, client = provider_client
        sent = await _chat_request(wire, client, _title_messages(), max_tokens=max_tokens)
        body = sent.json_body()
        assert body == _expected_body(provider, max_tokens)
        assert type(body[_CAP_KEY[provider]]) is int

    @pytest.mark.parametrize("max_tokens", [_CAP + 1, 1_000_000], ids=["just_above", "huge"])
    async def test_llm_client_chat_max_tokens_above_configured_cap_keeps_configured_cap(
        self, provider_client: tuple[str, Any], wire: _Wire, max_tokens: int
    ) -> None:
        """A per-call cap never raises the configured one (no error either)."""
        provider, client = provider_client
        sent = await _chat_request(wire, client, _title_messages(), max_tokens=max_tokens)
        assert sent.json_body() == _expected_body(provider, _CAP)

    async def test_llm_client_chat_max_tokens_changes_only_the_cap(
        self, provider_client: tuple[str, Any], wire: _Wire
    ) -> None:
        """With tools too, the capped request differs from today's in the cap value only."""
        provider, client = provider_client
        baseline = await _chat_request(wire, client, _title_messages(), tools=[_ECHO_TOOL])
        capped = await _chat_request(
            wire, client, _title_messages(), tools=[_ECHO_TOOL], max_tokens=_TITLE_CAP
        )
        assert "tools" in baseline.json_body()
        assert capped.json_body() == {**baseline.json_body(), _CAP_KEY[provider]: _TITLE_CAP}
        assert capped.comparable() == baseline.comparable()


# ===========================================================================
# 3. The clients: an invalid per-call cap
# ===========================================================================


class TestClientInvalidCap:
    """A cap below 1, a bool or a non-int is refused before any request."""

    @pytest.mark.parametrize("value", list(_INVALID_CAPS.values()), ids=list(_INVALID_CAPS))
    async def test_llm_client_chat_invalid_max_tokens_raises_value_error_without_request(
        self, provider_client: tuple[str, Any], wire: _Wire, value: object
    ) -> None:
        """ValueError (not TypeError, not an LLMError) and nothing reaches the wire."""
        _provider, client = provider_client
        with pytest.raises(ValueError):
            await client.chat(_title_messages(), max_tokens=value)
        assert wire.sent == []


# ===========================================================================
# 4. The title-shaped request: reasoning off, no tools, no identifiers
# ===========================================================================


class TestTitleShapedRequest:
    """What a title call (system + user, no tools, cap 40) puts on the wire."""

    async def test_llm_infomaniak_title_request_disables_reasoning_without_tools(
        self, wire: _Wire
    ) -> None:
        """Infomaniak keeps reasoning_effort "none" and stream false; no tools, no ids."""
        client = InfomaniakClient(_config("infomaniak"))
        try:
            sent = await _chat_request(
                wire, client, _title_messages(), tools=None, max_tokens=_TITLE_CAP
            )
        finally:
            await client.close()
        body = sent.json_body()
        assert body["reasoning_effort"] == "none"
        assert body["stream"] is False
        assert body["max_completion_tokens"] == _TITLE_CAP
        assert "max_tokens" not in body
        assert "tools" not in body
        assert "tool_choice" not in body
        assert not body.keys() & _IDENTIFIER_BODY_KEYS

    async def test_llm_client_title_request_sends_no_identifiers(
        self, provider_client: tuple[str, Any], wire: _Wire
    ) -> None:
        """No identifier body key, no OpenAI account header, no canary anywhere."""
        _provider, client = provider_client
        sent = await _chat_request(
            wire, client, _title_messages(), tools=None, max_tokens=_TITLE_CAP
        )
        assert not sent.json_body().keys() & _IDENTIFIER_BODY_KEYS
        assert not sent.header_names() & _ACCOUNT_HEADERS
        assert wire.leaked(_ORG_CANARY, _PROJECT_CANARY) == []


# ===========================================================================
# 5. Signatures (the protocol, the clients, the policy)
# ===========================================================================

_CHAT_FUNCTIONS: Final[dict[str, Callable[..., Any]]] = {
    "protocol": LLMClient.chat,
    "infomaniak": InfomaniakClient.chat,
    "vllm": VLLMClient.chat,
    "openai": OpenAIClient.chat,
    "anthropic": AnthropicClient.chat,
    "llm_policy": llm_policy.chat,
}


class TestSignatures:
    """``max_tokens`` is a keyword-only parameter defaulting to None everywhere."""

    @pytest.mark.parametrize("name", list(_CHAT_FUNCTIONS))
    def test_llm_chat_signature_max_tokens_keyword_only_default_none(self, name: str) -> None:
        """The protocol, each client and ``llm_policy.chat`` take ``*, max_tokens=None``."""
        parameters = inspect.signature(_CHAT_FUNCTIONS[name]).parameters
        assert "max_tokens" in parameters
        assert parameters["max_tokens"].kind is inspect.Parameter.KEYWORD_ONLY
        assert parameters["max_tokens"].default is None


# ===========================================================================
# 6. llm_policy.chat
# ===========================================================================


class RecordingClient:
    """Stand-in client: each ``chat`` returns or raises the next scripted item.

    Records ``(messages, tools, max_tokens)`` per call; ``max_tokens`` is
    ``_UNSET`` when the caller did not pass the keyword.
    """

    def __init__(
        self, script: list[LLMResponse | BaseException], *, provider: str = "infomaniak"
    ) -> None:
        self._script = list(script)
        self.provider = provider
        self.calls: list[tuple[object, object, object]] = []

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
        max_tokens: object = _UNSET,
    ) -> LLMResponse:
        self.calls.append((messages, tools, max_tokens))
        item = self._script[min(len(self.calls), len(self._script)) - 1]
        if isinstance(item, BaseException):
            raise item
        return item


class LegacyClient:
    """Stand-in client whose ``chat`` has no ``max_tokens`` keyword (today's fakes)."""

    provider = "infomaniak"

    def __init__(self, response: LLMResponse) -> None:
        self._response = response
        self.calls = 0

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = False,
    ) -> LLMResponse:
        self.calls += 1
        return self._response


def _ok(content: str = "Swiss passport renewal") -> LLMResponse:
    return LLMResponse(content=content, tool_calls=[], model="m", done=True)


@pytest.fixture()
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Record every ``llm_policy._sleep`` delay instead of sleeping; ``_random`` is 0.5."""
    slept: list[float] = []

    async def fake_sleep(delay: float) -> None:
        slept.append(delay)

    monkeypatch.setattr(llm_policy, "_sleep", fake_sleep)
    monkeypatch.setattr(llm_policy, "_random", lambda: 0.5)
    return slept


class TestPolicyChat:
    """``llm_policy.chat`` forwards a per-call cap and nothing else changes."""

    async def test_llm_policy_chat_max_tokens_omitted_or_none_does_not_pass_keyword(
        self,
    ) -> None:
        """Omitted and None both call ``client.chat`` without a ``max_tokens`` keyword."""
        client = RecordingClient([_ok()])
        messages = _title_messages()
        await llm_policy.chat(client, messages, None, data_residency=False, max_retries=0)
        await llm_policy.chat(
            client, messages, None, data_residency=False, max_retries=0, max_tokens=None
        )
        assert [call[2] for call in client.calls] == [_UNSET, _UNSET]

    async def test_llm_policy_chat_max_tokens_none_works_with_client_without_keyword(
        self,
    ) -> None:
        """A client whose ``chat`` lacks ``max_tokens`` still answers when it is None."""
        response = _ok()
        client = LegacyClient(response)
        result = await llm_policy.chat(
            client,  # type: ignore[arg-type]
            _title_messages(),
            None,
            data_residency=False,
            max_retries=0,
            max_tokens=None,
        )
        assert result is response
        assert client.calls == 1

    async def test_llm_policy_chat_max_tokens_sent_on_every_attempt(
        self, sleeps: list[float]
    ) -> None:
        """First call and each retry get ``max_tokens=40`` with the same objects."""
        response = _ok()
        client = RecordingClient(
            [
                LLMError("Fixed timeout text.", code="timeout"),
                LLMError("Fixed rate text.", 429, code="rate_limited"),
                response,
            ]
        )
        messages = _title_messages()
        tools = [_ECHO_TOOL]
        result = await llm_policy.chat(
            client,
            messages,
            tools,
            data_residency=False,
            max_retries=2,
            max_tokens=_TITLE_CAP,
        )
        assert result is response
        assert len(sleeps) == 2
        assert [
            (sent_messages is messages, sent_tools is tools, sent_cap)
            for sent_messages, sent_tools, sent_cap in client.calls
        ] == [(True, True, _TITLE_CAP)] * 3
        assert all(type(call[2]) is int for call in client.calls)

    async def test_llm_policy_chat_residency_blocked_before_call_with_max_tokens(
        self,
    ) -> None:
        """A residency org and a non-Swiss client: ``residency_blocked``, no call."""
        client = RecordingClient([_ok()], provider="openai")
        with pytest.raises(LLMError) as excinfo:
            await llm_policy.chat(
                client,
                _title_messages(),
                None,
                data_residency=True,
                max_retries=0,
                max_tokens=_TITLE_CAP,
            )
        assert excinfo.value.code == "residency_blocked"
        assert client.calls == []

    async def test_llm_policy_chat_invalid_max_retries_raises_before_call_with_max_tokens(
        self,
    ) -> None:
        """``max_retries`` outside 0..5 is still a ValueError before any call."""
        client = RecordingClient([_ok()])
        with pytest.raises(ValueError, match="max_retries"):
            await llm_policy.chat(
                client,
                _title_messages(),
                None,
                data_residency=False,
                max_retries=llm_policy.MAX_RETRIES_LIMIT + 1,
                max_tokens=_TITLE_CAP,
            )
        assert client.calls == []


# ===========================================================================
# 7. The agent's own calls
# ===========================================================================


class EchoArgs(BaseModel):
    """Args of the echo test tool."""

    text: str = Field(min_length=1, max_length=100)


async def _echo(args: EchoArgs, **_: object) -> str:
    return f"echo:{args.text}"


class _NoopRecorder:
    """Stand-in ``ToolCallRecorder`` (the audit row is not this file's concern)."""

    async def __call__(self, **_kwargs: Any) -> None:
        return None


class TestAgentCalls:
    """The agent loop never sets a per-call cap: its replies keep the configured one."""

    async def test_agent_run_llm_calls_never_pass_max_tokens(self) -> None:
        """A run with one tool round trip makes two LLM calls, neither with max_tokens."""
        register_tool("echo", "say", "Echo text", EchoArgs)(_echo)
        tool_call = ToolCall(tool="echo", action="say", args={"text": "x"}, tool_call_id="c-1")
        client = RecordingClient(
            [
                LLMResponse(content="", tool_calls=[tool_call], model="m", done=True),
                _ok("done"),
            ]
        )
        agent = Agent(
            llm_client=client,  # type: ignore[arg-type]
            tool_call_recorder=_NoopRecorder(),
            agent_config=AgentConfig(max_tool_calls=5, max_context_messages=20),
        )
        result = await agent.run(
            "hello",
            session_id="s-max-tokens-179",
            history=[],
            principal=_PRINCIPAL,
            tool_policy=ToolPolicy(
                permissions=PermissionsConfig(
                    tools={"echo": ToolPermissions(actions={"say": "allow"})}
                )
            ),
        )
        assert result.status == "final"
        assert [call[2] for call in client.calls] == [_UNSET, _UNSET]
