"""Wire-level spec: no identifiers in provider requests, SDK retries off (GH-242).

Every provider client (``InfomaniakClient``, ``VLLMClient``, ``OpenAIClient``,
``AnthropicClient``) is built from a real ``LLMConfig`` and driven against a fake
wire: ``httpx.AsyncClient.send`` is replaced by a recorder that keeps every
outgoing ``httpx.Request`` (method, URL, headers, body) and answers with a canned
``httpx.Response``. Both SDKs (and Infomaniak's product discovery) send through
``httpx.AsyncClient.send``, so the recorder sees exactly what would hit the
network, and no real request is ever made.

What these tests pin down (contract #242 section 1):

- No identifiers in requests. A ``chat()`` with tools sends only the allowed
  top-level body keys (OpenAI-compatible: model, messages, max_tokens,
  max_completion_tokens, tools, stream, stream_options, reasoning_effort;
  Anthropic: model, messages, max_tokens, system, tools), never ``user``,
  ``metadata``, ``safety_identifier``, ``prompt_cache_key`` or ``store``.
  No ``OpenAI-Organization`` / ``OpenAI-Project`` header is sent even with
  ``OPENAI_ORG_ID`` / ``OPENAI_PROJECT_ID`` set in the environment, and those
  canary values appear nowhere in any request (URL, headers, body). The same
  holds for ``InfomaniakClient.chat_stream`` and for Infomaniak's product
  discovery.
- SDK retries are off everywhere: a 503, a 429 (``retry-after: 0``) and a
  transport timeout each produce exactly ONE chat request per ``chat()`` call,
  and an ``LLMError`` is raised.
- The agent never passes a user/org id, email or name to a client: an
  ``Agent.run`` (with one tool round trip) whose principal has canary ids, and
  a server ``POST /api/message`` whose account has a canary email and name,
  produce requests without any of those strings (ids with or without dashes).

Speed: the SDKs' retry backoff sleep (``AsyncAPIClient._sleep_for_retry``) is
replaced by a no-op, so a client that still retries today fails fast instead of
sleeping.

Security notes:
- Every token, key and identifier here is a fixed fake value.
- The fake wire never forwards anything to a real host.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final
from urllib.parse import unquote

import anthropic._base_client as anthropic_base_client
import httpx
import openai._base_client as openai_base_client
import pytest
from pydantic import BaseModel, Field

from admino.access import Principal
from admino.agent import Agent
from admino.config import LLMConfig
from admino.llm import LLMError
from admino.llm_anthropic import AnthropicClient
from admino.llm_infomaniak import InfomaniakClient
from admino.llm_openai import OpenAIClient
from admino.llm_vllm import VLLMClient
from admino.models import AgentConfig, LLMMessage, ToolPolicy
from admino.permissions import PermissionsConfig, ToolPermissions
from admino.server import create_app
from admino.tools.registry import clear_registry, register_tool
from tests.db_fakes import FakeDb
from tests.tenancy_world import make_client, make_config, use_fake_database, use_roomy_rate_limits

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Generator

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROVIDERS: Final[tuple[str, ...]] = ("infomaniak", "vllm", "openai", "anthropic")

_INFOMANIAK_MODEL: Final = "Qwen/Qwen3.5-397B-A17B-FP8"
_VLLM_MODEL: Final = "Qwen/Qwen3-4B-Instruct-2507"
_OPENAI_MODEL: Final = "gpt-4o"
_ANTHROPIC_MODEL: Final = "claude-sonnet-4-6"
_PRODUCT_ID: Final = "7539"

# OpenAI account identifiers the SDK would read from the environment.
_ORG_CANARY: Final = "org-CANARY-ORG"
_PROJECT_CANARY: Final = "proj-CANARY-PROJ"

# The principal's ids (version-4 UUIDs with a recognisable shape).
_USER_ID: Final = uuid.UUID("5ca1ab1e-0242-4c0d-8e11-c0ffee000001")
_ORG_ID: Final = uuid.UUID("5ca1ab1e-0242-4c0d-8e11-c0ffee000002")
_PRINCIPAL: Final = Principal(user_id=_USER_ID, kind="member", org_id=_ORG_ID, role="editor")

# The server-level account's personal data.
_EMAIL_CANARY: Final = "wire.canary.242@example.ch"
_NAME_CANARY: Final = "Canaria Wirethal"

_SESSION_ID: Final = "s-wire-242"
_SYSTEM_PROMPT: Final = "You are admino."

# Contract #242: the only top-level request body keys each wire format may carry.
_OPENAI_COMPATIBLE_KEYS: Final = frozenset(
    {
        "model",
        "messages",
        "max_tokens",
        "max_completion_tokens",
        "tools",
        "stream",
        "stream_options",
        "reasoning_effort",
    }
)
_ANTHROPIC_KEYS: Final = frozenset({"model", "messages", "max_tokens", "system", "tools"})
_ALLOWED_BODY_KEYS: Final[dict[str, frozenset[str]]] = {
    "infomaniak": _OPENAI_COMPATIBLE_KEYS,
    "vllm": _OPENAI_COMPATIBLE_KEYS,
    "openai": _OPENAI_COMPATIBLE_KEYS,
    "anthropic": _ANTHROPIC_KEYS,
}
_IDENTIFIER_BODY_KEYS: Final = frozenset(
    {"user", "metadata", "safety_identifier", "prompt_cache_key", "store"}
)
_ACCOUNT_HEADERS: Final = frozenset({"openai-organization", "openai-project"})

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

# ---------------------------------------------------------------------------
# Canned provider responses
# ---------------------------------------------------------------------------


def _openai_completion(
    content: str | None = "Hello!",
    *,
    tool_calls: list[dict[str, Any]] | None = None,
    finish_reason: str = "stop",
) -> dict[str, Any]:
    """An OpenAI ``chat.completion`` JSON body."""
    message: dict[str, Any] = {"role": "assistant", "content": content}
    if tool_calls is not None:
        message["tool_calls"] = tool_calls
    return {
        "id": "chatcmpl-wire",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": "wire-model",
        "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
        "usage": {"prompt_tokens": 12, "completion_tokens": 3, "total_tokens": 15},
    }


def _openai_tool_call_completion() -> dict[str, Any]:
    """An OpenAI completion asking for one ``echo.say`` call."""
    call = {
        "id": "call_wire_01",
        "type": "function",
        "function": {"name": "echo.say", "arguments": json.dumps({"text": "hi"})},
    }
    return _openai_completion(None, tool_calls=[call], finish_reason="tool_calls")


def _anthropic_message(content: list[dict[str, Any]], stop_reason: str) -> dict[str, Any]:
    """An Anthropic ``message`` JSON body."""
    return {
        "id": "msg_wire_01",
        "type": "message",
        "role": "assistant",
        "model": _ANTHROPIC_MODEL,
        "content": content,
        "stop_reason": stop_reason,
        "stop_sequence": None,
        "usage": {"input_tokens": 12, "output_tokens": 3},
    }


def _anthropic_text() -> dict[str, Any]:
    """An Anthropic text reply."""
    return _anthropic_message([{"type": "text", "text": "Hello!"}], "end_turn")


def _anthropic_tool_use() -> dict[str, Any]:
    """An Anthropic reply asking for one ``echo.say`` call (``echo__say`` on the wire)."""
    block = {
        "type": "tool_use",
        "id": "toolu_wire_01",
        "name": "echo__say",
        "input": {"text": "hi"},
    }
    return _anthropic_message([block], "tool_use")


def _sse_body() -> bytes:
    """An OpenAI chat-completion SSE stream: two content chunks, a finish, ``[DONE]``."""
    chunks: list[dict[str, Any]] = [
        {
            "id": "chatcmpl-stream",
            "object": "chat.completion.chunk",
            "created": 1_700_000_000,
            "model": "wire-model",
            "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
        }
        for delta, finish in (({"content": "Hel"}, None), ({"content": "lo"}, None), ({}, "stop"))
    ]
    text = "".join(f"data: {json.dumps(chunk)}\n\n" for chunk in chunks) + "data: [DONE]\n\n"
    return text.encode("utf-8")


def _discovery_body() -> dict[str, Any]:
    """Infomaniak's ``GET /1/ai`` answer: exactly one AI product."""
    return {
        "result": "success",
        "data": [{"product_id": int(_PRODUCT_ID), "product_name": "AI", "status": "ok"}],
    }


# ---------------------------------------------------------------------------
# The fake wire
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Sent:
    """One recorded outgoing request."""

    method: str
    url: str
    headers: tuple[tuple[str, str], ...]
    body: bytes

    @property
    def path(self) -> str:
        """The URL path."""
        return httpx.URL(self.url).path

    @property
    def is_chat(self) -> bool:
        """True for a chat request (OpenAI-compatible completions or Anthropic messages)."""
        return self.method == "POST" and self.path.endswith(("/chat/completions", "/v1/messages"))

    def json_body(self) -> dict[str, Any]:
        """The JSON request body."""
        payload = json.loads(self.body)
        assert isinstance(payload, dict)
        return payload

    def header_names(self) -> set[str]:
        """The lower-cased header names."""
        return {name.lower() for name, _ in self.headers}

    def everything(self) -> str:
        """URL (raw and decoded), every header and the body, lower-cased, for canary scans."""
        parts = [
            self.method,
            self.url,
            unquote(self.url),
            *(f"{name}: {value}" for name, value in self.headers),
            self.body.decode("utf-8", errors="replace"),
        ]
        return "\n".join(parts).lower()


class _Wire:
    """Stands in for the network behind ``httpx.AsyncClient.send``.

    ``failure`` makes every chat request fail (``"http_503"``, ``"http_429"``
    or ``"read_timeout"``). ``queue`` holds scripted JSON chat replies, used in
    order before the default reply of the request's wire format.
    """

    def __init__(self) -> None:
        self.sent: list[_Sent] = []
        self.failure: str | None = None
        self.queue: list[dict[str, Any]] = []

    @property
    def chat_requests(self) -> list[_Sent]:
        """The recorded chat requests, in order."""
        return [sent for sent in self.sent if sent.is_chat]

    def leaked(self, *needles: str) -> list[str]:
        """The needles (case-insensitive) found anywhere in any recorded request."""
        haystacks = [sent.everything() for sent in self.sent]
        return [needle for needle in needles if any(needle.lower() in h for h in haystacks)]

    async def send(self, request: httpx.Request) -> httpx.Response:
        """Record ``request`` and answer it."""
        body = await request.aread()
        self.sent.append(
            _Sent(
                method=request.method,
                url=str(request.url),
                headers=tuple(request.headers.multi_items()),
                body=body,
            )
        )
        path = request.url.path
        if request.method == "GET" and path == "/1/ai":
            return httpx.Response(200, json=_discovery_body(), request=request)
        if not self.sent[-1].is_chat:
            return httpx.Response(404, json={"error": "unexpected path"}, request=request)
        if self.failure == "read_timeout":
            msg = "fake wire: read timed out"
            raise httpx.ReadTimeout(msg, request=request)
        if self.failure == "http_503":
            error = {"error": {"message": "overloaded", "type": "server_error"}}
            return httpx.Response(503, json=error, request=request)
        if self.failure == "http_429":
            error = {"error": {"message": "slow down", "type": "rate_limit_error"}}
            return httpx.Response(429, headers={"retry-after": "0"}, json=error, request=request)
        if json.loads(body).get("stream") is True:
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                content=_sse_body(),
                request=request,
            )
        if self.queue:
            return httpx.Response(200, json=self.queue.pop(0), request=request)
        reply = _anthropic_text() if path.endswith("/v1/messages") else _openai_completion()
        return httpx.Response(200, json=reply, request=request)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _provider_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every provider configured; the OpenAI account identifiers set to canaries."""
    monkeypatch.setenv("INFOMANIAK_API_TOKEN", "ik-wire-token-242")
    monkeypatch.setenv("INFOMANIAK_PRODUCT_ID", _PRODUCT_ID)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-wire-242")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-wire-242")
    monkeypatch.setenv("OPENAI_ORG_ID", _ORG_CANARY)
    monkeypatch.setenv("OPENAI_PROJECT_ID", _PROJECT_CANARY)
    for name in ("OPENAI_BASE_URL", "ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _no_sdk_retry_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """A client that still lets its SDK retry fails fast instead of sleeping between tries."""

    async def no_sleep(*_args: Any, **_kwargs: Any) -> None:
        return None

    monkeypatch.setattr(openai_base_client.AsyncAPIClient, "_sleep_for_retry", no_sleep)
    monkeypatch.setattr(anthropic_base_client.AsyncAPIClient, "_sleep_for_retry", no_sleep)


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


def _config(provider: str) -> LLMConfig:
    """A real LLMConfig selecting ``provider`` with a model set."""
    values: dict[str, Any] = {
        "provider": provider,
        "timeout_s": 5,
        "max_response_tokens": 1024,
        "infomaniak_model": _INFOMANIAK_MODEL,
        "vllm_model": _VLLM_MODEL,
        "vllm_base_url": "http://vllm:8000/v1",
        "openai_model": _OPENAI_MODEL,
        "anthropic_model": _ANTHROPIC_MODEL,
    }
    return LLMConfig(**values)


_CLIENT_CLASSES: Final[dict[str, Callable[[LLMConfig], Any]]] = {
    "infomaniak": InfomaniakClient,
    "vllm": VLLMClient,
    "openai": OpenAIClient,
    "anthropic": AnthropicClient,
}


@pytest.fixture()
async def build(wire: _Wire) -> AsyncIterator[Callable[[str], Any]]:
    """Build provider clients on the fake wire; every built client is closed after."""
    built: list[Any] = []

    def factory(provider: str) -> Any:
        client = _CLIENT_CLASSES[provider](_config(provider))
        built.append(client)
        return client

    yield factory
    for client in built:
        await client.close()


def _messages() -> list[LLMMessage]:
    """A system prompt and one user message."""
    return [
        LLMMessage(role="system", content=_SYSTEM_PROMPT),
        LLMMessage(role="user", content="Please say hi"),
    ]


def _id_forms(*ids: uuid.UUID) -> list[str]:
    """Each id as text, with and without dashes."""
    return [form for value in ids for form in (str(value), value.hex)]


# ---------------------------------------------------------------------------
# Request body: only allowed keys, no identifier keys
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("provider", PROVIDERS)
async def test_llm_chat_request_body_keys_are_within_the_allowed_set(
    provider: str, wire: _Wire, build: Callable[[str], Any]
) -> None:
    """A chat with tools sends exactly one request whose top-level keys are all allowed."""
    await build(provider).chat(_messages(), tools=[_ECHO_TOOL])

    assert len(wire.chat_requests) == 1
    body = wire.chat_requests[0].json_body()
    assert "tools" in body, "the tool definitions must be part of the inspected request"
    assert set(body) - _ALLOWED_BODY_KEYS[provider] == set()


@pytest.mark.parametrize("provider", PROVIDERS)
async def test_llm_chat_request_body_has_no_identifier_keys(
    provider: str, wire: _Wire, build: Callable[[str], Any]
) -> None:
    """No user, metadata, safety_identifier, prompt_cache_key or store key is sent."""
    await build(provider).chat(_messages(), tools=[_ECHO_TOOL])

    body = wire.chat_requests[0].json_body()
    assert set(body) & _IDENTIFIER_BODY_KEYS == set()


# ---------------------------------------------------------------------------
# Headers and the OpenAI account canaries
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("provider", PROVIDERS)
async def test_llm_chat_request_has_no_openai_account_headers_with_env_ids_set(
    provider: str, wire: _Wire, build: Callable[[str], Any]
) -> None:
    """OPENAI_ORG_ID / OPENAI_PROJECT_ID in the env never become OpenAI account headers."""
    await build(provider).chat(_messages(), tools=[_ECHO_TOOL])

    assert wire.sent, "the chat must have reached the wire"
    sent_headers = set().union(*(sent.header_names() for sent in wire.sent))
    assert sent_headers & _ACCOUNT_HEADERS == set()


@pytest.mark.parametrize("provider", PROVIDERS)
async def test_llm_chat_request_carries_no_openai_account_canary_anywhere(
    provider: str, wire: _Wire, build: Callable[[str], Any]
) -> None:
    """The env canaries appear in no URL, header or body of any request."""
    await build(provider).chat(_messages(), tools=[_ECHO_TOOL])

    assert wire.sent, "the chat must have reached the wire"
    assert wire.leaked(_ORG_CANARY, _PROJECT_CANARY) == []


async def test_infomaniak_chat_stream_request_carries_no_identifiers(
    wire: _Wire, build: Callable[[str], Any]
) -> None:
    """The streaming request: allowed body keys only, no account headers, no canaries."""
    items = [item async for item in build("infomaniak").chat_stream(_messages(), [_ECHO_TOOL])]

    assert items, "the stream must have produced its final reply"
    assert len(wire.chat_requests) == 1
    request = wire.chat_requests[0]
    body = request.json_body()
    assert body.get("stream") is True
    assert set(body) - _OPENAI_COMPATIBLE_KEYS == set()
    assert set(body) & _IDENTIFIER_BODY_KEYS == set()
    assert request.header_names() & _ACCOUNT_HEADERS == set()
    assert wire.leaked(_ORG_CANARY, _PROJECT_CANARY) == []


async def test_infomaniak_discovery_and_chat_carry_no_identifiers(
    wire: _Wire, build: Callable[[str], Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without INFOMANIAK_PRODUCT_ID, discovery and the chat stay free of identifiers."""
    monkeypatch.delenv("INFOMANIAK_PRODUCT_ID")

    await build("infomaniak").chat(_messages(), tools=[_ECHO_TOOL])

    assert [sent.path for sent in wire.sent if sent.method == "GET"] == ["/1/ai"]
    assert len(wire.chat_requests) == 1
    sent_headers = set().union(*(sent.header_names() for sent in wire.sent))
    assert sent_headers & _ACCOUNT_HEADERS == set()
    assert wire.leaked(_ORG_CANARY, _PROJECT_CANARY) == []


# ---------------------------------------------------------------------------
# SDK retries are off: one chat() = exactly one HTTP request
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("failure", ["http_503", "http_429", "read_timeout"])
@pytest.mark.parametrize("provider", PROVIDERS)
async def test_llm_chat_failure_sends_exactly_one_request_and_raises_llm_error(
    provider: str, failure: str, wire: _Wire, build: Callable[[str], Any]
) -> None:
    """A 503, a 429 (retry-after: 0) or a timeout is never retried by the SDK."""
    wire.failure = failure

    with pytest.raises(LLMError):
        await build(provider).chat(_messages(), tools=[_ECHO_TOOL])

    assert len(wire.chat_requests) == 1


# ---------------------------------------------------------------------------
# Agent level: the principal's ids never reach the wire
# ---------------------------------------------------------------------------


class _EchoArgs(BaseModel):
    """Args of the test-only ``echo.say`` tool."""

    text: str = Field(min_length=1, max_length=100)


async def _echo_handler(args: _EchoArgs, *, session_id: str, **_: object) -> str:
    """Answer with fixed text only (never the tenant's ids)."""
    return f"echo:{args.text}"


async def _no_op_recorder(**_: Any) -> None:
    """A ToolCallRecorder that records nothing."""


def _tool_policy() -> ToolPolicy:
    """A policy that allows ``echo.say``."""
    permissions = PermissionsConfig(tools={"echo": ToolPermissions(actions={"say": "allow"})})
    return ToolPolicy(permissions=permissions, enabled_tools={"echo": True})


def _tool_round_trip(provider: str) -> list[dict[str, Any]]:
    """The scripted replies: one ``echo.say`` call, then a text answer."""
    if provider == "anthropic":
        return [_anthropic_tool_use(), _anthropic_text()]
    return [_openai_tool_call_completion(), _openai_completion("Done.")]


@pytest.mark.parametrize("provider", PROVIDERS)
async def test_agent_run_sends_no_principal_ids_to_the_provider(
    provider: str, wire: _Wire, build: Callable[[str], Any]
) -> None:
    """A run with a tool round trip never sends the user or org id, dashed or not."""
    register_tool("echo", "say", "Say a short text back", _EchoArgs)(_echo_handler)
    wire.queue = _tool_round_trip(provider)
    agent = Agent(
        llm_client=build(provider),
        tool_call_recorder=_no_op_recorder,
        agent_config=AgentConfig(max_tool_calls=3, max_context_messages=20),
        system_prompt=_SYSTEM_PROMPT,
    )

    result = await agent.run(
        "Please say hi",
        _SESSION_ID,
        history=[],
        principal=_PRINCIPAL,
        tool_policy=_tool_policy(),
    )

    assert result.status == "final", result.response
    assert len(wire.chat_requests) == 2, "the tool result must go back to the provider"
    assert wire.leaked(*_id_forms(_USER_ID, _ORG_ID)) == []


# ---------------------------------------------------------------------------
# Server level: the account's email and name never reach the wire
# ---------------------------------------------------------------------------


def test_server_message_sends_no_account_email_name_or_ids_to_the_provider(
    wire: _Wire, monkeypatch: pytest.MonkeyPatch
) -> None:
    """POST /api/message for an account with canary personal data keeps it off the wire."""
    db = FakeDb()
    db.add_org(_ORG_ID, data_residency=False)
    db.add_permissions(_ORG_ID)
    db.add_org_settings(_ORG_ID)
    db.add_platform_settings()
    user_id = db.add_account(role="editor", org_id=_ORG_ID, email=_EMAIL_CANARY, name=_NAME_CANARY)
    token = db.open_session(user_id)
    use_fake_database(monkeypatch, db)
    use_roomy_rate_limits(monkeypatch)
    # Built here, not through ``build``: TestClient runs the app on its own event loop.
    agent = Agent(
        llm_client=InfomaniakClient(_config("infomaniak")),
        tool_call_recorder=_no_op_recorder,
        agent_config=AgentConfig(max_tool_calls=3, max_context_messages=20),
        system_prompt=_SYSTEM_PROMPT,
    )
    client = make_client(create_app(agent=agent, config=make_config()))

    response = client.post(
        "/api/message",
        headers={"Cookie": f"admino_session={token}"},
        json={"message": "Please say hi", "session_id": "chat-wire-242"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "final", response.text
    assert wire.chat_requests, "the message must have reached the provider"
    assert wire.leaked(_EMAIL_CANARY, _NAME_CANARY, *_id_forms(user_id, _ORG_ID)) == []
