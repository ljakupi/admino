"""Spec: the image gate in ``llm_policy`` (GH-189 Decision 2, contract C9).

Defence in depth behind the server's ``422 image_input_unsupported``: when the
stored platform ``llm.image_input`` is false, no image part may reach any
client. ``llm_policy.chat`` and ``llm_policy.chat_stream`` take a keyword-only
``image_input: bool = True``:

- ``image_input=False`` and ANY message whose content list holds an
  ``ImageContent`` (the current user message or an earlier one): an uncoded
  ``LLMError`` (``code`` None, ``user_facing`` False, so the agent ends the run
  with its generic error) is raised before any request. The client is never
  called and nothing is retried, even with ``max_retries`` 5; the stream yields
  nothing.
- Without an image (str content, or a text-only list) or with ``image_input``
  True (the default, also when the keyword is left out) the call goes through
  unchanged: the client gets the same messages and tools objects.
- The error message is fixed: the same text whatever the content, holding none
  of it. No log record (DEBUG included) holds the content or the image data.

The import boundary (stdlib, ``admino.llm``, ``admino.models`` only) stays
pinned by ``tests/test_llm_policy.py::TestModuleSurface::
test_llm_policy_imports_only_stdlib_llm_and_models``.

The policy module and the new content-part models are looked up inside
fixtures, so this file collects before they change and each test fails on its
own.
"""

from __future__ import annotations

import base64
import inspect
import logging
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, Final

import pytest

from admino.llm import LLMError, LLMResponse, LLMStreamDelta
from admino.models import LLMMessage

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from types import ModuleType

StreamItem = LLMStreamDelta | LLMResponse

# Content markers: they must never reach the error or a log record.
_TEXT_CANARY: Final = "CANARY-189-attachment-text"
_QUESTION_CANARY: Final = "CANARY-189-user-question"
_DATA_CANARY: Final = base64.b64encode(b"CANARY-189-image-bytes").decode("ascii")
_OTHER_TEXT: Final = "CANARY-189-other-text"
_OTHER_DATA: Final = base64.b64encode(b"CANARY-189-other-image").decode("ascii")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def policy() -> ModuleType:
    """The policy module, imported per test."""
    from admino import llm_policy

    return llm_policy


@pytest.fixture()
def mm() -> SimpleNamespace:
    """The GH-189 content-part models, imported per test."""
    from admino import models

    return SimpleNamespace(Text=models.TextContent, Image=models.ImageContent)


@pytest.fixture()
def sleeps(policy: ModuleType, monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Record every retry sleep instead of sleeping."""
    slept: list[float] = []

    async def fake_sleep(delay: float) -> None:
        slept.append(delay)

    monkeypatch.setattr(policy, "_sleep", fake_sleep)
    monkeypatch.setattr(policy, "_random", lambda: 0.5)
    return slept


# ---------------------------------------------------------------------------
# Fake clients
# ---------------------------------------------------------------------------


def _ok() -> LLMResponse:
    return LLMResponse(content="ok", tool_calls=[], model="m", done=True)


def _retryable() -> LLMError:
    return LLMError("Fixed catalogue text.", code="timeout")


class ChatClient:
    """``chat`` returns or raises the next scripted item and records its exact arguments."""

    provider = "infomaniak"

    def __init__(self, script: list[LLMResponse | BaseException]) -> None:
        self._script = script
        self.calls: list[tuple[object, object]] = []

    async def chat(
        self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None
    ) -> LLMResponse:
        self.calls.append((messages, tools))
        item = self._script[min(len(self.calls), len(self._script)) - 1]
        if isinstance(item, BaseException):
            raise item
        return item

    def chat_stream(
        self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None
    ) -> AsyncIterator[StreamItem]:
        self.calls.append((messages, tools))
        msg = "chat must not fall back to chat_stream"
        raise AssertionError(msg)


class StreamClient:
    """``chat_stream`` plays the script (an exception item is raised) and records each call."""

    provider = "infomaniak"

    def __init__(self, script: list[StreamItem | BaseException]) -> None:
        self._script = script
        self.calls: list[tuple[object, object]] = []

    def chat_stream(
        self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None
    ) -> AsyncIterator[StreamItem]:
        self.calls.append((messages, tools))
        return self._play()

    async def _play(self) -> AsyncIterator[StreamItem]:
        for item in self._script:
            if isinstance(item, BaseException):
                raise item
            yield item

    async def chat(
        self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None
    ) -> LLMResponse:
        self.calls.append((messages, tools))
        msg = "chat_stream must not fall back to chat"
        raise AssertionError(msg)


# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------


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


def _with_image(
    mm: SimpleNamespace, where: str, *, text: str = _TEXT_CANARY, data: str = _DATA_CANARY
) -> list[LLMMessage]:
    """A context whose current (or an earlier) user message holds an image part."""
    image_message = LLMMessage(
        role="user",
        content=[
            mm.Text(text=text),
            mm.Image(media_type="image/png", data=data),
            mm.Text(text=_QUESTION_CANARY),
        ],
    )
    if where == "current":
        return [
            LLMMessage(role="system", content="You are admino."),
            LLMMessage(role="user", content="Earlier question"),
            LLMMessage(role="assistant", content="Earlier answer"),
            image_message,
        ]
    return [
        LLMMessage(role="system", content="You are admino."),
        image_message,
        LLMMessage(role="assistant", content="Earlier answer"),
        LLMMessage(role="user", content="And now a text question"),
    ]


def _without_image(mm: SimpleNamespace | None, variant: str) -> list[LLMMessage]:
    """A context without image parts: str content only, or a text-only list."""
    system = LLMMessage(role="system", content="You are admino.")
    if variant == "str":
        return [system, LLMMessage(role="user", content="hello")]
    assert mm is not None
    parts = [mm.Text(text=_TEXT_CANARY), mm.Text(text=_QUESTION_CANARY)]
    return [system, LLMMessage(role="user", content=parts)]


async def _drain(stream: AsyncIterator[StreamItem], seen: list[StreamItem]) -> None:
    async for item in stream:
        seen.append(item)


async def _refused_chat(policy: ModuleType, messages: list[LLMMessage]) -> LLMError:
    client = ChatClient([_ok()])
    with pytest.raises(LLMError) as caught:
        await policy.chat(
            client, messages, _tools(), data_residency=False, max_retries=5, image_input=False
        )
    return caught.value


async def _refused_stream(policy: ModuleType, messages: list[LLMMessage]) -> LLMError:
    client = StreamClient([LLMStreamDelta(content="x"), _ok()])
    stream = policy.chat_stream(
        client, messages, _tools(), data_residency=False, max_retries=5, image_input=False
    )
    with pytest.raises(LLMError) as caught:
        await _drain(stream, [])
    return caught.value


# ===========================================================================
# 1. image_input False + an image part: refused before any request
# ===========================================================================


@pytest.mark.parametrize("where", ["current", "earlier"])
async def test_llm_policy_image_gate_chat_refuses_image_with_uncoded_internal_error(
    where: str, policy: ModuleType, mm: SimpleNamespace, sleeps: list[float]
) -> None:
    """The refusal is an uncoded, non-user-facing LLMError (the agent shows its generic error)."""
    error = await _refused_chat(policy, _with_image(mm, where))

    assert (error.code, error.user_facing, error.retryable) == (None, False, False)


async def test_llm_policy_image_gate_chat_refusal_calls_no_client_and_never_retries(
    policy: ModuleType, mm: SimpleNamespace, sleeps: list[float]
) -> None:
    """Even with max_retries 5 and a client that would fail retryably: no call, no sleep."""
    client = ChatClient([_retryable()])
    with pytest.raises(LLMError):
        await policy.chat(
            client,
            _with_image(mm, "current"),
            _tools(),
            data_residency=False,
            max_retries=5,
            image_input=False,
        )

    assert (client.calls, sleeps) == ([], [])


@pytest.mark.parametrize("where", ["current", "earlier"])
async def test_llm_policy_image_gate_chat_stream_refuses_image_with_uncoded_internal_error(
    where: str, policy: ModuleType, mm: SimpleNamespace, sleeps: list[float]
) -> None:
    error = await _refused_stream(policy, _with_image(mm, where))

    assert (error.code, error.user_facing, error.retryable) == (None, False, False)


async def test_llm_policy_image_gate_chat_stream_refusal_calls_no_client_yields_nothing(
    policy: ModuleType, mm: SimpleNamespace, sleeps: list[float]
) -> None:
    """No chat_stream (nor chat) call, nothing yielded, no retry sleep, with max_retries 5."""
    client = StreamClient([_retryable()])
    seen: list[StreamItem] = []
    stream = policy.chat_stream(
        client,
        _with_image(mm, "current"),
        _tools(),
        data_residency=False,
        max_retries=5,
        image_input=False,
    )
    with pytest.raises(LLMError):
        await _drain(stream, seen)

    assert (client.calls, seen, sleeps) == ([], [], [])


# ===========================================================================
# 2. No image, or image input on: the call goes through unchanged
# ===========================================================================


@pytest.mark.parametrize("variant", ["str", "text-list"])
async def test_llm_policy_image_gate_chat_without_image_goes_through(
    variant: str, policy: ModuleType, sleeps: list[float], request: pytest.FixtureRequest
) -> None:
    """image_input False: a context without image parts reaches the client as given."""
    mm = request.getfixturevalue("mm") if variant == "text-list" else None
    messages, tools, reply = _without_image(mm, variant), _tools(), _ok()
    client = ChatClient([reply])

    result = await policy.chat(
        client, messages, tools, data_residency=False, max_retries=0, image_input=False
    )

    assert (result is reply, len(client.calls), client.calls[0][0] is messages) == (
        True,
        1,
        True,
    )
    assert client.calls[0][1] is tools


@pytest.mark.parametrize("variant", ["str", "text-list"])
async def test_llm_policy_image_gate_chat_stream_without_image_goes_through(
    variant: str, policy: ModuleType, sleeps: list[float], request: pytest.FixtureRequest
) -> None:
    mm = request.getfixturevalue("mm") if variant == "text-list" else None
    messages, tools = _without_image(mm, variant), _tools()
    script: list[StreamItem | BaseException] = [LLMStreamDelta(content="Hi"), _ok()]
    client = StreamClient(script)
    seen: list[StreamItem] = []

    await _drain(
        policy.chat_stream(
            client, messages, tools, data_residency=False, max_retries=0, image_input=False
        ),
        seen,
    )

    assert (seen, len(client.calls), client.calls[0][0] is messages) == (script, 1, True)
    assert client.calls[0][1] is tools


def _image_input_kwargs(mode: str) -> dict[str, bool]:
    """``image_input=True`` passed explicitly, or the keyword left out (default True)."""
    return {"image_input": True} if mode == "explicit" else {}


@pytest.mark.parametrize("mode", ["explicit", "default"])
async def test_llm_policy_image_gate_chat_with_image_input_on_sends_images(
    mode: str, policy: ModuleType, mm: SimpleNamespace, sleeps: list[float]
) -> None:
    messages, tools, reply = _with_image(mm, "current"), _tools(), _ok()
    client = ChatClient([reply])

    result = await policy.chat(
        client, messages, tools, data_residency=False, max_retries=0, **_image_input_kwargs(mode)
    )

    assert (result is reply, len(client.calls), client.calls[0][0] is messages) == (
        True,
        1,
        True,
    )


@pytest.mark.parametrize("mode", ["explicit", "default"])
async def test_llm_policy_image_gate_chat_stream_with_image_input_on_sends_images(
    mode: str, policy: ModuleType, mm: SimpleNamespace, sleeps: list[float]
) -> None:
    messages, tools = _with_image(mm, "current"), _tools()
    script: list[StreamItem | BaseException] = [LLMStreamDelta(content="Hi"), _ok()]
    client = StreamClient(script)
    seen: list[StreamItem] = []

    await _drain(
        policy.chat_stream(
            client,
            messages,
            tools,
            data_residency=False,
            max_retries=0,
            **_image_input_kwargs(mode),
        ),
        seen,
    )

    assert (seen, len(client.calls), client.calls[0][0] is messages) == (script, 1, True)


# ===========================================================================
# 3. Fixed message, no content in logs, the signature
# ===========================================================================


async def test_llm_policy_image_gate_error_message_is_fixed_and_content_free(
    policy: ModuleType, mm: SimpleNamespace, sleeps: list[float]
) -> None:
    """chat and chat_stream, two different contents: one fixed, non-empty, content-free text."""
    errors = [
        await _refused_chat(policy, _with_image(mm, "current")),
        await _refused_chat(policy, _with_image(mm, "earlier", text=_OTHER_TEXT, data=_OTHER_DATA)),
        await _refused_stream(policy, _with_image(mm, "current")),
        await _refused_stream(
            policy, _with_image(mm, "earlier", text=_OTHER_TEXT, data=_OTHER_DATA)
        ),
    ]
    texts = {text for error in errors for text in (error.message, str(error))}
    leaked = [
        canary
        for canary in (_TEXT_CANARY, _QUESTION_CANARY, _DATA_CANARY, _OTHER_TEXT, _OTHER_DATA)
        if any(canary in text for text in texts)
    ]

    assert (len(texts), all(text.strip() for text in texts), leaked) == (1, True, [])


async def test_llm_policy_image_gate_refusal_logs_no_content(
    policy: ModuleType,
    mm: SimpleNamespace,
    sleeps: list[float],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """No log record (DEBUG included, any logger) holds the text, the question or the data."""
    caplog.set_level(logging.DEBUG)
    await _refused_chat(policy, _with_image(mm, "current"))
    await _refused_stream(policy, _with_image(mm, "earlier"))

    records = [f"{record.getMessage()} {record.args!r}" for record in caplog.records]
    leaked = [
        canary
        for canary in (_TEXT_CANARY, _QUESTION_CANARY, _DATA_CANARY)
        if any(canary in text for text in records)
    ]
    assert leaked == []


@pytest.mark.parametrize("name", ["chat", "chat_stream"])
def test_llm_policy_image_gate_signature_image_input_keyword_only_default_true(
    name: str, policy: ModuleType
) -> None:
    parameter = inspect.signature(getattr(policy, name)).parameters.get("image_input")

    assert parameter is not None
    assert (parameter.kind, parameter.default) == (inspect.Parameter.KEYWORD_ONLY, True)
