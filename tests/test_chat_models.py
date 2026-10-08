"""Tests for GH-176's chat API models in admino.models (contract section 6).

The chat routes (POST/GET/PATCH/DELETE /api/chats..., POST
/api/chats/{id}/messages) validate and answer with these models; they are the
contract in /api/openapi.json. New names are looked up per test (``_model``),
so each test fails on its own until its model exists.

What these tests pin down:
- ``models.MessageStatus`` is exactly the five stored message statuses
  (complete, stopped, error, awaiting_confirmation, limit_reached).
- Title rules, shared by ``ChatCreateRequest.title`` (optional: absent or null
  means "no title") and ``ChatUpdateRequest.title`` (required): whitespace is
  stripped, 1 to 200 characters (code points) after stripping, a
  whitespace-only title is refused, any Unicode control character (Cc: newline,
  tab, NUL, DEL, NEL, ESC, CR) and bidi/format characters (Cf: U+202E, U+200F,
  U+2066) are refused anywhere; ordinary Unicode text is kept as given.
- The three request models (``ChatCreateRequest``, ``ChatUpdateRequest``,
  ``ChatMessageCreate``) refuse unknown keys (an ``org_id``, ``user_id``,
  ``title_source`` or ``id`` never comes from the body) and hide their input
  from validation errors: a refused value never appears in the error text or
  in ``errors(include_input=False)``.
- ``ChatMessageCreate.message``: at most 32768 characters, required; an empty
  or whitespace-only message is valid and kept as given (GH-286: the route
  refuses a blank message without files with ``message_empty``).
- ``ChatMessageCreate.attachment_ids`` (GH-187 contract section 3.1): the
  model's fields are exactly ``message`` and ``attachment_ids``; a list of
  UUIDs, empty when absent, at most 50; duplicates refused (also the same UUID
  written in another case), a non-UUID refused at its index, neither echoed in
  the error. The legacy ``ChatRequest`` (``/api/message``) still refuses the
  key (extra="forbid"): attachments go through the chat route only.
- ``ChatSummary`` (id, title <= 200, title_source auto/user, created_at,
  last_activity_at), ``ChatListResponse`` (chats <= 100, next_cursor default
  None), ``ChatMessageView`` (id, role user/assistant/tool, content <= 65536
  sanitized exactly like ``ChatResponse.response``, tool_call_id, tool_calls
  as ``ToolCallRecord`` with sanitized args (<= 50), status a MessageStatus,
  created_at), ``ChatContext`` (message_count >= 0, max_context_messages within
  the platform limit's 1 to 200, truncated) and ``ChatDetailResponse`` (a
  ChatSummary plus messages <= 100, next_cursor, pending_confirmation as a
  ``PendingConfirmationSummary``, confirmation_status none/pending/expired,
  context). The JSON keys of each response model are exactly the contract's.
- No chat API model has a ``tool_use_blocks`` field or schema entry: the raw
  tool inputs are never exposed.

Security notes:
- Titles reach the chat list of every client: control and bidi characters
  could spoof or break what is shown, so they are refused, not stripped.
- Message content and tool-call args come from the LLM and from tools; the
  view model strips control characters and credential patterns the same way
  the live chat response does.
- hide_input_in_errors: a 422 never echoes a title or a message.
"""

from __future__ import annotations

import json
import typing
from typing import Any
from uuid import UUID

import pytest
from pydantic import BaseModel, ValidationError

import admino.models as models_module
from admino.models import (
    ChatRequest,
    ChatResponse,
    PendingConfirmationSummary,
    PlatformLimits,
    ToolCallRecord,
)

_UUID = "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b"
_OTHER_UUID = "0b8e7c6d-5a4f-4e3d-9c2b-1a0f9e8d7c6b"
_TIMESTAMP = "2026-10-05T09:30:00+00:00"
_LATER = "2026-10-05T10:45:00+00:00"
_EXPIRES = "2099-01-01T00:00:00+00:00"
_MARKER = "ZZ-SENTINEL-176"

_STATUSES = frozenset({"complete", "stopped", "error", "awaiting_confirmation", "limit_reached"})
_TITLE_MODELS = ("ChatCreateRequest", "ChatUpdateRequest")
_REQUEST_MODELS = ("ChatCreateRequest", "ChatUpdateRequest", "ChatMessageCreate")
_CHAT_API_MODELS = (
    "ChatCreateRequest",
    "ChatUpdateRequest",
    "ChatMessageCreate",
    "ChatSummary",
    "ChatListResponse",
    "ChatMessageView",
    "ChatContext",
    "ChatDetailResponse",
)
_SUMMARY_KEYS = frozenset({"id", "title", "title_source", "created_at", "last_activity_at"})
_MESSAGE_KEYS = frozenset(
    {"id", "role", "content", "tool_call_id", "tool_calls", "status", "created_at"}
)
_CONTEXT_KEYS = frozenset({"message_count", "max_context_messages", "truncated"})
_DETAIL_KEYS = _SUMMARY_KEYS | frozenset(
    {"messages", "next_cursor", "pending_confirmation", "confirmation_status", "context"}
)

# Characters built with chr() so they survive editing tools verbatim.
_RLO = chr(0x202E)  # RIGHT-TO-LEFT OVERRIDE
_RLM = chr(0x200F)  # RIGHT-TO-LEFT MARK
_LRI = chr(0x2066)  # LEFT-TO-RIGHT ISOLATE
_PDI = chr(0x2069)  # POP DIRECTIONAL ISOLATE
_ZWSP = chr(0x200B)  # ZERO WIDTH SPACE
_BOM = chr(0xFEFF)
_NEL = chr(0x85)
_ESC = chr(0x1B)
_FULLWIDTH_A = chr(0xFF21)
_E_ACUTE = chr(0xE9)
# Unicode controls (Cc), each placed mid-title: strip() can't remove them there.
_CONTROL_CHARS: tuple[tuple[str, str], ...] = (
    ("newline", chr(0x0A)),
    ("tab", chr(0x09)),
    ("carriage-return", chr(0x0D)),
    ("nul", chr(0x00)),
    ("escape", _ESC),
    ("del", chr(0x7F)),
    ("nel", _NEL),
)
# Bidi and format characters (Cf).
_FORMAT_CHARS: tuple[tuple[str, str], ...] = (
    ("rlo-u202e", _RLO),
    ("rlm-u200f", _RLM),
    ("lri-u2066", _LRI),
)
# Ordinary text a title keeps as given: accents, umlauts, CJK, an emoji, punctuation.
_UNICODE_TITLE = (
    "Offerte f"
    + chr(0xFC)
    + "r M"
    + chr(0xFC)
    + "ller & S"
    + chr(0xF6)
    + "hne (Q3/2026) "
    + chr(0x65E5)
    + chr(0x672C)
    + " "
    + chr(0x1F680)
)
_GITHUB_TOKEN = "ghp_" + "A" * 36
# Texts the view must sanitize exactly like ChatResponse.response does.
_CONTENT_SAMPLES: tuple[tuple[str, str], ...] = (
    ("ansi-and-nul", _ESC + "[31mred" + chr(0x00) + " text"),
    ("bidi", "abc" + _RLO + "def " + _LRI + "x" + _PDI),
    ("zero-width-and-bom", "pay" + _ZWSP + "ment" + _BOM),
    ("nel-and-c1", "line" + _NEL + "two" + chr(0x9B) + "3"),
    ("github-token", "your token is " + _GITHUB_TOKEN),
    ("bearer", "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789"),
    ("fullwidth", "caf" + _E_ACUTE + " " + _FULLWIDTH_A),
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _model(name: str) -> type[BaseModel]:
    """A GH-176 model from admino.models; fails the calling test when missing."""
    model = getattr(models_module, name, None)
    if model is None:
        pytest.fail(f"admino.models.{name} does not exist (GH-176)")
    assert isinstance(model, type)
    assert issubclass(model, BaseModel)
    return model


def _rejects(model: type[BaseModel], payload: dict[str, Any]) -> ValidationError:
    with pytest.raises(ValidationError) as exc_info:
        model.model_validate(payload)
    return exc_info.value


def _accepts(model: type[BaseModel], payload: dict[str, Any]) -> bool:
    try:
        model.model_validate(payload)
    except ValidationError:
        return False
    return True


def _locs(exc: ValidationError) -> list[tuple[int | str, ...]]:
    return [tuple(error["loc"]) for error in exc.errors(include_url=False, include_input=False)]


def _error_text(exc: ValidationError) -> str:
    """Everything a 422 or a log line could show: str(exc) plus the input-free errors."""
    errors = exc.errors(include_url=False, include_input=False)
    return str(exc) + json.dumps(errors, default=str)


def _dumped_keys(instance: BaseModel) -> frozenset[str]:
    return frozenset(json.loads(instance.model_dump_json()))


def _summary_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": _UUID,
        "title": "Quarterly report",
        "title_source": "user",
        "created_at": _TIMESTAMP,
        "last_activity_at": _LATER,
    }
    payload.update(overrides)
    return payload


def _record_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "tool": "gmail",
        "action": "read",
        "args": {"message_id": "m1"},
        "permission": "allow",
        "success": True,
    }
    payload.update(overrides)
    return payload


def _message_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": _UUID,
        "role": "assistant",
        "content": "Done.",
        "status": "complete",
        "created_at": _TIMESTAMP,
    }
    payload.update(overrides)
    return payload


def _context_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {"message_count": 3, "max_context_messages": 40, "truncated": False}
    payload.update(overrides)
    return payload


def _pending_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "confirmation_id": "conf-1",
        "tool": "gmail",
        "action": "send",
        "args": {"subject": "Offer"},
        "expires_at": _EXPIRES,
    }
    payload.update(overrides)
    return payload


def _detail_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        **_summary_payload(),
        "messages": [_message_payload()],
        "confirmation_status": "none",
        "context": _context_payload(),
    }
    payload.update(overrides)
    return payload


def _sanitized_like_chat_response(text: str) -> str:
    """What ChatResponse.response keeps of a text (the live chat's sanitizer)."""
    response = ChatResponse.model_validate({"chat_id": _UUID, "session_id": "s1", "response": text})
    return response.response


def _platform_context_bounds() -> tuple[int, int]:
    """PlatformLimits.max_context_messages' (ge, le): the stored platform limit's range."""
    metadata = PlatformLimits.model_fields["max_context_messages"].metadata
    low = next(item.ge for item in metadata if hasattr(item, "ge"))
    high = next(item.le for item in metadata if hasattr(item, "le"))
    return int(low), int(high)


# ---------------------------------------------------------------------------
# 1. MessageStatus
# ---------------------------------------------------------------------------


class TestMessageStatus:
    """The stored message statuses."""

    def test_chat_models_message_status_is_the_five_statuses(self) -> None:
        status = getattr(models_module, "MessageStatus", None)

        assert status is not None, "admino.models.MessageStatus does not exist (GH-176)"
        assert typing.get_origin(status) is typing.Literal
        assert frozenset(typing.get_args(status)) == _STATUSES
        assert len(typing.get_args(status)) == len(_STATUSES)


# ---------------------------------------------------------------------------
# 2. Request models: configuration
# ---------------------------------------------------------------------------


class TestChatRequestConfig:
    """Request bodies refuse unknown keys and hide their input from errors."""

    @pytest.mark.parametrize("name", _REQUEST_MODELS)
    def test_chat_models_request_forbids_extra_and_hides_input(self, name: str) -> None:
        config = _model(name).model_config

        assert config.get("extra") == "forbid"
        assert config.get("hide_input_in_errors") is True


# ---------------------------------------------------------------------------
# 3. Title rules (ChatCreateRequest and ChatUpdateRequest)
# ---------------------------------------------------------------------------


class TestChatTitleRules:
    """Stripped, 1 to 200 characters, no control or bidi/format character."""

    @pytest.mark.parametrize("name", _TITLE_MODELS)
    def test_chat_models_title_is_stripped(self, name: str) -> None:
        request = _model(name).model_validate({"title": "   Quarterly report  "})

        assert request.title == "Quarterly report"  # type: ignore[attr-defined]

    @pytest.mark.parametrize("name", _TITLE_MODELS)
    def test_chat_models_title_of_200_characters_after_stripping_is_accepted(
        self, name: str
    ) -> None:
        """200 code points (accented letters count once each), surrounding spaces stripped."""
        model = _model(name)
        ascii_title = model.model_validate({"title": "  " + "a" * 200 + "  "})
        accented = model.model_validate({"title": _E_ACUTE * 200})

        assert ascii_title.title == "a" * 200  # type: ignore[attr-defined]
        assert accented.title == _E_ACUTE * 200  # type: ignore[attr-defined]

    @pytest.mark.parametrize("name", _TITLE_MODELS)
    def test_chat_models_title_of_201_characters_is_refused(self, name: str) -> None:
        exc = _rejects(_model(name), {"title": "a" * 201})

        assert _locs(exc) == [("title",)]

    @pytest.mark.parametrize("name", _TITLE_MODELS)
    @pytest.mark.parametrize("title", ["", " ", "     ", chr(0x09) + " "], ids=repr)
    def test_chat_models_empty_or_whitespace_title_is_refused(self, name: str, title: str) -> None:
        exc = _rejects(_model(name), {"title": title})

        assert _locs(exc) == [("title",)]

    @pytest.mark.parametrize("name", _TITLE_MODELS)
    @pytest.mark.parametrize(("label", "char"), _CONTROL_CHARS, ids=[c[0] for c in _CONTROL_CHARS])
    def test_chat_models_title_with_a_control_character_is_refused(
        self, name: str, label: str, char: str
    ) -> None:
        exc = _rejects(_model(name), {"title": "Report" + char + "2026"})

        assert _locs(exc) == [("title",)], label

    @pytest.mark.parametrize("name", _TITLE_MODELS)
    @pytest.mark.parametrize(("label", "char"), _FORMAT_CHARS, ids=[c[0] for c in _FORMAT_CHARS])
    def test_chat_models_title_with_a_bidi_or_format_character_is_refused(
        self, name: str, label: str, char: str
    ) -> None:
        exc = _rejects(_model(name), {"title": "Invoice " + char + "fdp.exe"})

        assert _locs(exc) == [("title",)], label

    @pytest.mark.parametrize("name", _TITLE_MODELS)
    def test_chat_models_title_keeps_ordinary_unicode_text(self, name: str) -> None:
        """Accents, umlauts, CJK and emoji are titles like any other, kept as given."""
        request = _model(name).model_validate({"title": _UNICODE_TITLE})

        assert request.title == _UNICODE_TITLE  # type: ignore[attr-defined]

    @pytest.mark.parametrize("name", _TITLE_MODELS)
    @pytest.mark.parametrize("key", ["org_id", "user_id", "title_source", "id"])
    def test_chat_models_title_request_refuses_unknown_keys(self, name: str, key: str) -> None:
        """The org, the owner, the title source and the id never come from the body."""
        exc = _rejects(_model(name), {"title": "Report", key: _OTHER_UUID})

        assert _locs(exc) == [(key,)]

    @pytest.mark.parametrize("name", _TITLE_MODELS)
    @pytest.mark.parametrize(
        "payload",
        [
            {"title": _MARKER + "a" * 200},
            {"title": _MARKER + chr(0x0A) + "x"},
            {"title": _MARKER + _RLO + "x"},
            {"title": "Report", "org_id": _MARKER},
        ],
        ids=["too-long", "control", "bidi", "extra-key"],
    )
    def test_chat_models_title_request_errors_never_echo_the_input(
        self, name: str, payload: dict[str, Any]
    ) -> None:
        exc = _rejects(_model(name), payload)

        assert _MARKER not in _error_text(exc)

    def test_chat_models_create_request_title_is_optional(self) -> None:
        """No title (absent or null): the chat starts untitled for #179's auto title."""
        model = _model("ChatCreateRequest")

        assert model.model_validate({}).title is None  # type: ignore[attr-defined]
        assert model.model_validate({"title": None}).title is None  # type: ignore[attr-defined]

    @pytest.mark.parametrize("payload", [{}, {"title": None}], ids=["absent", "null"])
    def test_chat_models_update_request_title_is_required(self, payload: dict[str, Any]) -> None:
        exc = _rejects(_model("ChatUpdateRequest"), payload)

        assert _locs(exc) == [("title",)]


# ---------------------------------------------------------------------------
# 4. ChatMessageCreate
# ---------------------------------------------------------------------------


class TestChatMessageCreate:
    """POST /api/chats/{id}/messages: one message of at most 32768 characters."""

    @pytest.mark.parametrize("length", [1, 32768])
    def test_chat_models_message_create_accepts_1_to_32768_characters(self, length: int) -> None:
        request = _model("ChatMessageCreate").model_validate({"message": "m" * length})

        assert request.message == "m" * length  # type: ignore[attr-defined]

    def test_chat_models_message_create_accepts_empty_and_whitespace_only_as_given(
        self,
    ) -> None:
        """GH-286: the model takes a blank message, unstripped (the route answers a blank
        one without files with ``message_empty``)."""
        model = _model("ChatMessageCreate")
        texts = ["", " ", chr(0x09) + chr(0x0A), chr(0x3000), " " * 32768]

        accepted = [model.model_validate({"message": text}).message for text in texts]  # type: ignore[attr-defined]

        assert accepted == texts

    @pytest.mark.parametrize("message", ["m" * 32769], ids=["32769"])
    def test_chat_models_message_create_refuses_out_of_range(self, message: str) -> None:
        exc = _rejects(_model("ChatMessageCreate"), {"message": message})

        assert _locs(exc) == [("message",)]

    def test_chat_models_message_create_message_is_required(self) -> None:
        exc = _rejects(_model("ChatMessageCreate"), {})

        assert _locs(exc) == [("message",)]

    @pytest.mark.parametrize("key", ["session_id", "chat_id", "org_id", "user_id"])
    def test_chat_models_message_create_refuses_unknown_keys(self, key: str) -> None:
        """The chat comes from the path, the org and owner from the session."""
        exc = _rejects(_model("ChatMessageCreate"), {"message": "hi", key: _OTHER_UUID})

        assert _locs(exc) == [(key,)]

    @pytest.mark.parametrize(
        "payload",
        [{"message": _MARKER + "m" * 32769}, {"message": "hi", "org_id": _MARKER}],
        ids=["too-long", "extra-key"],
    )
    def test_chat_models_message_create_errors_never_echo_the_input(
        self, payload: dict[str, Any]
    ) -> None:
        exc = _rejects(_model("ChatMessageCreate"), payload)

        assert _MARKER not in _error_text(exc)


class TestChatMessageCreateAttachments:
    """GH-187: the files a message carries, by attachment id."""

    def test_chat_models_message_create_fields_are_message_and_attachment_ids(self) -> None:
        assert frozenset(_model("ChatMessageCreate").model_fields) == {"message", "attachment_ids"}

    def test_chat_models_message_create_attachment_ids_default_to_an_empty_list(self) -> None:
        model = _model("ChatMessageCreate")

        assert model.model_validate({"message": "hi"}).attachment_ids == []  # type: ignore[attr-defined]
        assert model.model_validate({"message": "hi", "attachment_ids": []}).attachment_ids == []  # type: ignore[attr-defined]

    def test_chat_models_message_create_attachment_ids_are_uuids(self) -> None:
        request = _model("ChatMessageCreate").model_validate(
            {"message": "hi", "attachment_ids": [_UUID, _OTHER_UUID]}
        )

        assert request.attachment_ids == [UUID(_UUID), UUID(_OTHER_UUID)]  # type: ignore[attr-defined]

    def test_chat_models_message_create_holds_at_most_50_attachment_ids(self) -> None:
        model = _model("ChatMessageCreate")
        ids = [str(UUID(int=index + 1)) for index in range(51)]

        accepted = model.model_validate({"message": "hi", "attachment_ids": ids[:50]})
        assert len(accepted.attachment_ids) == 50  # type: ignore[attr-defined]
        exc = _rejects(model, {"message": "hi", "attachment_ids": ids})
        assert _locs(exc) == [("attachment_ids",)]

    @pytest.mark.parametrize(
        "ids",
        [[_UUID, _OTHER_UUID, _UUID], [_UUID, _UUID.upper()]],
        ids=["repeated", "same-uuid-other-case"],
    )
    def test_chat_models_message_create_refuses_duplicate_attachment_ids(
        self, ids: list[str]
    ) -> None:
        """Each file once per message; the refused ids are not echoed."""
        model = _model("ChatMessageCreate")

        assert _accepts(model, {"message": "hi", "attachment_ids": [_UUID, _OTHER_UUID]})
        exc = _rejects(model, {"message": "hi", "attachment_ids": ids})
        assert _locs(exc) == [("attachment_ids",)]
        text = _error_text(exc).lower()
        assert _UUID not in text
        assert _UUID.replace("-", "") not in text

    def test_chat_models_message_create_refuses_a_non_uuid_attachment_id(self) -> None:
        exc = _rejects(
            _model("ChatMessageCreate"),
            {"message": "hi", "attachment_ids": [_UUID, _MARKER]},
        )

        assert _locs(exc) == [("attachment_ids", 1)]
        assert _MARKER not in _error_text(exc)


class TestLegacyChatRequest:
    """``/api/message`` (ChatRequest) takes no attachments (GH-187)."""

    def test_chat_models_legacy_chat_request_refuses_attachment_ids(self) -> None:
        exc = _rejects(
            ChatRequest, {"message": "hi", "session_id": "s1", "attachment_ids": [_UUID]}
        )

        errors = exc.errors(include_url=False, include_input=False)
        assert [(tuple(error["loc"]), error["type"]) for error in errors] == [
            (("attachment_ids",), "extra_forbidden")
        ]


# ---------------------------------------------------------------------------
# 5. ChatSummary and ChatListResponse
# ---------------------------------------------------------------------------


class TestChatSummary:
    """A chat in the list: id, title, title source and the two timestamps."""

    def test_chat_models_summary_json_keys_are_exactly_the_contract(self) -> None:
        summary = _model("ChatSummary").model_validate(_summary_payload())

        assert _dumped_keys(summary) == _SUMMARY_KEYS

    def test_chat_models_summary_title_may_be_empty_up_to_200(self) -> None:
        """'' is an untitled chat (title_source auto, #179 fills it)."""
        model = _model("ChatSummary")

        assert _accepts(model, _summary_payload(title="", title_source="auto"))
        assert _accepts(model, _summary_payload(title="a" * 200))
        assert _locs(_rejects(model, _summary_payload(title="a" * 201))) == [("title",)]

    @pytest.mark.parametrize("source", ["auto", "user"])
    def test_chat_models_summary_title_source_accepts_auto_and_user(self, source: str) -> None:
        summary = _model("ChatSummary").model_validate(_summary_payload(title_source=source))

        assert summary.title_source == source  # type: ignore[attr-defined]

    @pytest.mark.parametrize("source", ["system", "", "USER"])
    def test_chat_models_summary_title_source_refuses_others(self, source: str) -> None:
        exc = _rejects(_model("ChatSummary"), _summary_payload(title_source=source))

        assert _locs(exc) == [("title_source",)]

    def test_chat_models_summary_id_must_be_a_uuid(self) -> None:
        exc = _rejects(_model("ChatSummary"), _summary_payload(id="chat-1"))

        assert _locs(exc) == [("id",)]


class TestChatListResponse:
    """GET /api/chats: up to 100 chats and a cursor for the next page."""

    def test_chat_models_list_json_keys_and_next_cursor_default(self) -> None:
        listing = _model("ChatListResponse").model_validate({"chats": [_summary_payload()]})

        assert _dumped_keys(listing) == {"chats", "next_cursor"}
        assert listing.next_cursor is None  # type: ignore[attr-defined]

    def test_chat_models_list_holds_at_most_100_chats(self) -> None:
        model = _model("ChatListResponse")

        assert _accepts(model, {"chats": [_summary_payload()] * 100, "next_cursor": "c"})
        assert _locs(_rejects(model, {"chats": [_summary_payload()] * 101})) == [("chats",)]


# ---------------------------------------------------------------------------
# 6. ChatMessageView
# ---------------------------------------------------------------------------


class TestChatMessageView:
    """One stored message as the API shows it: sanitized, without raw tool inputs."""

    def test_chat_models_message_view_json_keys_are_exactly_the_contract(self) -> None:
        view = _model("ChatMessageView").model_validate(_message_payload())

        assert _dumped_keys(view) == _MESSAGE_KEYS

    def test_chat_models_message_view_has_no_tool_use_blocks(self) -> None:
        """The raw tool inputs stay in the database; tool_calls is the sanitized summary."""
        model = _model("ChatMessageView")
        view = model.model_validate(_message_payload())

        assert "tool_use_blocks" not in model.model_fields
        assert "tool_use_blocks" not in json.loads(view.model_dump_json())

    @pytest.mark.parametrize("role", ["user", "assistant", "tool"])
    def test_chat_models_message_view_role_accepts_stored_roles(self, role: str) -> None:
        view = _model("ChatMessageView").model_validate(_message_payload(role=role))

        assert view.role == role  # type: ignore[attr-defined]

    @pytest.mark.parametrize("role", ["system", "", "admin"])
    def test_chat_models_message_view_role_refuses_others(self, role: str) -> None:
        """No system role: system prompts are never stored, so never shown."""
        exc = _rejects(_model("ChatMessageView"), _message_payload(role=role))

        assert _locs(exc) == [("role",)]

    @pytest.mark.parametrize("status", sorted(_STATUSES))
    def test_chat_models_message_view_status_accepts_each_message_status(self, status: str) -> None:
        view = _model("ChatMessageView").model_validate(_message_payload(status=status))

        assert view.status == status  # type: ignore[attr-defined]

    @pytest.mark.parametrize("status", ["final", "", "pending"])
    def test_chat_models_message_view_status_refuses_others(self, status: str) -> None:
        """'final' is the run status; the stored message says 'complete'."""
        exc = _rejects(_model("ChatMessageView"), _message_payload(status=status))

        assert _locs(exc) == [("status",)]

    def test_chat_models_message_view_status_is_message_status(self) -> None:
        annotation = _model("ChatMessageView").model_fields["status"].annotation

        assert frozenset(typing.get_args(annotation)) == _STATUSES

    def test_chat_models_message_view_content_holds_up_to_65536(self) -> None:
        model = _model("ChatMessageView")

        assert _accepts(model, _message_payload(content=""))
        assert _accepts(model, _message_payload(content="a" * 65536))
        assert _locs(_rejects(model, _message_payload(content="a" * 65537))) == [("content",)]

    @pytest.mark.parametrize(
        ("label", "text"), _CONTENT_SAMPLES, ids=[s[0] for s in _CONTENT_SAMPLES]
    )
    def test_chat_models_message_view_content_is_sanitized_like_chat_response(
        self, label: str, text: str
    ) -> None:
        """Control and bidi characters and credential patterns go, as in the live reply."""
        expected = _sanitized_like_chat_response(text)
        view = _model("ChatMessageView").model_validate(_message_payload(content=text))

        assert expected != text, label
        assert view.content == expected  # type: ignore[attr-defined]

    def test_chat_models_message_view_content_keeps_tab_and_newlines(self) -> None:
        text = "line 1" + chr(0x0A) + "line 2" + chr(0x09) + "col" + chr(0x0D) + chr(0x0A)
        view = _model("ChatMessageView").model_validate(_message_payload(content=text))

        assert view.content == _sanitized_like_chat_response(text) == text  # type: ignore[attr-defined]

    def test_chat_models_message_view_optional_fields_default_to_none(self) -> None:
        view = _model("ChatMessageView").model_validate(_message_payload())

        assert view.tool_call_id is None  # type: ignore[attr-defined]
        assert view.tool_calls is None  # type: ignore[attr-defined]

    def test_chat_models_message_view_tool_calls_are_sanitized_records(self) -> None:
        """tool_calls are ToolCallRecords, their string args stripped of credentials."""
        args = {"query": "token " + _GITHUB_TOKEN, "max_results": 5}
        view = _model("ChatMessageView").model_validate(
            _message_payload(tool_calls=[_record_payload(args=args)])
        )
        expected = ToolCallRecord.model_validate(_record_payload(args=args)).args

        records = view.tool_calls  # type: ignore[attr-defined]
        assert len(records) == 1
        assert isinstance(records[0], ToolCallRecord)
        assert records[0].args == expected
        assert _GITHUB_TOKEN not in json.dumps(records[0].args)

    def test_chat_models_message_view_holds_at_most_50_tool_calls(self) -> None:
        model = _model("ChatMessageView")

        assert _accepts(model, _message_payload(tool_calls=[_record_payload()] * 50))
        exc = _rejects(model, _message_payload(tool_calls=[_record_payload()] * 51))
        assert _locs(exc) == [("tool_calls",)]

    def test_chat_models_message_view_tool_call_id_is_kept(self) -> None:
        view = _model("ChatMessageView").model_validate(
            _message_payload(role="tool", tool_call_id="toolu_01")
        )

        assert view.tool_call_id == "toolu_01"  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# 7. ChatContext
# ---------------------------------------------------------------------------


class TestChatContext:
    """The interim context field (until #190): how much of the chat the model sees."""

    def test_chat_models_context_json_keys_are_exactly_the_contract(self) -> None:
        context = _model("ChatContext").model_validate(_context_payload())

        assert _dumped_keys(context) == _CONTEXT_KEYS

    def test_chat_models_context_message_count_is_never_negative(self) -> None:
        model = _model("ChatContext")

        assert _accepts(model, _context_payload(message_count=0))
        assert _locs(_rejects(model, _context_payload(message_count=-1))) == [("message_count",)]

    def test_chat_models_context_max_messages_is_the_platform_limit_range(self) -> None:
        """1 to 200, the range of the stored platform limits.max_context_messages."""
        model = _model("ChatContext")
        low, high = _platform_context_bounds()

        assert (low, high) == (1, 200)
        assert _accepts(model, _context_payload(max_context_messages=low))
        assert _accepts(model, _context_payload(max_context_messages=high))
        for value in (low - 1, high + 1):
            exc = _rejects(model, _context_payload(max_context_messages=value))
            assert _locs(exc) == [("max_context_messages",)], value

    def test_chat_models_context_truncated_is_a_bool(self) -> None:
        context = _model("ChatContext").model_validate(
            _context_payload(message_count=41, max_context_messages=40, truncated=True)
        )

        assert context.truncated is True  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# 8. ChatDetailResponse
# ---------------------------------------------------------------------------


class TestChatDetailResponse:
    """GET /api/chats/{id}: the summary plus a page of messages and the chat's state."""

    def test_chat_models_detail_is_a_chat_summary(self) -> None:
        assert issubclass(_model("ChatDetailResponse"), _model("ChatSummary"))

    def test_chat_models_detail_json_keys_are_exactly_the_contract(self) -> None:
        detail = _model("ChatDetailResponse").model_validate(_detail_payload())

        assert _dumped_keys(detail) == _DETAIL_KEYS

    def test_chat_models_detail_defaults(self) -> None:
        detail = _model("ChatDetailResponse").model_validate(_detail_payload())

        assert detail.next_cursor is None  # type: ignore[attr-defined]
        assert detail.pending_confirmation is None  # type: ignore[attr-defined]

    def test_chat_models_detail_holds_at_most_100_messages(self) -> None:
        model = _model("ChatDetailResponse")

        assert _accepts(model, _detail_payload(messages=[_message_payload()] * 100))
        exc = _rejects(model, _detail_payload(messages=[_message_payload()] * 101))
        assert _locs(exc) == [("messages",)]

    def test_chat_models_detail_messages_are_sanitized_views(self) -> None:
        text = "your token is " + _GITHUB_TOKEN
        detail = _model("ChatDetailResponse").model_validate(
            _detail_payload(messages=[_message_payload(content=text)])
        )

        messages = detail.messages  # type: ignore[attr-defined]
        assert isinstance(messages[0], _model("ChatMessageView"))
        assert messages[0].content == _sanitized_like_chat_response(text)

    @pytest.mark.parametrize("status", ["none", "pending", "expired"])
    def test_chat_models_detail_confirmation_status_accepts_the_three(self, status: str) -> None:
        detail = _model("ChatDetailResponse").model_validate(
            _detail_payload(confirmation_status=status)
        )

        assert detail.confirmation_status == status  # type: ignore[attr-defined]

    @pytest.mark.parametrize("status", ["awaiting_confirmation", "", "PENDING"])
    def test_chat_models_detail_confirmation_status_refuses_others(self, status: str) -> None:
        exc = _rejects(_model("ChatDetailResponse"), _detail_payload(confirmation_status=status))

        assert _locs(exc) == [("confirmation_status",)]

    def test_chat_models_detail_pending_confirmation_is_a_summary(self) -> None:
        """The safe subset of the pending confirmation (no session id), args sanitized."""
        pending = _pending_payload(args={"body": "key " + _GITHUB_TOKEN}, session_id="s1")
        detail = _model("ChatDetailResponse").model_validate(
            _detail_payload(pending_confirmation=pending, confirmation_status="pending")
        )

        summary = detail.pending_confirmation  # type: ignore[attr-defined]
        assert isinstance(summary, PendingConfirmationSummary)
        assert summary.args == PendingConfirmationSummary.model_validate(pending).args
        assert _dumped_keys(summary) == frozenset(PendingConfirmationSummary.model_fields)
        assert "session_id" not in _dumped_keys(summary)

    def test_chat_models_detail_context_is_a_chat_context(self) -> None:
        detail = _model("ChatDetailResponse").model_validate(_detail_payload())

        assert isinstance(detail.context, _model("ChatContext"))  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# 9. No raw tool inputs anywhere
# ---------------------------------------------------------------------------


class TestNoToolUseBlocks:
    """No chat API model (or anything nested in it) exposes tool_use_blocks."""

    @pytest.mark.parametrize("name", _CHAT_API_MODELS)
    def test_chat_models_api_model_schema_has_no_tool_use_blocks(self, name: str) -> None:
        model = _model(name)

        assert "tool_use_blocks" not in model.model_fields
        assert "tool_use_blocks" not in json.dumps(model.model_json_schema())
