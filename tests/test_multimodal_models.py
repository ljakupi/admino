"""Spec for GH-189's content-part models (contract C1, issue Decision 1).

What is pinned here (``admino.models``):

- ``TextContent(type="text", text)``: frozen, ``extra="forbid"``. A text whose
  ``text.strip() == ""`` is refused: the empty string and every character for which
  ``str.isspace`` is true (ASCII, the Unicode spaces, the line and paragraph separators).
  A zero-width space alone is not blank (``strip`` keeps it). An accepted text is kept
  verbatim. A refusal never echoes the input.
- ``ImageContent(type="image", media_type, data)``: frozen, ``extra="forbid"``.
  ``media_type`` is ``image/jpeg`` or ``image/png`` only. ``data`` is standard base64
  (``^[A-Za-z0-9+/]+={0,2}$``): a ``data:`` prefix, whitespace (a trailing newline
  too), the URL-safe alphabet and the empty string are refused, and never echoed.
- ``LLMMessage.content``: a ``str`` (at most 65536 characters, as today) or a
  non-empty list of parts, discriminated by ``type`` (dicts are parsed, an unknown
  type is refused). A list is allowed on ``user`` messages only. The 65536 maximum is
  the ``str``'s: a text part inside a list isn't capped (attachments go in full,
  Decision 5). The other fields are unchanged.
- ``AttachmentContent``: ``id``, ``filename`` (1 to 255), ``kind`` (the nine
  ``AttachmentKind`` values), ``page_count`` (``None`` or >= 0) and ``parts`` (a tuple
  of content parts), frozen and ``extra="forbid"``; ``has_images`` is true when a part
  is an ``ImageContent``. GH-190 adds ``token_estimate`` (default 0, pinned in
  tests/test_context_models.py).
- ``AgentConfig.image_input`` defaults to ``True`` and accepts ``False``.

The new names are looked up at test time, so this file collects before GH-189 and
every test fails on its own.

Security notes: content parts carry user file content; a validation error must never
repeat it (tracker #139 section 5).
"""

from __future__ import annotations

import json
from typing import Any, Final, get_args
from uuid import UUID

import pytest
from pydantic import BaseModel, ValidationError

import admino.models as models_module
from admino.models import AgentConfig, LLMMessage

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MARKER: Final = "ZZ-SENTINEL-189"
_PNG_B64: Final = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5E"
    "rkJggg=="
)
_JPEG_B64: Final = "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8U+Q=="
_ATTACHMENT_ID: Final = UUID("8a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d")
_KINDS: Final = ("pdf", "docx", "xlsx", "csv", "txt", "md", "png", "jpeg", "webp")
_CONTENT_MAX: Final = 65536
_FILENAME_MAX: Final = 255
_ZWSP: Final = chr(0x200B)
_EM_SPACE: Final = chr(0x2003)
_IDEOGRAPHIC_SPACE: Final = chr(0x3000)

# Every character str.isspace() calls whitespace: what str.strip() removes.
_WHITESPACE: Final[tuple[str, ...]] = tuple(
    chr(code) for code in range(0x110000) if chr(code).isspace()
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _model(name: str) -> type[BaseModel]:
    """A GH-189 model from admino.models; fails the calling test when missing."""
    model = getattr(models_module, name, None)
    if model is None:
        pytest.fail(f"admino.models.{name} does not exist (GH-189)")
    assert isinstance(model, type)
    assert issubclass(model, BaseModel)
    return model


def _text(text: str) -> BaseModel:
    return _model("TextContent").model_validate({"type": "text", "text": text})


def _image(media_type: str = "image/png", data: str = _PNG_B64) -> BaseModel:
    return _model("ImageContent").model_validate(
        {"type": "image", "media_type": media_type, "data": data}
    )


def _rejects(model: type[BaseModel], payload: dict[str, Any]) -> ValidationError:
    with pytest.raises(ValidationError) as exc_info:
        model.model_validate(payload)
    return exc_info.value


def _error_text(exc: ValidationError) -> str:
    """Everything a 422 or a log line could show: str(exc) plus the input-free errors."""
    errors = exc.errors(include_url=False, include_input=False)
    return str(exc) + json.dumps(errors, default=str)


def _attachment(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": _ATTACHMENT_ID,
        "filename": "report.pdf",
        "kind": "pdf",
        "page_count": 3,
        "parts": [{"type": "text", "text": "[report.pdf — page 1]\nHello"}],
    }
    payload.update(overrides)
    return payload


# ===========================================================================
# 1. TextContent
# ===========================================================================


class TestTextContent:
    """A text part: never blank, kept verbatim, sealed."""

    def test_multimodal_models_text_content_builds_a_text_part(self) -> None:
        part = _model("TextContent")(text="Hello")  # type: ignore[call-arg]

        assert (part.type, part.text) == ("text", "Hello")  # type: ignore[attr-defined]

    def test_multimodal_models_text_content_keeps_the_text_verbatim(self) -> None:
        """Blankness is a check, not a transform: surrounding whitespace stays."""
        assert _text("  Hello\n").text == "  Hello\n"  # type: ignore[attr-defined]

    def test_multimodal_models_text_content_empty_text_is_refused(self) -> None:
        _rejects(_model("TextContent"), {"type": "text", "text": ""})

    @pytest.mark.parametrize("char", _WHITESPACE, ids=[f"U+{ord(c):04X}" for c in _WHITESPACE])
    def test_multimodal_models_text_content_whitespace_only_text_is_refused(
        self, char: str
    ) -> None:
        """Every str.isspace character, alone and repeated, is blank (text.strip() == "")."""
        model = _model("TextContent")

        _rejects(model, {"type": "text", "text": char})
        _rejects(model, {"type": "text", "text": char * 3})

    def test_multimodal_models_text_content_mixed_whitespace_is_refused(self) -> None:
        _rejects(_model("TextContent"), {"type": "text", "text": "".join(_WHITESPACE)})

    def test_multimodal_models_text_content_zero_width_space_alone_is_not_blank(self) -> None:
        """U+200B is a format character, not whitespace: strip() keeps it."""
        assert _text(_ZWSP).text == _ZWSP  # type: ignore[attr-defined]

    def test_multimodal_models_text_content_blank_refusal_never_echoes_the_input(self) -> None:
        exc = _rejects(
            _model("TextContent"),
            {"type": "text", "text": _EM_SPACE + _IDEOGRAPHIC_SPACE + _EM_SPACE},
        )

        assert "input_value" not in str(exc)
        assert _EM_SPACE not in _error_text(exc)
        assert "\\u2003" not in _error_text(exc)

    def test_multimodal_models_text_content_extra_field_is_refused_and_not_echoed(self) -> None:
        exc = _rejects(_model("TextContent"), {"type": "text", "text": "Hello", "label": _MARKER})

        assert _MARKER not in _error_text(exc)

    @pytest.mark.parametrize("part_type", ["image", "TEXT", "", "image_url"])
    def test_multimodal_models_text_content_other_type_is_refused(self, part_type: str) -> None:
        _rejects(_model("TextContent"), {"type": part_type, "text": "Hello"})

    def test_multimodal_models_text_content_is_frozen(self) -> None:
        part = _text("Hello")

        with pytest.raises(ValidationError):
            part.text = "changed"  # type: ignore[attr-defined]


# ===========================================================================
# 2. ImageContent
# ===========================================================================


class TestImageContent:
    """An image part: JPEG or PNG, standard base64 without a data: prefix."""

    @pytest.mark.parametrize(
        ("media_type", "data"),
        [("image/png", _PNG_B64), ("image/jpeg", _JPEG_B64)],
        ids=["png", "jpeg"],
    )
    def test_multimodal_models_image_content_accepts_png_and_jpeg(
        self, media_type: str, data: str
    ) -> None:
        part = _image(media_type, data)

        assert (part.type, part.media_type, part.data) == ("image", media_type, data)  # type: ignore[attr-defined]

    @pytest.mark.parametrize(
        "media_type",
        [
            "image/webp",
            "image/gif",
            "image/svg+xml",
            "image/jpg",
            "IMAGE/PNG",
            "image/png; charset=binary",
            " image/png",
            "application/pdf",
            "",
        ],
    )
    def test_multimodal_models_image_content_other_media_type_is_refused(
        self, media_type: str
    ) -> None:
        _rejects(
            _model("ImageContent"),
            {"type": "image", "media_type": media_type, "data": _PNG_B64},
        )

    @pytest.mark.parametrize(
        "data",
        ["QQ", "QUI=", "QQ==", "ab+/", "A", "+/+/"],
        ids=["no-padding", "one-pad", "two-pad", "plus-slash", "one-char", "symbols-only"],
    )
    def test_multimodal_models_image_content_standard_base64_is_accepted(self, data: str) -> None:
        assert _image(data=data).data == data  # type: ignore[attr-defined]

    @pytest.mark.parametrize(
        "data",
        [
            pytest.param("data:image/png;base64," + _PNG_B64, id="data-uri-prefix"),
            pytest.param("data:image/png;base64,", id="data-uri-prefix-only"),
            pytest.param("iVBO Rw0K", id="inner-space"),
            pytest.param("iVBO\nRw0K", id="inner-newline"),
            pytest.param("iVBORw0K\n", id="trailing-newline"),
            pytest.param(" iVBORw0K", id="leading-space"),
            pytest.param("iVBORw0K\t", id="trailing-tab"),
            pytest.param("iVBO-w0K_g", id="url-safe-alphabet"),
            pytest.param("iVBO_w0K", id="url-safe-underscore"),
            pytest.param("", id="empty"),
            pytest.param("=", id="padding-only"),
            pytest.param("QQ===", id="three-padding"),
            pytest.param("Q=Q=", id="inner-padding"),
            pytest.param("iVBØRw0K", id="non-ascii"),
            pytest.param("iVBORw0K" + _ZWSP, id="zero-width-space"),
            pytest.param("https://example.com/a.png", id="url"),
        ],
    )
    def test_multimodal_models_image_content_non_standard_base64_is_refused(
        self, data: str
    ) -> None:
        _rejects(
            _model("ImageContent"),
            {"type": "image", "media_type": "image/png", "data": data},
        )

    def test_multimodal_models_image_content_refusal_never_echoes_the_data(self) -> None:
        exc = _rejects(
            _model("ImageContent"),
            {"type": "image", "media_type": "image/png", "data": f"data:{_MARKER}"},
        )

        assert _MARKER not in _error_text(exc)

    @pytest.mark.parametrize(
        ("field", "value"),
        [("url", "https://example.com/a.png"), ("label", "a.png"), ("detail", "high")],
    )
    def test_multimodal_models_image_content_extra_field_is_refused(
        self, field: str, value: str
    ) -> None:
        payload = {"type": "image", "media_type": "image/png", "data": _PNG_B64, field: value}

        _rejects(_model("ImageContent"), payload)

    def test_multimodal_models_image_content_is_frozen(self) -> None:
        part = _image()

        with pytest.raises(ValidationError):
            part.data = "QQ=="  # type: ignore[attr-defined]


# ===========================================================================
# 3. LLMMessage
# ===========================================================================


class TestLLMMessageContentParts:
    """LLMMessage.content: a str as today, or a non-empty list of parts on user messages."""

    def test_multimodal_models_llm_message_user_accepts_text_and_image_parts(self) -> None:
        text = _text("Look at this")
        image = _image()

        message = LLMMessage(role="user", content=[text, image])  # type: ignore[list-item]

        assert message.content == [text, image]

    @pytest.mark.parametrize("role", ["system", "assistant", "tool"])
    def test_multimodal_models_llm_message_list_on_a_non_user_role_is_refused(
        self, role: str
    ) -> None:
        """Only user messages may carry parts (every provider takes images there only):
        the same list is accepted on a user message and refused on this role."""
        content = [{"type": "text", "text": "Hi"}]
        payload: dict[str, Any] = {"role": role, "content": content}
        if role == "tool":
            payload["tool_call_id"] = "tc-1"

        assert LLMMessage.model_validate({"role": "user", "content": content}).role == "user"
        with pytest.raises(ValidationError):
            LLMMessage.model_validate(payload)

    def test_multimodal_models_llm_message_empty_list_is_refused(self) -> None:
        """A list holds at least one part: one part is accepted, none is refused."""
        one = LLMMessage.model_validate(
            {"role": "user", "content": [{"type": "text", "text": "Hi"}]}
        )

        assert len(one.content) == 1
        with pytest.raises(ValidationError):
            LLMMessage.model_validate({"role": "user", "content": []})

    def test_multimodal_models_llm_message_dict_parts_are_parsed_by_type_in_order(self) -> None:
        text_model = _model("TextContent")
        image_model = _model("ImageContent")

        message = LLMMessage.model_validate(
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Intro"},
                    {"type": "image", "media_type": "image/jpeg", "data": _JPEG_B64},
                    {"type": "text", "text": "End"},
                ],
            }
        )

        assert [type(part) for part in message.content] == [text_model, image_model, text_model]
        assert [getattr(part, "text", None) for part in message.content] == ["Intro", None, "End"]

    @pytest.mark.parametrize(
        "part",
        [
            pytest.param({"type": "image_url", "image_url": {"url": "data:,"}}, id="image-url"),
            pytest.param({"type": "file", "data": _PNG_B64}, id="file"),
            pytest.param({"type": "document", "text": "Hi"}, id="document"),
            pytest.param({"type": "TEXT", "text": "Hi"}, id="upper-case-text"),
            pytest.param({"type": "", "text": "Hi"}, id="empty-type"),
            pytest.param({"text": "Hi"}, id="no-type"),
            pytest.param({"type": "text", "media_type": "image/png", "data": _PNG_B64}, id="mixed"),
            pytest.param("Hi", id="plain-string"),
            pytest.param(None, id="none"),
        ],
    )
    def test_multimodal_models_llm_message_unknown_part_is_refused(self, part: object) -> None:
        """The discriminator is "type": anything that isn't a text or image part is refused."""
        assert LLMMessage.model_validate(
            {"role": "user", "content": [{"type": "text", "text": "Hi"}]}
        )

        with pytest.raises(ValidationError):
            LLMMessage.model_validate({"role": "user", "content": [part]})

    def test_multimodal_models_llm_message_blank_text_part_in_a_list_is_refused(self) -> None:
        """Nested parts are validated: no whitespace-only text block can be built."""
        assert LLMMessage.model_validate(
            {"role": "user", "content": [{"type": "text", "text": "Hi"}]}
        )

        with pytest.raises(ValidationError):
            LLMMessage.model_validate({"role": "user", "content": [{"type": "text", "text": " "}]})

    def test_multimodal_models_llm_message_maximum_applies_to_str_content_only(self) -> None:
        """A str keeps its 65536 maximum; a text part is never capped (Decision 5)."""
        long_part = _text("c" * (_CONTENT_MAX + 1))

        at_max = LLMMessage(role="user", content="c" * _CONTENT_MAX)
        with pytest.raises(ValidationError):
            LLMMessage(role="user", content="c" * (_CONTENT_MAX + 1))
        in_list = LLMMessage(role="user", content=[long_part])  # type: ignore[list-item]

        assert (type(at_max.content), len(at_max.content)) == (str, _CONTENT_MAX)
        assert in_list.content == [long_part]

    def test_multimodal_models_llm_message_other_fields_are_unchanged(self) -> None:
        """role, content, tool_call_id and tool_use_blocks, with today's defaults."""
        message = LLMMessage(role="user", content=[_text("Hi")])  # type: ignore[list-item]

        assert frozenset(LLMMessage.model_fields) == {
            "role",
            "content",
            "tool_call_id",
            "tool_use_blocks",
        }
        assert (message.tool_call_id, message.tool_use_blocks) == (None, None)


# ===========================================================================
# 4. AttachmentContent
# ===========================================================================


class TestAttachmentContent:
    """One active attachment as the slot needs it: id, name, kind, pages, parts."""

    def test_multimodal_models_attachment_content_fields_are_exactly_the_contract(self) -> None:
        assert frozenset(_model("AttachmentContent").model_fields) == {
            "id",
            "filename",
            "kind",
            "page_count",
            "parts",
            "token_estimate",
        }

    def test_multimodal_models_attachment_content_parses_parts_into_a_tuple_in_order(
        self,
    ) -> None:
        text_model = _model("TextContent")
        image_model = _model("ImageContent")

        content = _model("AttachmentContent").model_validate(
            _attachment(
                kind="png",
                page_count=None,
                filename="a.png",
                parts=[
                    {"type": "text", "text": "[a.png]"},
                    {"type": "image", "media_type": "image/png", "data": _PNG_B64},
                ],
            )
        )

        assert type(content.parts) is tuple  # type: ignore[attr-defined]
        assert [type(part) for part in content.parts] == [text_model, image_model]  # type: ignore[attr-defined]
        assert (content.id, content.filename, content.kind, content.page_count) == (  # type: ignore[attr-defined]
            _ATTACHMENT_ID,
            "a.png",
            "png",
            None,
        )

    @pytest.mark.parametrize("length", [1, _FILENAME_MAX])
    def test_multimodal_models_attachment_content_filename_within_bounds_is_accepted(
        self, length: int
    ) -> None:
        content = _model("AttachmentContent").model_validate(_attachment(filename="a" * length))

        assert len(content.filename) == length  # type: ignore[attr-defined]

    @pytest.mark.parametrize("length", [0, _FILENAME_MAX + 1])
    def test_multimodal_models_attachment_content_filename_out_of_bounds_is_refused(
        self, length: int
    ) -> None:
        _rejects(_model("AttachmentContent"), _attachment(filename="a" * length))

    def test_multimodal_models_attachment_content_filename_refusal_is_not_echoed(self) -> None:
        exc = _rejects(
            _model("AttachmentContent"),
            _attachment(filename=_MARKER + "a" * _FILENAME_MAX),
        )

        assert _MARKER not in _error_text(exc)

    @pytest.mark.parametrize("kind", _KINDS)
    def test_multimodal_models_attachment_content_every_attachment_kind_is_accepted(
        self, kind: str
    ) -> None:
        assert frozenset(get_args(models_module.AttachmentKind)) == frozenset(_KINDS)
        content = _model("AttachmentContent").model_validate(_attachment(kind=kind))

        assert content.kind == kind  # type: ignore[attr-defined]

    @pytest.mark.parametrize("kind", ["gif", "PDF", "exe", "jpg", ""])
    def test_multimodal_models_attachment_content_other_kind_is_refused(self, kind: str) -> None:
        _rejects(_model("AttachmentContent"), _attachment(kind=kind))

    @pytest.mark.parametrize("page_count", [None, 0, 1, 1000])
    def test_multimodal_models_attachment_content_page_count_none_or_not_negative(
        self, page_count: int | None
    ) -> None:
        content = _model("AttachmentContent").model_validate(_attachment(page_count=page_count))

        assert content.page_count == page_count  # type: ignore[attr-defined]

    def test_multimodal_models_attachment_content_negative_page_count_is_refused(self) -> None:
        _rejects(_model("AttachmentContent"), _attachment(page_count=-1))

    @pytest.mark.parametrize(
        "overrides",
        [
            pytest.param({"id": "not-a-uuid"}, id="id-not-a-uuid"),
            pytest.param({"parts": [{"type": "text", "text": "  "}]}, id="blank-text-part"),
            pytest.param({"parts": [{"type": "image_url", "url": "x"}]}, id="unknown-part"),
            pytest.param({"parts": ["Hello"]}, id="plain-string-part"),
            pytest.param({"size_bytes": 12}, id="extra-size"),
            pytest.param({"content": "Hello"}, id="extra-content"),
        ],
    )
    def test_multimodal_models_attachment_content_invalid_field_is_refused(
        self, overrides: dict[str, Any]
    ) -> None:
        _rejects(_model("AttachmentContent"), _attachment(**overrides))

    @pytest.mark.parametrize(
        ("parts", "expected"),
        [
            pytest.param([{"type": "text", "text": "Hello"}], False, id="text-only"),
            pytest.param([], False, id="no-parts"),
            pytest.param(
                [{"type": "image", "media_type": "image/png", "data": _PNG_B64}], True, id="image"
            ),
            pytest.param(
                [
                    {"type": "text", "text": "[a.pdf — page 1]"},
                    {"type": "text", "text": "[a.pdf — page 1, image 1]"},
                    {"type": "image", "media_type": "image/jpeg", "data": _JPEG_B64},
                ],
                True,
                id="text-then-image",
            ),
        ],
    )
    def test_multimodal_models_attachment_content_has_images_reports_an_image_part(
        self, parts: list[dict[str, Any]], expected: bool
    ) -> None:
        content = _model("AttachmentContent").model_validate(_attachment(parts=parts))

        assert content.has_images is expected  # type: ignore[attr-defined]

    def test_multimodal_models_attachment_content_is_frozen(self) -> None:
        content = _model("AttachmentContent").model_validate(_attachment())

        with pytest.raises(ValidationError):
            content.filename = "other.pdf"  # type: ignore[attr-defined]


# ===========================================================================
# 5. AgentConfig.image_input
# ===========================================================================


class TestAgentConfigImageInput:
    """The stored platform llm.image_input of a run."""

    def test_multimodal_models_agent_config_image_input_defaults_to_true(self) -> None:
        assert AgentConfig().image_input is True  # type: ignore[attr-defined]

    def test_multimodal_models_agent_config_image_input_accepts_false(self) -> None:
        assert AgentConfig(image_input=False).image_input is False  # type: ignore[call-arg,attr-defined]
