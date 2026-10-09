"""Tests for GH-187's attachment API models in ``admino.models`` (contract section 3.1).

``POST /api/chats/{chat_id}/attachments`` and ``GET /api/attachments/{id}``
answer with ``AttachmentSummary``; it is the contract in /api/openapi.json.
New names are looked up per test (``_model`` / ``_literal``), so this file
collects before they exist and each test fails on its own.

What these tests pin down:
- ``models.AttachmentKind`` is exactly the nine kinds in the contract's order
  (pdf, docx, xlsx, csv, txt, md, png, jpeg, webp) and
  ``models.AttachmentStatus`` the four statuses (uploaded, processing, ready,
  failed).
- ``AttachmentSummary``: JSON keys exactly id, chat_id, message_id, filename,
  kind, size_bytes, status, failure_reason, page_count, token_estimate (GH-188),
  created_at (never an org, an owner or a path); one example's JSON shape and a
  ready file's; ``kind`` and ``status``
  refuse anything outside their Literal (``jpg``, ``PDF``, ``pptx``,
  ``deleted``...); ``filename`` 1 to 255 characters (code points);
  ``size_bytes`` 1 to 524288000 (500 MiB, the DB CHECK); ``failure_reason``
  None or a code matching ``^[a-z][a-z0-9_]{0,63}$`` (no capital, no leading
  digit or underscore, no space, dash or trailing newline, at most 64);
  ``page_count`` None or >= 0; ``message_id`` None or a UUID; ``id`` and
  ``chat_id`` UUIDs.
- GH-188 (contract section 9): ``token_estimate`` is ``int | None`` with ge=0
  (None until the file is ready, then the estimated tokens of its text and
  images), required (no default: the response always carries it), the field
  right after ``page_count``.
- GH-190 (contract C2): the JSON keys gain ``active`` (required) and
  ``context_report`` (null unless the file failed with ``context_overflow``);
  both are pinned in tests/test_context_models.py.

Security notes:
- The summary is what a client sees of a stored file: the filename is the
  sanitized one, the failure reason is a code (never an exception text), and
  no field can carry a filesystem path or another tenant's id.
"""

from __future__ import annotations

import json
import typing
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

import admino.models as models_module

_UUID = "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b"
_CHAT_UUID = "0b8e7c6d-5a4f-4e3d-9c2b-1a0f9e8d7c6b"
_MESSAGE_UUID = "3c2d1e0f-9a8b-4c7d-8e6f-5a4b3c2d1e0f"
_TIMESTAMP = "2026-10-07T09:30:00+00:00"
_MAX_SIZE = 524_288_000

_KINDS = ("pdf", "docx", "xlsx", "csv", "txt", "md", "png", "jpeg", "webp")
_STATUSES = ("uploaded", "processing", "ready", "failed")
_SUMMARY_KEYS = frozenset(
    {
        "id",
        "chat_id",
        "message_id",
        "filename",
        "kind",
        "size_bytes",
        "status",
        "failure_reason",
        "page_count",
        "token_estimate",
        "active",
        "context_report",
        "created_at",
    }
)
_E_ACUTE = chr(0xE9)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _model(name: str) -> type[BaseModel]:
    """A GH-187 model from admino.models; fails the calling test when missing."""
    model = getattr(models_module, name, None)
    if model is None:
        pytest.fail(f"admino.models.{name} does not exist (GH-187)")
    assert isinstance(model, type)
    assert issubclass(model, BaseModel)
    return model


def _literal(name: str) -> tuple[Any, ...]:
    """The members of a GH-187 Literal alias in admino.models, in order."""
    alias = getattr(models_module, name, None)
    if alias is None:
        pytest.fail(f"admino.models.{name} does not exist (GH-187)")
    assert typing.get_origin(alias) is typing.Literal
    return typing.get_args(alias)


def _payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": _UUID,
        "chat_id": _CHAT_UUID,
        "message_id": None,
        "filename": "Q3 report.pdf",
        "kind": "pdf",
        "size_bytes": 48213,
        "status": "uploaded",
        "failure_reason": None,
        "page_count": None,
        "token_estimate": None,
        "active": True,
        "created_at": _TIMESTAMP,
    }
    payload.update(overrides)
    return payload


def _outcome(**overrides: Any) -> str | list[tuple[int | str, ...]]:
    """``"accepted"`` or the error locations of a summary built with ``overrides``."""
    try:
        _model("AttachmentSummary").model_validate(_payload(**overrides))
    except ValidationError as exc:
        return [tuple(error["loc"]) for error in exc.errors(include_url=False, include_input=False)]
    return "accepted"


# ---------------------------------------------------------------------------
# 1. The Literals
# ---------------------------------------------------------------------------


class TestAttachmentLiterals:
    """AttachmentKind and AttachmentStatus."""

    def test_attachment_models_kind_is_the_nine_kinds_in_order(self) -> None:
        assert _literal("AttachmentKind") == _KINDS

    def test_attachment_models_status_is_the_four_statuses(self) -> None:
        assert _literal("AttachmentStatus") == _STATUSES


# ---------------------------------------------------------------------------
# 2. AttachmentSummary
# ---------------------------------------------------------------------------


class TestAttachmentSummary:
    """One stored attachment as the API shows it."""

    def test_attachment_models_summary_json_shape_of_an_example(self) -> None:
        summary = _model("AttachmentSummary").model_validate(
            _payload(
                message_id=_MESSAGE_UUID,
                kind="docx",
                status="failed",
                failure_reason="corrupted_file",
                page_count=0,
            )
        )

        assert json.loads(summary.model_dump_json()) == {
            "id": _UUID,
            "chat_id": _CHAT_UUID,
            "message_id": _MESSAGE_UUID,
            "filename": "Q3 report.pdf",
            "kind": "docx",
            "size_bytes": 48213,
            "status": "failed",
            "failure_reason": "corrupted_file",
            "page_count": 0,
            "token_estimate": None,
            "active": True,
            "context_report": None,
            "created_at": "2026-10-07T09:30:00Z",
        }

    def test_attachment_models_summary_json_of_a_ready_file_carries_its_token_estimate(
        self,
    ) -> None:
        summary = _model("AttachmentSummary").model_validate(
            _payload(status="ready", page_count=12, token_estimate=4195)
        )

        assert {
            key: value
            for key, value in json.loads(summary.model_dump_json()).items()
            if key in ("status", "page_count", "token_estimate")
        } == {"status": "ready", "page_count": 12, "token_estimate": 4195}

    def test_attachment_models_summary_json_keys_are_exactly_the_contract(self) -> None:
        """No org, owner, path or deletion field ever reaches a client."""
        model = _model("AttachmentSummary")
        summary = model.model_validate(_payload())

        assert frozenset(json.loads(summary.model_dump_json())) == _SUMMARY_KEYS
        assert frozenset(model.model_fields) == _SUMMARY_KEYS

    def test_attachment_models_summary_kind_is_one_of_the_nine(self) -> None:
        outcomes = {kind: _outcome(kind=kind) for kind in (*_KINDS, "jpg", "PDF", "pptx", "exe")}

        assert outcomes == {
            **dict.fromkeys(_KINDS, "accepted"),
            **{kind: [("kind",)] for kind in ("jpg", "PDF", "pptx", "exe")},
        }

    def test_attachment_models_summary_status_is_one_of_the_four(self) -> None:
        refused = ("deleted", "trashed", "READY", "")
        outcomes = {status: _outcome(status=status) for status in (*_STATUSES, *refused)}

        assert outcomes == {
            **dict.fromkeys(_STATUSES, "accepted"),
            **{status: [("status",)] for status in refused},
        }

    def test_attachment_models_summary_filename_holds_1_to_255_characters(self) -> None:
        outcomes = {
            "empty": _outcome(filename=""),
            "one": _outcome(filename="a"),
            "255": _outcome(filename="a" * 255),
            "255-accented": _outcome(filename=_E_ACUTE * 255),
            "256": _outcome(filename="a" * 256),
        }

        assert outcomes == {
            "empty": [("filename",)],
            "one": "accepted",
            "255": "accepted",
            "255-accented": "accepted",
            "256": [("filename",)],
        }

    def test_attachment_models_summary_size_is_1_byte_to_500_mib(self) -> None:
        sizes = (-1, 0, 1, _MAX_SIZE, _MAX_SIZE + 1)
        outcomes = {size: _outcome(size_bytes=size) for size in sizes}

        assert outcomes == {
            -1: [("size_bytes",)],
            0: [("size_bytes",)],
            1: "accepted",
            _MAX_SIZE: "accepted",
            _MAX_SIZE + 1: [("size_bytes",)],
        }

    @pytest.mark.parametrize(
        "reason",
        [None, "corrupted_file", "too_many_pages", "a", "a" + "0" * 63],
        ids=["none", "corrupted-file", "too-many-pages", "one-letter", "64-chars"],
    )
    def test_attachment_models_summary_failure_reason_accepts_codes(
        self, reason: str | None
    ) -> None:
        summary = _model("AttachmentSummary").model_validate(
            _payload(status="failed" if reason else "uploaded", failure_reason=reason)
        )

        assert summary.failure_reason == reason  # type: ignore[attr-defined]

    @pytest.mark.parametrize(
        "reason",
        [
            "",
            "Corrupted_file",
            "1corrupted",
            "_corrupted",
            "corrupted file",
            "corrupted-file",
            "a" * 65,
            "corrupted_file" + chr(0x0A),
            "fichier_" + _E_ACUTE,
        ],
        ids=[
            "empty",
            "capital",
            "leading-digit",
            "leading-underscore",
            "space",
            "dash",
            "65-chars",
            "trailing-newline",
            "non-ascii",
        ],
    )
    def test_attachment_models_summary_failure_reason_refuses_non_codes(self, reason: str) -> None:
        assert _outcome(status="failed", failure_reason=reason) == [("failure_reason",)]

    def test_attachment_models_summary_page_count_is_none_or_not_negative(self) -> None:
        outcomes = {value: _outcome(page_count=value) for value in (None, 0, 7, -1)}

        assert outcomes == {None: "accepted", 0: "accepted", 7: "accepted", -1: [("page_count",)]}

    def test_attachment_models_summary_token_estimate_is_none_or_not_negative(self) -> None:
        outcomes = {value: _outcome(token_estimate=value) for value in (None, 0, 4195, -1)}

        assert outcomes == {
            None: "accepted",
            0: "accepted",
            4195: "accepted",
            -1: [("token_estimate",)],
        }

    def test_attachment_models_summary_token_estimate_is_required(self) -> None:
        """No default: a summary built without it is refused, so every response
        carries the key (null until the file is ready)."""
        payload = _payload()
        del payload["token_estimate"]

        try:
            _model("AttachmentSummary").model_validate(payload)
        except ValidationError as exc:
            errors = [
                (tuple(error["loc"]), error["type"])
                for error in exc.errors(include_url=False, include_input=False)
            ]
        else:
            errors = []

        assert errors == [(("token_estimate",), "missing")]

    def test_attachment_models_summary_token_estimate_follows_page_count(self) -> None:
        fields = list(_model("AttachmentSummary").model_fields)

        assert "token_estimate" in fields
        assert fields[fields.index("page_count") + 1] == "token_estimate"

    def test_attachment_models_summary_ids_are_uuids(self) -> None:
        outcomes = {
            "message-none": _outcome(message_id=None),
            "message-uuid": _outcome(message_id=_MESSAGE_UUID),
            "message-not-uuid": _outcome(message_id="m1"),
            "id-not-uuid": _outcome(id="attachment-1"),
            "chat-not-uuid": _outcome(chat_id="chat-1"),
        }

        assert outcomes == {
            "message-none": "accepted",
            "message-uuid": "accepted",
            "message-not-uuid": [("message_id",)],
            "id-not-uuid": [("id",)],
            "chat-not-uuid": [("chat_id",)],
        }
