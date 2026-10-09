"""Tests for GH-194's trash API models in ``admino.models`` (contract section 3).

``GET /api/trash`` answers with ``TrashListResponse`` (a page of ``TrashItem``)
and ``DELETE /api/trash`` with ``TrashEmptyResponse``; they are the contract in
/api/openapi.json (issue #194, Decision 6). New names are looked up per test
(``_model`` / ``_literal``), so this file collects before they exist and each
test fails on its own.

What these tests pin down:
- ``models.TrashItemType`` is exactly ``chat`` and ``attachment``, in that order.
- ``TrashItem``: the fields are exactly item_type, id, name, chat_id, deleted_at
  and expires_at (never an org, an owner or a trash group); ``item_type`` refuses
  anything outside the Literal; ``name`` is a chat's title (an untitled chat's
  empty title included) or a file's name, at most 255 characters (the file name
  bound of migration 0027); ``chat_id`` is required and None (a chat) or a UUID
  (a file's chat); the ids are UUIDs; the two times are timezone-aware
  datetimes, serialized with their offset.
- ``TrashListResponse``: ``items`` (at most 100, a page's maximum ``limit``),
  ``next_cursor`` (None by default, bounded like ``ChatListResponse``'s) and
  ``retention_days`` (required, 0 to 90, the org setting's range).
- ``TrashEmptyResponse``: ``chats`` and ``attachments``, both required ints >= 0.
- Response models: they are not required to refuse unknown keys.

Security notes:
- A trash item is metadata only: the name a client already showed, ids and
  times. No org id, owner id or path reaches a client, and the item names its
  chat by id only.

Harness: no database, no app: pure Pydantic validation with fixed fake values.
"""

from __future__ import annotations

import json
import typing
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

import admino.models as models_module

_CHAT_ID = "0b8e7c6d-5a4f-4e3d-9c2b-1a0f9e8d7c6b"
_FILE_ID = "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b"
_DELETED = "2026-10-07T09:30:00+00:00"
_EXPIRES = "2026-11-06T09:30:00+00:00"
_ITEM_FIELDS = frozenset({"item_type", "id", "name", "chat_id", "deleted_at", "expires_at"})
_E_ACUTE = chr(0xE9)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _model(name: str) -> type[BaseModel]:
    """A GH-194 model from admino.models; fails the calling test when missing."""
    model = getattr(models_module, name, None)
    if model is None:
        pytest.fail(f"admino.models.{name} does not exist (GH-194)")
    assert isinstance(model, type)
    assert issubclass(model, BaseModel)
    return model


def _literal(name: str) -> tuple[Any, ...]:
    """The members of a GH-194 Literal alias in admino.models, in order."""
    alias = getattr(models_module, name, None)
    if alias is None:
        pytest.fail(f"admino.models.{name} does not exist (GH-194)")
    assert typing.get_origin(alias) is typing.Literal
    return typing.get_args(alias)


def _item(**overrides: Any) -> dict[str, Any]:
    """A trashed file's item payload, overridden by keyword."""
    payload: dict[str, Any] = {
        "item_type": "attachment",
        "id": _FILE_ID,
        "name": "Q3 report.pdf",
        "chat_id": _CHAT_ID,
        "deleted_at": _DELETED,
        "expires_at": _EXPIRES,
    }
    payload.update(overrides)
    return payload


def _listing(**overrides: Any) -> dict[str, Any]:
    """A trash page payload with one item, overridden by keyword."""
    payload: dict[str, Any] = {"items": [_item()], "next_cursor": None, "retention_days": 30}
    payload.update(overrides)
    return payload


def _outcome(model_name: str, payload: dict[str, Any]) -> str | list[tuple[int | str, ...]]:
    """``"accepted"`` or the error locations of ``model_name`` built from ``payload``."""
    try:
        _model(model_name).model_validate(payload)
    except ValidationError as exc:
        return [tuple(error["loc"]) for error in exc.errors(include_url=False, include_input=False)]
    return "accepted"


def _without(payload: dict[str, Any], key: str) -> dict[str, Any]:
    """The payload without one key."""
    return {name: value for name, value in payload.items() if name != key}


def _cursor_bound() -> int:
    """The max_length of ``ChatListResponse.next_cursor``: the other lists' cursor bound."""
    lengths = [
        bound
        for item in models_module.ChatListResponse.model_fields["next_cursor"].metadata
        if (bound := getattr(item, "max_length", None)) is not None
    ]
    assert len(lengths) == 1, lengths
    return int(lengths[0])


# ---------------------------------------------------------------------------
# 1. TrashItemType
# ---------------------------------------------------------------------------


class TestTrashItemType:
    """The two kinds of trash item in V1 (Decision 1: chats and attachments only)."""

    def test_trash_models_item_type_is_chat_then_attachment(self) -> None:
        assert _literal("TrashItemType") == ("chat", "attachment")


# ---------------------------------------------------------------------------
# 2. TrashItem
# ---------------------------------------------------------------------------


class TestTrashItem:
    """One item of the caller's trash: metadata only."""

    def test_trash_models_item_json_of_a_chat_and_of_a_file(self) -> None:
        """A chat has no chat_id (null) and may have an empty title; a file names its
        chat. The times are serialized as UTC instants."""
        model = _model("TrashItem")
        chat = model.model_validate(_item(item_type="chat", id=_CHAT_ID, name="", chat_id=None))
        attachment = model.model_validate(_item())

        assert [json.loads(chat.model_dump_json()), json.loads(attachment.model_dump_json())] == [
            {
                "item_type": "chat",
                "id": _CHAT_ID,
                "name": "",
                "chat_id": None,
                "deleted_at": "2026-10-07T09:30:00Z",
                "expires_at": "2026-11-06T09:30:00Z",
            },
            {
                "item_type": "attachment",
                "id": _FILE_ID,
                "name": "Q3 report.pdf",
                "chat_id": _CHAT_ID,
                "deleted_at": "2026-10-07T09:30:00Z",
                "expires_at": "2026-11-06T09:30:00Z",
            },
        ]

    def test_trash_models_item_fields_are_exactly_the_contract(self) -> None:
        """No org, owner, trash group or path field ever reaches a client."""
        model = _model("TrashItem")

        assert frozenset(model.model_fields) == _ITEM_FIELDS
        assert frozenset(json.loads(model.model_validate(_item()).model_dump_json())) == (
            _ITEM_FIELDS
        )

    def test_trash_models_item_type_is_one_of_the_two(self) -> None:
        refused = ("project", "file", "Chat", "")
        outcomes = {
            kind: _outcome("TrashItem", _item(item_type=kind))
            for kind in ("chat", "attachment", *refused)
        }

        assert outcomes == {
            "chat": "accepted",
            "attachment": "accepted",
            **{kind: [("item_type",)] for kind in refused},
        }

    def test_trash_models_item_name_holds_0_to_255_characters(self) -> None:
        """An untitled chat's name is empty; a file name is at most 255 characters."""
        outcomes = {
            "empty": _outcome("TrashItem", _item(name="")),
            "255": _outcome("TrashItem", _item(name="a" * 255)),
            "255-accented": _outcome("TrashItem", _item(name=_E_ACUTE * 255)),
            "256": _outcome("TrashItem", _item(name="a" * 256)),
        }

        assert outcomes == {
            "empty": "accepted",
            "255": "accepted",
            "255-accented": "accepted",
            "256": [("name",)],
        }

    def test_trash_models_item_chat_id_is_required_and_none_or_a_uuid(self) -> None:
        """None for a chat, the chat's UUID for a file; no default, so every item
        carries the key."""
        outcomes = {
            "none": _outcome("TrashItem", _item(chat_id=None)),
            "uuid": _outcome("TrashItem", _item(chat_id=_CHAT_ID)),
            "not-uuid": _outcome("TrashItem", _item(chat_id="chat-1")),
            "omitted": _outcome("TrashItem", _without(_item(), "chat_id")),
        }

        assert outcomes == {
            "none": "accepted",
            "uuid": "accepted",
            "not-uuid": [("chat_id",)],
            "omitted": [("chat_id",)],
        }

    def test_trash_models_item_id_is_a_uuid(self) -> None:
        assert _outcome("TrashItem", _item(id="attachment-1")) == [("id",)]

    def test_trash_models_item_times_are_aware_and_keep_their_offset(self) -> None:
        """An aware deleted_at / expires_at is kept as the same instant with its offset
        (expires_at is deleted_at plus the retention, computed by the server)."""
        zurich = timezone(timedelta(hours=2))
        deleted = datetime(2026, 10, 7, 11, 30, tzinfo=zurich)
        expires = deleted + timedelta(days=30)
        item = _model("TrashItem").model_validate(_item(deleted_at=deleted, expires_at=expires))
        dumped = json.loads(item.model_dump_json())

        assert (item.deleted_at, item.expires_at) == (deleted, expires)  # type: ignore[attr-defined]
        assert item.deleted_at.utcoffset() == timedelta(hours=2)  # type: ignore[attr-defined]
        assert (dumped["deleted_at"], dumped["expires_at"]) == (
            "2026-10-07T11:30:00+02:00",
            "2026-11-06T11:30:00+02:00",
        )
        assert datetime.fromisoformat(dumped["deleted_at"]).astimezone(UTC) == datetime(
            2026, 10, 7, 9, 30, tzinfo=UTC
        )


# ---------------------------------------------------------------------------
# 3. TrashListResponse
# ---------------------------------------------------------------------------


class TestTrashListResponse:
    """GET /api/trash: a page of items, the cursor and the org's effective retention."""

    def test_trash_models_list_json_keys_and_next_cursor_default(self) -> None:
        listing = _model("TrashListResponse").model_validate({"items": [], "retention_days": 30})

        assert json.loads(listing.model_dump_json()) == {
            "items": [],
            "next_cursor": None,
            "retention_days": 30,
        }

    def test_trash_models_list_holds_at_most_100_items(self) -> None:
        """100 items (the most a page's limit asks for) fit; 101 don't."""
        outcomes = {
            count: _outcome("TrashListResponse", _listing(items=[_item()] * count))
            for count in (0, 100, 101)
        }

        assert outcomes == {0: "accepted", 100: "accepted", 101: [("items",)]}

    def test_trash_models_list_next_cursor_is_bounded_like_the_chat_list(self) -> None:
        """The same bound as the other list responses' cursors (200 characters)."""
        bound = _cursor_bound()
        outcomes = {
            length: _outcome("TrashListResponse", _listing(next_cursor="c" * length))
            for length in (bound, bound + 1)
        }

        assert bound == 200
        assert outcomes == {bound: "accepted", bound + 1: [("next_cursor",)]}

    def test_trash_models_list_retention_days_is_required_and_0_to_90(self) -> None:
        """The org setting's range (Decision 4): 0 (purged at once) to 90."""
        outcomes: dict[Any, Any] = {
            days: _outcome("TrashListResponse", _listing(retention_days=days))
            for days in (-1, 0, 30, 90, 91)
        }
        outcomes["omitted"] = _outcome("TrashListResponse", _without(_listing(), "retention_days"))

        assert outcomes == {
            -1: [("retention_days",)],
            0: "accepted",
            30: "accepted",
            90: "accepted",
            91: [("retention_days",)],
            "omitted": [("retention_days",)],
        }

    def test_trash_models_list_items_are_trash_items(self) -> None:
        """An item is validated as a TrashItem (its index in the error location)."""
        payload = _listing(items=[_item(), _item(item_type="project")])

        assert _outcome("TrashListResponse", payload) == [("items", 1, "item_type")]


# ---------------------------------------------------------------------------
# 4. TrashEmptyResponse
# ---------------------------------------------------------------------------


class TestTrashEmptyResponse:
    """DELETE /api/trash: how many chats and files were purged."""

    def test_trash_models_empty_json_shape(self) -> None:
        emptied = _model("TrashEmptyResponse").model_validate({"chats": 2, "attachments": 3})

        assert json.loads(emptied.model_dump_json()) == {"chats": 2, "attachments": 3}
        assert frozenset(_model("TrashEmptyResponse").model_fields) == {"chats", "attachments"}

    def test_trash_models_empty_counts_are_required_non_negative_ints(self) -> None:
        base = {"chats": 0, "attachments": 0}
        outcomes = {
            "zero": _outcome("TrashEmptyResponse", base),
            "chats -1": _outcome("TrashEmptyResponse", {**base, "chats": -1}),
            "attachments -1": _outcome("TrashEmptyResponse", {**base, "attachments": -1}),
            "chats omitted": _outcome("TrashEmptyResponse", _without(base, "chats")),
            "attachments omitted": _outcome("TrashEmptyResponse", _without(base, "attachments")),
        }

        assert outcomes == {
            "zero": "accepted",
            "chats -1": [("chats",)],
            "attachments -1": [("attachments",)],
            "chats omitted": [("chats",)],
            "attachments omitted": [("attachments",)],
        }
