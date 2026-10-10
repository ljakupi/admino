"""Spec of GH-302's fixed 422 validation messages (Decision 4, contract C5).

Issue #302, criterion 4: the shared ``422`` handler returns a fixed message per
validation error type, so no part of the request input is echoed back (security
audit of #194, server L-1: ``DELETE /x/SECRETxyz`` answered ``"msg": "Input should
be a valid UUID, invalid character: found `S` at 1"``). The envelope, ``loc``,
``type`` and every ``reason`` code stay as they are.

What is pinned:
- ``server._VALIDATION_MESSAGES`` is exactly contract C5's table (36 types) and
  read-only; ``server._VALIDATION_FALLBACK_MESSAGE`` is ``"Invalid input"``.
- ``server._request_validation_error_handler`` (FastAPI's RequestValidationError),
  for every type of the table, answers ``422 {"detail": [{"loc", "msg", "type"}]}``
  with ``msg`` = the table's text, ``loc`` items ``str()``-ed and ``type`` kept,
  keys in that order, and none of pydantic's ``msg``, ``input``, ``ctx`` or ``url``
  in the body (a canary sits in each). A type outside the table gets the fallback;
  an error without ``type`` gets ``value_error`` and ``"Invalid value"``.
- ``server._validation_error_handler`` (pydantic's ValidationError) does the same
  for real pydantic errors: a UUID adapter over the canary, a field validator whose
  text carries the input, one error of every table type at once (canaries in
  ``input`` and ``ctx``), and a custom type outside the table (the fallback).
- Through real routes, as a logged-in Editor of the tenancy world (tests/tenancy_world.py):
  a malformed UUID path id (``GET /api/chats/{chat_id}`` and ``DELETE
  /api/attachments/{attachment_id}``) answers ``uuid_parsing`` / "Input should be
  a valid UUID" with no character of the id in the body and none in an app log
  line; a missing body field is ``missing`` / "Field required"; an out-of-range
  ``limit`` of ``GET /api/chats/{chat_id}`` is "Input is too small" below and
  "Input is too large" above, the same text for two different inputs, with neither
  the input nor the bound (no digit at all) in the body; a malformed JSON body is
  ``json_invalid`` / "Invalid JSON" with no fragment of the body; a model
  validator's own text ("Give at least one setting to change.") becomes
  ``value_error`` / "Invalid value" on ``["body"]``; several errors keep FastAPI's
  order, ``loc`` (an extra field's ``loc`` still names the field) and ``type``;
  a reason-coded 422 (``invalid_cursor``) is unchanged.

The new names are read inside the tests, so the file collects before GH-302 is
implemented. The canary is three Greek capital letters (built with ``chr``): none
of them occurs in the table, in a ``loc`` or in a ``type``.

Security notes: every id, text and name here is a fixed fake value. No network, no
real PostgreSQL, no LLM.
"""

from __future__ import annotations

import json
import logging
import uuid
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final

import pytest
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, TypeAdapter, ValidationError, field_validator
from pydantic_core import InitErrorDetails, PydanticCustomError
from starlette.requests import Request

from admino import server
from tests.db_fakes import FakeDb
from tests.tenancy_world import (
    build_world,
    make_app,
    make_client,
    seed_chat,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)

if TYPE_CHECKING:
    import httpx
    from fastapi.responses import JSONResponse
    from fastapi.testclient import TestClient

    from tests.tenancy_world import World

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Contract C5's table, spelled out here (never read from server.py).
_EXPECTED_MESSAGES: Final[dict[str, str]] = {
    "missing": "Field required",
    "extra_forbidden": "Extra inputs are not permitted",
    "uuid_parsing": "Input should be a valid UUID",
    "uuid_type": "Input should be a valid UUID",
    "uuid_version": "Input should be a valid UUID",
    "int_parsing": "Input should be a valid integer",
    "int_type": "Input should be a valid integer",
    "int_from_float": "Input should be a valid integer",
    "float_parsing": "Input should be a valid number",
    "float_type": "Input should be a valid number",
    "bool_parsing": "Input should be a valid boolean",
    "bool_type": "Input should be a valid boolean",
    "string_type": "Input should be a valid string",
    "string_too_short": "String is too short",
    "string_too_long": "String is too long",
    "string_pattern_mismatch": "String doesn't match the expected pattern",
    "too_short": "Too few items",
    "too_long": "Too many items",
    "greater_than": "Input is too small",
    "greater_than_equal": "Input is too small",
    "less_than": "Input is too large",
    "less_than_equal": "Input is too large",
    "literal_error": "Input isn't one of the allowed values",
    "enum": "Input isn't one of the allowed values",
    "list_type": "Input should be a valid list",
    "dict_type": "Input should be a valid object",
    "model_type": "Input should be a valid object",
    "model_attributes_type": "Input should be a valid object",
    "json_invalid": "Invalid JSON",
    "json_type": "Input should be valid JSON",
    "datetime_parsing": "Input should be a valid datetime",
    "datetime_type": "Input should be a valid datetime",
    "datetime_from_date_parsing": "Input should be a valid datetime",
    "timezone_aware": "Input should have a timezone",
    "value_error": "Invalid value",
    "assertion_error": "Invalid value",
}
_FALLBACK: Final = "Invalid input"
_INVALID_VALUE: Final = "Invalid value"
_INVALID_UUID: Final = "Input should be a valid UUID"

# Greek capital Omega, Psi and Phi: in no table text, loc or type.
_CANARY: Final = chr(0x3A9) + chr(0x3A8) + chr(0x3A6)
_CANARY_CHARS: Final = frozenset(_CANARY)
# A malformed path id of a UUID's length made of canary characters only.
_BAD_ID: Final = _CANARY * 12
# Every context key a pydantic error template of the table may read, each a canary
# where pydantic accepts a string (the lengths and the version must be integers).
_CTX: Final[dict[str, Any]] = {
    "error": _CANARY,
    "gt": _CANARY,
    "ge": _CANARY,
    "lt": _CANARY,
    "le": _CANARY,
    "min_length": 7,
    "max_length": 7,
    "actual_length": 9,
    "field_type": _CANARY,
    "expected": _CANARY,
    "pattern": _CANARY,
    "expected_version": 4,
    "class_name": _CANARY,
}
_UNKNOWN_TYPE: Final = "admino_probe_unlisted"
_KEY_ORDER: Final = ["loc", "msg", "type"]
_INVALID_CURSOR_BODY: Final = {"detail": "Invalid cursor", "reason": "invalid_cursor"}

# The two UUID routes of the malformed-id case: (method, path template, path param).
_UUID_ROUTES: Final = [
    pytest.param("GET", "/api/chats/{}", "chat_id", id="GET:/api/chats/{chat_id}"),
    pytest.param(
        "DELETE",
        "/api/attachments/{}",
        "attachment_id",
        id="DELETE:/api/attachments/{attachment_id}",
    ),
]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def world(monkeypatch: pytest.MonkeyPatch) -> World:
    """Orgs A and B (OA/ED/VI each) and a Super Admin behind the fake database; every
    rate-limit bucket roomy."""
    db = FakeDb()
    built = build_world(db)
    use_fake_database(monkeypatch, db)
    use_fast_passwords(monkeypatch)
    use_roomy_rate_limits(monkeypatch)
    return built


@pytest.fixture()
def client(world: World) -> TestClient:
    """The app (a stub agent) and a client at ``CLIENT_IP``."""
    return make_client(make_app())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _request() -> Request:
    """A bare HTTP request (the handlers don't read it)."""
    return Request(
        {"type": "http", "method": "GET", "path": "/", "headers": [], "query_string": b""}
    )


def _decoded(response: JSONResponse) -> Any:
    """The handler's JSON body, keys in the order they were written."""
    return json.loads(bytes(response.body))


def _leaked(text: str) -> set[str]:
    """The canary characters found in ``text``."""
    return _CANARY_CHARS & set(text)


def _response_leaks(response: JSONResponse) -> set[str]:
    """Canary characters in the raw body or in any decoded string of it."""
    raw = bytes(response.body).decode()
    return _leaked(raw) | _leaked(json.dumps(_decoded(response), ensure_ascii=False))


def _http_leaks(response: httpx.Response) -> set[str]:
    """Canary characters in an HTTP response's raw text or decoded JSON."""
    return _leaked(response.text) | _leaked(json.dumps(response.json(), ensure_ascii=False))


def _key_orders(body: Any) -> list[list[str]]:
    """The key order of each error of a ``{"detail": [...]}`` body."""
    return [list(error) for error in body["detail"]]


def _app_log_text(caplog: pytest.LogCaptureFixture) -> str:
    """Every app log message of the test (httpx's own request lines excluded: they
    quote the URL whatever the app does)."""
    return "\n".join(
        record.getMessage()
        for record in caplog.records
        if not record.name.startswith(("httpx", "httpcore"))
    )


def _synthetic_error(error_type: str | None) -> dict[str, Any]:
    """A FastAPI-style error dict carrying the canary in msg, input, ctx and url."""
    error: dict[str, Any] = {
        "loc": ("body", "items", 3),
        "msg": f"pydantic says {_CANARY}",
        "input": _CANARY,
        "ctx": {"error": _CANARY, "limit": _CANARY},
        "url": f"https://errors.pydantic.dev/2/v/{_CANARY}",
    }
    if error_type is not None:
        error["type"] = error_type
    return error


async def _handle_request_error(error: dict[str, Any]) -> JSONResponse:
    """Run ``server._request_validation_error_handler`` on one synthetic error."""
    exc = RequestValidationError([error])
    return await server._request_validation_error_handler(_request(), exc)


async def _handle_pydantic_error(exc: ValidationError) -> JSONResponse:
    """Run ``server._validation_error_handler`` on a pydantic ValidationError."""
    return await server._validation_error_handler(_request(), exc)


def _caught(call: Any) -> ValidationError:
    """The ValidationError ``call()`` raises."""
    with pytest.raises(ValidationError) as exc_info:
        call()
    return exc_info.value


class _ProbeNote(BaseModel):
    """A model whose field validator's text carries the input (like a careless one)."""

    note: str

    @field_validator("note")
    @classmethod
    def _refuse(cls, value: str) -> str:
        msg = f"note {value} is not allowed"
        raise ValueError(msg)


# ---------------------------------------------------------------------------
# The table
# ---------------------------------------------------------------------------


def test_validation_messages_table_is_the_contract_table_and_read_only() -> None:
    """``_VALIDATION_MESSAGES`` is exactly contract C5's table, in a read-only mapping."""
    table = server._VALIDATION_MESSAGES

    assert isinstance(table, MappingProxyType)
    assert dict(table) == _EXPECTED_MESSAGES
    with pytest.raises(TypeError):
        table["missing"] = "changed"  # type: ignore[index]


def test_validation_messages_fallback_is_invalid_input() -> None:
    """A type outside the table answers ``"Invalid input"``."""
    assert server._VALIDATION_FALLBACK_MESSAGE == _FALLBACK


# ---------------------------------------------------------------------------
# _request_validation_error_handler (FastAPI's RequestValidationError)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("error_type", list(_EXPECTED_MESSAGES))
async def test_validation_messages_request_handler_answers_the_fixed_message_per_type(
    error_type: str,
) -> None:
    """Each table type: msg is the table's text, loc str()-ed, type kept, keys in order,
    and pydantic's msg, input, ctx and url (each a canary) never reach the body."""
    response = await _handle_request_error(_synthetic_error(error_type))

    body = _decoded(response)
    assert response.status_code == 422
    assert body == {
        "detail": [
            {
                "loc": ["body", "items", "3"],
                "msg": _EXPECTED_MESSAGES[error_type],
                "type": error_type,
            }
        ]
    }
    assert _key_orders(body) == [_KEY_ORDER]
    assert _response_leaks(response) == set()


async def test_validation_messages_request_handler_unknown_type_gets_the_fallback() -> None:
    """A type outside the table keeps its type and answers ``"Invalid input"``."""
    response = await _handle_request_error(_synthetic_error(_UNKNOWN_TYPE))

    assert response.status_code == 422
    assert _decoded(response) == {
        "detail": [{"loc": ["body", "items", "3"], "msg": _FALLBACK, "type": _UNKNOWN_TYPE}]
    }
    assert _response_leaks(response) == set()


async def test_validation_messages_request_handler_error_without_type_is_value_error() -> None:
    """An error without ``type`` is ``value_error`` with ``"Invalid value"``."""
    response = await _handle_request_error(_synthetic_error(None))

    assert response.status_code == 422
    assert _decoded(response) == {
        "detail": [{"loc": ["body", "items", "3"], "msg": _INVALID_VALUE, "type": "value_error"}]
    }
    assert _response_leaks(response) == set()


# ---------------------------------------------------------------------------
# _validation_error_handler (pydantic's ValidationError)
# ---------------------------------------------------------------------------


async def test_validation_messages_pydantic_handler_uuid_canary_is_the_fixed_message() -> None:
    """A UUID adapter over the canary: "Input should be a valid UUID", no character of it."""
    exc = _caught(lambda: TypeAdapter(uuid.UUID).validate_python(_BAD_ID))

    response = await _handle_pydantic_error(exc)

    assert response.status_code == 422
    assert _decoded(response) == {
        "detail": [{"loc": [], "msg": _INVALID_UUID, "type": "uuid_parsing"}]
    }
    assert _response_leaks(response) == set()


async def test_validation_messages_pydantic_handler_validator_text_is_invalid_value() -> None:
    """A field validator's own text (which quotes the input) becomes ``"Invalid value"``;
    the loc still names the field."""
    exc = _caught(lambda: _ProbeNote.model_validate({"note": _CANARY}))

    response = await _handle_pydantic_error(exc)

    assert response.status_code == 422
    assert _decoded(response) == {
        "detail": [{"loc": ["note"], "msg": _INVALID_VALUE, "type": "value_error"}]
    }
    assert _response_leaks(response) == set()


async def test_validation_messages_pydantic_handler_every_table_type_answers_its_message() -> None:
    """One error of every table type (canaries in input and ctx), in order: each gets its
    table text, its loc str()-ed and its type, keys in order, no canary in the body."""
    line_errors = [
        InitErrorDetails(type=error_type, loc=("body", error_type, 0), input=_CANARY, ctx=_CTX)
        for error_type in _EXPECTED_MESSAGES
    ]
    exc = ValidationError.from_exception_data("Probe", line_errors)

    response = await _handle_pydantic_error(exc)

    body = _decoded(response)
    assert response.status_code == 422
    assert body == {
        "detail": [
            {"loc": ["body", error_type, "0"], "msg": message, "type": error_type}
            for error_type, message in _EXPECTED_MESSAGES.items()
        ]
    }
    assert _key_orders(body) == [_KEY_ORDER] * len(_EXPECTED_MESSAGES)
    assert _response_leaks(response) == set()


async def test_validation_messages_pydantic_handler_unknown_type_gets_the_fallback() -> None:
    """A custom error type outside the table keeps its type and answers ``"Invalid input"``."""
    custom = PydanticCustomError(_UNKNOWN_TYPE, "custom {detail}", {"detail": _CANARY})
    exc = ValidationError.from_exception_data(
        "Probe", [InitErrorDetails(type=custom, loc=("field",), input=_CANARY)]
    )

    response = await _handle_pydantic_error(exc)

    assert response.status_code == 422
    assert _decoded(response) == {
        "detail": [{"loc": ["field"], "msg": _FALLBACK, "type": _UNKNOWN_TYPE}]
    }
    assert _response_leaks(response) == set()


# ---------------------------------------------------------------------------
# Through real routes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("method", "template", "param"), _UUID_ROUTES)
def test_validation_messages_api_malformed_uuid_path_id_echoes_nothing(
    world: World,
    client: TestClient,
    caplog: pytest.LogCaptureFixture,
    method: str,
    template: str,
    param: str,
) -> None:
    """A malformed UUID path id: ``uuid_parsing`` with the fixed text; no character of
    the id in the body (security audit #194 L-1) and none in an app log line."""
    caplog.set_level(logging.DEBUG)
    editor = world.a["editor"]

    response = client.request(method, template.format(_BAD_ID), headers=editor.cookie)

    assert response.status_code == 422, response.text
    assert response.json() == {
        "detail": [{"loc": ["path", param], "msg": _INVALID_UUID, "type": "uuid_parsing"}]
    }
    assert set(_BAD_ID) & set(response.text) == set()
    assert _http_leaks(response) == set()
    assert _leaked(_app_log_text(caplog)) == set()


def test_validation_messages_api_missing_body_field_is_field_required(
    world: World, client: TestClient
) -> None:
    """``PATCH /api/chats/{chat_id}`` without the required title: ``missing``."""
    editor = world.a["editor"]
    chat_id = seed_chat(world.db, editor, title="Kept title")

    response = client.patch(f"/api/chats/{chat_id}", json={}, headers=editor.cookie)

    assert response.status_code == 422, response.text
    assert response.json() == {
        "detail": [{"loc": ["body", "title"], "msg": "Field required", "type": "missing"}]
    }


@pytest.mark.parametrize(
    ("limits", "error_type", "message"),
    [
        pytest.param((0, -7), "greater_than_equal", "Input is too small", id="below"),
        pytest.param((101, 4096), "less_than_equal", "Input is too large", id="above"),
    ],
)
def test_validation_messages_api_out_of_range_limit_is_one_fixed_message(
    world: World,
    client: TestClient,
    limits: tuple[int, int],
    error_type: str,
    message: str,
) -> None:
    """``GET /api/chats/{chat_id}`` with ``limit`` outside 1 to 100: the same body for
    two different inputs past one end, with neither the input nor the bound in it (no
    digit at all)."""
    editor = world.a["editor"]
    chat_id = seed_chat(world.db, editor, title="Paged", messages=[("user", "hello")])
    expected = {"detail": [{"loc": ["query", "limit"], "msg": message, "type": error_type}]}

    responses = [
        client.get(f"/api/chats/{chat_id}", params={"limit": limit}, headers=editor.cookie)
        for limit in limits
    ]

    assert [(response.status_code, response.json()) for response in responses] == [
        (422, expected),
        (422, expected),
    ]
    assert [char for response in responses for char in response.text if char.isdigit()] == []


def test_validation_messages_api_malformed_json_body_is_invalid_json(
    world: World, client: TestClient
) -> None:
    """A body that isn't JSON: ``json_invalid`` / "Invalid JSON" at FastAPI's loc
    (``["body", <position>]``), with no fragment of the body echoed."""
    editor = world.a["editor"]
    chat_id = seed_chat(world.db, editor, title="Kept title")
    raw = '{"title": "' + _CANARY + " draft"
    with pytest.raises(json.JSONDecodeError) as decode_error:
        json.loads(raw)

    response = client.patch(
        f"/api/chats/{chat_id}",
        content=raw.encode(),
        headers={**editor.cookie, "Content-Type": "application/json"},
    )

    assert response.status_code == 422, response.text
    assert response.json() == {
        "detail": [
            {
                "loc": ["body", str(decode_error.value.pos)],
                "msg": "Invalid JSON",
                "type": "json_invalid",
            }
        ]
    }
    assert _http_leaks(response) == set()
    assert "title" not in response.text
    assert "draft" not in response.text


def test_validation_messages_api_model_validator_text_is_invalid_value(
    world: World, client: TestClient
) -> None:
    """``PATCH /api/me/settings`` with nothing to change: the validator's own text is
    replaced by "Invalid value"; ``loc`` ``["body"]`` and ``value_error`` still say which
    check failed."""
    editor = world.a["editor"]

    response = client.patch("/api/me/settings", json={}, headers=editor.cookie)

    assert response.status_code == 422, response.text
    assert response.json() == {
        "detail": [{"loc": ["body"], "msg": _INVALID_VALUE, "type": "value_error"}]
    }
    assert "setting" not in response.text


def test_validation_messages_api_envelope_keeps_loc_type_and_order(
    world: World, client: TestClient
) -> None:
    """Three errors of one request (a malformed path id, a missing field, an extra field
    whose value is the canary): FastAPI's order, ``loc`` (the extra field's names it) and
    ``type`` kept, each ``{"loc", "msg", "type"}`` in that order, no canary."""
    editor = world.a["editor"]

    response = client.patch(
        f"/api/chats/{_BAD_ID}", json={"zz_unknown": _CANARY}, headers=editor.cookie
    )

    body = response.json()
    assert response.status_code == 422, response.text
    assert body == {
        "detail": [
            {"loc": ["path", "chat_id"], "msg": _INVALID_UUID, "type": "uuid_parsing"},
            {"loc": ["body", "title"], "msg": "Field required", "type": "missing"},
            {
                "loc": ["body", "zz_unknown"],
                "msg": "Extra inputs are not permitted",
                "type": "extra_forbidden",
            },
        ]
    }
    assert _key_orders(body) == [_KEY_ORDER] * 3
    assert _http_leaks(response) == set()


def test_validation_messages_api_reason_coded_422_is_unchanged(
    world: World, client: TestClient
) -> None:
    """A reason-coded 422 (a garbage cursor) keeps its own body: ``invalid_cursor``."""
    editor = world.a["editor"]
    chat_id = seed_chat(world.db, editor, title="Paged", messages=[("user", "hello")])

    response = client.get(
        f"/api/chats/{chat_id}", params={"cursor": "garbage"}, headers=editor.cookie
    )

    assert response.status_code == 422, response.text
    assert response.json() == _INVALID_CURSOR_BODY
