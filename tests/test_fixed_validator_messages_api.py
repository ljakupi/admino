"""Spec of GH-304's fixed validator messages in the 422 handlers (contract C1, C2).

Issue #304, criteria 1 and 2 (Decisions 1 and 5): GH-302 made every validation
``422`` take its ``msg`` from a fixed table keyed by the error type, which also
replaced the messages admino's own validators write ("Give at least one setting to
change.") with "Invalid value". Those messages come back, and only those: an admino
validator opts in by raising ``admino.models.FixedMessageError`` (a ``ValueError``
whose one ``message`` is a fixed string), and nothing that can quote the input passes.

What is pinned:
- ``models.FixedMessageError`` is a ``ValueError`` that takes one message, and
  ``str()`` of it is that message. Pydantic's own error for it is unchanged: type
  ``value_error``, msg ``"Value error, <message>"``, ``ctx["error"]`` the raised
  instance (model-level code that reads pydantic's ``msg`` sees no difference).
- ``server._request_validation_error_handler`` (FastAPI's RequestValidationError,
  driven with real pydantic errors of in-test models, ``loc`` prefixed with
  ``"body"`` as FastAPI does): a ``FixedMessageError`` raised by a field validator
  (after, before, wrap), an ``Annotated`` ``AfterValidator`` or a model validator
  answers ``msg`` = exactly its message, without pydantic's "Value error, " prefix;
  ``loc`` ``str()``-ed, ``type`` ``value_error``, keys ``loc``, ``msg``, ``type`` in
  that order, and no character of the input (a canary) in the body.
- The §5 negatives, each next to a ``FixedMessageError`` field that does pass (so
  the mapping is shown to be selective): a plain ``ValueError`` whose message quotes
  the input, library validators that quote it (``ipaddress.ip_address``,
  ``zoneinfo.ZoneInfo``), an email-validator-style ``PydanticCustomError``
  ``value_error`` whose message carries the input, and ``FixedMessageError("")`` all
  answer "Invalid value"; built-in types keep their table text; an unknown type gets
  "Invalid input". Synthetic error dicts: a ``ctx["error"]`` that is a string (even
  an admino text), a plain ``ValueError``, no ctx, a ``None`` ctx, a
  ``FixedMessageError`` under another ctx key or on a type other than ``value_error``
  (``assertion_error``, a built-in, an unknown type) all map to the table.
- ``server._validation_error_handler`` (pydantic's ValidationError) does the same: a
  field and a model validator's ``FixedMessageError`` pass, and one model mixing every
  case keeps pydantic's order with each error mapped.
- End to end over HTTP, through an app with exactly the two handlers ``create_app``
  registers: a body model mixing every case (the request handler) and a route that
  raises the same model's ValidationError inside (the pydantic handler); no canary
  in the body or in an app log line.
- The issue's example through the real route: ``PATCH /api/me/settings`` with ``{}``
  as a logged-in Editor answers ``{"detail": [{"loc": ["body"], "msg": "Give at least
  one setting to change.", "type": "value_error"}]}`` and writes nothing.

``FixedMessageError`` is imported inside the tests, so the file collects before
GH-304 is implemented. The canary is three Greek capital letters (built with
``chr``): none of them occurs in the table, in a fixed text, in a ``loc`` or in a
``type``.

Security notes: every id, text and name here is a fixed fake value. No network, no
real PostgreSQL, no LLM.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import logging
import zoneinfo
from typing import TYPE_CHECKING, Annotated, Any, Final, Self

import pytest
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.testclient import TestClient
from pydantic import (
    AfterValidator,
    BaseModel,
    Field,
    ValidationError,
    create_model,
    field_validator,
    model_validator,
)
from pydantic_core import PydanticCustomError
from starlette.requests import Request

from admino import server
from tests.db_fakes import FakeDb
from tests.tenancy_world import (
    build_world,
    make_app,
    make_client,
    use_fake_database,
    use_fast_passwords,
    use_roomy_rate_limits,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    import httpx
    from fastapi.responses import JSONResponse

    from tests.tenancy_world import World

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Greek capital Omega, Psi and Phi: in no table text, fixed text, loc or type.
_CANARY: Final = chr(0x3A9) + chr(0x3A8) + chr(0x3A6)
_CANARY_CHARS: Final = frozenset(_CANARY)

# Fixed texts of the in-test validators (written like admino's own).
_FIELD_TEXT: Final = "The probe note must not contain control characters."
_MODEL_TEXT: Final = "Give at least one probe value to change."
_OTHER_TEXT: Final = "Each probe can be sent only once."
_SETTINGS_TEXT: Final = "Give at least one setting to change."

_INVALID_VALUE: Final = "Invalid value"
_FALLBACK: Final = "Invalid input"
_INT_TEXT: Final = "Input should be a valid integer"
_TOO_LONG_TEXT: Final = "String is too long"
_UNKNOWN_TYPE: Final = "admino_probe_unlisted"
_KEY_ORDER: Final = ["loc", "msg", "type"]


# ---------------------------------------------------------------------------
# In-test validators and models
# ---------------------------------------------------------------------------


def _fixed(message: str) -> ValueError:
    """A ``FixedMessageError`` (imported here, so the file collects before GH-304)."""
    from admino.models import FixedMessageError

    return FixedMessageError(message)


def _fixed_class() -> type[ValueError]:
    """``admino.models.FixedMessageError``."""
    from admino.models import FixedMessageError

    return FixedMessageError


def _raise_field_text(value: str) -> str:
    """An admino-style validator: refuses with ``_FIELD_TEXT``."""
    raise _fixed(_FIELD_TEXT)


def _raise_other_text(value: str) -> str:
    """An admino-style validator: refuses with ``_OTHER_TEXT``."""
    raise _fixed(_OTHER_TEXT)


def _raise_empty_text(value: str) -> str:
    """A ``FixedMessageError`` without text (the table answers)."""
    raise _fixed("")


def _quote_input(value: str) -> str:
    """A careless validator: a plain ValueError whose message quotes the input."""
    msg = f"note {value} is not allowed"
    raise ValueError(msg)


def _email_style(value: str) -> str:
    """An email validator's refusal: a ``value_error`` whose message carries the input."""
    raise PydanticCustomError(
        "value_error", "value is not a valid email address: {reason}", {"reason": value}
    )


def _unlisted(value: str) -> str:
    """A library error of a type outside the table, quoting the input."""
    raise PydanticCustomError(_UNKNOWN_TYPE, "custom {detail}", {"detail": value})


_Fixed = Annotated[str, AfterValidator(_raise_field_text)]
_Other = Annotated[str, AfterValidator(_raise_other_text)]
_Empty = Annotated[str, AfterValidator(_raise_empty_text)]
_Quoted = Annotated[str, AfterValidator(_quote_input)]
_Address = Annotated[str, AfterValidator(ipaddress.ip_address)]
_Zone = Annotated[str, AfterValidator(zoneinfo.ZoneInfo)]
_Email = Annotated[str, AfterValidator(_email_style)]
_Unlisted = Annotated[str, AfterValidator(_unlisted)]
_Short = Annotated[str, Field(max_length=2)]


class _FieldAfter(BaseModel):
    """A field validator (after) refusing with a fixed text."""

    note: str

    @field_validator("note")
    @classmethod
    def _refuse(cls, value: str) -> str:
        raise _fixed(_FIELD_TEXT)


class _FieldBefore(BaseModel):
    """A field validator (before) refusing with a fixed text."""

    note: str

    @field_validator("note", mode="before")
    @classmethod
    def _refuse(cls, value: Any) -> Any:
        raise _fixed(_FIELD_TEXT)


class _FieldWrap(BaseModel):
    """A field validator (wrap) refusing with a fixed text after the inner validation."""

    note: str

    @field_validator("note", mode="wrap")
    @classmethod
    def _refuse(cls, value: Any, handler: Any) -> Any:
        handler(value)
        raise _fixed(_FIELD_TEXT)


class _AnnotatedAfter(BaseModel):
    """An ``Annotated`` ``AfterValidator`` refusing with a fixed text."""

    note: _Fixed


class _ModelAfter(BaseModel):
    """A model validator (after) refusing with a fixed text: the error sits on the model."""

    note: str

    @model_validator(mode="after")
    def _refuse(self) -> Self:
        raise _fixed(_MODEL_TEXT)


class _Mixed(BaseModel):
    """Every case in one model, in this field order."""

    fixed: _Fixed
    quoted: _Quoted
    address: _Address
    zone: _Zone
    email: _Email
    count: int
    short: _Short
    custom: _Unlisted
    empty: _Empty
    again: _Other


# The mixed model's input: every value a canary (the zone an absolute path, so the
# zoneinfo refusal is a ValueError that quotes it).
_MIXED_INPUT: Final[dict[str, str]] = {
    "fixed": _CANARY,
    "quoted": _CANARY,
    "address": _CANARY,
    "zone": "/" + _CANARY,
    "email": _CANARY,
    "count": _CANARY,
    "short": _CANARY,
    "custom": _CANARY,
    "empty": _CANARY,
    "again": _CANARY,
}

# Each field of the mixed model: (msg, type) the handlers answer, in order.
_MIXED_ANSWERS: Final[list[tuple[str, str, str]]] = [
    ("fixed", _FIELD_TEXT, "value_error"),
    ("quoted", _INVALID_VALUE, "value_error"),
    ("address", _INVALID_VALUE, "value_error"),
    ("zone", _INVALID_VALUE, "value_error"),
    ("email", _INVALID_VALUE, "value_error"),
    ("count", _INT_TEXT, "int_parsing"),
    ("short", _TOO_LONG_TEXT, "string_too_long"),
    ("custom", _FALLBACK, _UNKNOWN_TYPE),
    ("empty", _INVALID_VALUE, "value_error"),
    ("again", _OTHER_TEXT, "value_error"),
]


def _mixed_detail(prefix: list[str]) -> list[dict[str, Any]]:
    """The expected ``detail`` list of the mixed model, ``loc`` under ``prefix``."""
    return [
        {"loc": [*prefix, field], "msg": msg, "type": error_type}
        for field, msg, error_type in _MIXED_ANSWERS
    ]


# The validator kinds whose FixedMessageError passes: (model, expected loc, text).
_KINDS: Final = [
    pytest.param(_FieldAfter, ["body", "note"], _FIELD_TEXT, id="field-validator-after"),
    pytest.param(_FieldBefore, ["body", "note"], _FIELD_TEXT, id="field-validator-before"),
    pytest.param(_FieldWrap, ["body", "note"], _FIELD_TEXT, id="field-validator-wrap"),
    pytest.param(_AnnotatedAfter, ["body", "note"], _FIELD_TEXT, id="annotated-after-validator"),
    pytest.param(_ModelAfter, ["body"], _MODEL_TEXT, id="model-validator-after"),
]

# The §5 negatives of real pydantic errors: (field annotation, input, type, msg, whether
# pydantic's own msg quotes the input).
_NEGATIVES: Final = [
    pytest.param(
        _Quoted, _CANARY, "value_error", _INVALID_VALUE, True, id="plain-value-error-quoting-input"
    ),
    pytest.param(
        _Address, _CANARY, "value_error", _INVALID_VALUE, True, id="ipaddress-value-error"
    ),
    pytest.param(
        _Zone, "/" + _CANARY, "value_error", _INVALID_VALUE, True, id="zoneinfo-value-error"
    ),
    pytest.param(
        _Email, _CANARY, "value_error", _INVALID_VALUE, True, id="email-validator-value-error"
    ),
    pytest.param(int, _CANARY, "int_parsing", _INT_TEXT, False, id="builtin-int-parsing"),
    pytest.param(
        _Short, _CANARY, "string_too_long", _TOO_LONG_TEXT, False, id="builtin-string-too-long"
    ),
    pytest.param(_Unlisted, _CANARY, _UNKNOWN_TYPE, _FALLBACK, True, id="unknown-type"),
    pytest.param(_Empty, _CANARY, "value_error", _INVALID_VALUE, False, id="empty-fixed-message"),
]


def _synthetic_ctx_string(_: type[ValueError]) -> dict[str, Any]:
    return {"type": "value_error", "ctx": {"error": _FIELD_TEXT}}


def _synthetic_ctx_plain_value_error(_: type[ValueError]) -> dict[str, Any]:
    return {"type": "value_error", "ctx": {"error": ValueError(_FIELD_TEXT)}}


def _synthetic_no_ctx(_: type[ValueError]) -> dict[str, Any]:
    return {"type": "value_error"}


def _synthetic_none_ctx(_: type[ValueError]) -> dict[str, Any]:
    return {"type": "value_error", "ctx": None}


def _synthetic_other_ctx_key(fixed: type[ValueError]) -> dict[str, Any]:
    return {"type": "value_error", "ctx": {"reason": fixed(_FIELD_TEXT)}}


def _synthetic_assertion_error(fixed: type[ValueError]) -> dict[str, Any]:
    return {"type": "assertion_error", "ctx": {"error": fixed(_FIELD_TEXT)}}


def _synthetic_builtin_type(fixed: type[ValueError]) -> dict[str, Any]:
    return {"type": "string_too_long", "ctx": {"error": fixed(_FIELD_TEXT)}}


def _synthetic_unknown_type(fixed: type[ValueError]) -> dict[str, Any]:
    return {"type": _UNKNOWN_TYPE, "ctx": {"error": fixed(_FIELD_TEXT)}}


def _synthetic_empty_fixed(fixed: type[ValueError]) -> dict[str, Any]:
    return {"type": "value_error", "ctx": {"error": fixed("")}}


# Synthetic error dicts that must map to the table: (builder, type, msg).
_SYNTHETIC_NEGATIVES: Final = [
    pytest.param(_synthetic_ctx_string, "value_error", _INVALID_VALUE, id="ctx-error-is-a-string"),
    pytest.param(
        _synthetic_ctx_plain_value_error,
        "value_error",
        _INVALID_VALUE,
        id="ctx-error-is-a-plain-value-error",
    ),
    pytest.param(_synthetic_no_ctx, "value_error", _INVALID_VALUE, id="no-ctx"),
    pytest.param(_synthetic_none_ctx, "value_error", _INVALID_VALUE, id="ctx-is-none"),
    pytest.param(
        _synthetic_other_ctx_key,
        "value_error",
        _INVALID_VALUE,
        id="fixed-message-under-another-ctx-key",
    ),
    pytest.param(
        _synthetic_assertion_error,
        "assertion_error",
        _INVALID_VALUE,
        id="fixed-message-on-assertion-error",
    ),
    pytest.param(
        _synthetic_builtin_type,
        "string_too_long",
        _TOO_LONG_TEXT,
        id="fixed-message-on-builtin-type",
    ),
    pytest.param(
        _synthetic_unknown_type, _UNKNOWN_TYPE, _FALLBACK, id="fixed-message-on-unknown-type"
    ),
    pytest.param(_synthetic_empty_fixed, "value_error", _INVALID_VALUE, id="empty-fixed-message"),
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
    """The real app (a stub agent) and a client at ``CLIENT_IP``."""
    return make_client(make_app())


@pytest.fixture()
def probe_client() -> TestClient:
    """An app with exactly the two validation handlers ``create_app`` registers, and two
    probe routes: one takes the mixed model as its body (the request handler), the
    other validates it inside (the pydantic handler)."""
    app = FastAPI()
    app.add_exception_handler(
        RequestValidationError,
        server._request_validation_error_handler,  # type: ignore[arg-type]
    )
    app.add_exception_handler(
        ValidationError,
        server._validation_error_handler,  # type: ignore[arg-type]
    )

    async def probe_body(payload: _Mixed) -> dict[str, bool]:
        return {"accepted": True}

    async def probe_inner(payload: dict[str, Any]) -> dict[str, bool]:
        _Mixed.model_validate(payload)
        return {"accepted": True}

    app.add_api_route("/probe/body", probe_body, methods=["POST"])
    app.add_api_route("/probe/inner", probe_inner, methods=["POST"])
    return TestClient(app)


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
    """Every app log message of the test (httpx's own request lines excluded)."""
    return "\n".join(
        record.getMessage()
        for record in caplog.records
        if not record.name.startswith(("httpx", "httpcore"))
    )


def _caught(call: Callable[[], object]) -> ValidationError:
    """The ValidationError ``call()`` raises."""
    with pytest.raises(ValidationError) as exc_info:
        call()
    return exc_info.value


def _as_request_error(exc: ValidationError) -> RequestValidationError:
    """FastAPI's wrapping of a body model's errors: each ``loc`` under ``"body"``."""
    return RequestValidationError(
        [{**error, "loc": ("body", *error["loc"])} for error in exc.errors()]
    )


async def _handle_request_error(exc: RequestValidationError) -> JSONResponse:
    """Run ``server._request_validation_error_handler``."""
    return await server._request_validation_error_handler(_request(), exc)


async def _handle_pydantic_error(exc: ValidationError) -> JSONResponse:
    """Run ``server._validation_error_handler``."""
    return await server._validation_error_handler(_request(), exc)


def _synthetic(fields: dict[str, Any], loc: tuple[str | int, ...]) -> dict[str, Any]:
    """A FastAPI-style error dict: ``fields`` plus a canary in msg, input and url."""
    return {
        "loc": loc,
        "msg": f"pydantic says {_CANARY}",
        "input": _CANARY,
        "url": f"https://errors.pydantic.dev/2/v/{_CANARY}",
        **fields,
    }


# ---------------------------------------------------------------------------
# FixedMessageError (C1)
# ---------------------------------------------------------------------------


def test_fixed_validator_messages_error_is_a_value_error_with_one_message() -> None:
    """A ``ValueError`` subclass taking one message; ``str()`` is exactly that message."""
    fixed = _fixed_class()

    exc = fixed(_FIELD_TEXT)

    assert issubclass(fixed, ValueError)
    assert str(exc) == _FIELD_TEXT
    with pytest.raises(TypeError):
        fixed(_FIELD_TEXT, _OTHER_TEXT)  # type: ignore[call-arg]


@pytest.mark.parametrize(
    ("model", "loc", "text"),
    [
        pytest.param(_FieldAfter, ("note",), _FIELD_TEXT, id="field-validator"),
        pytest.param(_ModelAfter, (), _MODEL_TEXT, id="model-validator"),
    ],
)
def test_fixed_validator_messages_pydantic_error_is_unchanged(
    model: type[BaseModel], loc: tuple[str, ...], text: str
) -> None:
    """Pydantic's own error is a plain ``value_error``: msg "Value error, <text>", the
    raised instance as ``ctx["error"]``."""
    exc = _caught(lambda: model.model_validate({"note": _CANARY}))

    errors = exc.errors(include_input=False, include_url=False)

    assert [
        (error["type"], error["loc"], error["msg"], set(error.get("ctx", {}))) for error in errors
    ] == [("value_error", loc, f"Value error, {text}", {"error"})]
    ctx_error = errors[0]["ctx"]["error"]
    assert (type(ctx_error), str(ctx_error)) == (_fixed_class(), text)


# ---------------------------------------------------------------------------
# _request_validation_error_handler (FastAPI's RequestValidationError)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("model", "loc", "text"), _KINDS)
async def test_fixed_validator_messages_request_handler_answers_the_validator_text(
    model: type[BaseModel], loc: list[str], text: str
) -> None:
    """A FixedMessageError from any validator kind: ``msg`` is exactly its text (no
    "Value error, " prefix), ``loc`` and ``type`` as before, keys in order, no canary."""
    exc = _as_request_error(_caught(lambda: model.model_validate({"note": _CANARY})))

    response = await _handle_request_error(exc)

    body = _decoded(response)
    assert response.status_code == 422
    assert body == {"detail": [{"loc": loc, "msg": text, "type": "value_error"}]}
    assert _key_orders(body) == [_KEY_ORDER]
    assert _response_leaks(response) == set()


@pytest.mark.parametrize(("annotation", "value", "error_type", "msg", "quotes_input"), _NEGATIVES)
async def test_fixed_validator_messages_request_handler_other_errors_keep_the_table(
    annotation: Any, value: str, error_type: str, msg: str, quotes_input: bool
) -> None:
    """Next to a FixedMessageError that passes, a plain or library ``value_error``
    (which quotes the input), a built-in type, an unknown type and an empty fixed
    message answer the table's text (or the fallback); no canary in the body."""
    model = create_model("Probe", fixed=(_Fixed, ...), probe=(annotation, ...))
    validation_error = _caught(lambda: model.model_validate({"fixed": _CANARY, "probe": value}))
    probe_msg = validation_error.errors(include_input=False)[1]["msg"]

    response = await _handle_request_error(_as_request_error(validation_error))

    assert bool(_leaked(probe_msg)) is quotes_input, probe_msg
    assert response.status_code == 422
    assert _decoded(response) == {
        "detail": [
            {"loc": ["body", "fixed"], "msg": _FIELD_TEXT, "type": "value_error"},
            {"loc": ["body", "probe"], "msg": msg, "type": error_type},
        ]
    }
    assert _response_leaks(response) == set()


@pytest.mark.parametrize(("build", "error_type", "msg"), _SYNTHETIC_NEGATIVES)
async def test_fixed_validator_messages_request_handler_only_a_value_error_ctx_error_passes(
    build: Callable[[type[ValueError]], dict[str, Any]], error_type: str, msg: str
) -> None:
    """Only ``type == "value_error"`` with a non-empty FixedMessageError as
    ``ctx["error"]`` passes: a string or plain ValueError there, no ctx, a ``None`` ctx,
    the class under another key or on another type all answer the table."""
    fixed = _fixed_class()
    passing = _synthetic(
        {"type": "value_error", "ctx": {"error": fixed(_FIELD_TEXT)}}, ("body", "fixed")
    )
    refused = _synthetic(build(fixed), ("body", "probe", 0))

    response = await _handle_request_error(RequestValidationError([passing, refused]))

    body = _decoded(response)
    assert response.status_code == 422
    assert body == {
        "detail": [
            {"loc": ["body", "fixed"], "msg": _FIELD_TEXT, "type": "value_error"},
            {"loc": ["body", "probe", "0"], "msg": msg, "type": error_type},
        ]
    }
    assert _key_orders(body) == [_KEY_ORDER] * 2
    assert _response_leaks(response) == set()


# ---------------------------------------------------------------------------
# _validation_error_handler (pydantic's ValidationError)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("model", "loc", "text"),
    [
        pytest.param(_FieldAfter, ["note"], _FIELD_TEXT, id="field-validator"),
        pytest.param(_ModelAfter, [], _MODEL_TEXT, id="model-validator"),
    ],
)
async def test_fixed_validator_messages_pydantic_handler_answers_the_validator_text(
    model: type[BaseModel], loc: list[str], text: str
) -> None:
    """A FixedMessageError's text is the ``msg``; ``loc``, ``type`` and key order as
    before; no canary."""
    exc = _caught(lambda: model.model_validate({"note": _CANARY}))

    response = await _handle_pydantic_error(exc)

    body = _decoded(response)
    assert response.status_code == 422
    assert body == {"detail": [{"loc": loc, "msg": text, "type": "value_error"}]}
    assert _key_orders(body) == [_KEY_ORDER]
    assert _response_leaks(response) == set()


async def test_fixed_validator_messages_pydantic_handler_mixed_errors_keep_order() -> None:
    """Every case in one model: pydantic's order kept, the two fixed texts pass, every
    other error answers the table (or the fallback), no canary."""
    exc = _caught(lambda: _Mixed.model_validate(_MIXED_INPUT))

    response = await _handle_pydantic_error(exc)

    body = _decoded(response)
    assert response.status_code == 422
    assert body == {"detail": _mixed_detail([])}
    assert _key_orders(body) == [_KEY_ORDER] * len(_MIXED_ANSWERS)
    assert _response_leaks(response) == set()


# ---------------------------------------------------------------------------
# End to end over HTTP
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "prefix"),
    [
        pytest.param("/probe/body", ["body"], id="request-handler"),
        pytest.param("/probe/inner", [], id="pydantic-handler"),
    ],
)
def test_fixed_validator_messages_api_both_handlers_answer_fixed_texts_only(
    probe_client: TestClient, caplog: pytest.LogCaptureFixture, path: str, prefix: list[str]
) -> None:
    """Over HTTP, through either handler: the mixed model's two fixed texts pass, every
    other error answers the table, in order; no canary in the body or an app log line."""
    caplog.set_level(logging.DEBUG)

    response = probe_client.post(path, json=_MIXED_INPUT)

    assert response.status_code == 422, response.text
    assert response.json() == {"detail": _mixed_detail(prefix)}
    assert _key_orders(response.json()) == [_KEY_ORDER] * len(_MIXED_ANSWERS)
    assert _http_leaks(response) == set()
    assert _leaked(_app_log_text(caplog)) == set()


def test_fixed_validator_messages_api_empty_settings_patch_answers_the_validator_text(
    world: World, client: TestClient
) -> None:
    """The issue's example: ``PATCH /api/me/settings`` with ``{}`` as an Editor answers
    the validator's own text on ``["body"]``, and nothing is written."""
    editor = world.a["editor"]
    before = copy.deepcopy((world.db.user_settings, world.db.audit))

    response = client.patch("/api/me/settings", json={}, headers=editor.cookie)

    assert response.status_code == 422, response.text
    assert response.json() == {
        "detail": [{"loc": ["body"], "msg": _SETTINGS_TEXT, "type": "value_error"}]
    }
    assert (world.db.user_settings, world.db.audit) == before
