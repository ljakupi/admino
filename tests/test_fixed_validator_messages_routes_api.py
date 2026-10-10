"""Spec of GH-304's fixed validator messages through the real routes (contract C3).

Issue #304, criteria 1 and 2 (Decisions 1 and 2): a ``422`` caused by one of
admino's own request-model validators carries that validator's fixed message in
``msg`` again; ``loc``, ``type`` and the list envelope stay as they are, and no
part of the input is ever in the body (§5).

What is pinned, for each of contract C3's 20 raise sites and through every
request model that reaches it (the invitation email check through
``InvitationCreateRequest``, ``OrgCreateRequest``, ``OrgUserPatch`` and
``PlatformReinviteRequest``; the org name check through ``OrgCreateRequest`` and
``OrgSettingsPatch.profile.display_name``; the chat title check through chat
create and chat update), one case per (raise site, route):
- the real route of the tenancy world (tests/tenancy_world.py), called by a role
  it allows (Org Admin, Editor or Viewer of org A, or the Super Admin; the
  invitation acceptance is public), with an input that trips exactly that
  validator, answers ``422 {"detail": [...]}`` holding exactly one error
  ``{"loc": <FastAPI's loc>, "msg": <the C3 text, byte for byte>, "type":
  "value_error"}``, keys in that order;
- no character of the canary (embedded in every text field of the input) is in
  the body or in an app log line;
- nothing is written: every FakeDb table is unchanged (sessions compared without
  ``last_seen_at``, which any authenticated request refreshes), so no row and no
  audit event.

The expected texts are literals here, never read from ``admino.models``.

Negatives (§5, Decision 1's "every other error keeps the fixed table"): after C3 no
real route reaches a plain ``ValueError``, so probe routes added to the real app
stand in. A body validator whose plain ``ValueError`` quotes the input, a library
style ``PydanticCustomError`` of type ``value_error`` that quotes it, and a
``ValidationError`` raised inside a route from such a validator (the sibling
handler) all still answer "Invalid value" with no canary character. They pass
before GH-304 too (GH-302's table) and guard the opt-in against a handler that
would pass any validator's text.

Security notes: every id, text, email and name here is a fixed fake value. No
network, no real PostgreSQL, no LLM.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final, Literal

import pytest
from pydantic import BaseModel, ConfigDict, field_validator
from pydantic_core import PydanticCustomError

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
    from collections.abc import Callable

    import httpx
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from tests.tenancy_world import World

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Contract C3's texts, spelled out here (never read from models.py).
_ONE_CHAT_REFERENCE: Final = "Give exactly one of chat_id and session_id."
_MODEL_NAME: Final = "Model name contains invalid characters."
_ONE_SETTING: Final = "Give at least one setting to change."
_EMAIL_HIDDEN_CHARS: Final = (
    "The email must not contain whitespace, control or invisible characters."
)
_EMAIL_SHAPE: Final = "The email must look like name@example.com."
_NAME_CHARS: Final = "The name must not contain control or formatting characters."
_ONE_LIMIT: Final = "Give at least one limit to change."
_ROLE_NAME_OR_EMAIL: Final = "Give a role, a name or an email to change."
_UNKNOWN_TIMEZONE: Final = "Unknown timezone."
_PERSONAL_INSTRUCTIONS_CHARS: Final = (
    "The personal instructions must not contain control or formatting characters."
)
_ONE_FIELD: Final = "Give at least one field to change."
_ONLY_RESPONSE_LANGUAGE_NULL: Final = "Only response_language can be null."
_INSTRUCTIONS_CHARS: Final = "The instructions must not contain control or formatting characters."
_TITLE_CHARS: Final = "The title must not contain control or formatting characters."
_ATTACHMENT_ONCE: Final = "Each attachment can be sent only once per message."

# GH-302's table text for value_error (any validator that doesn't opt in).
_INVALID_VALUE: Final = "Invalid value"
_KEY_ORDER: Final = ["loc", "msg", "type"]

# Greek capital Omega, Psi and Phi: in no C3 text, loc or type.
_CANARY: Final = chr(0x3A9) + chr(0x3A8) + chr(0x3A6)
_CANARY_CHARS: Final = frozenset(_CANARY)
# A zero-width space (format, Cf): refused by every name, title and instructions rule.
_ZWSP: Final = chr(0x200B)
# An email with a space inside (stripping keeps it) and one without an '@'.
_EMAIL_WITH_SPACE: Final = f"{_CANARY} {_CANARY}@example.ch"
_EMAIL_WITHOUT_AT: Final = f"{_CANARY}-at-example.ch"
_GOOD_EMAIL: Final = "first-admin-304@example.ch"
_CONFIRMATION_ID: Final = "conf-gh304"
_PROBE_CHAT_ID: Final = "8f0c6a8e-3b0e-4d5e-9f43-3d1c2b0a9e01"
_DUPLICATE_ID: Final = "0b8f2f57-6f0c-4b55-8a6e-2c9a4f1d7e30"

Who = Literal["org_admin", "editor", "viewer", "super_admin", "public"]


def _org_create(**fields: Any) -> dict[str, Any]:
    """A valid POST /api/platform/orgs body with ``fields`` replaced."""
    return {
        "name": "Acme 304",
        "primary_admin_email": _GOOD_EMAIL,
        "seats": 5,
        "monthly_budget_chf": 100,
        "storage_quota": 1_000_000,
        **fields,
    }


@dataclass(frozen=True)
class _Case:
    """One (raise site, route): who calls, where, with what, and the expected error."""

    who: Who
    method: str
    path: Callable[[World], str]
    body: Any
    loc: list[str]
    msg: str


def _chat_path(suffix: str = "") -> Callable[[World], str]:
    """The path of a chat of org A's Editor (seeded for the case) plus ``suffix``."""

    def build(world: World) -> str:
        chat_id = seed_chat(world.db, world.a["editor"], title="Kept 304")
        return f"/api/chats/{chat_id}{suffix}"

    return build


def _org_user_path(world: World) -> str:
    """PATCH /api/org/users/{id} of org A's Editor."""
    return f"/api/org/users/{world.a['editor'].user_id}"


def _reinvite_path(world: World) -> str:
    """The re-invite path of org A's Org Admin (as the Super Admin sees it)."""
    return f"/api/platform/orgs/{world.org_a}/users/{world.a['org_admin'].user_id}/invitation"


def _limits_path(world: World) -> str:
    """PATCH /api/platform/orgs/{id}/limits of org A."""
    return f"/api/platform/orgs/{world.org_a}/limits"


def _fixed(path: str) -> Callable[[World], str]:
    """A path that doesn't depend on the world."""
    return lambda _world: path


# Contract C3, row by row, through every request model that reaches a raise site.
_CASES: Final[dict[str, _Case]] = {
    # 914 ConfirmRequest._check_one_chat_reference
    "confirm:both-chat-references": _Case(
        "editor",
        "POST",
        _fixed(f"/api/confirm/{_CONFIRMATION_ID}"),
        {
            "chat_id": _PROBE_CHAT_ID,
            "session_id": "sess-gh304-probe",
            "confirmation_id": _CONFIRMATION_ID,
            "approved": True,
        },
        ["body"],
        _ONE_CHAT_REFERENCE,
    ),
    # 2133 SettingsPatchLLM.validate_model_name
    "platform-settings:model-name": _Case(
        "super_admin",
        "PATCH",
        _fixed("/api/platform/settings"),
        {"llm": {"openai_model": f"gpt {_CANARY}"}},
        ["body", "llm", "openai_model"],
        _MODEL_NAME,
    ),
    # 2181 UserSettingsPatch._check_something_given
    "me-settings:nothing-given": _Case(
        "viewer",
        "PATCH",
        _fixed("/api/me/settings"),
        {"appearance": {"theme": None}, "notifications": {}},
        ["body"],
        _ONE_SETTING,
    ),
    # 2378 PlatformSettingsPatch._check_something_given
    "platform-settings:nothing-given": _Case(
        "super_admin",
        "PATCH",
        _fixed("/api/platform/settings"),
        {"llm": {"provider": None}, "security": {}},
        ["body"],
        _ONE_SETTING,
    ),
    # 2628 / 2632 _check_invite_email, through its four request models
    "org-invitations:email-hidden-chars": _Case(
        "org_admin",
        "POST",
        _fixed("/api/org/invitations"),
        {"email": _EMAIL_WITH_SPACE, "role": "editor"},
        ["body", "email"],
        _EMAIL_HIDDEN_CHARS,
    ),
    "org-invitations:email-shape": _Case(
        "org_admin",
        "POST",
        _fixed("/api/org/invitations"),
        {"email": _EMAIL_WITHOUT_AT, "role": "editor"},
        ["body", "email"],
        _EMAIL_SHAPE,
    ),
    "platform-orgs:email-hidden-chars": _Case(
        "super_admin",
        "POST",
        _fixed("/api/platform/orgs"),
        _org_create(primary_admin_email=_EMAIL_WITH_SPACE),
        ["body", "primary_admin_email"],
        _EMAIL_HIDDEN_CHARS,
    ),
    "platform-orgs:email-shape": _Case(
        "super_admin",
        "POST",
        _fixed("/api/platform/orgs"),
        _org_create(primary_admin_email=_EMAIL_WITHOUT_AT),
        ["body", "primary_admin_email"],
        _EMAIL_SHAPE,
    ),
    "org-users:email-hidden-chars": _Case(
        "org_admin",
        "PATCH",
        _org_user_path,
        {"email": _EMAIL_WITH_SPACE},
        ["body", "email"],
        _EMAIL_HIDDEN_CHARS,
    ),
    "org-users:email-shape": _Case(
        "org_admin",
        "PATCH",
        _org_user_path,
        {"email": _EMAIL_WITHOUT_AT},
        ["body", "email"],
        _EMAIL_SHAPE,
    ),
    "platform-reinvite:email-hidden-chars": _Case(
        "super_admin",
        "POST",
        _reinvite_path,
        {"email": _EMAIL_WITH_SPACE},
        ["body", "email"],
        _EMAIL_HIDDEN_CHARS,
    ),
    "platform-reinvite:email-shape": _Case(
        "super_admin",
        "POST",
        _reinvite_path,
        {"email": _EMAIL_WITHOUT_AT},
        ["body", "email"],
        _EMAIL_SHAPE,
    ),
    # 2727 InvitationAcceptRequest._check_name (public route)
    "invitation-accept:name": _Case(
        "public",
        "POST",
        _fixed("/api/auth/invitations/gh304-probe-token/accept"),
        {"name": f"{_CANARY}{_ZWSP}Ada", "password": f"pw-{_CANARY}-304"},
        ["body", "name"],
        _NAME_CHARS,
    ),
    # 2758 _check_org_name, through its two request models
    "platform-orgs:name": _Case(
        "super_admin",
        "POST",
        _fixed("/api/platform/orgs"),
        _org_create(name=f"{_CANARY}{_ZWSP}Org"),
        ["body", "name"],
        _NAME_CHARS,
    ),
    "org-settings:profile-display-name": _Case(
        "org_admin",
        "PATCH",
        _fixed("/api/org/settings"),
        {"profile": {"display_name": f"{_CANARY}{_ZWSP}Org"}},
        ["body", "profile", "display_name"],
        _NAME_CHARS,
    ),
    # 2821 OrgLimitsPatch._check_something_given
    "platform-limits:nothing-given": _Case(
        "super_admin",
        "PATCH",
        _limits_path,
        {"seats": None},
        ["body"],
        _ONE_LIMIT,
    ),
    # 2952 OrgUserPatch._check_name, 2966 OrgUserPatch._check_something_given
    "org-users:name": _Case(
        "org_admin",
        "PATCH",
        _org_user_path,
        {"name": f"{_CANARY}{_ZWSP}Ada"},
        ["body", "name"],
        _NAME_CHARS,
    ),
    "org-users:nothing-given": _Case(
        "org_admin",
        "PATCH",
        _org_user_path,
        {"role": None, "name": None},
        ["body"],
        _ROLE_NAME_OR_EMAIL,
    ),
    # 3150 / 3159 / 3172 / 3181 / 3187 MyAccountPatch
    "me:name": _Case(
        "viewer",
        "PATCH",
        _fixed("/api/me"),
        {"name": f"{_CANARY}{_ZWSP}Ada"},
        ["body", "name"],
        _NAME_CHARS,
    ),
    "me:timezone": _Case(
        "viewer",
        "PATCH",
        _fixed("/api/me"),
        {"timezone": f"Europe/{_CANARY}"},
        ["body", "timezone"],
        _UNKNOWN_TIMEZONE,
    ),
    "me:personal-instructions": _Case(
        "viewer",
        "PATCH",
        _fixed("/api/me"),
        {"personal_instructions": f"Be brief {_CANARY}{_ZWSP}."},
        ["body", "personal_instructions"],
        _PERSONAL_INSTRUCTIONS_CHARS,
    ),
    "me:nothing-given": _Case(
        "viewer",
        "PATCH",
        _fixed("/api/me"),
        {},
        ["body"],
        _ONE_FIELD,
    ),
    "me:null-for-a-required-field": _Case(
        "viewer",
        "PATCH",
        _fixed("/api/me"),
        {"timezone": None},
        ["body"],
        _ONLY_RESPONSE_LANGUAGE_NULL,
    ),
    # 3343 OrgSettingsPatch._check_instructions, 3354 OrgSettingsPatch._check_something_given
    "org-settings:instructions": _Case(
        "org_admin",
        "PATCH",
        _fixed("/api/org/settings"),
        {"instructions": f"Answer in {_CANARY}{_ZWSP}."},
        ["body", "instructions"],
        _INSTRUCTIONS_CHARS,
    ),
    "org-settings:nothing-given": _Case(
        "org_admin",
        "PATCH",
        _fixed("/api/org/settings"),
        {"tools": {}, "profile": {"display_name": None}},
        ["body"],
        _ONE_SETTING,
    ),
    # 3433 _check_chat_title, through chat create and chat update
    "chats-create:title": _Case(
        "editor",
        "POST",
        _fixed("/api/chats"),
        {"title": f"{_CANARY}{_ZWSP}Plan"},
        ["body", "title"],
        _TITLE_CHARS,
    ),
    "chats-update:title": _Case(
        "editor",
        "PATCH",
        _chat_path(),
        {"title": f"{_CANARY}{_ZWSP}Plan"},
        ["body", "title"],
        _TITLE_CHARS,
    ),
    # 3621 ChatMessageCreate._refuse_duplicates
    "chat-messages:duplicate-attachment": _Case(
        "editor",
        "POST",
        _chat_path("/messages"),
        {"message": f"Read {_CANARY}", "attachment_ids": [_DUPLICATE_ID, _DUPLICATE_ID]},
        ["body", "attachment_ids"],
        _ATTACHMENT_ONCE,
    ),
}

# ---------------------------------------------------------------------------
# Probe models and routes for the negatives (added to the real app)
# ---------------------------------------------------------------------------


class _ProbeEcho(BaseModel):
    """A body whose validator raises a plain ValueError quoting the input (no opt-in)."""

    model_config = ConfigDict(extra="forbid")

    note: str

    @field_validator("note")
    @classmethod
    def _refuse(cls, value: str) -> str:
        msg = f"note {value} is not allowed"
        raise ValueError(msg)


class _ProbeLibrary(BaseModel):
    """A body whose validator raises a library-style value_error quoting the input."""

    model_config = ConfigDict(extra="forbid")

    note: str

    @field_validator("note")
    @classmethod
    def _refuse(cls, value: str) -> str:
        raise PydanticCustomError(
            "value_error", "value is not a valid email address: {reason}", {"reason": value}
        )


async def _probe_echo(body: _ProbeEcho) -> dict[str, str]:
    """Never reached: the body is refused."""
    return {}


async def _probe_library(body: _ProbeLibrary) -> dict[str, str]:
    """Never reached: the body is refused."""
    return {}


async def _probe_inside() -> dict[str, str]:
    """Validate the canary inside the route (pydantic's ValidationError, the sibling handler)."""
    _ProbeEcho.model_validate({"note": _CANARY})
    return {}


_PROBE_ROUTES: Final[dict[str, Callable[..., Any]]] = {
    "/api/gh304-probe/echo": _probe_echo,
    "/api/gh304-probe/library": _probe_library,
    "/api/gh304-probe/inside": _probe_inside,
}

# (probe path, request body, the expected loc) of each negative.
_NEGATIVES: Final = [
    pytest.param(
        "/api/gh304-probe/echo", {"note": _CANARY}, ["body", "note"], id="plain-value-error"
    ),
    pytest.param(
        "/api/gh304-probe/library",
        {"note": _CANARY},
        ["body", "note"],
        id="library-value-error",
    ),
    pytest.param("/api/gh304-probe/inside", None, ["note"], id="raised-inside-the-route"),
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


@pytest.fixture()
def probe_client(world: World) -> TestClient:
    """The real app with the probe routes first (ahead of any static mount)."""
    app: FastAPI = make_app()
    for path, endpoint in _PROBE_ROUTES.items():
        app.add_api_route(path, endpoint, methods=["POST"], response_model=None)
        app.router.routes.insert(0, app.router.routes.pop())
    return make_client(app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _leaked(text: str) -> set[str]:
    """The canary characters found in ``text``."""
    return _CANARY_CHARS & set(text)


def _http_leaks(response: httpx.Response) -> set[str]:
    """Canary characters in an HTTP response's raw text or decoded JSON."""
    return _leaked(response.text) | _leaked(json.dumps(response.json(), ensure_ascii=False))


def _app_log_text(caplog: pytest.LogCaptureFixture) -> str:
    """Every app log message of the test (httpx's own request lines excluded)."""
    return "\n".join(
        record.getMessage()
        for record in caplog.records
        if not record.name.startswith(("httpx", "httpcore"))
    )


def _state(db: FakeDb) -> dict[str, Any]:
    """Every table; sessions without ``last_seen_at`` (any request refreshes it)."""
    tables = db.snapshot()
    tables["sessions"] = {
        key: {column: value for column, value in row.items() if column != "last_seen_at"}
        for key, row in tables["sessions"].items()
    }
    return tables


def _headers(world: World, who: Who) -> dict[str, str]:
    """The session cookie of ``who`` (none for the public route)."""
    if who == "public":
        return {}
    return world.by_role(who).cookie


def _envelope_orders(body: Any) -> list[list[str]]:
    """The top-level key order, then each error's key order."""
    return [list(body), *(list(error) for error in body["detail"])]


# ---------------------------------------------------------------------------
# Contract C3 through the real routes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", list(_CASES.values()), ids=list(_CASES))
def test_fixed_validator_messages_route_answers_the_validators_text(
    world: World,
    client: TestClient,
    caplog: pytest.LogCaptureFixture,
    case: _Case,
) -> None:
    """The route answers 422 with exactly one error: FastAPI's loc, the validator's C3
    text byte for byte, ``value_error``; keys in order; no canary in the body or an app
    log line; nothing written (no row, no audit event)."""
    caplog.set_level(logging.DEBUG)
    path = case.path(world)
    before = _state(world.db)

    response = client.request(case.method, path, json=case.body, headers=_headers(world, case.who))

    body = response.json()
    assert response.status_code == 422, response.text
    assert body == {"detail": [{"loc": case.loc, "msg": case.msg, "type": "value_error"}]}
    assert _envelope_orders(body) == [["detail"], _KEY_ORDER]
    assert _http_leaks(response) == set()
    assert _leaked(_app_log_text(caplog)) == set()
    assert _state(world.db) == before


# ---------------------------------------------------------------------------
# Negatives: validators that don't opt in keep the fixed table
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("path", "payload", "loc"), _NEGATIVES)
def test_fixed_validator_messages_probe_without_opt_in_is_invalid_value(
    probe_client: TestClient,
    caplog: pytest.LogCaptureFixture,
    path: str,
    payload: dict[str, str] | None,
    loc: list[str],
) -> None:
    """A plain ValueError or a library value_error quoting the canary (in the body or
    raised inside the route) answers "Invalid value": its own text, which carries the
    input, never reaches the body or an app log line."""
    caplog.set_level(logging.DEBUG)

    response = probe_client.post(path, json=payload)

    body = response.json()
    assert response.status_code == 422, response.text
    assert body == {"detail": [{"loc": loc, "msg": _INVALID_VALUE, "type": "value_error"}]}
    assert _envelope_orders(body) == [["detail"], _KEY_ORDER]
    assert _http_leaks(response) == set()
    assert _leaked(_app_log_text(caplog)) == set()
