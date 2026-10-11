"""Tests for the Super Admin user-administration API models in admino.models (GH-167).

``GET /api/platform/orgs/{org_id}/users`` answers ``PlatformUserListResponse``
(a list of ``PlatformUserSummary``); the deactivate and reactivate routes answer
one ``PlatformUserSummary``; ``GET /api/platform/orgs/{org_id}/metadata``
answers ``OrgMetadata``; ``POST .../users/{user_id}/invitation`` takes an
optional ``PlatformReinviteRequest``. Each test looks the models up on
``admino.models`` at call time, so a missing model fails only its own tests.

What these tests pin down:
- ``PlatformUserSummary`` has exactly ``id``, ``name``, ``email``, ``role``,
  ``status``, ``created_at`` and ``last_login_at`` (account metadata only).
  ``role`` is one of the two member roles (GH-306: the retired ``viewer`` is
  refused); ``status`` is ``active``, ``deactivated`` or ``invited`` (the
  Super Admin's list includes invited accounts, unlike the Org Admin's);
  ``name`` (None for an invited account) and ``last_login_at`` may be null.
  ``id`` is a plain ``uuid.UUID``.
- ``PlatformUserListResponse`` is exactly ``{"users": [PlatformUserSummary, ...]}``.
- ``OrgMetadata`` is exactly ``{"seats": {"used", "limit"}, "storage_used_bytes",
  "chat_count", "file_count"}``: ``seats`` is the existing ``OrgSeats``, every
  count a required integer >= 0 (``used`` may exceed ``limit``).
- ``PlatformReinviteRequest`` has one optional field, ``email``: absent or
  null means "resend"; a string is stripped and then follows exactly
  ``InvitationCreateRequest.email``'s rules (3 to 254 characters, no
  whitespace, control, format/invisible, direction-override, separator or
  surrogate characters, one '@' after a non-empty local part, a '.' inside
  the domain); capitalization is kept. An empty or whitespace-only string is
  not "not given": it is refused. Unknown fields are refused.

Security notes:
- No model has a password, token, hash or link field: a response can't carry
  a credential and a request can't set one (no impersonation, no password or
  token handling by the operator).
- ``OrgMetadata`` holds counts and sizes only, never a title, a name or any
  org content (operator blindness).
- ``PlatformReinviteRequest`` validation errors never repeat the input:
  neither ``str(error)`` nor the error list (without input) contains the
  submitted email or an unknown field's value.
- The body can't choose the org, the target user, the role or the language:
  those come from the path, the contract (always ``org_admin``) and the
  session.
"""

from __future__ import annotations

import json
import re
import typing
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from asyncpg.pgproto.pgproto import UUID as PgUUID  # noqa: N811
from pydantic import BaseModel, ValidationError

_LONGEST_EMAIL = "a" * (254 - len("@example.ch")) + "@example.ch"
_CREATED_AT = datetime(2026, 9, 1, 8, 30, tzinfo=UTC)
_LAST_LOGIN_AT = datetime(2026, 10, 1, 17, 5, tzinfo=UTC)
_USER_ID = uuid.UUID("7c1d2e3f-4a5b-4c6d-8e9f-0a1b2c3d4e5f")

_SUMMARY_FIELDS = frozenset(
    {"id", "name", "email", "role", "status", "created_at", "last_login_at"}
)
_METADATA_FIELDS = frozenset({"seats", "storage_used_bytes", "chat_count", "file_count"})
_COUNT_FIELDS = ("storage_used_bytes", "chat_count", "file_count")
_MEMBER_ROLES = ("org_admin", "editor")
_STATUSES = ("active", "deactivated", "invited")
_NEW_MODELS = (
    "PlatformUserSummary",
    "PlatformUserListResponse",
    "OrgMetadata",
    "PlatformReinviteRequest",
)

# Field names that would carry a credential, a link, a scope or the account kind.
_NEVER_FIELDS = frozenset(
    {
        "password",
        "new_password",
        "password_hash",
        "hash",
        "token",
        "token_hash",
        "reset_token",
        "session_token",
        "invitation_token",
        "accept_link",
        "reset_link",
        "link",
        "org_id",
        "kind",
        "is_super_admin",
        "deleted_at",
    }
)
# A title/name/content/file name field: org content the operator never sees.
_CONTENT_FIELD = re.compile(r"(?:^|_)(?:title|name|content|file_?name)s?(?:$|_)")


def _model(name: str) -> Any:
    """Look a model up on admino.models at call time (it is new in GH-167)."""
    from admino import models

    model = getattr(models, name, None)
    assert model is not None, f"admino.models must define {name}"
    return model


def _models_in(annotation: Any) -> list[type[BaseModel]]:
    """The Pydantic models inside a type: itself, or inside list/Optional/union."""
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return [annotation]
    found: list[type[BaseModel]] = []
    for arg in typing.get_args(annotation):
        found.extend(_models_in(arg))
    return found


def _field_names(model: type[BaseModel]) -> set[str]:
    """Every field name of ``model`` and of the models nested in it."""
    seen: list[type[BaseModel]] = []
    pending = [model]
    names: set[str] = set()
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.append(current)
        for name, field in current.model_fields.items():
            names.add(name)
            pending.extend(_models_in(field.annotation))
    return names


def _summary_data(**overrides: Any) -> dict[str, Any]:
    return {
        "id": _USER_ID,
        "name": "Ada Lovelace",
        "email": "Ada.Lovelace@Example.CH",
        "role": "org_admin",
        "status": "active",
        "created_at": _CREATED_AT,
        "last_login_at": _LAST_LOGIN_AT,
        **overrides,
    }


def _invited_data(**overrides: Any) -> dict[str, Any]:
    """An invited account: no name yet, never logged in."""
    return _summary_data(
        id=uuid.UUID("8d2e3f4a-5b6c-4d7e-9f0a-1b2c3d4e5f60"),
        name=None,
        email="first.admin@example.ch",
        status="invited",
        last_login_at=None,
        **overrides,
    )


def _summary(**overrides: Any) -> Any:
    return _model("PlatformUserSummary").model_validate(_summary_data(**overrides))


def _metadata_data(**overrides: Any) -> dict[str, Any]:
    return {
        "seats": {"used": 7, "limit": 10},
        "storage_used_bytes": 0,
        "chat_count": 0,
        "file_count": 0,
        **overrides,
    }


def _metadata(**overrides: Any) -> Any:
    return _model("OrgMetadata").model_validate(_metadata_data(**overrides))


def _reinvite(**values: Any) -> Any:
    return _model("PlatformReinviteRequest").model_validate(values)


def _accepted(build: Any) -> bool:
    try:
        build()
    except ValidationError:
        return False
    return True


def _error_locs(exc: ValidationError) -> list[tuple[Any, ...]]:
    return [error["loc"] for error in exc.errors(include_input=False, include_url=False)]


# ---------------------------------------------------------------------------
# 0. Every new model: no credential, link or token field
# ---------------------------------------------------------------------------


class TestNoCredentialFields:
    """No GH-167 model, nested models included, has a field that could hold a secret."""

    @pytest.mark.parametrize("name", _NEW_MODELS)
    def test_platform_user_models_have_no_credential_or_link_field(self, name: str) -> None:
        assert _field_names(_model(name)).isdisjoint(_NEVER_FIELDS)

    @pytest.mark.parametrize("name", _NEW_MODELS)
    def test_platform_user_models_are_documented(self, name: str) -> None:
        assert (_model(name).__doc__ or "").strip() != ""


# ---------------------------------------------------------------------------
# 1. PlatformUserSummary
# ---------------------------------------------------------------------------


class TestPlatformUserSummary:
    """One account of an org as the Super Admin sees it: account metadata only."""

    def test_platform_user_models_summary_has_exactly_the_contract_fields(self) -> None:
        assert set(_model("PlatformUserSummary").model_fields) == _SUMMARY_FIELDS

    def test_platform_user_models_summary_keeps_the_values(self) -> None:
        summary = _summary()

        assert summary.id == _USER_ID
        assert summary.name == "Ada Lovelace"
        assert summary.email == "Ada.Lovelace@Example.CH"
        assert summary.role == "org_admin"
        assert summary.status == "active"
        assert summary.created_at == _CREATED_AT
        assert summary.last_login_at == _LAST_LOGIN_AT

    def test_platform_user_models_summary_json_has_exactly_the_contract_keys(self) -> None:
        """The JSON object a client gets: the seven keys, the id and dates as strings."""
        dumped = json.loads(_summary().model_dump_json())

        assert set(dumped) == _SUMMARY_FIELDS
        assert dumped["id"] == str(_USER_ID)
        assert dumped["email"] == "Ada.Lovelace@Example.CH"
        assert isinstance(dumped["created_at"], str)
        assert isinstance(dumped["last_login_at"], str)

    def test_platform_user_models_summary_never_dumps_a_row_secret(self) -> None:
        """Built from a users row that also holds a hash, an org id, a kind and a language,
        the dumped summary carries none of them."""
        row = {
            **_summary_data(),
            "password_hash": "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA",
            "org_id": uuid.uuid4(),
            "kind": "member",
            "ui_language": "fr",
            "deleted_at": None,
        }

        try:
            summary = _model("PlatformUserSummary").model_validate(row)
        except ValidationError:
            return  # refusing the extra keys is as good as dropping them
        dumped = summary.model_dump(mode="json")

        assert set(dumped) == _SUMMARY_FIELDS
        assert "argon2" not in json.dumps(dumped)
        assert str(row["org_id"]) not in json.dumps(dumped)

    def test_platform_user_models_summary_id_is_a_plain_uuid(self) -> None:
        """An asyncpg UUID from a row becomes a plain uuid.UUID (PlainUUID)."""
        value = uuid.uuid4()

        summary = _summary(id=PgUUID(str(value)))

        assert type(summary.id) is uuid.UUID
        assert summary.id == value

    def test_platform_user_models_summary_holds_an_invited_account(self) -> None:
        """An invited account has no name and never logged in: both are null in the JSON."""
        summary = _model("PlatformUserSummary").model_validate(_invited_data())

        dumped = json.loads(summary.model_dump_json())
        assert (summary.status, summary.name, summary.last_login_at) == ("invited", None, None)
        assert (dumped["status"], dumped["name"], dumped["last_login_at"]) == (
            "invited",
            None,
            None,
        )

    @pytest.mark.parametrize("field", ["id", "email", "role", "status", "created_at"])
    def test_platform_user_models_summary_requires_field(self, field: str) -> None:
        data = _summary_data()
        del data[field]

        with pytest.raises(ValidationError) as caught:
            _model("PlatformUserSummary").model_validate(data)

        assert _error_locs(caught.value) == [(field,)]

    @pytest.mark.parametrize("role", _MEMBER_ROLES)
    def test_platform_user_models_summary_accepts_member_role(self, role: str) -> None:
        assert _summary(role=role).role == role

    @pytest.mark.parametrize(
        "role",
        ["super_admin", "viewer", "Org_Admin", "ORG_ADMIN", "admin", "owner", "", None, 1],
    )
    def test_platform_user_models_summary_rejects_role(self, role: Any) -> None:
        """A Super Admin is never an org's account; anything else is not a role."""
        with pytest.raises(ValidationError) as caught:
            _summary(role=role)

        assert _error_locs(caught.value) == [("role",)]

    @pytest.mark.parametrize("status", _STATUSES)
    def test_platform_user_models_summary_accepts_status(self, status: str) -> None:
        """Active, deactivated and invited accounts are all listed for the Super Admin."""
        assert _summary(status=status).status == status

    @pytest.mark.parametrize(
        "status",
        ["deleted", "pending", "Invited", "INVITED", "Active", "inactive", "", None, True],
    )
    def test_platform_user_models_summary_rejects_status(self, status: Any) -> None:
        """A deleted account is never listed; anything else is not a status."""
        with pytest.raises(ValidationError) as caught:
            _summary(status=status)

        assert _error_locs(caught.value) == [("status",)]

    def test_platform_user_models_summary_name_up_to_120_characters(self) -> None:
        assert _summary(name="n" * 120).name == "n" * 120

    def test_platform_user_models_summary_rejects_a_121_character_name(self) -> None:
        with pytest.raises(ValidationError) as caught:
            _summary(name="n" * 121)

        assert _error_locs(caught.value) == [("name",)]

    def test_platform_user_models_summary_email_up_to_254_characters(self) -> None:
        assert _summary(email=_LONGEST_EMAIL).email == _LONGEST_EMAIL

    def test_platform_user_models_summary_rejects_a_255_character_email(self) -> None:
        with pytest.raises(ValidationError) as caught:
            _summary(email="a" + _LONGEST_EMAIL)

        assert _error_locs(caught.value) == [("email",)]


# ---------------------------------------------------------------------------
# 2. PlatformUserListResponse
# ---------------------------------------------------------------------------


class TestPlatformUserListResponse:
    """GET /api/platform/orgs/{org_id}/users: {"users": [...]}, nothing else."""

    def test_platform_user_models_list_response_has_exactly_users(self) -> None:
        """No seats here: the seat usage is part of the org metadata route."""
        assert set(_model("PlatformUserListResponse").model_fields) == {"users"}

    def test_platform_user_models_list_response_validates_rows_into_summaries(self) -> None:
        response = _model("PlatformUserListResponse").model_validate(
            {"users": [_summary_data(), _invited_data()]}
        )

        assert [type(user) for user in response.users] == [_model("PlatformUserSummary")] * 2
        assert [user.status for user in response.users] == ["active", "invited"]

    def test_platform_user_models_list_response_keeps_the_order(self) -> None:
        first = _summary()
        second = _model("PlatformUserSummary").model_validate(_invited_data())
        third = _summary(id=uuid.uuid4(), email="c@example.ch", role="editor", status="deactivated")

        response = _model("PlatformUserListResponse")(users=[first, second, third])

        assert response.users == [first, second, third]

    def test_platform_user_models_list_response_json_shape(self) -> None:
        response = _model("PlatformUserListResponse").model_validate(
            {"users": [_summary_data(), _invited_data()]}
        )

        dumped = json.loads(response.model_dump_json())

        assert set(dumped) == {"users"}
        assert [set(user) for user in dumped["users"]] == [_SUMMARY_FIELDS, _SUMMARY_FIELDS]
        assert [user["status"] for user in dumped["users"]] == ["active", "invited"]

    def test_platform_user_models_list_response_may_be_empty(self) -> None:
        """An existing org with no account answers an empty list."""
        response = _model("PlatformUserListResponse")(users=[])

        assert json.loads(response.model_dump_json()) == {"users": []}

    def test_platform_user_models_list_response_requires_users(self) -> None:
        with pytest.raises(ValidationError) as caught:
            _model("PlatformUserListResponse").model_validate({})

        errors = caught.value.errors(include_input=False, include_url=False)
        assert [(error["loc"], error["type"]) for error in errors] == [(("users",), "missing")]

    def test_platform_user_models_list_response_validates_each_row(self) -> None:
        """A Super Admin row (role super_admin) inside the list is refused at its index."""
        with pytest.raises(ValidationError) as caught:
            _model("PlatformUserListResponse").model_validate(
                {"users": [_summary_data(), _summary_data(role="super_admin")]}
            )

        assert _error_locs(caught.value) == [("users", 1, "role")]


# ---------------------------------------------------------------------------
# 3. OrgMetadata
# ---------------------------------------------------------------------------


class TestOrgMetadata:
    """GET /api/platform/orgs/{org_id}/metadata: counts and sizes only."""

    def test_platform_user_models_metadata_has_exactly_the_contract_fields(self) -> None:
        assert set(_model("OrgMetadata").model_fields) == _METADATA_FIELDS

    def test_platform_user_models_metadata_has_no_content_field(self) -> None:
        """No title, name, content or file name field anywhere (seats included)."""
        names = _field_names(_model("OrgMetadata"))

        assert sorted(name for name in names if _CONTENT_FIELD.search(name)) == []

    def test_platform_user_models_metadata_seats_are_org_seats(self) -> None:
        """``seats`` is the existing OrgSeats model ({"used", "limit"})."""
        metadata = _metadata(seats={"used": 3, "limit": 10})

        assert isinstance(metadata.seats, _model("OrgSeats"))
        assert (metadata.seats.used, metadata.seats.limit) == (3, 10)

    def test_platform_user_models_metadata_json_is_exactly_the_contract_object(self) -> None:
        metadata = _metadata(
            seats={"used": 3, "limit": 10}, storage_used_bytes=0, chat_count=0, file_count=0
        )

        assert json.loads(metadata.model_dump_json()) == {
            "seats": {"used": 3, "limit": 10},
            "storage_used_bytes": 0,
            "chat_count": 0,
            "file_count": 0,
        }

    def test_platform_user_models_metadata_keeps_counts_as_ints(self) -> None:
        metadata = _metadata(storage_used_bytes=5 * 1024**4, chat_count=12, file_count=34)

        values = (metadata.storage_used_bytes, metadata.chat_count, metadata.file_count)
        assert values == (5 * 1024**4, 12, 34)
        assert [type(value) for value in values] == [int, int, int]

    def test_platform_user_models_metadata_accepts_all_zero(self) -> None:
        """Before chats and files exist (#176, #187), every count is 0."""
        metadata = _metadata(seats={"used": 0, "limit": 0})

        assert json.loads(metadata.model_dump_json()) == {
            "seats": {"used": 0, "limit": 0},
            "storage_used_bytes": 0,
            "chat_count": 0,
            "file_count": 0,
        }

    def test_platform_user_models_metadata_seats_used_may_exceed_the_limit(self) -> None:
        metadata = _metadata(seats={"used": 12, "limit": 10})

        assert (metadata.seats.used, metadata.seats.limit) == (12, 10)

    @pytest.mark.parametrize("field", sorted(_METADATA_FIELDS))
    def test_platform_user_models_metadata_requires_field(self, field: str) -> None:
        data = _metadata_data()
        del data[field]

        with pytest.raises(ValidationError) as caught:
            _model("OrgMetadata").model_validate(data)

        errors = caught.value.errors(include_input=False, include_url=False)
        assert [(error["loc"], error["type"]) for error in errors] == [((field,), "missing")]

    @pytest.mark.parametrize("field", _COUNT_FIELDS)
    @pytest.mark.parametrize("value", [-1, -4096])
    def test_platform_user_models_metadata_refuses_a_negative_count(
        self, field: str, value: int
    ) -> None:
        with pytest.raises(ValidationError) as caught:
            _metadata(**{field: value})

        assert _error_locs(caught.value) == [(field,)]

    @pytest.mark.parametrize("seat_field", ["used", "limit"])
    def test_platform_user_models_metadata_refuses_negative_seats(self, seat_field: str) -> None:
        seats = {"used": 3, "limit": 10, seat_field: -1}

        with pytest.raises(ValidationError) as caught:
            _metadata(seats=seats)

        assert _error_locs(caught.value) == [("seats", seat_field)]

    @pytest.mark.parametrize("field", _COUNT_FIELDS)
    @pytest.mark.parametrize(
        "value", [None, "seven", 1.5, [], {}], ids=["none", "word", "float", "list", "dict"]
    )
    def test_platform_user_models_metadata_refuses_a_non_integer(
        self, field: str, value: Any
    ) -> None:
        with pytest.raises(ValidationError) as caught:
            _metadata(**{field: value})

        assert _error_locs(caught.value) == [(field,)]

    def test_platform_user_models_metadata_seats_must_be_an_object(self) -> None:
        with pytest.raises(ValidationError) as caught:
            _metadata(seats=7)

        assert [loc[0] for loc in _error_locs(caught.value)] == ["seats"]


# ---------------------------------------------------------------------------
# 4. PlatformReinviteRequest: shape, unknown fields, null = not given
# ---------------------------------------------------------------------------


class TestPlatformReinviteRequestShape:
    """One optional field, ``email``; nothing else."""

    def test_platform_user_models_reinvite_has_exactly_email(self) -> None:
        assert set(_model("PlatformReinviteRequest").model_fields) == {"email"}

    def test_platform_user_models_reinvite_forbids_extra(self) -> None:
        assert _model("PlatformReinviteRequest").model_config.get("extra") == "forbid"

    @pytest.mark.parametrize(
        "values",
        [pytest.param({}, id="empty"), pytest.param({"email": None}, id="email-null")],
    )
    def test_platform_user_models_reinvite_without_email_means_resend(
        self, values: dict[str, Any]
    ) -> None:
        """No email (absent or null) is valid: the invitation is resent as it is."""
        assert _reinvite(**values).email is None

    @pytest.mark.parametrize(
        "raw",
        [pytest.param("{}", id="empty-object"), pytest.param('{"email": null}', id="null")],
    )
    def test_platform_user_models_reinvite_json_without_email_means_resend(self, raw: str) -> None:
        assert _model("PlatformReinviteRequest").model_validate_json(raw).email is None

    def test_platform_user_models_reinvite_from_json_strips_and_keeps_case(self) -> None:
        request = _model("PlatformReinviteRequest").model_validate_json(
            '{"email": "  New.Admin@Example.CH\\t"}'
        )

        assert request.email == "New.Admin@Example.CH"

    @pytest.mark.parametrize(
        "extra",
        [
            pytest.param({"org_id": str(uuid.uuid4())}, id="org_id"),
            pytest.param({"user_id": str(uuid.uuid4())}, id="user_id"),
            pytest.param({"invitation_id": str(uuid.uuid4())}, id="invitation_id"),
            pytest.param({"role": "org_admin"}, id="role"),
            pytest.param({"role": "editor"}, id="role-editor"),
            pytest.param({"name": "Grace Hopper"}, id="name"),
            pytest.param({"language": "fr"}, id="language"),
            pytest.param({"ui_language": "fr"}, id="ui_language"),
            pytest.param({"status": "active"}, id="status"),
            pytest.param({"kind": "super_admin"}, id="kind"),
            pytest.param({"password": "correct horse battery staple"}, id="password"),
            pytest.param({"token": "a-token-of-gh167"}, id="token"),
            pytest.param({"Email": "x@example.ch"}, id="case-variant-key"),
        ],
    )
    @pytest.mark.parametrize(
        "email", [pytest.param(None, id="resend"), pytest.param("ok@example.ch", id="replace")]
    )
    def test_platform_user_models_reinvite_refuses_unknown_fields(
        self, extra: dict[str, Any], email: str | None
    ) -> None:
        """The org, the target, the role, the language and the status are never chosen by
        the body, whether it resends or replaces."""
        with pytest.raises(ValidationError) as caught:
            _reinvite(email=email, **extra)

        errors = caught.value.errors(include_input=False, include_url=False)
        assert [(error["loc"], error["type"]) for error in errors] == [
            ((next(iter(extra)),), "extra_forbidden")
        ]


# ---------------------------------------------------------------------------
# 5. PlatformReinviteRequest.email: InvitationCreateRequest's rules
# ---------------------------------------------------------------------------

_REJECTED_EMAILS: list[Any] = [
    pytest.param("", id="empty"),
    pytest.param("   ", id="whitespace-only"),
    pytest.param("\t\n", id="tab-newline-only"),
    pytest.param("a@b", id="no-dot-3-chars"),
    pytest.param("no-at-sign.example.ch", id="no-at"),
    pytest.param("@example.ch", id="empty-local-part"),
    pytest.param("a@b@example.ch", id="two-ats"),
    pytest.param("a@examplech", id="no-dot-in-domain"),
    pytest.param("a@.examplech", id="only-dot-first-in-domain"),
    pytest.param("a@examplech.", id="only-dot-last-in-domain"),
    pytest.param("a@", id="empty-domain"),
    pytest.param("new admin@example.ch", id="space-inside"),
    pytest.param("new.admin@exa\tmple.ch", id="tab-inside"),
    pytest.param("new.admin@example.ch\nBcc: x@example.ch", id="newline-inside"),
    pytest.param("a" + chr(0) + "b@example.ch", id="nul"),
    pytest.param("a" + chr(0x1B) + "b@example.ch", id="escape"),
    pytest.param("a" + chr(0x7F) + "b@example.ch", id="del"),
    pytest.param("a" + chr(0x85) + "b@example.ch", id="c1-next-line"),
    pytest.param("a" + chr(0xA0) + "b@example.ch", id="nbsp"),
    pytest.param("a" + chr(0xAD) + "b@example.ch", id="soft-hyphen"),
    pytest.param("a" + chr(0x200B) + "b@example.ch", id="zero-width-space"),
    pytest.param("a" + chr(0x200D) + "b@example.ch", id="zero-width-joiner"),
    pytest.param("a" + chr(0x200E) + "b@example.ch", id="ltr-mark"),
    pytest.param("a" + chr(0x202E) + "b@example.ch", id="rtl-override"),
    pytest.param("a" + chr(0x202D) + "b@example.ch", id="ltr-override"),
    pytest.param("a" + chr(0x2066) + "b@example.ch", id="ltr-isolate"),
    pytest.param("a" + chr(0x061C) + "b@example.ch", id="arabic-letter-mark"),
    pytest.param(chr(0xFEFF) + "ab@example.ch", id="bom"),
    pytest.param("a" + chr(0x2028) + "b@example.ch", id="line-separator"),
    pytest.param("a" + chr(0x2029) + "b@example.ch", id="paragraph-separator"),
    pytest.param("a" + chr(0xD800) + "b@example.ch", id="lone-surrogate"),
    pytest.param("a" + _LONGEST_EMAIL, id="255-chars"),
    pytest.param(123, id="int"),
    pytest.param(True, id="bool"),
    pytest.param(["a@example.ch"], id="list"),
    pytest.param({"email": "a@example.ch"}, id="dict"),
]


class TestPlatformReinviteRequestEmail:
    """The replacement address follows the invitation rules exactly."""

    @pytest.mark.parametrize(
        ("email", "expected"),
        [
            pytest.param("ada@example.ch", "ada@example.ch", id="plain"),
            pytest.param("Ada.Lovelace@Example.CH", "Ada.Lovelace@Example.CH", id="case-kept"),
            pytest.param("x@y.z", "x@y.z", id="short"),
            pytest.param("first.last+tag@sub.example.co.uk", None, id="plus-and-subdomains"),
            pytest.param("  padded@example.ch\t", "padded@example.ch", id="stripped"),
            pytest.param(" " + _LONGEST_EMAIL + "\n", _LONGEST_EMAIL, id="254-after-strip"),
            pytest.param(_LONGEST_EMAIL, None, id="254-chars"),
        ],
    )
    def test_platform_user_models_reinvite_accepts_email(
        self, email: str, expected: str | None
    ) -> None:
        assert _reinvite(email=email).email == (expected or email)

    @pytest.mark.parametrize("email", _REJECTED_EMAILS)
    def test_platform_user_models_reinvite_rejects_email(self, email: Any) -> None:
        """An invalid address is refused at ``email``; an empty or blank one is not "resend"."""
        with pytest.raises(ValidationError) as caught:
            _reinvite(email=email)

        assert _error_locs(caught.value) == [("email",)]

    @pytest.mark.parametrize(
        "email",
        [
            "a@b@example.ch",
            "a@examplech",
            "a" + chr(0x200B) + "b@example.ch",
            "a" + chr(0x202E) + "b@example.ch",
            "x@y.z",
            " Mixed.Case@Example.ch ",
            "a@.examplech",
            "new admin@example.ch",
            "   ",
            "a" + _LONGEST_EMAIL,
            _LONGEST_EMAIL,
        ],
    )
    def test_platform_user_models_reinvite_email_matches_invitation_rules(self, email: str) -> None:
        """Same verdict, and the same stored value, as InvitationCreateRequest.email."""
        from admino.models import InvitationCreateRequest

        invitation = _accepted(lambda: InvitationCreateRequest(email=email, role="org_admin"))
        reinvite = _accepted(lambda: _reinvite(email=email))

        assert reinvite == invitation
        if invitation:
            expected = InvitationCreateRequest(email=email, role="org_admin").email
            assert _reinvite(email=email).email == expected


# ---------------------------------------------------------------------------
# 6. PlatformReinviteRequest: errors never repeat the input
# ---------------------------------------------------------------------------


class TestPlatformReinviteRequestErrorsHideInput:
    """Neither str(ValidationError) nor its error list (without input) repeats a value."""

    @pytest.mark.parametrize(
        ("values", "markers"),
        [
            pytest.param({"email": "zanzibar-marker@exa mple.ch"}, ["zanzibar"], id="email-space"),
            pytest.param({"email": "quokka-marker@examplech"}, ["quokka"], id="email-no-dot"),
            pytest.param({"email": "wombat@two@example.ch"}, ["wombat"], id="email-two-ats"),
            pytest.param(
                {"email": "capybara" + chr(0x200B) + "@example.ch"},
                ["capybara"],
                id="email-zero-width",
            ),
            pytest.param(
                {"email": "pangolin" + chr(0x202E) + "@example.ch"},
                ["pangolin"],
                id="email-rtl-override",
            ),
            pytest.param(
                {"email": "axolotl" * 40 + "@example.ch"}, ["axolotl"], id="email-too-long"
            ),
            pytest.param(
                {"email": None, "password": "hunter2-marker"},
                ["hunter2-marker"],
                id="extra-password",
            ),
            pytest.param(
                {"email": "ok@example.ch", "role": "superuser-marker-167"},
                ["superuser-marker-167"],
                id="extra-role",
            ),
        ],
    )
    def test_platform_user_models_reinvite_error_hides_input(
        self, values: dict[str, Any], markers: list[str]
    ) -> None:
        with pytest.raises(ValidationError) as exc_info:
            _reinvite(**values)

        text = str(exc_info.value)
        details = json.dumps(
            exc_info.value.errors(include_input=False, include_url=False), default=str
        )
        for marker in markers:
            assert marker not in text, text
            assert marker not in details, details
