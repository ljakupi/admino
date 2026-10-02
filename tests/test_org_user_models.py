"""Tests for the Org Admin user-management API models in admino.models (GH-164).

``GET /api/org/users`` answers ``OrgUserListResponse`` (a list of
``OrgUserSummary``); ``PATCH /api/org/users/{user_id}`` takes an
``OrgUserPatch`` and, like the status routes, answers one ``OrgUserSummary``.
The models are new, so each test looks them up on ``admino.models`` at call
time and fails on its own until they exist.

What these tests pin down:
- ``OrgUserSummary`` has exactly ``id``, ``name``, ``email``, ``role``,
  ``status``, ``created_at`` and ``last_login_at``: no password, hash, token,
  org id or account kind. ``role`` is one of the three member roles
  (``super_admin`` refused), ``status`` is ``active`` or ``deactivated`` only
  (an invited or deleted account is never a user here). ``name`` and
  ``last_login_at`` may be null. ``id`` is a plain ``uuid.UUID`` (an asyncpg
  UUID is converted), serialized as a string.
- ``OrgUserListResponse`` is ``{"users": [OrgUserSummary, ...]}``.
- ``OrgUserPatch`` (unknown fields refused: ``org_id``, ``user_id``,
  ``status``, ``kind``, ``password`` ...): any of ``role``, ``name`` and
  ``email``, a null counting as not given, at least one given. ``role`` is a
  member role. ``name`` is stripped, 1 to 120 characters, and refuses control
  (Cc), format (Cf, e.g. zero-width and direction overrides), surrogate (Cs)
  and line/paragraph separator (Zl, Zp) characters. ``email`` is stripped and
  follows exactly ``InvitationCreateRequest.email``'s rules (3 to 254
  characters, no whitespace or invisible characters, one '@' after a
  non-empty local part, a '.' inside the domain); capitalization is kept.

Security notes:
- Validation errors never contain the submitted name or email (nor any other
  rejected value): a 422 body or a log line built from them repeats nothing.
- The body can't choose the org, the target user, the status or the account
  kind: those come from the session, the path and the dedicated routes.
- A response never carries a credential: there is no field that could hold
  one.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from asyncpg.pgproto.pgproto import UUID as PgUUID  # noqa: N811
from pydantic import ValidationError

_LONGEST_EMAIL = "a" * (254 - len("@example.ch")) + "@example.ch"
_CREATED_AT = datetime(2026, 9, 1, 8, 30, tzinfo=UTC)
_LAST_LOGIN_AT = datetime(2026, 10, 1, 17, 5, tzinfo=UTC)

_SUMMARY_FIELDS = frozenset(
    {"id", "name", "email", "role", "status", "created_at", "last_login_at"}
)
_PATCH_FIELDS = frozenset({"role", "name", "email"})
_MEMBER_ROLES = ("org_admin", "editor", "viewer")

# Field names that would carry a credential, a scope or the account kind.
_NEVER_FIELDS = frozenset(
    {
        "password",
        "password_hash",
        "hash",
        "token",
        "token_hash",
        "reset_token",
        "session_token",
        "org_id",
        "kind",
        "is_super_admin",
        "deleted_at",
    }
)


def _model(name: str) -> Any:
    """Look a model up on admino.models at call time (it is new in GH-164)."""
    from admino import models

    model = getattr(models, name, None)
    assert model is not None, f"admino.models must define {name}"
    return model


def _summary_data(**overrides: Any) -> dict[str, Any]:
    return {
        "id": uuid.UUID("5b8e2c4a-1f3d-4e6b-9a7c-0d1e2f3a4b5c"),
        "name": "Ada Lovelace",
        "email": "Ada.Lovelace@Example.CH",
        "role": "editor",
        "status": "active",
        "created_at": _CREATED_AT,
        "last_login_at": _LAST_LOGIN_AT,
        **overrides,
    }


def _summary(**overrides: Any) -> Any:
    return _model("OrgUserSummary").model_validate(_summary_data(**overrides))


def _patch(**values: Any) -> Any:
    return _model("OrgUserPatch").model_validate(values)


def _accepted(build: Any) -> bool:
    try:
        build()
    except ValidationError:
        return False
    return True


# ---------------------------------------------------------------------------
# 1. OrgUserSummary
# ---------------------------------------------------------------------------


class TestOrgUserSummary:
    """One user of the caller's org: the list and change responses."""

    def test_org_user_models_summary_has_exactly_the_contract_fields(self) -> None:
        assert set(_model("OrgUserSummary").model_fields) == _SUMMARY_FIELDS

    def test_org_user_models_summary_has_no_credential_scope_or_kind_field(self) -> None:
        assert set(_model("OrgUserSummary").model_fields).isdisjoint(_NEVER_FIELDS)

    def test_org_user_models_summary_keeps_the_values(self) -> None:
        summary = _summary()

        assert summary.id == uuid.UUID("5b8e2c4a-1f3d-4e6b-9a7c-0d1e2f3a4b5c")
        assert summary.name == "Ada Lovelace"
        assert summary.email == "Ada.Lovelace@Example.CH"
        assert summary.role == "editor"
        assert summary.status == "active"
        assert summary.created_at == _CREATED_AT
        assert summary.last_login_at == _LAST_LOGIN_AT

    def test_org_user_models_summary_json_has_exactly_the_contract_keys(self) -> None:
        """The JSON object a client gets: the seven keys, the id and dates as strings."""
        dumped = json.loads(_summary().model_dump_json())

        assert set(dumped) == _SUMMARY_FIELDS
        assert dumped["id"] == "5b8e2c4a-1f3d-4e6b-9a7c-0d1e2f3a4b5c"
        assert isinstance(dumped["created_at"], str)
        assert isinstance(dumped["last_login_at"], str)

    def test_org_user_models_summary_never_dumps_a_row_secret(self) -> None:
        """Built from a users row that also holds a hash, an org id and a kind, the dumped
        summary carries none of them."""
        data = _summary_data()
        row = {
            **data,
            "password_hash": "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA",
            "org_id": uuid.uuid4(),
            "kind": "member",
        }

        try:
            summary = _model("OrgUserSummary").model_validate(row)
        except ValidationError:
            return  # refusing the extra keys is as good as dropping them
        dumped = summary.model_dump(mode="json")

        assert set(dumped) == _SUMMARY_FIELDS
        assert "argon2" not in json.dumps(dumped)

    def test_org_user_models_summary_id_is_a_plain_uuid(self) -> None:
        """An asyncpg UUID from a row becomes a plain uuid.UUID (PlainUUID)."""
        value = uuid.uuid4()

        summary = _summary(id=PgUUID(str(value)))

        assert type(summary.id) is uuid.UUID
        assert summary.id == value

    def test_org_user_models_summary_name_may_be_null(self) -> None:
        """users.name is nullable (an account created before a name was set)."""
        summary = _summary(name=None)

        assert summary.name is None
        assert json.loads(summary.model_dump_json())["name"] is None

    def test_org_user_models_summary_last_login_may_be_null(self) -> None:
        """A user who never signed in has no last login."""
        summary = _summary(last_login_at=None)

        assert summary.last_login_at is None
        assert json.loads(summary.model_dump_json())["last_login_at"] is None

    @pytest.mark.parametrize("field", ["id", "email", "role", "status", "created_at"])
    def test_org_user_models_summary_requires_field(self, field: str) -> None:
        data = _summary_data()
        del data[field]

        with pytest.raises(ValidationError):
            _model("OrgUserSummary").model_validate(data)

    @pytest.mark.parametrize("role", _MEMBER_ROLES)
    def test_org_user_models_summary_accepts_member_role(self, role: str) -> None:
        assert _summary(role=role).role == role

    @pytest.mark.parametrize(
        "role", ["super_admin", "Org_Admin", "ORG_ADMIN", "admin", "owner", "", None, 1]
    )
    def test_org_user_models_summary_rejects_role(self, role: Any) -> None:
        """A Super Admin is never an org user; anything else is not a role."""
        with pytest.raises(ValidationError):
            _summary(role=role)

    @pytest.mark.parametrize("status", ["active", "deactivated"])
    def test_org_user_models_summary_accepts_status(self, status: str) -> None:
        assert _summary(status=status).status == status

    @pytest.mark.parametrize(
        "status", ["invited", "deleted", "Active", "ACTIVE", "inactive", "", None, True]
    )
    def test_org_user_models_summary_rejects_status(self, status: Any) -> None:
        """An invited or deleted account is not a user here."""
        with pytest.raises(ValidationError):
            _summary(status=status)


# ---------------------------------------------------------------------------
# 2. OrgUserListResponse
# ---------------------------------------------------------------------------


class TestOrgUserListResponse:
    """GET /api/org/users: {"users": [...]}."""

    def test_org_user_models_list_response_has_only_users(self) -> None:
        assert set(_model("OrgUserListResponse").model_fields) == {"users"}

    def test_org_user_models_list_response_holds_summaries(self) -> None:
        first = _summary()
        second = _summary(
            id=uuid.uuid4(), name=None, email="b@example.ch", role="viewer", status="deactivated"
        )

        response = _model("OrgUserListResponse")(users=[first, second])

        assert response.users == [first, second]
        assert all(isinstance(user, _model("OrgUserSummary")) for user in response.users)

    def test_org_user_models_list_response_validates_rows_into_summaries(self) -> None:
        response = _model("OrgUserListResponse").model_validate({"users": [_summary_data()]})

        assert isinstance(response.users[0], _model("OrgUserSummary"))

    def test_org_user_models_list_response_json_shape(self) -> None:
        response = _model("OrgUserListResponse")(users=[_summary()])

        dumped = json.loads(response.model_dump_json())

        assert set(dumped) == {"users"}
        assert len(dumped["users"]) == 1
        assert set(dumped["users"][0]) == _SUMMARY_FIELDS

    def test_org_user_models_list_response_may_be_empty(self) -> None:
        response = _model("OrgUserListResponse")(users=[])

        assert json.loads(response.model_dump_json()) == {"users": []}

    def test_org_user_models_list_response_refuses_an_invited_row(self) -> None:
        with pytest.raises(ValidationError):
            _model("OrgUserListResponse").model_validate(
                {"users": [_summary_data(status="invited")]}
            )


# ---------------------------------------------------------------------------
# 3. OrgUserPatch: shape, unknown fields, "at least one"
# ---------------------------------------------------------------------------


class TestOrgUserPatchShape:
    """role, name and email, each optional; at least one; nothing else."""

    def test_org_user_models_patch_has_exactly_role_name_email(self) -> None:
        assert set(_model("OrgUserPatch").model_fields) == _PATCH_FIELDS

    def test_org_user_models_patch_forbids_extra(self) -> None:
        assert _model("OrgUserPatch").model_config.get("extra") == "forbid"

    @pytest.mark.parametrize(
        ("values", "expected"),
        [
            pytest.param({"role": "viewer"}, ("viewer", None, None), id="role"),
            pytest.param({"name": "Grace Hopper"}, (None, "Grace Hopper", None), id="name"),
            pytest.param(
                {"email": "grace@example.ch"}, (None, None, "grace@example.ch"), id="email"
            ),
            pytest.param(
                {"role": "org_admin", "name": "Grace", "email": "g@example.ch"},
                ("org_admin", "Grace", "g@example.ch"),
                id="all-three",
            ),
            pytest.param(
                {"role": "editor", "name": None, "email": None},
                ("editor", None, None),
                id="null-is-not-given",
            ),
        ],
    )
    def test_org_user_models_patch_accepts(
        self, values: dict[str, Any], expected: tuple[Any, Any, Any]
    ) -> None:
        patch = _patch(**values)

        assert (patch.role, patch.name, patch.email) == expected

    @pytest.mark.parametrize(
        "values",
        [
            pytest.param({}, id="empty"),
            pytest.param({"role": None}, id="role-null"),
            pytest.param({"name": None}, id="name-null"),
            pytest.param({"email": None}, id="email-null"),
            pytest.param({"role": None, "name": None, "email": None}, id="all-null"),
        ],
    )
    def test_org_user_models_patch_needs_at_least_one_field(self, values: dict[str, Any]) -> None:
        with pytest.raises(ValidationError):
            _patch(**values)

    @pytest.mark.parametrize(
        "raw",
        [
            pytest.param("{}", id="empty-object"),
            pytest.param('{"role": null, "name": null, "email": null}', id="all-null"),
        ],
    )
    def test_org_user_models_patch_empty_json_refused(self, raw: str) -> None:
        with pytest.raises(ValidationError):
            _model("OrgUserPatch").model_validate_json(raw)

    def test_org_user_models_patch_from_json(self) -> None:
        patch = _model("OrgUserPatch").model_validate_json(
            '{"role": "viewer", "name": " Grace ", "email": null}'
        )

        assert (patch.role, patch.name, patch.email) == ("viewer", "Grace", None)

    @pytest.mark.parametrize(
        "extra",
        [
            pytest.param({"org_id": str(uuid.uuid4())}, id="org_id"),
            pytest.param({"user_id": str(uuid.uuid4())}, id="user_id"),
            pytest.param({"id": str(uuid.uuid4())}, id="id"),
            pytest.param({"status": "active"}, id="status"),
            pytest.param({"status": "deactivated"}, id="status-deactivated"),
            pytest.param({"kind": "super_admin"}, id="kind"),
            pytest.param({"password": "correct horse battery staple"}, id="password"),
            pytest.param({"password_hash": "$argon2id$x"}, id="password_hash"),
            pytest.param({"created_at": "2026-01-01T00:00:00Z"}, id="created_at"),
            pytest.param({"last_login_at": None}, id="last_login_at"),
            pytest.param({"deleted_at": None}, id="deleted_at"),
            pytest.param({"ui_language": "fr"}, id="ui_language"),
            pytest.param({"Role": "viewer"}, id="case-variant-key"),
        ],
    )
    def test_org_user_models_patch_refuses_unknown_fields(self, extra: dict[str, Any]) -> None:
        """The org, the target, the status and the kind are never chosen by the body."""
        with pytest.raises(ValidationError):
            _patch(role="viewer", **extra)

    def test_org_user_models_patch_refuses_unknown_field_alone(self) -> None:
        """An unknown field doesn't count as the one given field."""
        with pytest.raises(ValidationError):
            _patch(status="deactivated")


# ---------------------------------------------------------------------------
# 4. OrgUserPatch.role
# ---------------------------------------------------------------------------


class TestOrgUserPatchRole:
    """A member role only."""

    @pytest.mark.parametrize("role", _MEMBER_ROLES)
    def test_org_user_models_patch_accepts_member_role(self, role: str) -> None:
        assert _patch(role=role).role == role

    @pytest.mark.parametrize(
        "role",
        [
            pytest.param("super_admin", id="super-admin"),
            pytest.param("Super_Admin", id="super-admin-case"),
            pytest.param("operator", id="operator"),
            pytest.param("admin", id="admin"),
            pytest.param("owner", id="owner"),
            pytest.param("Editor", id="case-variant"),
            pytest.param("VIEWER", id="upper-case"),
            pytest.param(" viewer", id="leading-space"),
            pytest.param("viewer\n", id="trailing-newline"),
            pytest.param("", id="empty"),
            pytest.param(1, id="int"),
            pytest.param(True, id="bool"),
            pytest.param(["viewer"], id="list"),
        ],
    )
    def test_org_user_models_patch_rejects_role(self, role: Any) -> None:
        with pytest.raises(ValidationError):
            _patch(role=role)


# ---------------------------------------------------------------------------
# 5. OrgUserPatch.name
# ---------------------------------------------------------------------------


class TestOrgUserPatchName:
    """Stripped, 1 to 120 characters, no Cc/Cf/Cs/Zl/Zp characters."""

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            pytest.param("Grace Hopper", "Grace Hopper", id="plain"),
            pytest.param("  Grace Hopper \t", "Grace Hopper", id="stripped"),
            pytest.param("Zoë Müller-Łukasiewicz", None, id="unicode"),
            pytest.param("O'Brien", None, id="apostrophe"),
            pytest.param("X", None, id="one-char"),
            pytest.param("a" * 120, None, id="120-chars"),
            pytest.param("  " + "a" * 120 + "\n", "a" * 120, id="120-after-strip"),
        ],
    )
    def test_org_user_models_patch_accepts_name(self, name: str, expected: str | None) -> None:
        assert _patch(name=name).name == (expected or name)

    @pytest.mark.parametrize(
        "name",
        [
            pytest.param("", id="empty"),
            pytest.param("   \t ", id="whitespace-only"),
            pytest.param("a" * 121, id="121-chars"),
            pytest.param(" " + "a" * 121 + " ", id="121-after-strip"),
            pytest.param("Gr" + chr(0) + "ace", id="nul"),
            pytest.param("Gr" + chr(0x1B) + "ace", id="escape"),
            pytest.param("Gr\nace", id="newline"),
            pytest.param("Grace\r\nBcc: x@example.ch", id="header-injection"),
            pytest.param("Gr\tace", id="tab"),
            pytest.param("Gr" + chr(0x7F) + "ace", id="del"),
            pytest.param("Gr" + chr(0x85) + "ace", id="c1-next-line"),
            pytest.param("Gr" + chr(0x200B) + "ace", id="zero-width-space"),
            pytest.param("Gr" + chr(0x200D) + "ace", id="zero-width-joiner"),
            pytest.param("Gr" + chr(0x202E) + "ace", id="rtl-override"),
            pytest.param("Gr" + chr(0x2066) + "ace", id="ltr-isolate"),
            pytest.param("Gr" + chr(0xFEFF) + "ace", id="bom"),
            pytest.param("Gr" + chr(0xAD) + "ace", id="soft-hyphen"),
            pytest.param("Gr" + chr(0xD800) + "ace", id="lone-surrogate"),
            pytest.param("Gr" + chr(0x2028) + "ace", id="line-separator"),
            pytest.param("Gr" + chr(0x2029) + "ace", id="paragraph-separator"),
            pytest.param(123, id="int"),
            pytest.param(["Grace"], id="list"),
        ],
    )
    def test_org_user_models_patch_rejects_name(self, name: Any) -> None:
        with pytest.raises(ValidationError):
            _patch(name=name)


# ---------------------------------------------------------------------------
# 6. OrgUserPatch.email: InvitationCreateRequest's rules
# ---------------------------------------------------------------------------

_REJECTED_EMAILS: list[Any] = [
    pytest.param("", id="empty"),
    pytest.param("   ", id="whitespace-only"),
    pytest.param("a@b", id="no-dot-3-chars"),
    pytest.param("no-at-sign.example.ch", id="no-at"),
    pytest.param("@example.ch", id="empty-local-part"),
    pytest.param("a@b@example.ch", id="two-ats"),
    pytest.param("a@examplech", id="no-dot-in-domain"),
    pytest.param("a@.examplech", id="only-dot-first-in-domain"),
    pytest.param("a@examplech.", id="only-dot-last-in-domain"),
    pytest.param("a@", id="empty-domain"),
    pytest.param("new person@example.ch", id="space-inside"),
    pytest.param("new.person@exa\tmple.ch", id="tab-inside"),
    pytest.param("new.person@example.ch\nBcc: x@example.ch", id="newline-inside"),
    pytest.param("a" + chr(0) + "b@example.ch", id="nul"),
    pytest.param("a" + chr(0x7F) + "b@example.ch", id="del"),
    pytest.param("a" + chr(0xA0) + "b@example.ch", id="nbsp"),
    pytest.param("a" + chr(0x200B) + "b@example.ch", id="zero-width-space"),
    pytest.param("a" + chr(0x202E) + "b@example.ch", id="rtl-override"),
    pytest.param(chr(0xFEFF) + "ab@example.ch", id="bom"),
    pytest.param("a" + chr(0x2028) + "b@example.ch", id="line-separator"),
    pytest.param("a" + chr(0x2029) + "b@example.ch", id="paragraph-separator"),
    pytest.param("a" + chr(0xD800) + "b@example.ch", id="lone-surrogate"),
    pytest.param("a" + _LONGEST_EMAIL, id="255-chars"),
    pytest.param(123, id="int"),
    pytest.param(["a@example.ch"], id="list"),
]


class TestOrgUserPatchEmail:
    """The new sign-in email follows the invitation rules exactly."""

    @pytest.mark.parametrize(
        ("email", "expected"),
        [
            pytest.param("ada@example.ch", "ada@example.ch", id="plain"),
            pytest.param("Ada.Lovelace@Example.CH", "Ada.Lovelace@Example.CH", id="case-kept"),
            pytest.param("x@y.z", "x@y.z", id="short"),
            pytest.param("first.last+tag@sub.example.co.uk", None, id="plus-and-subdomains"),
            pytest.param("  padded@example.ch\t", "padded@example.ch", id="stripped"),
            pytest.param(_LONGEST_EMAIL, None, id="254-chars"),
        ],
    )
    def test_org_user_models_patch_accepts_email(self, email: str, expected: str | None) -> None:
        assert _patch(email=email).email == (expected or email)

    @pytest.mark.parametrize("email", _REJECTED_EMAILS)
    def test_org_user_models_patch_rejects_email(self, email: Any) -> None:
        with pytest.raises(ValidationError):
            _patch(email=email)

    @pytest.mark.parametrize("email", _REJECTED_EMAILS)
    def test_org_user_models_patch_bad_email_rejects_even_with_a_role(self, email: Any) -> None:
        """A valid role next to it doesn't rescue a bad email (no partial patch)."""
        with pytest.raises(ValidationError):
            _patch(role="viewer", email=email)

    @pytest.mark.parametrize(
        "email",
        [
            "a@b@example.ch",
            "a@examplech",
            "a" + chr(0x200B) + "b@example.ch",
            "x@y.z",
            " Mixed.Case@Example.ch ",
            "a@.examplech",
            "new person@example.ch",
            "a" + _LONGEST_EMAIL,
            _LONGEST_EMAIL,
        ],
    )
    def test_org_user_models_patch_email_matches_invitation_rules(self, email: str) -> None:
        """Same verdict, and the same stored value, as InvitationCreateRequest.email."""
        from admino.models import InvitationCreateRequest

        invitation = _accepted(lambda: InvitationCreateRequest(email=email, role="viewer"))
        patch = _accepted(lambda: _patch(email=email))

        assert patch == invitation
        if invitation:
            expected = InvitationCreateRequest(email=email, role="viewer").email
            assert _patch(email=email).email == expected


# ---------------------------------------------------------------------------
# 7. OrgUserPatch: errors never repeat the input
# ---------------------------------------------------------------------------


class TestOrgUserPatchErrorsHideInput:
    """Neither str(ValidationError) nor its error list (without input) repeats a value."""

    @pytest.mark.parametrize(
        ("values", "markers"),
        [
            pytest.param(
                {"name": "Quetzalcoatl" + chr(0x202E) + "Hopper"},
                ["Quetzalcoatl", "Hopper"],
                id="name-invisible-char",
            ),
            pytest.param(
                {"name": "Xylophonist\nBcc: eve@evil.example"},
                ["Xylophonist", "eve@evil"],
                id="name-newline",
            ),
            pytest.param({"name": "Marmalade" * 14}, ["Marmalade"], id="name-too-long"),
            pytest.param({"email": "zanzibar-marker@exa mple.ch"}, ["zanzibar"], id="email-space"),
            pytest.param({"email": "quokka-marker@examplech"}, ["quokka"], id="email-no-dot"),
            pytest.param({"email": "wombat@two@example.ch"}, ["wombat"], id="email-two-ats"),
            pytest.param(
                {"email": "capybara" + chr(0x200B) + "@example.ch"},
                ["capybara"],
                id="email-zero-width",
            ),
            pytest.param({"role": "superuser-marker"}, ["superuser-marker"], id="role"),
            pytest.param(
                {"role": "viewer", "status": "marker-value-8472"},
                ["marker-value-8472"],
                id="extra-key",
            ),
            pytest.param(
                {"role": "viewer", "password": "hunter2-marker"},
                ["hunter2-marker"],
                id="extra-password",
            ),
        ],
    )
    def test_org_user_models_patch_error_hides_input(
        self, values: dict[str, Any], markers: list[str]
    ) -> None:
        with pytest.raises(ValidationError) as exc_info:
            _patch(**values)

        text = str(exc_info.value)
        details = json.dumps(
            exc_info.value.errors(include_input=False, include_url=False), default=str
        )
        for marker in markers:
            assert marker not in text, text
            assert marker not in details, details
