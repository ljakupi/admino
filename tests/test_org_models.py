"""Tests for the organization API models in admino.models (GH-154, GH-161).

The Super Admin's org routes (``/api/platform/orgs``) and the ``create-org``
CLI validate their input through these models; the responses carry org
metadata only. The models are new, so each test looks them up on
``admino.models`` at call time and fails on its own until they exist.

What these tests pin down:
- ``OrgCreateRequest`` (unknown fields refused, input hidden from errors):
  ``name`` stripped, 1 to 120 characters, no control (Cc), format (Cf, e.g.
  zero-width and direction overrides), surrogate (Cs) or line/paragraph
  separator (Zl, Zp) characters (the invitation email subject rule);
  ``primary_admin_email`` with exactly ``InvitationCreateRequest.email``'s
  rules; ``seats`` a strict int 1..100000; ``monthly_budget_chf`` a Decimal
  >= 0 that fits NUMERIC(12,2) (a JSON number or a numeric string; NaN,
  Infinity and booleans refused); ``storage_quota`` a strict int of bytes,
  0..2**53-1; ``status`` "active" (default) or "deactivated".
- ``OrgLimitsPatch``: the three limits, each optional with the same bounds;
  at least one non-null.
- ``OrgResidencyPatch``: ``enabled`` a strict bool.
- ``OrgSummary`` has exactly the listed JSON keys (no content), serializes the
  budget as a decimal string; ``OrgListResponse`` and ``OrgCreateResponse``
  wrap it (the create response holds an ``InvitationSummary``: no token, no
  link).
- GH-161 (tool permissions per org): ``ToolPolicy`` is frozen (assigning a
  field raises) and holds one org's ``PermissionsConfig``, its promoted
  (tool, action) pairs (a frozenset, empty by default) and its enabled tool
  switches (empty by default); ``permissions`` is required.
  ``CriticalPermissionPromote`` is the re-auth body of a promotion:
  ``password`` a ``SecretStr`` of 1 to 128 characters, unknown fields refused
  (the old ``bearer_token`` too), never shown by ``repr()``/``str()``/JSON,
  and never echoed by a validation error. ``PermissionSummaryEntry`` (``tool``
  and ``action`` with the permission engine's identifier pattern, ``state``
  one of allow / confirm / deny / disabled) and
  ``PermissionsSummaryResponse`` (``permissions``: a list of them) carry the
  read-only summary and nothing else.

Security notes:
- Validation errors never contain the rejected input (``hide_input_in_errors``
  plus fixed messages): an org name or admin email must not land in a log or
  a 422 body.
- The org name reaches an email Subject header: control, separator and
  invisible characters are refused, not stripped.
- Strict ints and bools: "10", 10.0 or true never pass as seats, and "true"
  or 1 never pass as a residency switch.
- The re-auth password can't leak through a repr, a log line or a 422 body,
  and a run's ToolPolicy can't be changed after it was loaded (one run never
  sees another org's policy through a shared, mutated object).
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any, get_args

import pytest
from asyncpg.pgproto.pgproto import UUID as PgUUID  # noqa: N811
from pydantic import SecretStr, ValidationError

from admino.permissions import PermissionsConfig, validate_permissions_config

_MAX_STORAGE = 2**53 - 1
_LONGEST_EMAIL = "a" * (254 - len("@example.ch")) + "@example.ch"

_VALID_CREATE: dict[str, Any] = {
    "name": "Acme AG",
    "primary_admin_email": "ada@example.ch",
    "seats": 10,
    "monthly_budget_chf": "100.00",
    "storage_quota": 10 * 1024**3,
}

_SUMMARY_KEYS = frozenset(
    {
        "id",
        "name",
        "status",
        "seats",
        "monthly_budget_chf",
        "storage_quota",
        "data_residency",
        "deletion_requested_at",
        "purge_after",
        "created_at",
        "updated_at",
    }
)


def _model(name: str) -> Any:
    """Look a model up on admino.models at call time (it is new in GH-154)."""
    from admino import models

    model = getattr(models, name, None)
    assert model is not None, f"admino.models must define {name}"
    return model


def _create(**overrides: Any) -> Any:
    return _model("OrgCreateRequest").model_validate({**_VALID_CREATE, **overrides})


def _summary_data(**overrides: Any) -> dict[str, Any]:
    now = datetime(2026, 9, 28, 12, 0, tzinfo=UTC)
    return {
        "id": uuid.uuid4(),
        "name": "Acme AG",
        "status": "active",
        "seats": 10,
        "monthly_budget_chf": Decimal("100.00"),
        "storage_quota": 10 * 1024**3,
        "data_residency": True,
        "deletion_requested_at": None,
        "purge_after": None,
        "created_at": now,
        "updated_at": now,
        **overrides,
    }


# Shared bounds (OrgCreateRequest and OrgLimitsPatch).
_VALID_SEATS = [pytest.param(1, id="1"), pytest.param(10, id="10"), pytest.param(100000, id="max")]
_INVALID_SEATS = [
    pytest.param(0, id="0"),
    pytest.param(-1, id="negative"),
    pytest.param(100001, id="over-max"),
    pytest.param("10", id="numeric-string"),
    pytest.param(True, id="bool"),
    pytest.param(10.0, id="float-integral"),
    pytest.param(Decimal(10), id="decimal"),
    pytest.param("ten", id="text"),
    pytest.param([10], id="list"),
]
_VALID_BUDGETS = [
    pytest.param("99.50", Decimal("99.50"), id="string-2-decimals"),
    pytest.param(100, Decimal(100), id="int"),
    pytest.param(0, Decimal(0), id="zero"),
    pytest.param("0.00", Decimal(0), id="zero-string"),
    pytest.param(99.5, Decimal("99.5"), id="float"),
    pytest.param(Decimal("12.3"), Decimal("12.3"), id="decimal"),
    pytest.param("9999999999.99", Decimal("9999999999.99"), id="12-digits"),
]
_INVALID_BUDGETS = [
    pytest.param("-0.01", id="negative-cent"),
    pytest.param(-1, id="negative"),
    pytest.param("1.001", id="3-decimals"),
    pytest.param("0.005", id="half-cent"),
    pytest.param("1234567890123", id="13-digits"),
    pytest.param("12345678901.23", id="13-digits-with-decimals"),
    pytest.param("NaN", id="nan-string"),
    pytest.param(float("nan"), id="nan"),
    pytest.param("Infinity", id="infinity-string"),
    pytest.param(float("inf"), id="infinity"),
    pytest.param("-Infinity", id="minus-infinity"),
    pytest.param(True, id="true"),
    pytest.param(False, id="false"),
    pytest.param("", id="empty"),
    pytest.param("abc", id="text"),
    pytest.param([100], id="list"),
]
_VALID_STORAGE = [
    pytest.param(0, id="0"),
    pytest.param(1, id="1"),
    pytest.param(10 * 1024**3, id="10-gib"),
    pytest.param(_MAX_STORAGE, id="max-safe-integer"),
]
_INVALID_STORAGE = [
    pytest.param(-1, id="negative"),
    pytest.param(2**53, id="over-max-safe-integer"),
    pytest.param("1024", id="numeric-string"),
    pytest.param(True, id="bool"),
    pytest.param(1024.0, id="float-integral"),
    pytest.param(Decimal(1024), id="decimal"),
]


# ---------------------------------------------------------------------------
# 1. OrgCreateRequest: shape and config
# ---------------------------------------------------------------------------


class TestOrgCreateRequestShape:
    """The fields, the defaults and the config."""

    def test_org_models_create_request_has_exactly_the_listed_fields(self) -> None:
        assert set(_model("OrgCreateRequest").model_fields) == {
            "name",
            "primary_admin_email",
            "seats",
            "monthly_budget_chf",
            "storage_quota",
            "status",
        }

    def test_org_models_create_request_forbids_extra_and_hides_input(self) -> None:
        config = _model("OrgCreateRequest").model_config

        assert config.get("extra") == "forbid"
        assert config.get("hide_input_in_errors") is True

    def test_org_models_create_request_valid_payload_builds(self) -> None:
        request = _create()

        assert request.name == "Acme AG"
        assert request.primary_admin_email == "ada@example.ch"
        assert request.seats == 10
        assert request.monthly_budget_chf == Decimal("100.00")
        assert request.storage_quota == 10 * 1024**3

    def test_org_models_create_request_status_defaults_to_active(self) -> None:
        assert _create().status == "active"

    @pytest.mark.parametrize(
        "missing",
        ["name", "primary_admin_email", "seats", "monthly_budget_chf", "storage_quota"],
    )
    def test_org_models_create_request_requires_field(self, missing: str) -> None:
        data = {key: value for key, value in _VALID_CREATE.items() if key != missing}

        with pytest.raises(ValidationError):
            _model("OrgCreateRequest").model_validate(data)

    @pytest.mark.parametrize(
        "extra",
        [
            pytest.param({"id": str(uuid.uuid4())}, id="id"),
            pytest.param({"org_id": str(uuid.uuid4())}, id="org_id"),
            pytest.param({"data_residency": False}, id="data_residency"),
            pytest.param({"language": "fr"}, id="language"),
            pytest.param({"purge_after": "2026-10-28T00:00:00Z"}, id="purge_after"),
            pytest.param({"role": "editor"}, id="role"),
            pytest.param({"storage_quota_bytes": 1}, id="db-column-name"),
        ],
    )
    def test_org_models_create_request_refuses_unknown_fields(self, extra: dict[str, Any]) -> None:
        """Residency keeps its default, the language comes from the session: nothing else
        is chosen by the body."""
        with pytest.raises(ValidationError):
            _create(**extra)


# ---------------------------------------------------------------------------
# 2. OrgCreateRequest.name
# ---------------------------------------------------------------------------


class TestOrgCreateRequestName:
    """Stripped, 1 to 120 characters, no Cc/Cf/Cs/Zl/Zp characters."""

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            pytest.param("Acme AG", "Acme AG", id="plain"),
            pytest.param("  Acme AG \t", "Acme AG", id="stripped"),
            pytest.param("Zoë Müller & Łukasiewicz SA", None, id="unicode"),
            pytest.param("X", None, id="one-char"),
            pytest.param("a" * 120, None, id="120-chars"),
            pytest.param("  " + "a" * 120 + "\n", "a" * 120, id="120-after-strip"),
        ],
    )
    def test_org_models_create_request_accepts_name(self, name: str, expected: str | None) -> None:
        assert _create(name=name).name == (expected or name)

    @pytest.mark.parametrize(
        "name",
        [
            pytest.param("", id="empty"),
            pytest.param("   \t ", id="whitespace-only"),
            pytest.param("a" * 121, id="121-chars"),
            pytest.param(" " + "a" * 121 + " ", id="121-after-strip"),
            pytest.param("Ac" + chr(0) + "me", id="nul"),
            pytest.param("Ac" + chr(0x1B) + "me", id="escape"),
            pytest.param("Ac\nme", id="newline"),
            pytest.param("Acme\r\nBcc: x@example.ch", id="header-injection"),
            pytest.param("Ac\tme", id="tab"),
            pytest.param("Ac" + chr(0x7F) + "me", id="del"),
            pytest.param("Ac" + chr(0x85) + "me", id="c1-next-line"),
            pytest.param("Ac" + chr(0x200B) + "me", id="zero-width-space"),
            pytest.param("Ac" + chr(0x200D) + "me", id="zero-width-joiner"),
            pytest.param("Ac" + chr(0x202E) + "me", id="rtl-override"),
            pytest.param("Ac" + chr(0x2066) + "me", id="ltr-isolate"),
            pytest.param("Ac" + chr(0xFEFF) + "me", id="bom"),
            pytest.param("Ac" + chr(0xAD) + "me", id="soft-hyphen"),
            pytest.param("Ac" + chr(0xD800) + "me", id="lone-surrogate"),
            pytest.param("Ac" + chr(0x2028) + "me", id="line-separator"),
            pytest.param("Ac" + chr(0x2029) + "me", id="paragraph-separator"),
            pytest.param(123, id="int"),
            pytest.param(None, id="none"),
            pytest.param(["Acme"], id="list"),
        ],
    )
    def test_org_models_create_request_rejects_name(self, name: Any) -> None:
        with pytest.raises(ValidationError):
            _create(name=name)


# ---------------------------------------------------------------------------
# 3. OrgCreateRequest.primary_admin_email: InvitationCreateRequest's rules
# ---------------------------------------------------------------------------


class TestOrgCreateRequestEmail:
    """The first Org Admin's email follows the invitation rules exactly."""

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
    def test_org_models_create_request_accepts_email(
        self, email: str, expected: str | None
    ) -> None:
        assert _create(primary_admin_email=email).primary_admin_email == (expected or email)

    @pytest.mark.parametrize(
        "email",
        [
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
            pytest.param(None, id="none"),
            pytest.param(["a@example.ch"], id="list"),
        ],
    )
    def test_org_models_create_request_rejects_email(self, email: Any) -> None:
        with pytest.raises(ValidationError):
            _create(primary_admin_email=email)

    @pytest.mark.parametrize(
        "email",
        ["a@b@example.ch", "a@examplech", "a" + chr(0x200B) + "b@example.ch", "x@y.z"],
    )
    def test_org_models_create_request_email_matches_invitation_rules(self, email: str) -> None:
        """Same verdict as InvitationCreateRequest.email for the same input."""
        from admino.models import InvitationCreateRequest

        def accepted(build: Any) -> bool:
            try:
                build()
            except ValidationError:
                return False
            return True

        invitation = accepted(lambda: InvitationCreateRequest(email=email, role="org_admin"))
        org = accepted(lambda: _create(primary_admin_email=email))

        assert org == invitation


# ---------------------------------------------------------------------------
# 4. OrgCreateRequest: seats, budget, storage, status
# ---------------------------------------------------------------------------


class TestOrgCreateRequestLimits:
    """The plan limits and the starting status."""

    @pytest.mark.parametrize("seats", _VALID_SEATS)
    def test_org_models_create_request_accepts_seats(self, seats: int) -> None:
        request = _create(seats=seats)

        assert request.seats == seats
        assert type(request.seats) is int

    @pytest.mark.parametrize("seats", _INVALID_SEATS)
    def test_org_models_create_request_rejects_seats(self, seats: Any) -> None:
        with pytest.raises(ValidationError):
            _create(seats=seats)

    @pytest.mark.parametrize(("budget", "expected"), _VALID_BUDGETS)
    def test_org_models_create_request_accepts_budget(self, budget: Any, expected: Decimal) -> None:
        request = _create(monthly_budget_chf=budget)

        assert isinstance(request.monthly_budget_chf, Decimal)
        assert request.monthly_budget_chf == expected

    @pytest.mark.parametrize("budget", _INVALID_BUDGETS)
    def test_org_models_create_request_rejects_budget(self, budget: Any) -> None:
        with pytest.raises(ValidationError):
            _create(monthly_budget_chf=budget)

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            pytest.param("99.5", Decimal("99.5"), id="json-number"),
            pytest.param('"99.50"', Decimal("99.50"), id="json-string"),
            pytest.param("0", Decimal(0), id="json-zero"),
        ],
    )
    def test_org_models_create_request_budget_from_json(self, raw: str, expected: Decimal) -> None:
        """The API receives JSON: a number or a numeric string."""
        body = json.dumps({**_VALID_CREATE, "monthly_budget_chf": "__BUDGET__"})
        request = _model("OrgCreateRequest").model_validate_json(body.replace('"__BUDGET__"', raw))

        assert request.monthly_budget_chf == expected

    @pytest.mark.parametrize(
        "raw",
        [
            pytest.param("true", id="json-true"),
            pytest.param("NaN", id="json-nan"),
            pytest.param("Infinity", id="json-infinity"),
            pytest.param('"NaN"', id="json-nan-string"),
            pytest.param("-5", id="json-negative"),
            pytest.param("null", id="json-null"),
        ],
    )
    def test_org_models_create_request_budget_from_json_refused(self, raw: str) -> None:
        body = json.dumps({**_VALID_CREATE, "monthly_budget_chf": "__BUDGET__"})

        with pytest.raises(ValidationError):
            _model("OrgCreateRequest").model_validate_json(body.replace('"__BUDGET__"', raw))

    @pytest.mark.parametrize(
        "raw",
        [
            pytest.param('{"seats": "10"}', id="seats-string"),
            pytest.param('{"seats": 10.0}', id="seats-float"),
            pytest.param('{"seats": true}', id="seats-bool"),
            pytest.param('{"storage_quota": "1024"}', id="storage-string"),
            pytest.param('{"storage_quota": 1024.0}', id="storage-float"),
        ],
    )
    def test_org_models_create_request_strict_ints_from_json(self, raw: str) -> None:
        body = {**_VALID_CREATE, **json.loads(raw)}

        with pytest.raises(ValidationError):
            _model("OrgCreateRequest").model_validate_json(json.dumps(body))

    @pytest.mark.parametrize("storage", _VALID_STORAGE)
    def test_org_models_create_request_accepts_storage_quota(self, storage: int) -> None:
        request = _create(storage_quota=storage)

        assert request.storage_quota == storage
        assert type(request.storage_quota) is int

    @pytest.mark.parametrize("storage", _INVALID_STORAGE)
    def test_org_models_create_request_rejects_storage_quota(self, storage: Any) -> None:
        with pytest.raises(ValidationError):
            _create(storage_quota=storage)

    @pytest.mark.parametrize("status", ["active", "deactivated"])
    def test_org_models_create_request_accepts_status(self, status: str) -> None:
        assert _create(status=status).status == status

    @pytest.mark.parametrize(
        "status", ["pending_deletion", "Active", "ACTIVE", "", "deleted", "suspended", None, 1]
    )
    def test_org_models_create_request_rejects_status(self, status: Any) -> None:
        """An org can't be created already pending deletion."""
        with pytest.raises(ValidationError):
            _create(status=status)


# ---------------------------------------------------------------------------
# 5. OrgCreateRequest: errors never repeat the input
# ---------------------------------------------------------------------------


class TestOrgCreateRequestErrorsHideInput:
    """str(ValidationError) never contains the rejected value."""

    @pytest.mark.parametrize(
        ("overrides", "markers"),
        [
            pytest.param(
                {"name": "Quetzalcoatl" + chr(0x202E) + "Industries"},
                ["Quetzalcoatl", "Industries"],
                id="name-invisible-char",
            ),
            pytest.param({"name": "Xylophonist" * 12}, ["Xylophonist"], id="name-too-long"),
            pytest.param(
                {"primary_admin_email": "zanzibar-marker@exa mple.ch"},
                ["zanzibar"],
                id="email-space",
            ),
            pytest.param(
                {"primary_admin_email": "quokka-marker@examplech"}, ["quokka"], id="email-no-dot"
            ),
            pytest.param({"seats": 7777777}, ["7777777"], id="seats-too-many"),
            pytest.param({"seats": "4242"}, ["4242"], id="seats-string"),
            pytest.param({"monthly_budget_chf": "-31337.5"}, ["31337"], id="budget-negative"),
            pytest.param({"monthly_budget_chf": "271828.183"}, ["271828"], id="budget-3-decimals"),
            pytest.param({"storage_quota": 2**60}, [str(2**60)], id="storage-too-big"),
            pytest.param({"status": "exfiltrated"}, ["exfiltrated"], id="status"),
            pytest.param({"org_id": "marker-value-8472"}, ["marker-value-8472"], id="extra-key"),
        ],
    )
    def test_org_models_create_request_error_hides_input(
        self, overrides: dict[str, Any], markers: list[str]
    ) -> None:
        with pytest.raises(ValidationError) as exc_info:
            _create(**overrides)

        text = str(exc_info.value)
        assert all(marker not in text for marker in markers), text


# ---------------------------------------------------------------------------
# 6. OrgLimitsPatch
# ---------------------------------------------------------------------------


def _patch(**values: Any) -> Any:
    return _model("OrgLimitsPatch").model_validate(values)


class TestOrgLimitsPatch:
    """Any of the three limits; at least one non-null; the same bounds as on create."""

    def test_org_models_limits_patch_has_exactly_the_three_limits(self) -> None:
        assert set(_model("OrgLimitsPatch").model_fields) == {
            "seats",
            "monthly_budget_chf",
            "storage_quota",
        }

    def test_org_models_limits_patch_forbids_extra_and_hides_input(self) -> None:
        config = _model("OrgLimitsPatch").model_config

        assert config.get("extra") == "forbid"
        assert config.get("hide_input_in_errors") is True

    @pytest.mark.parametrize(
        ("values", "expected"),
        [
            pytest.param({"seats": 5}, (5, None, None), id="seats"),
            pytest.param(
                {"monthly_budget_chf": "250.25"}, (None, Decimal("250.25"), None), id="budget"
            ),
            pytest.param({"storage_quota": 0}, (None, None, 0), id="storage-zero"),
            pytest.param(
                {"seats": 1, "monthly_budget_chf": 0, "storage_quota": _MAX_STORAGE},
                (1, Decimal(0), _MAX_STORAGE),
                id="all-three",
            ),
            pytest.param(
                {"seats": None, "storage_quota": 5}, (None, None, 5), id="null-is-not-given"
            ),
        ],
    )
    def test_org_models_limits_patch_accepts(
        self, values: dict[str, Any], expected: tuple[Any, Any, Any]
    ) -> None:
        patch = _patch(**values)

        assert (patch.seats, patch.monthly_budget_chf, patch.storage_quota) == expected

    @pytest.mark.parametrize(
        "values",
        [
            pytest.param({}, id="empty"),
            pytest.param({"seats": None}, id="one-null"),
            pytest.param(
                {"seats": None, "monthly_budget_chf": None, "storage_quota": None}, id="all-null"
            ),
        ],
    )
    def test_org_models_limits_patch_needs_at_least_one_limit(self, values: dict[str, Any]) -> None:
        with pytest.raises(ValidationError):
            _patch(**values)

    def test_org_models_limits_patch_empty_json_refused(self) -> None:
        with pytest.raises(ValidationError):
            _model("OrgLimitsPatch").model_validate_json("{}")

    @pytest.mark.parametrize("seats", _INVALID_SEATS)
    def test_org_models_limits_patch_rejects_seats(self, seats: Any) -> None:
        with pytest.raises(ValidationError):
            _patch(seats=seats)

    @pytest.mark.parametrize("budget", _INVALID_BUDGETS)
    def test_org_models_limits_patch_rejects_budget(self, budget: Any) -> None:
        with pytest.raises(ValidationError):
            _patch(monthly_budget_chf=budget)

    @pytest.mark.parametrize("storage", _INVALID_STORAGE)
    def test_org_models_limits_patch_rejects_storage_quota(self, storage: Any) -> None:
        with pytest.raises(ValidationError):
            _patch(storage_quota=storage)

    @pytest.mark.parametrize(
        "extra",
        [
            pytest.param({"name": "Renamed AG"}, id="name"),
            pytest.param({"status": "active"}, id="status"),
            pytest.param({"data_residency": False}, id="data_residency"),
            pytest.param({"primary_admin_email": "a@example.ch"}, id="email"),
            pytest.param({"purge_after": None}, id="purge_after"),
        ],
    )
    def test_org_models_limits_patch_refuses_unknown_fields(self, extra: dict[str, Any]) -> None:
        with pytest.raises(ValidationError):
            _patch(seats=5, **extra)

    @pytest.mark.parametrize(
        ("values", "marker"),
        [
            pytest.param({"seats": 8888888}, "8888888", id="seats"),
            pytest.param({"monthly_budget_chf": "-16180.3"}, "16180", id="budget"),
            pytest.param({"storage_quota": 2**61}, str(2**61), id="storage"),
            pytest.param({"seats": 5, "name": "Marmoset Holdings"}, "Marmoset", id="extra"),
        ],
    )
    def test_org_models_limits_patch_error_hides_input(
        self, values: dict[str, Any], marker: str
    ) -> None:
        with pytest.raises(ValidationError) as exc_info:
            _patch(**values)

        assert marker not in str(exc_info.value)


# ---------------------------------------------------------------------------
# 7. OrgResidencyPatch
# ---------------------------------------------------------------------------


class TestOrgResidencyPatch:
    """{"enabled": <bool>} and nothing else."""

    def test_org_models_residency_patch_has_only_enabled(self) -> None:
        assert set(_model("OrgResidencyPatch").model_fields) == {"enabled"}

    def test_org_models_residency_patch_forbids_extra_and_hides_input(self) -> None:
        config = _model("OrgResidencyPatch").model_config

        assert config.get("extra") == "forbid"
        assert config.get("hide_input_in_errors") is True

    @pytest.mark.parametrize(
        ("values", "marker"),
        [
            pytest.param({"enabled": "Quokka-7741"}, "Quokka", id="enabled"),
            pytest.param({"enabled": True, "org_name": "Wombat Holdings"}, "Wombat", id="extra"),
        ],
    )
    def test_org_models_residency_patch_error_hides_input(
        self, values: dict[str, Any], marker: str
    ) -> None:
        with pytest.raises(ValidationError) as exc_info:
            _model("OrgResidencyPatch").model_validate(values)

        assert marker not in str(exc_info.value)

    @pytest.mark.parametrize("enabled", [True, False])
    def test_org_models_residency_patch_accepts_bool(self, enabled: bool) -> None:
        patch = _model("OrgResidencyPatch").model_validate({"enabled": enabled})

        assert patch.enabled is enabled

    @pytest.mark.parametrize(
        "enabled", ["true", "false", "yes", "on", 1, 0, 1.0, None, [True], {"value": True}]
    )
    def test_org_models_residency_patch_rejects_non_bool(self, enabled: Any) -> None:
        with pytest.raises(ValidationError):
            _model("OrgResidencyPatch").model_validate({"enabled": enabled})

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [('{"enabled": true}', True), ('{"enabled": false}', False)],
    )
    def test_org_models_residency_patch_from_json(self, raw: str, expected: bool) -> None:
        assert _model("OrgResidencyPatch").model_validate_json(raw).enabled is expected

    @pytest.mark.parametrize(
        "raw", ['{"enabled": "true"}', '{"enabled": 1}', '{"enabled": null}', "{}"]
    )
    def test_org_models_residency_patch_from_json_refused(self, raw: str) -> None:
        with pytest.raises(ValidationError):
            _model("OrgResidencyPatch").model_validate_json(raw)

    def test_org_models_residency_patch_refuses_unknown_fields(self) -> None:
        with pytest.raises(ValidationError):
            _model("OrgResidencyPatch").model_validate(
                {"enabled": True, "org_id": str(uuid.uuid4())}
            )


# ---------------------------------------------------------------------------
# 8. OrgSummary, OrgListResponse, OrgCreateResponse
# ---------------------------------------------------------------------------


class TestOrgSummary:
    """Org metadata only, with exactly the listed JSON keys."""

    def test_org_models_summary_has_exactly_the_listed_fields(self) -> None:
        assert set(_model("OrgSummary").model_fields) == _SUMMARY_KEYS

    def test_org_models_summary_json_has_exactly_the_listed_keys(self) -> None:
        summary = _model("OrgSummary").model_validate(_summary_data())

        assert set(summary.model_dump(mode="json")) == _SUMMARY_KEYS
        assert set(json.loads(summary.model_dump_json())) == _SUMMARY_KEYS

    @pytest.mark.parametrize(
        ("budget", "expected"),
        [
            pytest.param(Decimal("100.00"), Decimal("100.00"), id="two-decimals"),
            pytest.param(Decimal(100), Decimal(100), id="integral"),
            pytest.param(Decimal("0.05"), Decimal("0.05"), id="cents"),
        ],
    )
    def test_org_models_summary_serializes_budget_as_decimal_string(
        self, budget: Decimal, expected: Decimal
    ) -> None:
        """A JSON string, never a float: 0.1 + 0.2 rounding stays out of money."""
        summary = _model("OrgSummary").model_validate(_summary_data(monthly_budget_chf=budget))
        dumped = json.loads(summary.model_dump_json())["monthly_budget_chf"]

        assert isinstance(dumped, str)
        assert Decimal(dumped) == expected

    @pytest.mark.parametrize("status", ["active", "deactivated", "pending_deletion"])
    def test_org_models_summary_accepts_every_status(self, status: str) -> None:
        purge = datetime(2026, 10, 28, tzinfo=UTC)
        dates = (
            {"deletion_requested_at": purge - timedelta(days=30), "purge_after": purge}
            if status == "pending_deletion"
            else {}
        )
        summary = _model("OrgSummary").model_validate(_summary_data(status=status, **dates))

        assert summary.status == status

    @pytest.mark.parametrize("status", ["deleted", "purged", "Active", ""])
    def test_org_models_summary_rejects_unknown_status(self, status: str) -> None:
        with pytest.raises(ValidationError):
            _model("OrgSummary").model_validate(_summary_data(status=status))

    def test_org_models_summary_deletion_dates_serialize(self) -> None:
        """null while not pending; ISO timestamps once scheduled."""
        purge = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)
        pending = _model("OrgSummary").model_validate(
            _summary_data(
                status="pending_deletion",
                deletion_requested_at=purge - timedelta(days=30),
                purge_after=purge,
            )
        )
        active = json.loads(_model("OrgSummary").model_validate(_summary_data()).model_dump_json())
        scheduled = json.loads(pending.model_dump_json())

        assert active["deletion_requested_at"] is None
        assert active["purge_after"] is None
        assert datetime.fromisoformat(scheduled["purge_after"]) == purge
        assert datetime.fromisoformat(scheduled["deletion_requested_at"]) == purge - timedelta(
            days=30
        )

    def test_org_models_summary_builds_from_an_asyncpg_row(self) -> None:
        """A row's asyncpg UUID and Decimal come through; ints and bools keep their type."""
        raw = uuid.uuid4()
        summary = _model("OrgSummary").model_validate(_summary_data(id=PgUUID(str(raw))))
        dumped = json.loads(summary.model_dump_json())

        assert summary.id == raw
        assert dumped["id"] == str(raw)
        assert dumped["seats"] == 10
        assert dumped["storage_quota"] == 10 * 1024**3
        assert dumped["data_residency"] is True


def _invitation() -> Any:
    from admino.models import InvitationSummary

    now = datetime.now(UTC)
    return InvitationSummary(
        id=uuid.uuid4(),
        email="ada@example.ch",
        role="org_admin",
        sent_at=now,
        expires_at=now + timedelta(hours=72),
        expired=False,
    )


class TestOrgResponses:
    """The list and create responses wrap OrgSummary; no token, no link."""

    def test_org_models_list_response_has_only_organizations(self) -> None:
        assert set(_model("OrgListResponse").model_fields) == {"organizations"}

    def test_org_models_list_response_holds_summaries(self) -> None:
        summaries = [_model("OrgSummary").model_validate(_summary_data()) for _ in range(2)]
        response = _model("OrgListResponse")(organizations=summaries)
        dumped = json.loads(response.model_dump_json())

        assert [set(item) for item in dumped["organizations"]] == [_SUMMARY_KEYS] * 2

    def test_org_models_create_response_has_organization_and_invitation(self) -> None:
        from admino.models import InvitationSummary

        fields = _model("OrgCreateResponse").model_fields

        assert set(fields) == {"organization", "invitation"}
        assert fields["organization"].annotation is _model("OrgSummary")
        assert fields["invitation"].annotation is InvitationSummary

    def test_org_models_create_response_json_carries_no_token_or_link(self) -> None:
        """The invitation part is the InvitationSummary: id, email, role, dates, expired."""
        response = _model("OrgCreateResponse")(
            organization=_model("OrgSummary").model_validate(_summary_data()),
            invitation=_invitation(),
        )
        dumped = json.loads(response.model_dump_json())

        assert set(dumped) == {"organization", "invitation"}
        assert set(dumped["organization"]) == _SUMMARY_KEYS
        assert set(dumped["invitation"]) == {
            "id",
            "email",
            "role",
            "sent_at",
            "expires_at",
            "expired",
        }
        assert "token" not in response.model_dump_json()
        assert "accept-invitation" not in response.model_dump_json()


# ---------------------------------------------------------------------------
# 9. GH-161: ToolPolicy (one org's permissions for one agent run)
# ---------------------------------------------------------------------------

_POLICY_FIELDS = frozenset({"permissions", "promoted", "enabled_tools", "data_residency"})
_NEWLINE = chr(0x0A)
_PASSWORD = "Correct-Horse-Battery-Staple-42"
_PASSWORD_MARKER = "Pw-Marker-7f3a9c"


def _org_permissions() -> PermissionsConfig:
    return validate_permissions_config(
        {"gmail": {"read": "allow", "send": "deny"}, "memory": {"store": "allow"}}
    )


def _policy(**overrides: Any) -> Any:
    return _model("ToolPolicy")(**{"permissions": _org_permissions(), **overrides})


class TestToolPolicy:
    """ToolPolicy: frozen, holds a PermissionsConfig, promoted pairs and tool switches."""

    def test_org_models_tool_policy_has_exactly_the_contract_fields(self) -> None:
        assert set(_model("ToolPolicy").model_fields) == _POLICY_FIELDS

    def test_org_models_tool_policy_holds_the_permissions_config(self) -> None:
        config = _org_permissions()

        policy = _model("ToolPolicy")(permissions=config)

        assert isinstance(policy.permissions, PermissionsConfig)
        assert policy.permissions == config
        assert policy.permissions.tools["gmail"].actions["send"] == "deny"

    def test_org_models_tool_policy_defaults_to_nothing_promoted_or_switched(self) -> None:
        policy = _policy()

        assert policy.promoted == frozenset()
        assert type(policy.promoted) is frozenset
        assert policy.enabled_tools == {}

    @pytest.mark.parametrize(
        "overrides",
        [
            pytest.param({}, id="missing"),
            pytest.param({"permissions": None}, id="none"),
            pytest.param({"permissions": "allow everything"}, id="text"),
        ],
    )
    def test_org_models_tool_policy_requires_a_permissions_config(
        self, overrides: dict[str, Any]
    ) -> None:
        with pytest.raises(ValidationError):
            _model("ToolPolicy")(**overrides)

    def test_org_models_tool_policy_keeps_promoted_pairs_as_a_frozenset(self) -> None:
        promoted = {("gmail", "send"), ("outlook", "send")}

        policy = _policy(promoted=promoted)

        assert policy.promoted == frozenset(promoted)
        assert type(policy.promoted) is frozenset

    def test_org_models_tool_policy_keeps_the_enabled_tool_switches(self) -> None:
        switches = {"gmail": False, "memory": True}

        assert _policy(enabled_tools=switches).enabled_tools == switches

    def test_org_models_tool_policy_is_configured_frozen(self) -> None:
        assert _model("ToolPolicy").model_config.get("frozen") is True

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            pytest.param("permissions", PermissionsConfig(), id="permissions"),
            pytest.param("promoted", frozenset({("gmail", "send")}), id="promoted"),
            pytest.param("enabled_tools", {"gmail": False}, id="enabled_tools"),
        ],
    )
    def test_org_models_tool_policy_assignment_raises(self, field: str, value: object) -> None:
        """A loaded policy can't be changed: assigning any field raises, nothing changes."""
        policy = _policy()
        before = getattr(policy, field)

        with pytest.raises(ValidationError):
            setattr(policy, field, value)

        assert getattr(policy, field) == before


# ---------------------------------------------------------------------------
# 10. GH-161: CriticalPermissionPromote (the promotion's re-auth body)
# ---------------------------------------------------------------------------


def _promote(data: object) -> Any:
    return _model("CriticalPermissionPromote").model_validate(data)


def _error_summary(exc: ValidationError) -> list[tuple[tuple[int | str, ...], str]]:
    return [
        (tuple(error["loc"]), error["type"])
        for error in exc.errors(include_input=False, include_url=False)
    ]


class TestCriticalPermissionPromote:
    """The password a promotion re-authenticates with: a bounded SecretStr, never shown."""

    def test_org_models_promote_has_exactly_the_password_field(self) -> None:
        assert set(_model("CriticalPermissionPromote").model_fields) == {"password"}

    def test_org_models_promote_config_forbids_extra_and_hides_input(self) -> None:
        config = _model("CriticalPermissionPromote").model_config

        assert config.get("extra") == "forbid"
        assert config.get("hide_input_in_errors") is True

    def test_org_models_promote_password_is_a_secret_str(self) -> None:
        body = _promote({"password": _PASSWORD})

        assert isinstance(body.password, SecretStr)
        assert body.password.get_secret_value() == _PASSWORD

    @pytest.mark.parametrize("length", [1, 128], ids=["1", "128"])
    def test_org_models_promote_password_length_bounds_are_accepted(self, length: int) -> None:
        assert len(_promote({"password": "p" * length}).password.get_secret_value()) == length

    @pytest.mark.parametrize(
        ("password", "error_type"),
        [
            pytest.param("", "too_short", id="empty"),
            pytest.param("p" * 129, "too_long", id="129"),
            pytest.param("p" * 4096, "too_long", id="4096"),
        ],
    )
    def test_org_models_promote_password_out_of_bounds_is_refused(
        self, password: str, error_type: str
    ) -> None:
        """The length bound is the refusal (SecretStr reports too_short / too_long)."""
        with pytest.raises(ValidationError) as caught:
            _promote({"password": password})

        [(loc, kind)] = _error_summary(caught.value)
        assert loc == ("password",)
        assert kind in {error_type, f"string_{error_type}"}

    @pytest.mark.parametrize(
        "data",
        [
            pytest.param({}, id="missing"),
            pytest.param({"password": None}, id="none"),
            pytest.param({"password": 12345678}, id="int"),
            pytest.param({"password": ["hunter2"]}, id="list"),
            pytest.param({"password": {"value": "hunter2"}}, id="object"),
        ],
    )
    def test_org_models_promote_password_must_be_a_string(self, data: dict[str, Any]) -> None:
        with pytest.raises(ValidationError) as caught:
            _promote(data)

        assert [loc for loc, _ in _error_summary(caught.value)] == [("password",)]

    @pytest.mark.parametrize("extra", ["bearer_token", "tool", "confirm", "Password"])
    def test_org_models_promote_unknown_field_is_refused(self, extra: str) -> None:
        """Only the password: the old bearer_token (or anything else) is refused."""
        with pytest.raises(ValidationError) as caught:
            _promote({"password": _PASSWORD, extra: "x"})

        assert _error_summary(caught.value) == [((extra,), "extra_forbidden")]

    def test_org_models_promote_repr_and_str_never_show_the_password(self) -> None:
        body = _promote({"password": _PASSWORD})

        assert _PASSWORD not in repr(body)
        assert _PASSWORD not in str(body)
        assert _PASSWORD not in repr(body.password)
        assert _PASSWORD not in body.model_dump_json()

    @pytest.mark.parametrize(
        "data",
        [
            pytest.param({"password": _PASSWORD_MARKER + "x" * 200}, id="too-long"),
            pytest.param({"password": _PASSWORD, "note": _PASSWORD_MARKER}, id="extra-field"),
            pytest.param({"password": [_PASSWORD_MARKER]}, id="wrong-type"),
        ],
    )
    def test_org_models_promote_validation_error_never_echoes_the_input(
        self, data: dict[str, Any]
    ) -> None:
        """A 422 or a log line built from the error carries none of the submitted text."""
        with pytest.raises(ValidationError) as caught:
            _promote(data)

        assert _PASSWORD_MARKER not in str(caught.value)
        assert _PASSWORD_MARKER not in repr(caught.value)
        assert _PASSWORD not in str(caught.value)


# ---------------------------------------------------------------------------
# 11. GH-161: PermissionSummaryEntry and PermissionsSummaryResponse
# ---------------------------------------------------------------------------

_SUMMARY_STATES = ("allow", "confirm", "deny", "disabled")
_IDENTIFIER_CASES: list[Any] = [
    pytest.param("gmail", True, id="gmail"),
    pytest.param("google_calendar", True, id="snake"),
    pytest.param("a", True, id="one-char"),
    pytest.param("a" * 63, True, id="63-chars"),
    pytest.param("a" * 64, False, id="64-chars"),
    pytest.param("", False, id="empty"),
    pytest.param("Gmail", False, id="upper-case"),
    pytest.param("gmail" + _NEWLINE, False, id="trailing-newline"),
    pytest.param("gmail.send", False, id="dotted"),
    pytest.param("gmail send", False, id="space"),
    pytest.param("1gmail", False, id="leading-digit"),
    pytest.param("_gmail", False, id="leading-underscore"),
]


def _summary_entry(**overrides: Any) -> Any:
    data = {"tool": "gmail", "action": "send", "state": "deny", **overrides}
    return _model("PermissionSummaryEntry").model_validate(data)


class TestPermissionSummary:
    """The read-only summary rows: (tool, action) and the effective state, nothing else."""

    def test_org_models_summary_entry_has_exactly_tool_action_state(self) -> None:
        assert set(_model("PermissionSummaryEntry").model_fields) == {"tool", "action", "state"}

    def test_org_models_summary_entry_state_literal_includes_disabled(self) -> None:
        annotation = _model("PermissionSummaryEntry").model_fields["state"].annotation

        assert set(get_args(annotation)) == set(_SUMMARY_STATES)

    @pytest.mark.parametrize("state", _SUMMARY_STATES)
    def test_org_models_summary_entry_accepts_each_state(self, state: str) -> None:
        assert _summary_entry(state=state).state == state

    @pytest.mark.parametrize(
        "state", ["enabled", "Allow", "DISABLED", "disabled ", "", None, 1, True, "pending"]
    )
    def test_org_models_summary_entry_refuses_other_states(self, state: object) -> None:
        with pytest.raises(ValidationError) as caught:
            _summary_entry(state=state)

        assert [loc for loc, _ in _error_summary(caught.value)] == [("state",)]

    @pytest.mark.parametrize("field", ["tool", "action"])
    @pytest.mark.parametrize(("value", "accepted"), _IDENTIFIER_CASES)
    def test_org_models_summary_entry_identifier_pattern(
        self, field: str, value: str, accepted: bool
    ) -> None:
        """tool and action follow the permission engine's identifier rule, like
        PermissionEntry: ^[a-z][a-z0-9_]{0,62}$, no trailing newline."""
        _summary_entry()  # the defaults are valid: a refusal below is the field's own
        try:
            entry = _summary_entry(**{field: value})
        except ValidationError as exc:
            assert not accepted, f"{value!r} must be accepted"
            assert [loc for loc, _ in _error_summary(exc)] == [(field,)]
        else:
            assert accepted, f"{value!r} must be refused"
            assert getattr(entry, field) == value

    def test_org_models_summary_entry_json_has_exactly_the_three_keys(self) -> None:
        dumped = json.loads(_summary_entry(state="disabled").model_dump_json())

        assert dumped == {"tool": "gmail", "action": "send", "state": "disabled"}

    def test_org_models_summary_response_wraps_the_entries_in_order(self) -> None:
        rows = [
            {"tool": "gmail", "action": "read", "state": "allow"},
            {"tool": "gmail", "action": "send", "state": "confirm"},
            {"tool": "memory", "action": "store", "state": "disabled"},
        ]

        response = _model("PermissionsSummaryResponse").model_validate({"permissions": rows})

        assert json.loads(response.model_dump_json()) == {"permissions": rows}

    def test_org_models_summary_response_has_exactly_the_permissions_field(self) -> None:
        assert set(_model("PermissionsSummaryResponse").model_fields) == {"permissions"}

    def test_org_models_summary_response_accepts_an_empty_list(self) -> None:
        response = _model("PermissionsSummaryResponse").model_validate({"permissions": []})

        assert response.permissions == []

    @pytest.mark.parametrize(
        "data",
        [
            pytest.param({}, id="missing"),
            pytest.param({"permissions": None}, id="none"),
            pytest.param(
                {"permissions": [{"tool": "gmail", "action": "send", "state": "granted"}]},
                id="bad-state",
            ),
            pytest.param(
                {"permissions": [{"tool": "Gmail", "action": "send", "state": "deny"}]},
                id="bad-tool",
            ),
            pytest.param(
                {"permissions": [{"tool": "gmail", "action": "send"}]},
                id="entry-without-state",
            ),
        ],
    )
    def test_org_models_summary_response_refuses_invalid_data(self, data: dict[str, Any]) -> None:
        with pytest.raises(ValidationError):
            _model("PermissionsSummaryResponse").model_validate(data)
