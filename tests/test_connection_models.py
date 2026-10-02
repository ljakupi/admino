"""Tests for the per-user connection models in admino.models (GH-162).

Each user connects their own Google and Microsoft accounts; the Tools page
("my connections") shows per provider whether the caller is connected and
which of the provider's services the org has switched on. An org's data
residency policy switches the Google and Microsoft tools off.

What these tests pin down:
- ``PROVIDER_TOOLS``: a read-only mapping (assignment, insertion and deletion
  raise ``TypeError``) of exactly ``google`` -> ``("gmail", "google_calendar",
  "google_drive")`` and ``microsoft`` -> ``("outlook", "outlook_calendar",
  "onedrive")``, in that order; its keys are the ``OAuthProvider`` literal and
  every tool is a ``ToolsSettings`` field.
- ``RESIDENCY_BLOCKED_TOOLS``: a frozenset of exactly those six tools (the
  union of ``PROVIDER_TOOLS``); ``memory`` is not in it and is the only
  ``ToolsSettings`` field left out.
- ``ConnectorTool`` is the Literal of the six tool names.
- ``OAuthServiceStatus``: exactly ``tool`` (one of the six, anything else
  refused) and ``enabled`` (bool), both required.
- ``OAuthConnectionStatus``: exactly ``connected``, ``healthy``, ``email``,
  ``data_residency`` (new, default False) and ``services`` (now a list of
  ``OAuthServiceStatus``, default a fresh empty list; the old list-of-names
  shape is refused). ``connected`` / ``healthy`` / ``email`` keep their
  defaults and the email validation (pattern, 254 characters, None allowed).
- ``OrgSettingsResponse`` requires ``data_residency`` (bool) next to ``tools``.

New symbols are looked up per test, so a missing name fails its own tests and
not the whole module.

Security notes:
- ``PROVIDER_TOOLS`` and ``RESIDENCY_BLOCKED_TOOLS`` drive residency gating;
  they are immutable so no code path can widen or empty them at runtime.
- ``memory`` stays outside the residency set: it never leaves the server.
- ``OAuthServiceStatus.tool`` is a closed Literal, so a status body can only
  ever name one of the six connector tools.
"""

from __future__ import annotations

import typing
from collections.abc import Mapping
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

import admino.models as models_module
from admino import oauth as oauth_mod
from admino.models import ToolsSettings

_GOOGLE_TOOLS = ("gmail", "google_calendar", "google_drive")
_MICROSOFT_TOOLS = ("outlook", "outlook_calendar", "onedrive")
_CONNECTOR_TOOLS = _GOOGLE_TOOLS + _MICROSOFT_TOOLS
_STATUS_FIELDS = frozenset({"connected", "healthy", "email", "data_residency", "services"})
_BAD_TOOLS: tuple[object, ...] = (
    "memory",
    "files",
    "documents",
    "search",
    "google",
    "microsoft",
    "GMAIL",
    "Gmail",
    "gmail ",
    " gmail",
    "gmail" + chr(0x0A),
    "gmail.read",
    "google-calendar",
    "",
    None,
    1,
    ["gmail"],
)
_VALID_EMAIL = "someone@example.com"


def _attr(name: str) -> Any:
    return getattr(models_module, name)


def _model(name: str) -> type[BaseModel]:
    model = getattr(models_module, name)
    assert isinstance(model, type)
    assert issubclass(model, BaseModel)
    return model


def _service(tool: str = "gmail", *, enabled: bool = True) -> dict[str, object]:
    return {"tool": tool, "enabled": enabled}


def _error_locs(error: pytest.ExceptionInfo[ValidationError]) -> set[tuple[int | str, ...]]:
    return {tuple(item["loc"]) for item in error.value.errors()}


# ---------------------------------------------------------------------------
# 1. PROVIDER_TOOLS
# ---------------------------------------------------------------------------


class TestProviderTools:
    """The OAuth provider -> its three tools, read-only."""

    def test_models_provider_tools_maps_each_provider_to_its_tools(self) -> None:
        assert dict(_attr("PROVIDER_TOOLS")) == {
            "google": _GOOGLE_TOOLS,
            "microsoft": _MICROSOFT_TOOLS,
        }

    @pytest.mark.parametrize(
        ("provider", "tools"), [("google", _GOOGLE_TOOLS), ("microsoft", _MICROSOFT_TOOLS)]
    )
    def test_models_provider_tools_values_are_ordered_tuples(
        self, provider: str, tools: tuple[str, ...]
    ) -> None:
        """A tuple in the contract order (the status lists services in this order)."""
        value = _attr("PROVIDER_TOOLS")[provider]

        assert isinstance(value, tuple)
        assert value == tools

    def test_models_provider_tools_is_a_mapping(self) -> None:
        assert isinstance(_attr("PROVIDER_TOOLS"), Mapping)

    def test_models_provider_tools_keys_are_the_oauth_providers(self) -> None:
        assert set(_attr("PROVIDER_TOOLS")) == set(typing.get_args(oauth_mod.OAuthProvider))

    def test_models_provider_tools_assignment_raises_type_error(self) -> None:
        mapping = _attr("PROVIDER_TOOLS")

        with pytest.raises(TypeError):
            mapping["google"] = ("gmail",)

        assert mapping["google"] == _GOOGLE_TOOLS

    def test_models_provider_tools_insertion_raises_type_error(self) -> None:
        mapping = _attr("PROVIDER_TOOLS")

        with pytest.raises(TypeError):
            mapping["github"] = ("repos",)

        assert "github" not in mapping

    def test_models_provider_tools_deletion_raises_type_error(self) -> None:
        mapping = _attr("PROVIDER_TOOLS")

        with pytest.raises(TypeError):
            del mapping["microsoft"]

        assert mapping["microsoft"] == _MICROSOFT_TOOLS

    def test_models_provider_tools_tools_are_tools_settings_fields(self) -> None:
        tools = {tool for value in _attr("PROVIDER_TOOLS").values() for tool in value}

        assert tools == set(_CONNECTOR_TOOLS)
        assert tools <= set(ToolsSettings.model_fields)


# ---------------------------------------------------------------------------
# 2. RESIDENCY_BLOCKED_TOOLS and ConnectorTool
# ---------------------------------------------------------------------------


class TestResidencyBlockedTools:
    """The tools an org's data residency policy switches off."""

    def test_models_residency_blocked_tools_is_exactly_the_six_connector_tools(self) -> None:
        blocked = _attr("RESIDENCY_BLOCKED_TOOLS")

        assert isinstance(blocked, frozenset)
        assert blocked == frozenset(_CONNECTOR_TOOLS)

    def test_models_residency_blocked_tools_excludes_memory(self) -> None:
        assert "memory" not in _attr("RESIDENCY_BLOCKED_TOOLS")

    def test_models_residency_blocked_tools_is_the_union_of_provider_tools(self) -> None:
        union = {tool for value in _attr("PROVIDER_TOOLS").values() for tool in value}

        assert union == _attr("RESIDENCY_BLOCKED_TOOLS")

    def test_models_residency_blocked_tools_names_are_tools_settings_fields(self) -> None:
        """Every blocked name is a service switch; memory is the only one left on."""
        blocked = _attr("RESIDENCY_BLOCKED_TOOLS")
        fields = set(ToolsSettings.model_fields)

        assert blocked <= fields
        assert fields - blocked == {"memory"}

    def test_models_connector_tool_literal_is_the_six_tools(self) -> None:
        assert typing.get_args(_attr("ConnectorTool")) == _CONNECTOR_TOOLS


# ---------------------------------------------------------------------------
# 3. OAuthServiceStatus
# ---------------------------------------------------------------------------


class TestOAuthServiceStatus:
    """One service of a provider and the org's switch for it."""

    def test_models_oauth_service_status_has_exactly_tool_and_enabled(self) -> None:
        assert set(_model("OAuthServiceStatus").model_fields) == {"tool", "enabled"}

    def test_models_oauth_service_status_enabled_is_bool(self) -> None:
        assert _model("OAuthServiceStatus").model_fields["enabled"].annotation is bool

    @pytest.mark.parametrize("tool", _CONNECTOR_TOOLS)
    @pytest.mark.parametrize("enabled", [True, False])
    def test_models_oauth_service_status_accepts_each_connector_tool(
        self, tool: str, enabled: bool
    ) -> None:
        status = _model("OAuthServiceStatus").model_validate(_service(tool, enabled=enabled))

        assert status.model_dump() == {"tool": tool, "enabled": enabled}

    @pytest.mark.parametrize("tool", _BAD_TOOLS, ids=[repr(t)[:30] for t in _BAD_TOOLS])
    def test_models_oauth_service_status_rejects_unknown_tool(self, tool: object) -> None:
        with pytest.raises(ValidationError) as error:
            _model("OAuthServiceStatus").model_validate({"tool": tool, "enabled": True})

        assert _error_locs(error) == {("tool",)}

    @pytest.mark.parametrize("missing", ["tool", "enabled"])
    def test_models_oauth_service_status_requires_both_fields(self, missing: str) -> None:
        body = _service()
        del body[missing]

        with pytest.raises(ValidationError) as error:
            _model("OAuthServiceStatus").model_validate(body)

        assert _error_locs(error) == {(missing,)}

    @pytest.mark.parametrize("enabled", [None, "not-a-bool", [True], {"on": True}])
    def test_models_oauth_service_status_rejects_non_bool_enabled(self, enabled: object) -> None:
        with pytest.raises(ValidationError) as error:
            _model("OAuthServiceStatus").model_validate({"tool": "gmail", "enabled": enabled})

        assert _error_locs(error) == {("enabled",)}


# ---------------------------------------------------------------------------
# 4. OAuthConnectionStatus
# ---------------------------------------------------------------------------


class TestOAuthConnectionStatus:
    """The caller's connection to a provider, its residency flag and its services."""

    def test_models_oauth_connection_status_has_exactly_the_contract_fields(self) -> None:
        assert set(_model("OAuthConnectionStatus").model_fields) == _STATUS_FIELDS

    def test_models_oauth_connection_status_field_types(self) -> None:
        fields = _model("OAuthConnectionStatus").model_fields

        assert fields["connected"].annotation is bool
        assert fields["healthy"].annotation is bool
        assert fields["data_residency"].annotation is bool
        assert fields["services"].annotation == list[_model("OAuthServiceStatus")]

    def test_models_oauth_connection_status_defaults(self) -> None:
        """Not connected, not healthy, no email, residency off, no services."""
        first = _model("OAuthConnectionStatus")()
        first.services.append(_model("OAuthServiceStatus")(tool="gmail", enabled=True))
        second = _model("OAuthConnectionStatus")()

        assert second.model_dump() == {
            "connected": False,
            "healthy": False,
            "email": None,
            "data_residency": False,
            "services": [],
        }

    def test_models_oauth_connection_status_data_residency_round_trips(self) -> None:
        status = _model("OAuthConnectionStatus")(data_residency=True)

        assert status.data_residency is True
        assert status.model_dump()["data_residency"] is True

    def test_models_oauth_connection_status_services_are_service_statuses(self) -> None:
        services = [
            _service(tool, enabled=index % 2 == 0) for index, tool in enumerate(_GOOGLE_TOOLS)
        ]

        status = _model("OAuthConnectionStatus").model_validate(
            {"connected": True, "healthy": True, "services": services}
        )

        assert all(isinstance(item, _model("OAuthServiceStatus")) for item in status.services)
        assert status.model_dump()["services"] == services

    def test_models_oauth_connection_status_full_dump(self) -> None:
        """The JSON shape the Tools page reads."""
        status = _model("OAuthConnectionStatus").model_validate(
            {
                "connected": True,
                "healthy": False,
                "email": _VALID_EMAIL,
                "data_residency": True,
                "services": [_service(tool, enabled=False) for tool in _MICROSOFT_TOOLS],
            }
        )

        assert status.model_dump(mode="json") == {
            "connected": True,
            "healthy": False,
            "email": _VALID_EMAIL,
            "data_residency": True,
            "services": [{"tool": tool, "enabled": False} for tool in _MICROSOFT_TOOLS],
        }

    def test_models_oauth_connection_status_rejects_the_old_list_of_names(self) -> None:
        """services was a list of tool names; it is now a list of objects."""
        with pytest.raises(ValidationError) as error:
            _model("OAuthConnectionStatus").model_validate({"services": ["gmail"]})

        assert {loc[0] for loc in _error_locs(error)} == {"services"}
        assert _model("OAuthConnectionStatus").model_fields["services"].annotation != list[str]

    def test_models_oauth_connection_status_rejects_an_unknown_service_tool(self) -> None:
        with pytest.raises(ValidationError) as error:
            _model("OAuthConnectionStatus").model_validate(
                {"services": [_service("gmail"), _service("memory")]}
            )

        assert _error_locs(error) == {("services", 1, "tool")}

    @pytest.mark.parametrize(
        "email",
        ["not-an-email", "a b@example.com", "@example.com", "someone@", "x@" + "a" * 250 + ".ch"],
        ids=["no-at", "space", "no-local", "no-domain", "too-long"],
    )
    def test_models_oauth_connection_status_email_validation_unchanged(self, email: str) -> None:
        """Only the email is refused, next to otherwise valid new fields."""
        body = {
            "connected": True,
            "healthy": True,
            "email": email,
            "data_residency": False,
            "services": [_service(tool) for tool in _GOOGLE_TOOLS],
        }

        with pytest.raises(ValidationError) as error:
            _model("OAuthConnectionStatus").model_validate(body)

        assert _error_locs(error) == {("email",)}

    @pytest.mark.parametrize("email", [_VALID_EMAIL, None, "a@b.ch"])
    def test_models_oauth_connection_status_accepts_valid_or_missing_email(
        self, email: str | None
    ) -> None:
        status = _model("OAuthConnectionStatus").model_validate(
            {"email": email, "data_residency": True, "services": [_service("onedrive")]}
        )

        assert status.email == email
        assert status.data_residency is True


# ---------------------------------------------------------------------------
# 5. OrgSettingsResponse
# ---------------------------------------------------------------------------


class TestOrgSettingsResponseResidency:
    """The org settings response carries the org's residency policy, read-only."""

    def test_models_org_settings_response_requires_data_residency(self) -> None:
        with pytest.raises(ValidationError) as error:
            _model("OrgSettingsResponse").model_validate({"tools": ToolsSettings().model_dump()})

        assert _error_locs(error) == {("data_residency",)}
        assert {item["type"] for item in error.value.errors()} == {"missing"}

    def test_models_org_settings_response_data_residency_is_bool(self) -> None:
        assert _model("OrgSettingsResponse").model_fields["data_residency"].annotation is bool

    @pytest.mark.parametrize("residency", [True, False])
    def test_models_org_settings_response_dumps_data_residency(self, residency: bool) -> None:
        body = _model("OrgSettingsResponse")(tools=ToolsSettings(), data_residency=residency)

        assert body.model_dump() == {
            "tools": ToolsSettings().model_dump(),
            "data_residency": residency,
        }

    def test_models_org_settings_patch_has_no_residency_key(self) -> None:
        """The policy is the Super Admin's (PATCH /api/platform/orgs/{id}/residency);
        an Org Admin's settings patch can't carry it, and the response now does."""
        with pytest.raises(ValidationError):
            _model("OrgSettingsPatch").model_validate(
                {"tools": {"gmail": False}, "data_residency": False}
            )

        assert "data_residency" in _model("OrgSettingsResponse").model_fields
