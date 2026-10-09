"""Spec for GH-190's API and agent models in ``admino.models`` (contract C2, Amendment A1).

The new models are the contract in /api/openapi.json: the chat responses carry
``context_usage`` and ``context_notice``, the send refusals a per-file report,
and the two new attachment routes their request and list bodies. New names are
looked up per test (``_model``), so this file collects before they exist and
each test fails on its own.

What these tests pin down:
- ``ContextUsage`` ``{used >= 0, max >= 1, percent >= 0}`` (above 100 allowed),
  ``extra="forbid"``; its JSON and OpenAPI property names are exactly
  ``used``, ``max``, ``percent`` (``max`` is serialized as ``"max"``).
- ``ContextNotice`` ``{dropped_turns >= 1, dropped_messages >= 1}``, forbid.
- ``ContextReportItem`` ``{attachment_id: UUID, token_estimate >= 0,
  derived_bytes >= 0}`` names a file by id only (no filename field, a
  ``filename`` key refused); ``ContextReport`` (items, the two token and two
  byte figures, ``max_bytes >= 1``); ``ContextRefusal`` ``{detail, reason,
  report}`` with ``reason`` exactly ``context_overflow`` or
  ``attachment_bytes_exceeded``. All forbid unknown keys.
- ``AttachmentUpdateRequest`` ``{active: StrictBool}``: ``"true"``, ``1``,
  ``0``, ``1.0`` and null refused (Python and JSON), the key required, unknown
  keys refused, and a refusal never echoes the input.
- ``AttachmentListResponse`` ``{attachments: [AttachmentSummary] <= 100,
  next_cursor: str | None <= 200}``.
- ``AttachmentSummary`` gains ``active`` (required) and ``context_report``
  (``ContextReport | None``, default None); ``AttachmentContent`` gains
  ``token_estimate`` (>= 0, required since GH-294 Decision 9: every caller passes
  the stored estimate); ``ChatMessageView`` gains
  ``attachment_ids`` (UUIDs, default ``[]``, at most 50).
- ``ChatDetailResponse`` requires ``context_usage`` and has no ``context``
  field; ``ChatContext`` is gone from ``admino.models``.
- ``ChatResponse`` requires ``context_usage`` and has ``context_notice``
  (default None); ``AgentResult`` has ``context_notice`` (default None) and
  ``external_content`` (default False, Amendment A1).
- ``AgentConfig``: ``max_context_messages`` 0 to 200 (default 40, 0 now means
  no cap), ``max_input_tokens`` 1000 to 2000000 (200000),
  ``reserved_output_tokens`` 1 to 65536 (4096), ``context_margin_percent`` 0 to
  50 (10), ``max_tool_result_tokens`` 256 to 100000 (8000).
- ``PlatformLimits`` / ``PlatformLimitsPatch``: ``max_context_messages`` 0 to 200.

Security notes: the report names files by id, never by name (Decision 5); the
update request is a strict bool and nothing else, and its errors never repeat
the body (tracker #139 section 5).
"""

from __future__ import annotations

import json
from typing import Any, Final

import pytest
from pydantic import BaseModel, ValidationError

import admino.models as models_module
from admino.models import AgentConfig, AgentResult, ChatResponse, PlatformLimits

_UUID: Final = "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b"
_CHAT_UUID: Final = "0b8e7c6d-5a4f-4e3d-9c2b-1a0f9e8d7c6b"
_OTHER_UUID: Final = "3c2d1e0f-9a8b-4c7d-8e6f-5a4b3c2d1e0f"
_TIMESTAMP: Final = "2026-10-09T09:30:00+00:00"
_MARKER: Final = "ZZ-SENTINEL-190"
_MIB: Final = 1_048_576

_USAGE: Final = {"used": 5200, "max": 180_000, "percent": 2}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _model(name: str) -> type[BaseModel]:
    """A model from admino.models; fails the calling test when missing."""
    model = getattr(models_module, name, None)
    if model is None:
        pytest.fail(f"admino.models.{name} does not exist (GH-190)")
    assert isinstance(model, type)
    assert issubclass(model, BaseModel)
    return model


def _errors(exc: ValidationError) -> list[tuple[tuple[int | str, ...], str]]:
    return [
        (tuple(error["loc"]), error["type"])
        for error in exc.errors(include_url=False, include_input=False)
    ]


def _outcome(model: type[BaseModel], payload: object) -> str | list[tuple[int | str, ...]]:
    """``"accepted"`` or the error locations of validating ``payload``."""
    try:
        model.model_validate(payload)
    except ValidationError as exc:
        return [loc for loc, _ in _errors(exc)]
    return "accepted"


def _json_outcome(model: type[BaseModel], body: str) -> str | list[tuple[int | str, ...]]:
    try:
        model.model_validate_json(body)
    except ValidationError as exc:
        return [loc for loc, _ in _errors(exc)]
    return "accepted"


def _dumped(instance: BaseModel) -> Any:
    return json.loads(instance.model_dump_json())


def _report_item(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "attachment_id": _UUID,
        "token_estimate": 4195,
        "derived_bytes": 52_000,
    }
    payload.update(overrides)
    return payload


def _report(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "attachments": [_report_item(), _report_item(attachment_id=_OTHER_UUID, token_estimate=0)],
        "attachment_tokens": 4195,
        "available_tokens": 3000,
        "attachment_bytes": 104_000,
        "max_bytes": 64 * _MIB,
    }
    payload.update(overrides)
    return payload


def _summary(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": _UUID,
        "chat_id": _CHAT_UUID,
        "message_id": None,
        "filename": "Q3 report.pdf",
        "kind": "pdf",
        "size_bytes": 48213,
        "status": "ready",
        "failure_reason": None,
        "page_count": 12,
        "token_estimate": 4195,
        "active": True,
        "created_at": _TIMESTAMP,
    }
    payload.update(overrides)
    return payload


def _message_view(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": _UUID,
        "role": "user",
        "content": "Summarise the attached report.",
        "status": "complete",
        "created_at": _TIMESTAMP,
    }
    payload.update(overrides)
    return payload


def _detail(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": _CHAT_UUID,
        "title": "Quarterly report",
        "title_source": "user",
        "created_at": _TIMESTAMP,
        "last_activity_at": _TIMESTAMP,
        "messages": [_message_view()],
        "confirmation_status": "none",
        "context_usage": dict(_USAGE),
    }
    payload.update(overrides)
    return payload


def _chat_response(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "chat_id": _CHAT_UUID,
        "response": "Here is the summary.",
        "context_usage": dict(_USAGE),
    }
    payload.update(overrides)
    return payload


# ---------------------------------------------------------------------------
# 1. ContextUsage
# ---------------------------------------------------------------------------


class TestContextUsage:
    """{used, max, percent}: the chat as its next turn will start."""

    def test_context_models_usage_json_is_used_max_percent(self) -> None:
        usage = _model("ContextUsage").model_validate({"used": 5, "max": 10, "percent": 50})

        assert _dumped(usage) == {"used": 5, "max": 10, "percent": 50}

    def test_context_models_usage_bounds(self) -> None:
        model = _model("ContextUsage")

        def outcome(**overrides: int) -> str | list[tuple[int | str, ...]]:
            return _outcome(model, {"used": 0, "max": 1, "percent": 0, **overrides})

        outcomes = {
            "minimum": outcome(),
            "used-negative": outcome(used=-1),
            "max-zero": outcome(max=0),
            "percent-negative": outcome(percent=-1),
            "percent-above-100": outcome(used=150, max=100, percent=150),
        }

        assert outcomes == {
            "minimum": "accepted",
            "used-negative": [("used",)],
            "max-zero": [("max",)],
            "percent-negative": [("percent",)],
            "percent-above-100": "accepted",
        }

    def test_context_models_usage_refuses_unknown_keys(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            _model("ContextUsage").model_validate({**_USAGE, "budget": 1})

        assert _errors(exc_info.value) == [(("budget",), "extra_forbidden")]

    @pytest.mark.parametrize("mode", ["validation", "serialization"])
    def test_context_models_usage_openapi_properties_are_used_max_percent(self, mode: str) -> None:
        schema = _model("ContextUsage").model_json_schema(mode=mode)  # type: ignore[arg-type]

        assert sorted(schema["properties"]) == ["max", "percent", "used"]
        assert sorted(schema["required"]) == ["max", "percent", "used"]


# ---------------------------------------------------------------------------
# 2. ContextNotice
# ---------------------------------------------------------------------------


class TestContextNotice:
    """{dropped_turns, dropped_messages}: counts only, both at least 1."""

    def test_context_models_notice_json_and_bounds(self) -> None:
        model = _model("ContextNotice")
        notice = model.model_validate({"dropped_turns": 2, "dropped_messages": 7})
        outcomes = {
            "ones": _outcome(model, {"dropped_turns": 1, "dropped_messages": 1}),
            "no-turns": _outcome(model, {"dropped_turns": 0, "dropped_messages": 1}),
            "no-messages": _outcome(model, {"dropped_turns": 1, "dropped_messages": 0}),
            "extra": _outcome(model, {"dropped_turns": 1, "dropped_messages": 1, "chat_id": _UUID}),
        }

        assert _dumped(notice) == {"dropped_turns": 2, "dropped_messages": 7}
        assert outcomes == {
            "ones": "accepted",
            "no-turns": [("dropped_turns",)],
            "no-messages": [("dropped_messages",)],
            "extra": [("chat_id",)],
        }


# ---------------------------------------------------------------------------
# 3. The per-file report and the refusal body
# ---------------------------------------------------------------------------


class TestContextReport:
    """ContextReportItem, ContextReport and ContextRefusal (Decision 5)."""

    def test_context_models_report_item_names_a_file_by_id_only(self) -> None:
        model = _model("ContextReportItem")
        item = model.model_validate(_report_item())

        assert _dumped(item) == {
            "attachment_id": _UUID,
            "token_estimate": 4195,
            "derived_bytes": 52_000,
        }
        assert sorted(model.model_fields) == ["attachment_id", "derived_bytes", "token_estimate"]

    def test_context_models_report_item_bounds_and_unknown_keys(self) -> None:
        model = _model("ContextReportItem")
        outcomes = {
            "zeros": _outcome(model, _report_item(token_estimate=0, derived_bytes=0)),
            "tokens-negative": _outcome(model, _report_item(token_estimate=-1)),
            "bytes-negative": _outcome(model, _report_item(derived_bytes=-1)),
            "id-not-uuid": _outcome(model, _report_item(attachment_id="a1")),
            "filename": _outcome(model, _report_item(filename="Q3 report.pdf")),
        }

        assert outcomes == {
            "zeros": "accepted",
            "tokens-negative": [("token_estimate",)],
            "bytes-negative": [("derived_bytes",)],
            "id-not-uuid": [("attachment_id",)],
            "filename": [("filename",)],
        }

    def test_context_models_report_json_is_the_contract(self) -> None:
        report = _model("ContextReport").model_validate(_report())

        assert _dumped(report) == {
            "attachments": [
                {"attachment_id": _UUID, "token_estimate": 4195, "derived_bytes": 52_000},
                {"attachment_id": _OTHER_UUID, "token_estimate": 0, "derived_bytes": 52_000},
            ],
            "attachment_tokens": 4195,
            "available_tokens": 3000,
            "attachment_bytes": 104_000,
            "max_bytes": 64 * _MIB,
        }
        assert isinstance(report.attachments[0], _model("ContextReportItem"))  # type: ignore[attr-defined]

    def test_context_models_report_bounds_and_unknown_keys(self) -> None:
        model = _model("ContextReport")
        outcomes = {
            "zeros": _outcome(
                model,
                _report(
                    attachments=[],
                    attachment_tokens=0,
                    available_tokens=0,
                    attachment_bytes=0,
                    max_bytes=1,
                ),
            ),
            "tokens-negative": _outcome(model, _report(attachment_tokens=-1)),
            "available-negative": _outcome(model, _report(available_tokens=-1)),
            "bytes-negative": _outcome(model, _report(attachment_bytes=-1)),
            "max-bytes-zero": _outcome(model, _report(max_bytes=0)),
            "extra": _outcome(model, _report(org_id=_UUID)),
        }

        assert outcomes == {
            "zeros": "accepted",
            "tokens-negative": [("attachment_tokens",)],
            "available-negative": [("available_tokens",)],
            "bytes-negative": [("attachment_bytes",)],
            "max-bytes-zero": [("max_bytes",)],
            "extra": [("org_id",)],
        }

    def test_context_models_refusal_reason_is_one_of_the_two_codes(self) -> None:
        model = _model("ContextRefusal")

        def outcome(reason: str) -> str | list[tuple[int | str, ...]]:
            return _outcome(
                model, {"detail": "The chat's attachments", "reason": reason, "report": _report()}
            )

        reasons = (
            "context_overflow",
            "attachment_bytes_exceeded",
            "image_input_unsupported",
            "storage_unavailable",
            "",
        )
        outcomes = {reason: outcome(reason) for reason in reasons}

        assert outcomes == {
            "context_overflow": "accepted",
            "attachment_bytes_exceeded": "accepted",
            "image_input_unsupported": [("reason",)],
            "storage_unavailable": [("reason",)],
            "": [("reason",)],
        }

    def test_context_models_refusal_json_and_unknown_keys(self) -> None:
        model = _model("ContextRefusal")
        body = {
            "detail": "The chat's attachments don't fit the model's context",
            "reason": "context_overflow",
            "report": _report(),
        }
        refusal = model.model_validate(body)

        assert _dumped(refusal) == {**body, "report": _dumped(_model("ContextReport")(**_report()))}
        assert _outcome(model, {**body, "filenames": ["Q3 report.pdf"]}) == [("filenames",)]


# ---------------------------------------------------------------------------
# 4. AttachmentUpdateRequest
# ---------------------------------------------------------------------------


class TestAttachmentUpdateRequest:
    """PATCH /api/attachments/{id}: a strict bool and nothing else (Decision 10)."""

    def test_context_models_update_request_accepts_true_and_false(self) -> None:
        model = _model("AttachmentUpdateRequest")
        values = {
            "python-true": model.model_validate({"active": True}).active,  # type: ignore[attr-defined]
            "python-false": model.model_validate({"active": False}).active,  # type: ignore[attr-defined]
            "json-true": model.model_validate_json('{"active": true}').active,  # type: ignore[attr-defined]
            "json-false": model.model_validate_json('{"active": false}').active,  # type: ignore[attr-defined]
        }

        assert values == {
            "python-true": True,
            "python-false": False,
            "json-true": True,
            "json-false": False,
        }
        assert all(type(value) is bool for value in values.values())

    def test_context_models_update_request_refuses_anything_but_a_bool(self) -> None:
        model = _model("AttachmentUpdateRequest")
        python_values: dict[str, object] = {
            "string-true": "true",
            "string-false": "false",
            "one": 1,
            "zero": 0,
            "float": 1.0,
            "null": None,
        }
        json_bodies = {
            "json-string": '{"active": "true"}',
            "json-one": '{"active": 1}',
            "json-null": '{"active": null}',
        }

        outcomes = {
            **{label: _outcome(model, {"active": value}) for label, value in python_values.items()},
            **{label: _json_outcome(model, body) for label, body in json_bodies.items()},
        }

        assert outcomes == {label: [("active",)] for label in [*python_values, *json_bodies]}

    def test_context_models_update_request_requires_active_and_refuses_extra_keys(self) -> None:
        model = _model("AttachmentUpdateRequest")
        outcomes = {
            "empty": _outcome(model, {}),
            "org-id": _outcome(model, {"active": False, "org_id": _UUID}),
            "status": _outcome(model, {"active": True, "status": "ready"}),
        }

        assert sorted(model.model_fields) == ["active"]
        assert outcomes == {
            "empty": [("active",)],
            "org-id": [("org_id",)],
            "status": [("status",)],
        }

    def test_context_models_update_request_errors_never_echo_the_input(self) -> None:
        model = _model("AttachmentUpdateRequest")
        texts: list[str] = []
        for payload in ({"active": _MARKER}, {"active": True, "note": _MARKER}):
            with pytest.raises(ValidationError) as exc_info:
                model.model_validate(payload)
            errors = exc_info.value.errors(include_url=False, include_input=False)
            texts.append(str(exc_info.value) + json.dumps(errors, default=str))

        assert [_MARKER in text for text in texts] == [False, False]


# ---------------------------------------------------------------------------
# 5. AttachmentListResponse
# ---------------------------------------------------------------------------


class TestAttachmentListResponse:
    """GET /api/chats/{chat_id}/attachments: one page of the chat's attachments."""

    def test_context_models_list_response_json_is_the_contract(self) -> None:
        page = _model("AttachmentListResponse").model_validate({"attachments": [_summary()]})

        assert sorted(_dumped(page)) == ["attachments", "next_cursor"]
        assert page.next_cursor is None  # type: ignore[attr-defined]
        assert isinstance(page.attachments[0], _model("AttachmentSummary"))  # type: ignore[attr-defined]

    def test_context_models_list_response_bounds(self) -> None:
        model = _model("AttachmentListResponse")
        outcomes = {
            "100": _outcome(model, {"attachments": [_summary()] * 100}),
            "101": _outcome(model, {"attachments": [_summary()] * 101}),
            "cursor-200": _outcome(model, {"attachments": [], "next_cursor": "c" * 200}),
            "cursor-201": _outcome(model, {"attachments": [], "next_cursor": "c" * 201}),
        }

        assert outcomes == {
            "100": "accepted",
            "101": [("attachments",)],
            "cursor-200": "accepted",
            "cursor-201": [("next_cursor",)],
        }


# ---------------------------------------------------------------------------
# 6. The changed attachment models
# ---------------------------------------------------------------------------


class TestAttachmentSummaryContext:
    """AttachmentSummary.active and .context_report; AttachmentContent.token_estimate."""

    def test_context_models_summary_active_is_required(self) -> None:
        payload = _summary()
        del payload["active"]

        with pytest.raises(ValidationError) as exc_info:
            _model("AttachmentSummary").model_validate(payload)

        assert _errors(exc_info.value) == [(("active",), "missing")]

    def test_context_models_summary_json_carries_active_and_no_report_by_default(self) -> None:
        model = _model("AttachmentSummary")
        dumped = {
            active: {
                key: value
                for key, value in _dumped(model.model_validate(_summary(active=active))).items()
                if key in ("active", "context_report")
            }
            for active in (True, False)
        }

        assert dumped == {
            True: {"active": True, "context_report": None},
            False: {"active": False, "context_report": None},
        }

    def test_context_models_summary_of_an_overflowing_file_carries_its_report(self) -> None:
        summary = _model("AttachmentSummary").model_validate(
            _summary(status="failed", failure_reason="context_overflow", context_report=_report())
        )

        assert _dumped(summary)["context_report"] == _dumped(
            _model("ContextReport").model_validate(_report())
        )
        assert isinstance(summary.context_report, _model("ContextReport"))  # type: ignore[attr-defined]

    def test_context_models_attachment_content_token_estimate_is_required(self) -> None:
        """GH-294 Decision 9: no default, so every caller passes the stored estimate."""
        model = _model("AttachmentContent")
        base: dict[str, Any] = {
            "id": _UUID,
            "filename": "a.txt",
            "kind": "txt",
            "page_count": None,
            "parts": [],
        }
        with pytest.raises(ValidationError) as exc_info:
            model.model_validate(base)
        values = {
            "zero": getattr(
                model.model_validate({**base, "token_estimate": 0}), "token_estimate", None
            ),
            "given": getattr(
                model.model_validate({**base, "token_estimate": 4195}), "token_estimate", None
            ),
        }

        assert _errors(exc_info.value) == [(("token_estimate",), "missing")]
        assert values == {"zero": 0, "given": 4195}
        assert _outcome(model, {**base, "token_estimate": -1}) == [("token_estimate",)]


# ---------------------------------------------------------------------------
# 7. Chat messages and the chat detail
# ---------------------------------------------------------------------------


class TestChatModelsContext:
    """ChatMessageView.attachment_ids, ChatDetailResponse.context_usage, no ChatContext."""

    def test_context_models_message_view_attachment_ids_default_to_empty(self) -> None:
        view = _model("ChatMessageView").model_validate(_message_view())

        assert _dumped(view)["attachment_ids"] == []

    def test_context_models_message_view_attachment_ids_are_uuids_in_order(self) -> None:
        view = _model("ChatMessageView").model_validate(
            _message_view(attachment_ids=[_OTHER_UUID, _UUID])
        )

        assert _dumped(view)["attachment_ids"] == [_OTHER_UUID, _UUID]

    def test_context_models_message_view_attachment_ids_bounds(self) -> None:
        model = _model("ChatMessageView")
        outcomes = {
            "50": _outcome(model, _message_view(attachment_ids=[_UUID] * 50)),
            "51": _outcome(model, _message_view(attachment_ids=[_UUID] * 51)),
            "not-uuid": _outcome(model, _message_view(attachment_ids=["a1"])),
        }

        assert outcomes == {
            "50": "accepted",
            "51": [("attachment_ids",)],
            "not-uuid": [("attachment_ids", 0)],
        }

    def test_context_models_detail_requires_context_usage(self) -> None:
        payload = _detail()
        del payload["context_usage"]

        with pytest.raises(ValidationError) as exc_info:
            _model("ChatDetailResponse").model_validate(payload)

        assert _errors(exc_info.value) == [(("context_usage",), "missing")]

    def test_context_models_detail_json_has_context_usage_instead_of_context(self) -> None:
        model = _model("ChatDetailResponse")
        dumped = _dumped(model.model_validate(_detail()))

        assert dumped["context_usage"] == _USAGE
        assert "context" not in dumped
        assert "context" not in model.model_fields

    def test_context_models_chat_context_is_gone(self) -> None:
        assert not hasattr(models_module, "ChatContext")


# ---------------------------------------------------------------------------
# 8. ChatResponse and AgentResult
# ---------------------------------------------------------------------------


class TestChatResponseContext:
    """Every turn's response carries context_usage; context_notice when turns were dropped."""

    def test_context_models_chat_response_requires_context_usage(self) -> None:
        payload = _chat_response()
        del payload["context_usage"]

        with pytest.raises(ValidationError) as exc_info:
            ChatResponse.model_validate(payload)

        assert _errors(exc_info.value) == [(("context_usage",), "missing")]

    def test_context_models_chat_response_json_without_a_notice(self) -> None:
        dumped = _dumped(ChatResponse.model_validate(_chat_response()))

        assert {key: dumped.get(key, "missing") for key in ("context_usage", "context_notice")} == {
            "context_usage": _USAGE,
            "context_notice": None,
        }

    def test_context_models_chat_response_json_with_a_notice(self) -> None:
        notice = {"dropped_turns": 3, "dropped_messages": 11}
        dumped = _dumped(ChatResponse.model_validate(_chat_response(context_notice=notice)))

        assert dumped.get("context_notice") == notice

    def test_context_models_chat_response_refuses_a_zero_notice(self) -> None:
        payload = _chat_response(context_notice={"dropped_turns": 0, "dropped_messages": 1})

        assert _outcome(ChatResponse, payload) == [("context_notice", "dropped_turns")]

    def test_context_models_agent_result_context_fields_default(self) -> None:
        result = AgentResult(status="final", response="Done.")

        assert {
            "context_notice": getattr(result, "context_notice", "missing"),
            "external_content": getattr(result, "external_content", "missing"),
        } == {"context_notice": None, "external_content": False}

    def test_context_models_agent_result_carries_a_notice(self) -> None:
        result = AgentResult.model_validate(
            {
                "status": "final",
                "response": "Done.",
                "context_notice": {"dropped_turns": 1, "dropped_messages": 4},
                "external_content": True,
            }
        )

        notice = getattr(result, "context_notice", None)
        assert isinstance(notice, _model("ContextNotice"))
        assert notice.model_dump() == {"dropped_turns": 1, "dropped_messages": 4}
        assert getattr(result, "external_content", None) is True


# ---------------------------------------------------------------------------
# 9. AgentConfig and the platform limits
# ---------------------------------------------------------------------------

# field -> (default, low, high)
_AGENT_FIELDS: Final = {
    "max_context_messages": (40, 0, 200),
    "max_input_tokens": (200_000, 1000, 2_000_000),
    "reserved_output_tokens": (4096, 1, 65536),
    "context_margin_percent": (10, 0, 50),
    "max_tool_result_tokens": (8000, 256, 100_000),
}


@pytest.mark.parametrize("field", sorted(_AGENT_FIELDS))
def test_context_models_agent_config_budget_field_default_and_bounds(field: str) -> None:
    default, low, high = _AGENT_FIELDS[field]
    outcomes = {
        "default": getattr(AgentConfig(), field, "missing"),
        "low": _outcome(AgentConfig, {field: low}),
        "high": _outcome(AgentConfig, {field: high}),
        "below": _outcome(AgentConfig, {field: low - 1}),
        "above": _outcome(AgentConfig, {field: high + 1}),
    }

    assert outcomes == {
        "default": default,
        "low": "accepted",
        "high": "accepted",
        "below": [(field,)],
        "above": [(field,)],
    }


def test_context_models_platform_limits_max_context_messages_is_0_to_200() -> None:
    limits = {
        "max_tool_calls_per_message": 10,
        "max_pending_confirmations": 3,
        "confirmation_timeout_s": 300,
        "max_message_length": 4000,
    }
    patch_model = _model("PlatformLimitsPatch")
    outcomes = {
        value: (
            _outcome(PlatformLimits, {**limits, "max_context_messages": value}),
            _outcome(patch_model, {"max_context_messages": value}),
        )
        for value in (-1, 0, 200, 201)
    }

    refused = ([("max_context_messages",)], [("max_context_messages",)])
    assert outcomes == {
        -1: refused,
        0: ("accepted", "accepted"),
        200: ("accepted", "accepted"),
        201: refused,
    }
