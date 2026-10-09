"""Spec for GH-190's config keys in ``admino.config`` and the shipped config.yaml (contract C3).

Issue #190 Decisions 1, 6, 8 and 9: the budget's safety margin, the per-turn
attachment byte cap and the tool-result cap are config.yaml keys of a new
``context`` section, read at start (not platform settings);
``limits.max_context_messages`` becomes an optional secondary cap where 0
means no cap.

What these tests pin down:
- ``ContextConfig``: ``safety_margin_percent`` 0 to 50 (default 10),
  ``max_attachment_mb_per_turn`` 1 to 1024 (default 64),
  ``max_tool_result_tokens`` 256 to 100000 (default 8000): each bound accepted,
  one past it refused at the field.
- ``AppConfig.context`` defaults to ``ContextConfig()`` and parses a
  ``context`` section, from a dict and from a config.yaml file
  (``load_app_config``); an out-of-range value is refused at
  ``("context", <field>)``.
- ``LimitsConfig.max_context_messages``: default 0 (no cap), 0 to 200.
- The shipped ``config/config.yaml``: ``limits.max_context_messages`` is 0, and
  its ``context`` section (commented out, or set) lists exactly the three
  defaults.
"""

from __future__ import annotations

import re
import textwrap
from pathlib import Path
from typing import Any, Final

import pytest
import yaml
from pydantic import BaseModel, ValidationError

import admino.config as config_module
from admino.config import AppConfig, LimitsConfig, load_app_config

_SHIPPED_CONFIG: Final = Path(__file__).resolve().parent.parent / "config" / "config.yaml"
_DEFAULTS: Final = {
    "safety_margin_percent": 10,
    "max_attachment_mb_per_turn": 64,
    "max_tool_result_tokens": 8000,
}
# field -> (low, high)
_BOUNDS: Final = {
    "safety_margin_percent": (0, 50),
    "max_attachment_mb_per_turn": (1, 1024),
    "max_tool_result_tokens": (256, 100_000),
}


def _context_config() -> type[BaseModel]:
    model = getattr(config_module, "ContextConfig", None)
    if model is None:
        pytest.fail("admino.config.ContextConfig does not exist (GH-190)")
    assert isinstance(model, type)
    assert issubclass(model, BaseModel)
    return model


def _outcome(model: type[BaseModel], payload: dict[str, Any]) -> str | list[tuple[int | str, ...]]:
    try:
        model.model_validate(payload)
    except ValidationError as exc:
        return [tuple(error["loc"]) for error in exc.errors(include_url=False, include_input=False)]
    return "accepted"


# ---------------------------------------------------------------------------
# 1. ContextConfig
# ---------------------------------------------------------------------------


def test_context_config_defaults() -> None:
    assert _context_config()().model_dump() == _DEFAULTS


@pytest.mark.parametrize("field", sorted(_BOUNDS))
def test_context_config_bounds_are_inclusive(field: str) -> None:
    low, high = _BOUNDS[field]
    model = _context_config()
    outcomes = {
        "low": _outcome(model, {field: low}),
        "high": _outcome(model, {field: high}),
        "below": _outcome(model, {field: low - 1}),
        "above": _outcome(model, {field: high + 1}),
    }

    assert outcomes == {
        "low": "accepted",
        "high": "accepted",
        "below": [(field,)],
        "above": [(field,)],
    }


# ---------------------------------------------------------------------------
# 2. AppConfig.context
# ---------------------------------------------------------------------------


def test_context_config_app_config_defaults_to_the_context_defaults() -> None:
    context = getattr(AppConfig(), "context", None)

    assert isinstance(context, _context_config())
    assert context.model_dump() == _DEFAULTS


def test_context_config_app_config_parses_a_context_section() -> None:
    values = {
        "safety_margin_percent": 0,
        "max_attachment_mb_per_turn": 1024,
        "max_tool_result_tokens": 256,
    }

    config = AppConfig.model_validate({"context": values})

    assert getattr(config, "context", None) == _context_config()(**values)


def test_context_config_app_config_refuses_an_out_of_range_context_value() -> None:
    assert _outcome(AppConfig, {"context": {"safety_margin_percent": 51}}) == [
        ("context", "safety_margin_percent")
    ]


def test_context_config_load_app_config_reads_the_context_section(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("LLM_PROVIDER", "VLLM_MODEL", "VLLM_BASE_URL", "VLLM_MAX_MODEL_LEN"):
        monkeypatch.delenv(name, raising=False)
    path = tmp_path / "config.yaml"
    path.write_text(
        textwrap.dedent(
            """\
            llm:
              provider: "infomaniak"
              max_response_tokens: 2048
            context:
              safety_margin_percent: 20
              max_attachment_mb_per_turn: 16
              max_tool_result_tokens: 4000
            """
        ),
        encoding="utf-8",
    )

    config = load_app_config(path)

    assert getattr(config, "context", None) == _context_config()(
        safety_margin_percent=20, max_attachment_mb_per_turn=16, max_tool_result_tokens=4000
    )
    assert config.llm.max_response_tokens == 2048


# ---------------------------------------------------------------------------
# 3. LimitsConfig.max_context_messages: an optional secondary cap
# ---------------------------------------------------------------------------


def test_context_config_max_context_messages_defaults_to_no_cap() -> None:
    assert LimitsConfig().max_context_messages == 0


def test_context_config_max_context_messages_is_0_to_200() -> None:
    outcomes = {
        value: _outcome(LimitsConfig, {"max_context_messages": value})
        for value in (-1, 0, 200, 201)
    }

    assert outcomes == {
        -1: [("max_context_messages",)],
        0: "accepted",
        200: "accepted",
        201: [("max_context_messages",)],
    }


# ---------------------------------------------------------------------------
# 4. The shipped config/config.yaml
# ---------------------------------------------------------------------------


def _commented_context_section(text: str) -> dict[str, int] | None:
    """The ``# context:`` block's ``#   key: value`` lines, or None without one.

    The block runs over the comment lines that follow ``# context:``; comment
    lines between the keys (explanations) are skipped.
    """
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if re.fullmatch(r"#\s*context:\s*(?:#.*)?", line):
            section: dict[str, int] = {}
            for entry in lines[index + 1 :]:
                if not entry.startswith("#"):
                    break
                match = re.fullmatch(r"#\s+([a-z_]+):\s*(\d+)\s*(?:#.*)?", entry)
                if match is not None:
                    section[match.group(1)] = int(match.group(2))
            return section
    return None


def test_context_config_shipped_config_has_no_message_cap() -> None:
    raw = yaml.safe_load(_SHIPPED_CONFIG.read_text(encoding="utf-8"))

    assert raw["limits"]["max_context_messages"] == 0


def test_context_config_shipped_config_lists_the_context_defaults() -> None:
    """A set section must hold the defaults; a commented one documents them."""
    text = _SHIPPED_CONFIG.read_text(encoding="utf-8")
    raw = yaml.safe_load(text)

    section = raw["context"] if "context" in raw else _commented_context_section(text)

    assert section == _DEFAULTS
