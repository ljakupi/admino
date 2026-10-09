"""Spec for the start check of the context budget in ``admino.config`` (GH-294 Decisions 1, 2).

A model whose reserved output (``llm.max_response_tokens``) plus the safety margin don't
fit within its ``llm.max_input_tokens`` refuses every turn at runtime (#190 audit core
L-1). GH-294 refuses it where it is configured, at start.

What these tests pin down:

- Decision 1 (when a model fits): the budget is ``budget_limit(llm.max_input_tokens,
  context.safety_margin_percent)``, that is ``max_input_tokens - ceil(max_input_tokens *
  margin / 100)``. The model fits when the reserve is BELOW the budget (at least one input
  token is left); a reserve equal to the budget is refused like one above it. With the
  defaults (4096 reserved, 10 %), ``max_input_tokens`` 4553 fits, 4552 and 4551 don't.
  Each group below checks one under, at and over the budget: the defaults, no margin, the
  ceiling (10_001 at 10 % is 9_000, a floor would give 9_001), the largest reserve (65536)
  and the largest margin (50 %) at the smallest ``max_input_tokens`` (1000).
- Decision 2 (config validation): ``AppConfig`` validation refuses such a config, so
  ``load_app_config`` raises ``ValueError`` and its error log names the model. The
  validation message names ``llm.provider``'s value and the active model ID (or
  ``no model set``), plus ``llm.max_input_tokens``, ``llm.max_response_tokens`` and
  ``context.safety_margin_percent``, each with its value as a plain integer. It holds
  config values only: no API token, no URL credentials. ``LLMConfig`` and ``AgentConfig``
  on their own don't check (each lacks the other section): those are guards that pass
  today by design.

Security notes: every value is fake; the canaries only prove what isn't echoed.
"""

from __future__ import annotations

import logging
import re
import textwrap
from typing import TYPE_CHECKING, Any, Final

import pytest
from pydantic import ValidationError

from admino.config import AppConfig, LLMConfig, load_app_config
from admino.models import AgentConfig
from tests.log_capture import configured_logging

if TYPE_CHECKING:
    from pathlib import Path

_INFOMANIAK_MODEL: Final = "Qwen/Qwen3.5-397B-A17B-FP8"
_VLLM_MODEL: Final = "acme/fit-check-model-7b"
_TOKEN_CANARY: Final = "TOKEN-294-kittiwake"
_URL_CANARY: Final = "K9-guillemot"
_ENV_OVERRIDES: Final = (
    "LLM_PROVIDER",
    "VLLM_MODEL",
    "VLLM_BASE_URL",
    "VLLM_MAX_MODEL_LEN",
    "COOKIE_SECURE",
    "ADMINO_PUBLIC_URL",
    "ADMINO_TRUSTED_PROXIES",
    "LOG_LEVEL",
    "LOG_FORMAT",
)


@pytest.fixture(autouse=True)
def _no_env_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    """No deployment env override changes the configs these tests load."""
    for name in _ENV_OVERRIDES:
        monkeypatch.delenv(name, raising=False)


def _config(
    *,
    max_input_tokens: int | None = None,
    max_response_tokens: int | None = None,
    margin: int | None = None,
    **llm: Any,
) -> dict[str, Any]:
    """An ``AppConfig`` payload; an omitted value keeps its default."""
    llm_section: dict[str, Any] = dict(llm)
    if max_input_tokens is not None:
        llm_section["max_input_tokens"] = max_input_tokens
    if max_response_tokens is not None:
        llm_section["max_response_tokens"] = max_response_tokens
    payload: dict[str, Any] = {"llm": llm_section}
    if margin is not None:
        payload["context"] = {"safety_margin_percent": margin}
    return payload


def _outcome(payload: dict[str, Any]) -> str:
    """``"fits"`` when ``AppConfig`` accepts ``payload``, ``"refused"`` when it doesn't."""
    try:
        AppConfig.model_validate(payload)
    except ValidationError:
        return "refused"
    return "fits"


def _refusal(payload: dict[str, Any]) -> str:
    """The one validation message ``AppConfig`` refuses ``payload`` with."""
    with pytest.raises(ValidationError) as exc_info:
        AppConfig.model_validate(payload)
    messages = [
        str(error["msg"]) for error in exc_info.value.errors(include_url=False, include_input=False)
    ]
    assert len(messages) == 1, messages
    return messages[0]


def _names(message: str, setting: str, value: int) -> bool:
    """Whether ``message`` names ``setting`` with ``value`` right after it (a plain integer)."""
    pattern = re.escape(setting) + r"\D{0,8}?" + str(value) + r"(?!\d)"
    return re.search(pattern, message) is not None


# ---------------------------------------------------------------------------
# 1. When a model fits (Decision 1)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("payloads", "_why"),
    [
        pytest.param(
            {
                "under": _config(max_input_tokens=4553),
                "at": _config(max_input_tokens=4552),
                "over": _config(max_input_tokens=4551),
            },
            "4096 reserved at 10 %: budgets 4097, 4096, 4095",
            id="defaults",
        ),
        pytest.param(
            {
                "under": _config(max_input_tokens=5000, max_response_tokens=4999, margin=0),
                "at": _config(max_input_tokens=5000, max_response_tokens=5000, margin=0),
                "over": _config(max_input_tokens=5000, max_response_tokens=5001, margin=0),
            },
            "no margin: the budget is max_input_tokens itself",
            id="no-margin",
        ),
        pytest.param(
            {
                "under": _config(max_input_tokens=10_001, max_response_tokens=8999, margin=10),
                "at": _config(max_input_tokens=10_001, max_response_tokens=9000, margin=10),
                "over": _config(max_input_tokens=10_001, max_response_tokens=9001, margin=10),
            },
            "the margin is rounded up: 10_001 at 10 % is 9_000 (a floor gives 9_001)",
            id="margin-rounded-up",
        ),
        pytest.param(
            {
                "under": _config(max_input_tokens=72_819, max_response_tokens=65536, margin=10),
                "at": _config(max_input_tokens=72_818, max_response_tokens=65536, margin=10),
                "over": _config(max_input_tokens=72_817, max_response_tokens=65536, margin=10),
            },
            "the largest reserve: budgets 65_537, 65_536, 65_535",
            id="largest-reserve",
        ),
        pytest.param(
            {
                "under": _config(max_input_tokens=1000, max_response_tokens=499, margin=50),
                "at": _config(max_input_tokens=1000, max_response_tokens=500, margin=50),
                "over": _config(max_input_tokens=1000, max_response_tokens=501, margin=50),
            },
            "the largest margin at the smallest max_input_tokens: the budget is 500",
            id="largest-margin",
        ),
    ],
)
def test_config_context_fit_reserve_below_the_budget_fits_at_or_over_it_is_refused(
    payloads: dict[str, dict[str, Any]], _why: str
) -> None:
    """Under the budget fits; a reserve equal to the budget leaves no input and is refused."""
    outcomes = {case: _outcome(payload) for case, payload in payloads.items()}

    assert outcomes == {"under": "fits", "at": "refused", "over": "refused"}


# ---------------------------------------------------------------------------
# 2. The validation message (Decision 2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("llm", "provider", "model"),
    [
        pytest.param({"provider": "infomaniak"}, "infomaniak", _INFOMANIAK_MODEL, id="infomaniak"),
        pytest.param(
            {"provider": "vllm", "vllm_model": _VLLM_MODEL}, "vllm", _VLLM_MODEL, id="vllm"
        ),
        pytest.param(
            {"provider": "anthropic", "anthropic_model": None},
            "anthropic",
            "no model set",
            id="anthropic-without-a-model",
        ),
    ],
)
def test_config_context_fit_refusal_names_the_active_model_and_the_three_settings(
    llm: dict[str, Any], provider: str, model: str
) -> None:
    """5000 at 20 % is a budget of 4000, exactly the reserve: refused, naming every value."""
    message = _refusal(_config(max_input_tokens=5000, max_response_tokens=4000, margin=20, **llm))

    named = {
        "provider": re.search(rf"\b{provider}\b", message) is not None,
        "model": model in message,
        "llm.max_input_tokens": _names(message, "llm.max_input_tokens", 5000),
        "llm.max_response_tokens": _names(message, "llm.max_response_tokens", 4000),
        "context.safety_margin_percent": _names(message, "context.safety_margin_percent", 20),
    }

    assert named == dict.fromkeys(named, True), message


def test_config_context_fit_refusal_holds_config_values_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No API token and no credential of ``vllm_base_url`` reach the error or the log output.

    The URL is the input's last value, so a repr of the input (which pydantic cuts to its
    first and last 25 characters) would show its password.
    """
    for name in ("INFOMANIAK_API_TOKEN", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.setenv(name, _TOKEN_CANARY)
    path = tmp_path / "config.yaml"
    path.write_text(
        textwrap.dedent(
            f"""\
            llm:
              provider: "vllm"
              vllm_model: "{_VLLM_MODEL}"
              max_input_tokens: 4552
              vllm_base_url: "http://op:{_URL_CANARY}@v/v1"
            """
        ),
        encoding="utf-8",
    )

    with configured_logging("DEBUG", "text") as logs:
        with pytest.raises(ValueError, match="config") as exc_info:
            load_app_config(path)
        records = [repr(vars(record)) for record in logs.records]

    haystack = "\n".join([str(exc_info.value), str(exc_info.value.__cause__), logs.text, *records])
    leaks = [canary for canary in (_TOKEN_CANARY, _URL_CANARY) if canary in haystack]
    # The positive control: the refusal is the fit check's, and its log line was captured.
    assert (_VLLM_MODEL in str(exc_info.value.__cause__), _VLLM_MODEL in logs.text, leaks) == (
        True,
        True,
        [],
    )


def test_config_context_fit_load_app_config_refuses_to_start_and_logs_the_model(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """``load_app_config`` raises, so admino doesn't start; the error log names the model."""
    path = tmp_path / "config.yaml"
    path.write_text(
        textwrap.dedent(
            f"""\
            llm:
              provider: "infomaniak"
              infomaniak_model: "{_INFOMANIAK_MODEL}"
              max_input_tokens: 4552
            """
        ),
        encoding="utf-8",
    )

    with caplog.at_level(logging.ERROR, logger="admino.config"), pytest.raises(ValueError):
        load_app_config(path)

    lines = [
        record.getMessage()
        for record in caplog.records
        if record.levelno >= logging.ERROR and _INFOMANIAK_MODEL in record.getMessage()
    ]
    assert len(lines) == 1, [record.getMessage() for record in caplog.records]
    assert [
        _names(lines[0], "llm.max_input_tokens", 4552),
        _names(lines[0], "llm.max_response_tokens", 4096),
        _names(lines[0], "context.safety_margin_percent", 10),
    ] == [True, True, True], lines[0]


# ---------------------------------------------------------------------------
# 3. Guards: neither section on its own checks (Decision 2)
# ---------------------------------------------------------------------------


def test_config_context_fit_llm_config_alone_does_not_check() -> None:
    """``LLMConfig`` lacks the margin: 1000 input tokens beside the 4096 reserve is valid."""
    llm = LLMConfig.model_validate({"max_input_tokens": 1000, "max_response_tokens": 65536})

    assert (llm.max_input_tokens, llm.max_response_tokens) == (1000, 65536)


def test_config_context_fit_agent_config_is_unchanged() -> None:
    """``AgentConfig`` holds a run's values and doesn't check them either."""
    config = AgentConfig(
        max_input_tokens=1000, reserved_output_tokens=65536, context_margin_percent=50
    )

    assert (
        config.max_input_tokens,
        config.reserved_output_tokens,
        config.context_margin_percent,
    ) == (1000, 65536, 50)
