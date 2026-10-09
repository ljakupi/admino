"""Spec for the location in ``load_app_config``'s validation error log line (GH-296 Decisions 4, 5).

``load_app_config`` logs one ``Config validation error at <location>: <message>`` line per
Pydantic error, then raises its generic ``ValueError`` ("Invalid application config ...
check server logs for details"), so admino doesn't start.

What these tests pin down:

- Decision 4 (the location): a model-level error of the whole config (an empty Pydantic
  ``loc``, such as the context budget fit check of GH-294) names the fixed label
  ``(config)`` instead of printing an empty location (``at : ``). The record's message, and
  the line the configured text and JSON formatters write, is exactly
  ``Config validation error at (config): Value error, The context budget doesn't fit ...``.
  Everything else keeps its dotted path, as today: a field (``llm.max_input_tokens``,
  ``server.public_url``), a top-level field (``log_level``), a list item with its index
  (``server.trusted_proxies.0``) and a section's model-level error under the section's name
  (``server``, the insecure cookie check). Those cells are guards that pass today by design;
  each one is proven on a mutant that labels too much ``(config)``.
- Decision 5 (no values): the line adds nothing to the error's own message but its
  location. The expected message is ``Config validation error at <location>: `` followed by
  the error's ``msg`` exactly as Pydantic reports it for the same payload (each anchored to
  its literal start), so the line can't carry the input. The leak cells set token canaries
  in ``INFOMANIAK_API_TOKEN``, ``ANTHROPIC_API_KEY`` and ``OPENAI_API_KEY`` and use fields
  whose messages don't repeat the input: ``llm.max_input_tokens`` given a canary string,
  ``server.public_url`` with a credential canary in its user info, and the fit check with a
  credential canary in ``llm.vllm_base_url`` (the input's first value, so even a 64
  character cut of the input would show it). They scan the raised error, the formatted
  output (text and JSON) and every captured record (message, args, ``repr(vars(record))``),
  each with a positive control that the error's line was captured. The fit check's own
  message (provider, model ID, three integers, GH-294 Decision 2) is pinned by
  ``tests/test_config_context_fit.py`` and stays as it is.

Harness: the YAML is written under ``tmp_path`` and loaded with ``load_app_config``; the
deployment env overrides are cleared with ``monkeypatch``. ``caplog`` holds the records for
the location cells; ``tests.log_capture.configured_logging`` configures logging the way
``main()`` does (inside the test body) for the formatted-output cells.

Security notes: every value is fake; the canaries only prove what isn't echoed.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any, Final

import pytest
import yaml
from pydantic import ValidationError

from admino.config import AppConfig, load_app_config
from tests.log_capture import configured_logging

if TYPE_CHECKING:
    from pathlib import Path

    from tests.log_capture import CapturedLogs

_PREFIX: Final = "Config validation error at "
_ROOT_LABEL: Final = "(config)"
# load_app_config's own error: the count of errors, never a path or a value.
_GENERIC_ERROR: Final = (
    r"^Invalid application config: validation failed on 1 field\(s\)"
    r" .{1,3} check server logs for details$"
)
# The text formatter writes "<asctime> <LEVEL> <logger> [<request id>] <em dash> <message>".
_TEXT_SEPARATOR: Final = f"] {chr(0x2014)} "
_EMPTY_LOCATION: Final = re.compile(r"error at\s*:")

_VLLM_MODEL: Final = "acme/location-check-model-7b"
_FIELD_CANARY: Final = "CANARY-296-razorbill"
_URL_CANARY: Final = "K9-296-shearwater"
_BASE_URL_CANARY: Final = "K9-296-guillemot"
_TOKEN_CANARY: Final = "TOKEN-296-kittiwake"
_CANARIES: Final = (_FIELD_CANARY, _URL_CANARY, _BASE_URL_CANARY, _TOKEN_CANARY)
_TOKEN_ENV: Final = ("INFOMANIAK_API_TOKEN", "ANTHROPIC_API_KEY", "OPENAI_API_KEY")
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

# The fit check (GH-294): 4096 reserved at 10 % doesn't fit 4552 input tokens.
_FIT_CHECK: Final[dict[str, Any]] = {
    "llm": {
        "vllm_base_url": f"http://op:{_BASE_URL_CANARY}@v/v1",
        "provider": "vllm",
        "vllm_model": _VLLM_MODEL,
        "max_input_tokens": 4552,
    }
}
_FIT_CHECK_START: Final = (
    f"Value error, The context budget doesn't fit llm.provider vllm (model {_VLLM_MODEL}): "
)
_FIELD_INT: Final[dict[str, Any]] = {"llm": {"max_input_tokens": _FIELD_CANARY}}
_FIELD_INT_START: Final = "Input should be a valid integer"
_FIELD_URL: Final[dict[str, Any]] = {
    "server": {"public_url": f"https://op:{_URL_CANARY}@admino.example.ch"}
}
_FIELD_URL_START: Final = "Value error, server.public_url must be an https origin"


@pytest.fixture(autouse=True)
def _no_env_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    """No deployment env override changes the configs these tests load."""
    for name in _ENV_OVERRIDES:
        monkeypatch.delenv(name, raising=False)


def _write(tmp_path: Path, payload: dict[str, Any]) -> Path:
    """Write ``payload`` as config.yaml (keys in their given order) and return its path."""
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path


def _own_message(payload: dict[str, Any]) -> str:
    """The one message Pydantic refuses ``payload`` with (no input, as load_app_config reads it)."""
    with pytest.raises(ValidationError) as exc_info:
        AppConfig.model_validate(payload)
    messages = [str(error["msg"]) for error in exc_info.value.errors(include_input=False)]
    assert len(messages) == 1, messages
    return messages[0]


def _error_lines(records: list[logging.LogRecord]) -> list[str]:
    """The messages of the ERROR records ``admino.config`` logged."""
    return [
        record.getMessage()
        for record in records
        if record.name == "admino.config" and record.levelno == logging.ERROR
    ]


def _formatted_messages(logs: CapturedLogs, log_format: str) -> list[str]:
    """The message part of every line the configured handler wrote."""
    if log_format == "json":
        return [str(entry["message"]) for entry in logs.json_lines()]
    return [line.split(_TEXT_SEPARATOR, 1)[1] for line in logs.lines() if _TEXT_SEPARATOR in line]


# ---------------------------------------------------------------------------
# 1. A model-level error of the whole config names (config) (Decision 4)
# ---------------------------------------------------------------------------


def test_config_error_location_root_model_error_is_labelled_config(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The fit check (an empty ``loc``) logs one line at ``(config)``, with its own message."""
    message = _own_message(_FIT_CHECK)

    with (
        caplog.at_level(logging.ERROR, logger="admino.config"),
        pytest.raises(ValueError, match=_GENERIC_ERROR),
    ):
        load_app_config(_write(tmp_path, _FIT_CHECK))

    assert (message.startswith(_FIT_CHECK_START), _error_lines(caplog.records)) == (
        True,
        [f"{_PREFIX}{_ROOT_LABEL}: {message}"],
    )


@pytest.mark.parametrize("log_format", ["text", "json"])
def test_config_error_location_root_model_error_line_has_no_empty_location(
    tmp_path: Path, log_format: str
) -> None:
    """The configured output holds the ``(config)`` line and no ``at :`` with nothing between."""
    message = _own_message(_FIT_CHECK)

    with configured_logging("DEBUG", log_format) as logs:
        with pytest.raises(ValueError, match=_GENERIC_ERROR):
            load_app_config(_write(tmp_path, _FIT_CHECK))
        located = [
            line for line in _formatted_messages(logs, log_format) if line.startswith(_PREFIX)
        ]
        empty = [line for line in logs.lines() if _EMPTY_LOCATION.search(line)]
        empty += [
            record.getMessage()
            for record in logs.records
            if _EMPTY_LOCATION.search(record.getMessage())
        ]

    assert (located, empty) == ([f"{_PREFIX}{_ROOT_LABEL}: {message}"], [])


# ---------------------------------------------------------------------------
# 2. Every other error keeps its path (Decision 4; guards)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("payload", "location", "message_start"),
    [
        pytest.param(
            _FIELD_INT, "llm.max_input_tokens", _FIELD_INT_START, id="field-llm-max-input-tokens"
        ),
        pytest.param(
            _FIELD_URL, "server.public_url", _FIELD_URL_START, id="field-server-public-url"
        ),
        pytest.param(
            {"log_level": "LOUD"},
            "log_level",
            "Input should be 'DEBUG', 'INFO'",
            id="top-level-field-log-level",
        ),
        pytest.param(
            {"server": {"trusted_proxies": [5]}},
            "server.trusted_proxies.0",
            "Input should be a valid string",
            id="list-item-server-trusted-proxies-0",
        ),
        pytest.param(
            {"server": {"cookie_secure": False, "public_url": "https://admino.example.ch"}},
            "server",
            "Value error, server.cookie_secure may be false",
            id="section-model-error-server",
        ),
    ],
)
def test_config_error_location_non_root_error_keeps_its_path(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    payload: dict[str, Any],
    location: str,
    message_start: str,
) -> None:
    """A field, list item or section error logs its dotted path, never ``(config)``."""
    message = _own_message(payload)

    with (
        caplog.at_level(logging.ERROR, logger="admino.config"),
        pytest.raises(ValueError, match=_GENERIC_ERROR),
    ):
        load_app_config(_write(tmp_path, payload))

    assert (message.startswith(message_start), _error_lines(caplog.records)) == (
        True,
        [f"{_PREFIX}{location}: {message}"],
    )


# ---------------------------------------------------------------------------
# 3. No values or secrets in the line (Decision 5)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("log_format", ["text", "json"])
@pytest.mark.parametrize(
    ("payload", "location"),
    [
        pytest.param(_FIT_CHECK, _ROOT_LABEL, id="root-fit-check"),
        pytest.param(_FIELD_INT, "llm.max_input_tokens", id="field-llm-max-input-tokens"),
        pytest.param(_FIELD_URL, "server.public_url", id="field-server-public-url"),
    ],
)
def test_config_error_location_line_holds_no_input_and_no_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, Any],
    location: str,
    log_format: str,
) -> None:
    """No canary reaches the error, the formatted output or any captured record.

    The positive control: the error's exact line (its location plus its own message) is in
    the formatted output and among the records.
    """
    for name in _TOKEN_ENV:
        monkeypatch.setenv(name, _TOKEN_CANARY)
    expected = f"{_PREFIX}{location}: {_own_message(payload)}"

    with configured_logging("DEBUG", log_format) as logs:
        with pytest.raises(ValueError, match=_GENERIC_ERROR) as exc_info:
            load_app_config(_write(tmp_path, payload))
        channels = {
            "error": f"{exc_info.value}\n{exc_info.value.__cause__}",
            "output": logs.text,
            "message": "\n".join(record.getMessage() for record in logs.records),
            "args": "\n".join(repr(record.args) for record in logs.records),
            "record": "\n".join(repr(vars(record)) for record in logs.records),
        }
        captured = (expected in logs.text, _error_lines(logs.records))

    leaks = [
        (channel, canary)
        for channel, text in channels.items()
        for canary in _CANARIES
        if canary.casefold() in text.casefold()
    ]
    assert (captured, leaks) == ((True, [expected]), [])
