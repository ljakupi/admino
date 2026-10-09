"""Spec for the cleaned field path in ``load_app_config``'s validation log line (GH-298 Decision 6).

``load_app_config`` logs one ``Config validation error at <location>: <message>`` line per
Pydantic error, then raises its generic ``ValueError``. Decision 6 pins the location:

- each part of a non-empty location is shown as ``safe_log`` renders it (``str(part)`` cut to
  64 characters, then every control, format and other non-printable character escaped as
  ``\\uXXXX``), and the parts are joined with ``.``;
- a list index shows as its decimal number (``server.trusted_proxies.2``), a nested field as
  its dotted parts (``llm.max_input_tokens``);
- no input value or secret appears (GH-296 Decision 5, unchanged).

Today's code already does this (the tests are guards, each proven on a mutant: ``str(part)``
instead of ``safe_log(part)``, the cut dropped, another separator, only the last part, the
index parts dropped, the input appended).

What these tests pin down:

- Real config: a nested field (``llm.max_input_tokens`` given a canary string) and a
  list-indexed one (``server.trusted_proxies.2`` given a mapping holding a canary) each log
  exactly ``Config validation error at <path>: <Pydantic's own message>``, in the record and
  in the text and JSON output, and no canary reaches any channel.
- Hostile location parts: the shipped models take no free-form key, so ``admino.config``'s
  ``AppConfig`` is replaced (``monkeypatch``) by a model with a ``dict[str, list[dict[str,
  int]]]`` field. A YAML key then reaches the location for real:
  ``('llm', <hostile key>, 2, <long key>)``. The hostile key carries ESC (an ANSI colour), a
  CR/LF that would start a forged second line, NUL and a bidi override (U+202E); the long key
  is longer than 64 characters with BEL and ESC as its 63rd and 64th characters and a forged
  line after them. The expected cleaned location is hard-coded (never computed with
  ``safe_log``, so a change to it is caught): the hostile key fully escaped (its 50 raw
  characters become 80, so the cut runs on the raw text, before escaping), the index as
  ``2``, and the long key cut to its first 64 raw characters, then escaped. No raw control
  character reaches the output or any record, every output line is one formatted record (no
  forged line), and no canary (the model's input, the token env vars) appears.

Harness: the YAML is written under ``tmp_path`` (``yaml.safe_dump`` escapes the control
characters in double-quoted keys; ``load_app_config`` reads them back) and loaded with
``load_app_config``; the deployment env overrides are cleared with ``monkeypatch``.
``tests.log_capture.configured_logging`` configures logging the way ``main()`` does (inside
the test body) and keeps the raw records next to the formatted output. The text formatter
escapes control characters in the whole message too, so the raw-character checks also read
the records, where only ``safe_log`` cleans the location.

Security notes: every value is fake; the canaries only prove what isn't echoed.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any, Final

import pytest
import yaml
from pydantic import BaseModel, ConfigDict, ValidationError

import admino.config as config_module
from admino.config import AppConfig, load_app_config
from tests.log_capture import configured_logging

if TYPE_CHECKING:
    from pathlib import Path

    from tests.log_capture import CapturedLogs

_PREFIX: Final = "Config validation error at "
# load_app_config's own error: the count of errors, never a path or a value.
_GENERIC_ERROR: Final = (
    r"^Invalid application config: validation failed on 1 field\(s\)"
    r" .{1,3} check server logs for details$"
)
# The text formatter writes "<asctime> <LEVEL> <logger> [<request id>] <em dash> <message>".
_TEXT_SEPARATOR: Final = f"] {chr(0x2014)} "
_TEXT_LINE: Final = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\S* [A-Z]+ +\S+ \[[^\]]*\] ")

_FIELD_CANARY: Final = "CANARY-298-goldeneye"
_PROXY_CANARY: Final = "K9-298-merganser"
_HOSTILE_CANARY: Final = "CANARY-298-pochard"
_TOKEN_CANARY: Final = "TOKEN-298-smew"
_CANARIES: Final = (_FIELD_CANARY, _PROXY_CANARY, _HOSTILE_CANARY, _TOKEN_CANARY)
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

# --- Real config: a nested field and a list item at index 2 -------------------------------
_NESTED: Final[dict[str, Any]] = {"llm": {"max_input_tokens": _FIELD_CANARY}}
_NESTED_START: Final = "Input should be a valid integer"
_LIST_INDEXED: Final[dict[str, Any]] = {
    "server": {"trusted_proxies": ["10.0.0.0/8", "192.168.0.0/16", {"op": _PROXY_CANARY}]}
}
_LIST_INDEXED_START: Final = "Input should be a valid string"

# --- Hostile location parts ---------------------------------------------------------------
_ESC: Final = chr(0x1B)
_BEL: Final = chr(0x07)
_NUL: Final = chr(0x00)
_CR: Final = chr(0x0D)
_LF: Final = chr(0x0A)
_RLO: Final = chr(0x202E)  # RIGHT-TO-LEFT OVERRIDE (a bidi format character)
_RAW_UNSAFE: Final = (_ESC, _BEL, _NUL, _CR, _LF, _RLO)
_FORGED: Final = "FORGED-298"

# 50 raw characters: ESC (twice), CR, LF, NUL and U+202E around printable text.
_HOSTILE_KEY: Final = (
    f"{_ESC}[31mlimits{_ESC}[0m{_CR}{_LF}{_FORGED} at llm: ok{_NUL}nul{_RLO}esrever"
)
# 62 printable characters, then BEL and ESC (the 63rd and 64th), then a forged line past the cut.
_LONG_KEY: Final = "budget-" + "k" * 55 + f"{_BEL}{_ESC}TAIL-298 cut off{_CR}{_LF}{_FORGED}-TAIL"
_CUT_TAIL: Final = "TAIL-298"
# The hostile key escaped as safe_log documents it (lowercase hex, four digits): 80 characters.
_HOSTILE_KEY_CLEANED: Final = (
    "\\u001b[31mlimits\\u001b[0m\\u000d\\u000aFORGED-298 at llm: ok\\u0000nul\\u202eesrever"
)
# The long key cut to its first 64 raw characters, then escaped.
_LONG_KEY_CLEANED: Final = "budget-" + "k" * 55 + "\\u0007\\u001b"
_HOSTILE_LOCATION: Final = f"llm.{_HOSTILE_KEY_CLEANED}.2.{_LONG_KEY_CLEANED}"
_HOSTILE_PAYLOAD: Final[dict[str, Any]] = {
    "llm": {_HOSTILE_KEY: [{}, {}, {_LONG_KEY: _HOSTILE_CANARY}]}
}
_HOSTILE_START: Final = "Input should be a valid integer"


class _FreeFormKeyConfig(BaseModel):
    """A config with a free-form key, so a YAML key reaches the error location.

    Hides its input in errors like ``AppConfig`` does.
    """

    model_config = ConfigDict(hide_input_in_errors=True)

    llm: dict[str, list[dict[str, int]]]


@pytest.fixture(autouse=True)
def _no_env_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    """No deployment env override changes the configs these tests load."""
    for name in _ENV_OVERRIDES:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def _token_canaries(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every provider token env var holds the token canary."""
    for name in _TOKEN_ENV:
        monkeypatch.setenv(name, _TOKEN_CANARY)


@pytest.fixture
def _free_form_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """``load_app_config`` validates with the free-form key model instead of ``AppConfig``."""
    monkeypatch.setattr(config_module, "AppConfig", _FreeFormKeyConfig)


def _write(tmp_path: Path, payload: dict[str, Any]) -> Path:
    """Write ``payload`` as config.yaml (keys in their given order) and return its path."""
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path


def _own_message(model: type[BaseModel], payload: dict[str, Any]) -> str:
    """The one message ``model`` refuses ``payload`` with (no input, as load_app_config does)."""
    with pytest.raises(ValidationError) as exc_info:
        model.model_validate(payload)
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


def _located(logs: CapturedLogs, log_format: str) -> list[str]:
    """The formatted messages that are config validation error lines."""
    return [line for line in _formatted_messages(logs, log_format) if line.startswith(_PREFIX)]


def _record_texts(records: list[logging.LogRecord]) -> list[str]:
    """Every record's message, its raw ``msg`` and each of its args, as plain strings."""
    texts: list[str] = []
    for record in records:
        texts.append(record.getMessage())
        texts.append(str(record.msg))
        args = record.args if isinstance(record.args, tuple) else (record.args,)
        texts.extend(str(arg) for arg in args)
    return texts


def _leaks(
    exc: BaseException, logs: CapturedLogs, canaries: tuple[str, ...]
) -> list[tuple[str, str]]:
    """The (channel, canary) pairs where a canary shows up, case-insensitively."""
    channels = {
        "error": f"{exc}\n{exc.__cause__}",
        "output": logs.text,
        "message": "\n".join(record.getMessage() for record in logs.records),
        "args": "\n".join(repr(record.args) for record in logs.records),
        "record": "\n".join(repr(vars(record)) for record in logs.records),
    }
    return [
        (channel, canary)
        for channel, text in channels.items()
        for canary in canaries
        if canary.casefold() in text.casefold()
    ]


# ---------------------------------------------------------------------------
# 1. Real config: a nested and a list-indexed path, exact and value-free
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("_token_canaries")
@pytest.mark.parametrize("log_format", ["text", "json"])
@pytest.mark.parametrize(
    ("payload", "location", "message_start"),
    [
        pytest.param(_NESTED, "llm.max_input_tokens", _NESTED_START, id="nested-llm"),
        pytest.param(
            _LIST_INDEXED, "server.trusted_proxies.2", _LIST_INDEXED_START, id="list-index-2"
        ),
    ],
)
def test_config_error_location_cleaning_real_path_is_exact_and_holds_no_value(
    tmp_path: Path,
    payload: dict[str, Any],
    location: str,
    message_start: str,
    log_format: str,
) -> None:
    """The line is ``Config validation error at <path>: <message>``, in the record and output.

    The path is the dotted field names with a list index as its decimal number; the message
    is Pydantic's own for the payload. No canary (the input, the token env vars) reaches the
    raised error, the output or any record.
    """
    message = _own_message(AppConfig, payload)
    expected = f"{_PREFIX}{location}: {message}"

    with configured_logging("DEBUG", log_format) as logs:
        with pytest.raises(ValueError, match=_GENERIC_ERROR) as exc_info:
            load_app_config(_write(tmp_path, payload))
        outcome = (
            message.startswith(message_start),
            _located(logs, log_format),
            _error_lines(logs.records),
            _leaks(exc_info.value, logs, _CANARIES),
        )

    assert outcome == (True, [expected], [expected], [])


# ---------------------------------------------------------------------------
# 2. Hostile location parts: escaped, cut, joined with "."
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("_free_form_config")
@pytest.mark.parametrize("log_format", ["text", "json"])
def test_config_error_location_cleaning_hostile_parts_are_shown_cleaned(
    tmp_path: Path, log_format: str
) -> None:
    """A hostile, nested, list-indexed location logs its hard-coded cleaned form.

    ``('llm', <hostile key>, 2, <long key>)`` becomes ``llm.<hostile key escaped>.2.<long key
    cut to 64, then escaped>``, both in the record and in the formatted output.
    """
    message = _own_message(_FreeFormKeyConfig, _HOSTILE_PAYLOAD)
    expected = f"{_PREFIX}{_HOSTILE_LOCATION}: {message}"

    with configured_logging("DEBUG", log_format) as logs:
        with pytest.raises(ValueError, match=_GENERIC_ERROR):
            load_app_config(_write(tmp_path, _HOSTILE_PAYLOAD))
        outcome = (
            message.startswith(_HOSTILE_START),
            _error_lines(logs.records),
            _located(logs, log_format),
        )

    assert outcome == (True, [expected], [expected])


@pytest.mark.usefixtures("_free_form_config")
@pytest.mark.parametrize("log_format", ["text", "json"])
def test_config_error_location_cleaning_hostile_parts_leave_no_raw_control_character(
    tmp_path: Path, log_format: str
) -> None:
    """No raw ESC, BEL, NUL, CR, LF or U+202E reaches the output or a record; no forged line.

    Every output line is one formatted record (a text line in the formatter's shape, or a
    JSON object), no output line or record message starts a line with the forged text, and
    nothing past the long key's 64-character cut appears. The positive control: the error's
    one line was logged (whatever its location looks like).
    """
    with configured_logging("DEBUG", log_format) as logs:
        with pytest.raises(ValueError, match=_GENERIC_ERROR):
            load_app_config(_write(tmp_path, _HOSTILE_PAYLOAD))
        output_lines = logs.text.split(_LF)[:-1]
        record_texts = _record_texts(logs.records)
        located = [line for line in _error_lines(logs.records) if line.startswith(f"{_PREFIX}llm.")]
        raw = sorted(
            {
                (channel, f"U+{ord(char):04X}")
                for channel, texts in (("output", output_lines), ("record", record_texts))
                for text in texts
                for char in _RAW_UNSAFE
                if char in text
            }
        )
        if log_format == "json":
            malformed = [line for line in output_lines if not line.startswith("{")]
            logs.json_lines()  # every line parses as one JSON object
        else:
            malformed = [line for line in output_lines if not _TEXT_LINE.match(line)]
        forged = [
            line
            for text in [*output_lines, *_formatted_messages(logs, log_format), *record_texts]
            for line in text.splitlines()
            if line.startswith(_FORGED)
        ]
        cut_tail = [
            text for text in [logs.text, *record_texts] if _CUT_TAIL.casefold() in text.casefold()
        ]

    assert (len(located), raw, malformed, forged, cut_tail) == (1, [], [], [], [])


@pytest.mark.usefixtures("_free_form_config", "_token_canaries")
@pytest.mark.parametrize("log_format", ["text", "json"])
def test_config_error_location_cleaning_hostile_parts_line_holds_no_input_and_no_secret(
    tmp_path: Path, log_format: str
) -> None:
    """The model's input canary and the token canaries reach no channel.

    The channels: the raised error and its cause, the formatted output and every record
    (message, args, ``repr(vars(record))``). The positive control: the error's exact line is
    in the output and among the records.
    """
    expected = f"{_PREFIX}{_HOSTILE_LOCATION}: {_own_message(_FreeFormKeyConfig, _HOSTILE_PAYLOAD)}"

    with configured_logging("DEBUG", log_format) as logs:
        with pytest.raises(ValueError, match=_GENERIC_ERROR) as exc_info:
            load_app_config(_write(tmp_path, _HOSTILE_PAYLOAD))
        outcome = (
            _located(logs, log_format),
            _error_lines(logs.records),
            _leaks(exc_info.value, logs, (_HOSTILE_CANARY, _TOKEN_CANARY)),
        )

    assert outcome == ([expected], [expected], [])
