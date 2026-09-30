"""Tests for admino.logs and main._configure_logging — log hygiene (GH-158).

Spec pinned here (tests written before the implementation):

- ``safe_log(value, max_len=64)``: ``str(value)[:max_len]``, then every
  character that isn't ``isprintable()`` or whose Unicode category is ``Cf``
  becomes backslash-u plus at least 4 hex digits (``"\\u%04x"``). It is THE one
  sanitizer for identifiers in logs: ``permissions._safe_log`` is gone,
  permissions.py imports ``safe_log`` from ``admino.logs``, and no other module
  under src/admino defines a ``safe_log`` / ``_safe_log``.
- ``safe_url(url)``: ``scheme://host[:port]/path``. The query string, the
  fragment and any userinfo (``user:pass@``) are dropped; a URL that
  ``urllib.parse.urlsplit`` can't parse gives the fixed ``"[invalid url]"``,
  never the raw input.
- ``request_id_var`` (a ``ContextVar``, default None) and ``RequestIdFilter``,
  which copies it onto every record as ``record.request_id`` (overwriting
  anything a caller passed) and always returns True.
- ``JsonFormatter``: one JSON object per line with exactly ``ts`` (ISO-8601,
  UTC), ``level``, ``logger``, ``message``, ``request_id``, plus ``exc_type``
  (the class name only) when the record has exc_info. ``TextFormatter``:
  ``"<asctime> <LEVEL> <logger> [<request_id or ->] — <message>"`` plus
  ``" [exc_type=<ClassName>]"``. Neither ever writes a traceback, an exception
  message or stack_info, and both cut the query string and fragment off every
  http(s) URL in the message.
- ``main._configure_logging(level, log_format="text", *, stream=None)``: ONE
  root ``StreamHandler`` (``stream`` or stderr) with a ``RequestIdFilter`` and
  the JSON formatter for ``"json"``, the text formatter for anything else; the
  httpx, httpcore, openai, anthropic, googleapiclient and urllib3 loggers are
  pinned at WARNING (they log request URLs with query strings at INFO and whole
  request payloads, i.e. conversation content, at DEBUG).
- Static guards over src/admino: logs.py imports only the standard library; no
  log call argument references a content identifier (email, display_name,
  subject, title, file name, body, content, query, instructions, password,
  token, message, ...) outside ``len(...)``; no ``logger.exception`` and no
  ``exc_info=`` / ``stack_info=`` on log calls; no third-party error tracking or
  analytics SDK in pyproject.toml, uv.lock, static-src/package.json, the
  backend imports or the frontend source, and that is documented.
- ``.env.example`` documents ``LOG_FORMAT``.

Security notes:
- Every secret-looking value here is a distinctive fake marker; the tests only
  check that it never reaches the formatted output.
- ``admino.logs`` is imported per test through the ``logs`` fixture, so each
  test fails on its own before the module exists.
- Root logging is changed only inside ``restored_logging()`` /
  ``configured_logging()`` (tests/log_capture.py), which put it back.
"""

from __future__ import annotations

import ast
import contextvars
import inspect
import io
import json
import logging
import re
import sys
import tomllib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final
from uuid import UUID

import pytest

from tests.log_capture import PINNED_THIRD_PARTY_LOGGERS, restored_logging

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

_REPO_ROOT: Final = Path(__file__).resolve().parent.parent
_SRC_DIR: Final = _REPO_ROOT / "src" / "admino"
_LOGS_PATH: Final = _SRC_DIR / "logs.py"

_BACKSLASH: Final = chr(92)
_INVALID_URL: Final = "[invalid url]"
_BASE_KEYS: Final = frozenset({"ts", "level", "logger", "message", "request_id"})
_PROBE_LOGGER: Final = "tests.gh158.probe"


def _esc(codepoint: int) -> str:
    """The escape safe_log writes for ``chr(codepoint)`` (backslash-u, %04x)."""
    return f"{_BACKSLASH}u{codepoint:04x}"


class _KestrelProbeError(Exception):
    """A custom exception: exc_type must be its bare class name."""


@pytest.fixture()
def logs() -> Any:
    """admino.logs, imported per test (each test fails on its own before GH-158)."""
    from admino import logs as logs_module

    return logs_module


def _render(formatter: logging.Formatter, emit: Callable[[logging.Logger], None]) -> str:
    """Emit records through ``formatter`` (with a RequestIdFilter) and return the output."""
    from admino import logs as logs_module

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.addFilter(logs_module.RequestIdFilter())
    handler.setFormatter(formatter)
    probe = logging.getLogger(_PROBE_LOGGER)
    probe.handlers = [handler]
    probe.propagate = False
    probe.setLevel(logging.DEBUG)
    try:
        emit(probe)
    finally:
        probe.handlers = []
        probe.propagate = True
        probe.setLevel(logging.NOTSET)
    return stream.getvalue()


def _record(message: str = "probe") -> logging.LogRecord:
    """A bare INFO record."""
    return logging.LogRecord(_PROBE_LOGGER, logging.INFO, __file__, 1, message, None, None)


def _log_value_error(logger: logging.Logger) -> None:
    """Log an ERROR with exc_info for a ValueError whose message is a secret marker."""
    try:
        raise ValueError("wolfram-secret-771")
    except ValueError:
        logger.error("boom", exc_info=True)


# ---------------------------------------------------------------------------
# 1. safe_log — the one identifier sanitizer
# ---------------------------------------------------------------------------


class TestSafeLog:
    """safe_log escapes control and format characters and truncates."""

    @pytest.mark.parametrize(
        "codepoint",
        [0x00, 0x07, 0x09, 0x0A, 0x0D, 0x1B, 0x7F, 0x85, 0x9B],
        ids=["nul", "bel", "tab", "lf", "cr", "esc", "del", "nel", "csi"],
    )
    def test_logs_safe_log_escapes_control_character(self, logs: Any, codepoint: int) -> None:
        """A control character becomes its backslash-u escape; the text around stays."""
        assert logs.safe_log(f"a{chr(codepoint)}b") == f"a{_esc(codepoint)}b"

    def test_logs_safe_log_escapes_ansi_escape_sequence(self, logs: Any) -> None:
        """An ANSI colour sequence can't reach a terminal: ESC is escaped."""
        assert logs.safe_log(chr(0x1B) + "[31mred") == _esc(0x1B) + "[31mred"

    @pytest.mark.parametrize(
        "codepoint",
        [0x202E, 0x200B, 0x2066, 0xFEFF, 0x200D, 0xE0001],
        ids=["rlo", "zero-width-space", "lri", "bom", "zwj", "language-tag"],
    )
    def test_logs_safe_log_escapes_format_character(self, logs: Any, codepoint: int) -> None:
        """Bidi overrides, zero-width and other Cf characters are escaped (%04x hex)."""
        assert logs.safe_log(f"x{chr(codepoint)}y") == f"x{_esc(codepoint)}y"

    def test_logs_safe_log_escapes_lone_surrogate(self, logs: Any) -> None:
        assert logs.safe_log(chr(0xD800)) == _esc(0xD800)

    def test_logs_safe_log_keeps_printable_text(self, logs: Any) -> None:
        """Printable text, non-ASCII letters included, passes through unchanged."""
        text = f"Z{chr(0xFC)}rich gmail.list ok-42_a/b:c"

        assert logs.safe_log(text) == text

    def test_logs_safe_log_truncates_to_64_by_default(self, logs: Any) -> None:
        assert logs.safe_log("x" * 100) == "x" * 64

    def test_logs_safe_log_default_max_len_is_64(self, logs: Any) -> None:
        assert inspect.signature(logs.safe_log).parameters["max_len"].default == 64

    def test_logs_safe_log_honours_max_len(self, logs: Any) -> None:
        assert logs.safe_log("abcdef", max_len=3) == "abc"

    def test_logs_safe_log_truncates_before_escaping(self, logs: Any) -> None:
        """The cut is on the input (64 characters), each then escaped."""
        assert logs.safe_log(chr(0x0A) * 100) == _esc(0x0A) * 64

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (UUID("0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0"), "0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0"),
            (42, "42"),
            (None, "None"),
        ],
        ids=["uuid", "int", "none"],
    )
    def test_logs_safe_log_accepts_non_str(self, logs: Any, value: object, expected: str) -> None:
        """Any object is logged through ``str()``."""
        assert logs.safe_log(value) == expected

    def test_logs_safe_log_sanitizes_str_of_an_object(self, logs: Any) -> None:
        """An object whose ``__str__`` carries control characters is sanitized too."""

        class _Sneaky:
            def __str__(self) -> str:
                return f"id{chr(0x0A)}FAKE LINE"

        assert logs.safe_log(_Sneaky()) == f"id{_esc(0x0A)}FAKE LINE"

    def test_logs_safe_log_returns_plain_str(self, logs: Any) -> None:
        assert type(logs.safe_log(UUID(int=7))) is str


# ---------------------------------------------------------------------------
# 2. safe_url — URLs are never logged with their query string
# ---------------------------------------------------------------------------


class TestSafeUrl:
    """safe_url keeps scheme, host, port and path only."""

    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("https://h.example/p?q=secret", "https://h.example/p"),
            ("https://h.example/p#frag", "https://h.example/p"),
            ("https://h.example/p?q=1#frag", "https://h.example/p"),
            ("https://alice:hunter2@h.example/p", "https://h.example/p"),
            ("https://alice@h.example/p?x=1", "https://h.example/p"),
            ("http://h.example:8443/a/b?x=y", "http://h.example:8443/a/b"),
            ("http://h.example/a/b", "http://h.example/a/b"),
            ("https://h.example", "https://h.example"),
            ("http://[::1]:8000/p?q=1", "http://[::1]:8000/p"),
            (
                "https://gmail.googleapis.com/gmail/v1/users/me/messages?q=from%3Aalice%40example.com",
                "https://gmail.googleapis.com/gmail/v1/users/me/messages",
            ),
        ],
        ids=[
            "query",
            "fragment",
            "query-and-fragment",
            "userinfo-with-password",
            "userinfo-user-only",
            "port-kept",
            "no-query-unchanged",
            "no-path",
            "ipv6-host",
            "gmail-search",
        ],
    )
    def test_logs_safe_url_keeps_scheme_host_port_path(
        self, logs: Any, url: str, expected: str
    ) -> None:
        assert logs.safe_url(url) == expected

    @pytest.mark.parametrize(
        "url",
        ["http://[::1", "http://[secret-host-7731/p?q=kestrel-7731"],
        ids=["unclosed-ipv6", "unclosed-ipv6-with-query"],
    )
    def test_logs_safe_url_unparseable_gives_placeholder(self, logs: Any, url: str) -> None:
        """A URL urlsplit can't parse is the fixed placeholder, never the raw input."""
        assert logs.safe_url(url) == _INVALID_URL

    @pytest.mark.parametrize(
        "url",
        [
            "/api/search?q=kestrel-7731",
            "?q=kestrel-7731",
            "http://h.example:99999/p?q=kestrel-7731",
            "https://h.example/p?kestrel-7731",
            "https://h.example/p#kestrel-7731",
        ],
        ids=["relative", "query-only", "port-out-of-range", "bare-query", "bare-fragment"],
    )
    def test_logs_safe_url_never_returns_the_query(self, logs: Any, url: str) -> None:
        """Whatever the input, the result is a str without the query or fragment."""
        result = logs.safe_url(url)

        assert isinstance(result, str)
        assert "kestrel-7731" not in result

    def test_logs_safe_url_never_returns_userinfo(self, logs: Any) -> None:
        result = logs.safe_url("https://svc-user-7731:pw-7731@h.example/")

        assert "7731" not in result
        assert "@" not in result


# ---------------------------------------------------------------------------
# 3. request_id_var and RequestIdFilter
# ---------------------------------------------------------------------------


class TestRequestIdFilter:
    """RequestIdFilter copies the request's id (or None) onto every record."""

    def test_logs_request_id_var_is_a_context_var(self, logs: Any) -> None:
        assert isinstance(logs.request_id_var, contextvars.ContextVar)

    def test_logs_request_id_var_defaults_to_none(self, logs: Any) -> None:
        """In a fresh context (no request) the id is None, not a LookupError."""
        assert contextvars.Context().run(logs.request_id_var.get) is None

    def test_logs_request_id_filter_is_a_logging_filter(self, logs: Any) -> None:
        assert issubclass(logs.RequestIdFilter, logging.Filter)

    def test_logs_request_id_filter_sets_none_outside_a_request(self, logs: Any) -> None:
        record = _record()

        kept = logs.RequestIdFilter().filter(record)

        assert (kept, record.request_id) == (True, None)

    def test_logs_request_id_filter_copies_the_current_id(self, logs: Any) -> None:
        record = _record()
        token = logs.request_id_var.set("0123abcd" * 4)
        try:
            kept = logs.RequestIdFilter().filter(record)
        finally:
            logs.request_id_var.reset(token)

        assert (kept, record.request_id) == (True, "0123abcd" * 4)

    def test_logs_request_id_filter_overwrites_a_forged_id(self, logs: Any) -> None:
        """A request_id passed through ``extra=`` can't forge the request's id."""
        record = _record()
        record.request_id = "forged-by-caller"

        logs.RequestIdFilter().filter(record)

        assert record.request_id is None


# ---------------------------------------------------------------------------
# 4. JsonFormatter
# ---------------------------------------------------------------------------


class TestJsonFormatter:
    """One JSON object per line, exactly the pinned keys, no tracebacks."""

    def test_logs_json_formatter_is_a_logging_formatter(self, logs: Any) -> None:
        assert isinstance(logs.JsonFormatter(), logging.Formatter)

    def test_logs_json_one_object_per_line(self, logs: Any) -> None:
        def emit(logger: logging.Logger) -> None:
            logger.info("first")
            logger.warning("second")

        output = _render(logs.JsonFormatter(), emit)

        lines = output.splitlines()
        assert len(lines) == 2
        assert [json.loads(line)["message"] for line in lines] == ["first", "second"]

    def test_logs_json_has_exactly_the_pinned_keys(self, logs: Any) -> None:
        output = _render(logs.JsonFormatter(), lambda logger: logger.info("hello"))

        assert set(json.loads(output)) == _BASE_KEYS

    def test_logs_json_level_logger_and_formatted_message(self, logs: Any) -> None:
        output = _render(logs.JsonFormatter(), lambda logger: logger.warning("count=%d", 3))

        entry = json.loads(output)
        assert (entry["level"], entry["logger"], entry["message"]) == (
            "WARNING",
            _PROBE_LOGGER,
            "count=3",
        )

    def test_logs_json_ts_is_iso8601_utc(self, logs: Any) -> None:
        output = _render(logs.JsonFormatter(), lambda logger: logger.info("hello"))

        ts = datetime.fromisoformat(json.loads(output)["ts"])
        assert ts.utcoffset() == timedelta(0)
        assert abs(datetime.now(UTC) - ts) < timedelta(minutes=1)

    def test_logs_json_request_id_null_outside_a_request(self, logs: Any) -> None:
        output = _render(logs.JsonFormatter(), lambda logger: logger.info("hello"))

        assert json.loads(output)["request_id"] is None

    def test_logs_json_request_id_inside_a_request(self, logs: Any) -> None:
        token = logs.request_id_var.set("f" * 32)
        try:
            output = _render(logs.JsonFormatter(), lambda logger: logger.info("hello"))
        finally:
            logs.request_id_var.reset(token)

        assert json.loads(output)["request_id"] == "f" * 32

    def test_logs_json_multiline_message_stays_one_line(self, logs: Any) -> None:
        """A newline in the message can't start a forged log line."""
        output = _render(
            logs.JsonFormatter(),
            lambda logger: logger.info("first%ssecond", chr(0x0A)),
        )

        assert output.count(chr(0x0A)) == 1
        assert isinstance(json.loads(output), dict)

    def test_logs_json_exc_info_gives_exc_type_only(self, logs: Any) -> None:
        output = _render(logs.JsonFormatter(), _log_value_error)

        entry = json.loads(output)
        assert set(entry) == _BASE_KEYS | {"exc_type"}
        assert (entry["exc_type"], entry["message"]) == ("ValueError", "boom")

    def test_logs_json_exc_info_writes_no_traceback_or_exception_message(self, logs: Any) -> None:
        output = _render(logs.JsonFormatter(), _log_value_error)

        assert output.count(chr(0x0A)) == 1
        assert "wolfram-secret-771" not in output
        assert "Traceback" not in output

    def test_logs_json_logger_exception_gives_exc_type_only(self, logs: Any) -> None:
        def emit(logger: logging.Logger) -> None:
            try:
                raise KeyError("wolfram-secret-772")
            except KeyError:
                logger.exception("lookup failed")

        output = _render(logs.JsonFormatter(), emit)

        entry = json.loads(output)
        assert entry["exc_type"] == "KeyError"
        assert "wolfram-secret-772" not in output

    def test_logs_json_exc_type_is_the_bare_class_name(self, logs: Any) -> None:
        def emit(logger: logging.Logger) -> None:
            try:
                raise _KestrelProbeError("wolfram-secret-773")
            except _KestrelProbeError:
                logger.error("custom", exc_info=True)

        output = _render(logs.JsonFormatter(), emit)

        assert json.loads(output)["exc_type"] == "_KestrelProbeError"
        assert "tests." not in json.loads(output)["exc_type"]

    def test_logs_json_stack_info_is_dropped(self, logs: Any) -> None:
        output = _render(
            logs.JsonFormatter(), lambda logger: logger.info("with stack", stack_info=True)
        )

        assert output.count(chr(0x0A)) == 1
        assert "Stack (most recent call last)" not in output
        assert "test_logs.py" not in output
        assert set(json.loads(output)) == _BASE_KEYS

    def test_logs_json_extra_fields_are_not_emitted(self, logs: Any) -> None:
        """``extra=`` can't smuggle content into the JSON line: the key set is fixed."""
        output = _render(
            logs.JsonFormatter(),
            lambda logger: logger.info("hello", extra={"email": "alice-7731@example.com"}),
        )

        assert set(json.loads(output)) == _BASE_KEYS
        assert "alice-7731" not in output


# ---------------------------------------------------------------------------
# 5. TextFormatter
# ---------------------------------------------------------------------------

_TEXT_LINE: Final = re.compile(
    r"^(?P<asctime>\d{4}-\d{2}-\d{2}.*?) (?P<level>[A-Z]+) +(?P<logger>\S+) "
    r"\[(?P<request_id>[^\]]*)\] — (?P<message>.*)$"
)


class TestTextFormatter:
    """``<asctime> <LEVEL> <logger> [<request_id or ->] — <message>``, no tracebacks."""

    def test_logs_text_formatter_is_a_logging_formatter(self, logs: Any) -> None:
        assert isinstance(logs.TextFormatter(), logging.Formatter)

    def test_logs_text_line_outside_a_request(self, logs: Any) -> None:
        output = _render(logs.TextFormatter(), lambda logger: logger.info("hello %s", "there"))

        match = _TEXT_LINE.match(output.rstrip(chr(0x0A)))
        assert match is not None, output
        assert match.group("level", "logger", "request_id", "message") == (
            "INFO",
            _PROBE_LOGGER,
            "-",
            "hello there",
        )

    def test_logs_text_line_inside_a_request(self, logs: Any) -> None:
        token = logs.request_id_var.set("0123abcd" * 4)
        try:
            output = _render(logs.TextFormatter(), lambda logger: logger.warning("hello"))
        finally:
            logs.request_id_var.reset(token)

        match = _TEXT_LINE.match(output.rstrip(chr(0x0A)))
        assert match is not None, output
        assert match.group("level", "request_id") == ("WARNING", "0123abcd" * 4)

    def test_logs_text_exc_info_appends_exc_type_only(self, logs: Any) -> None:
        output = _render(logs.TextFormatter(), _log_value_error)

        assert output.count(chr(0x0A)) == 1
        assert output.rstrip(chr(0x0A)).endswith(" — boom [exc_type=ValueError]")

    def test_logs_text_exc_info_writes_no_traceback_or_exception_message(self, logs: Any) -> None:
        output = _render(logs.TextFormatter(), _log_value_error)

        assert "wolfram-secret-771" not in output
        assert "Traceback" not in output

    def test_logs_text_exc_type_is_the_bare_class_name(self, logs: Any) -> None:
        def emit(logger: logging.Logger) -> None:
            try:
                raise _KestrelProbeError("wolfram-secret-774")
            except _KestrelProbeError:
                logger.error("custom", exc_info=True)

        output = _render(logs.TextFormatter(), emit)

        assert output.rstrip(chr(0x0A)).endswith(" [exc_type=_KestrelProbeError]")
        assert "wolfram-secret-774" not in output

    def test_logs_text_message_escapes_control_and_format_characters(self, logs: Any) -> None:
        """An ANSI escape, a bidi override or a zero-width char can't reach a text log raw."""
        esc, rlo, zwsp = chr(0x1B), chr(0x202E), chr(0x200B)
        output = _render(
            logs.TextFormatter(),
            lambda logger: logger.warning("id %s", f"{esc}[31mred{rlo}txt{zwsp}"),
        )

        line = output.rstrip(chr(0x0A))
        assert all(c not in line for c in (esc, rlo, zwsp)), repr(line)
        assert line.endswith(f" — id {_esc(0x1B)}[31mred{_esc(0x202E)}txt{_esc(0x200B)}")

    def test_logs_text_stack_info_is_dropped(self, logs: Any) -> None:
        output = _render(
            logs.TextFormatter(), lambda logger: logger.info("with stack", stack_info=True)
        )

        assert output.count(chr(0x0A)) == 1
        assert "Stack (most recent call last)" not in output
        assert "test_logs.py" not in output


# ---------------------------------------------------------------------------
# 6. Both formatters cut query strings and fragments off URLs
# ---------------------------------------------------------------------------


def _formatter(logs: Any, name: str) -> logging.Formatter:
    """A fresh JsonFormatter ("json") or TextFormatter ("text")."""
    formatter: logging.Formatter = logs.JsonFormatter() if name == "json" else logs.TextFormatter()
    return formatter


def _message_of(output: str, name: str) -> str:
    """The message part of one rendered line."""
    if name == "json":
        return str(json.loads(output)["message"])
    return output


@pytest.mark.parametrize("formatter_name", ["json", "text"])
class TestUrlRedaction:
    """``GET https://h.example/p?q=secret#frag`` is logged as ``GET https://h.example/p``."""

    def test_logs_formatter_strips_query_and_fragment_from_message(
        self, logs: Any, formatter_name: str
    ) -> None:
        output = _render(
            _formatter(logs, formatter_name),
            lambda logger: logger.info("GET https://h.example/p?q=secret-7731#frag-7731"),
        )

        assert "https://h.example/p" in _message_of(output, formatter_name)
        assert "q=" not in output
        assert "secret-7731" not in output
        assert "frag-7731" not in output

    def test_logs_formatter_strips_query_from_formatted_args(
        self, logs: Any, formatter_name: str
    ) -> None:
        """httpx's own line shape: the URL arrives as a %-format argument."""
        output = _render(
            _formatter(logs, formatter_name),
            lambda logger: logger.info(
                'HTTP Request: %s %s "%s"',
                "GET",
                "https://gmail.googleapis.com/x?q=alice%40example.com",
                "HTTP/1.1 200 OK",
            ),
        )

        assert "https://gmail.googleapis.com/x" in _message_of(output, formatter_name)
        assert "alice" not in output

    def test_logs_formatter_strips_every_url_and_keeps_other_text(
        self, logs: Any, formatter_name: str
    ) -> None:
        output = _render(
            _formatter(logs, formatter_name),
            lambda logger: logger.info(
                "a http://one.example/a?t=kestrel-1 b https://two.example/b#kestrel-2 c"
            ),
        )

        message = _message_of(output, formatter_name)
        assert "http://one.example/a" in message
        assert "https://two.example/b" in message
        assert " b " in message
        assert "kestrel" not in output


# ---------------------------------------------------------------------------
# 7. main._configure_logging
# ---------------------------------------------------------------------------


@pytest.fixture()
def configure() -> Iterator[Callable[..., None]]:
    """main._configure_logging, with the root logger put back afterwards."""
    from admino import main

    with restored_logging():
        yield main._configure_logging


def _root_handler() -> logging.Handler:
    """The one root handler (fails when there isn't exactly one)."""
    handlers = logging.getLogger().handlers
    assert len(handlers) == 1, handlers
    return handlers[0]


class TestConfigureLogging:
    """One root StreamHandler with the request-id filter and the chosen formatter."""

    def test_logs_configure_logging_installs_one_stream_handler(
        self, configure: Callable[..., None]
    ) -> None:
        """Calling it twice still leaves exactly one handler, writing to ``stream``."""
        stream = io.StringIO()
        configure("INFO", "json", stream=stream)
        configure("INFO", "json", stream=stream)

        handler = _root_handler()
        assert isinstance(handler, logging.StreamHandler)
        assert handler.stream is stream

    def test_logs_configure_logging_handler_carries_request_id_filter(
        self, logs: Any, configure: Callable[..., None]
    ) -> None:
        configure("INFO", "text", stream=io.StringIO())

        assert any(isinstance(f, logs.RequestIdFilter) for f in _root_handler().filters)

    @pytest.mark.parametrize(
        ("log_format", "formatter_class"),
        [("json", "JsonFormatter"), ("text", "TextFormatter"), ("xml", "TextFormatter")],
        ids=["json", "text", "unknown-falls-back-to-text"],
    )
    def test_logs_configure_logging_picks_the_formatter(
        self,
        logs: Any,
        configure: Callable[..., None],
        log_format: str,
        formatter_class: str,
    ) -> None:
        configure("INFO", log_format, stream=io.StringIO())

        assert isinstance(_root_handler().formatter, getattr(logs, formatter_class))

    def test_logs_configure_logging_defaults_to_text(
        self, logs: Any, configure: Callable[..., None]
    ) -> None:
        configure("INFO", stream=io.StringIO())

        assert isinstance(_root_handler().formatter, logs.TextFormatter)

    def test_logs_configure_logging_defaults_to_stderr(
        self, configure: Callable[..., None]
    ) -> None:
        configure("INFO", "json")

        handler = _root_handler()
        assert isinstance(handler, logging.StreamHandler)
        assert handler.stream is sys.stderr

    def test_logs_configure_logging_invalid_level_falls_back_to_info(
        self, configure: Callable[..., None]
    ) -> None:
        configure("NOT_A_LEVEL", "json", stream=io.StringIO())

        assert logging.getLogger().level == logging.INFO

    def test_logs_configure_logging_json_writes_json_lines(
        self, configure: Callable[..., None]
    ) -> None:
        stream = io.StringIO()
        configure("INFO", "json", stream=stream)

        logging.getLogger("admino.probe").info("json probe %d", 5)

        entry = json.loads(stream.getvalue().splitlines()[-1])
        assert set(entry) == _BASE_KEYS
        assert (entry["logger"], entry["message"]) == ("admino.probe", "json probe 5")

    @pytest.mark.parametrize("root_level", ["DEBUG", "INFO"])
    @pytest.mark.parametrize("name", PINNED_THIRD_PARTY_LOGGERS)
    def test_logs_configure_logging_pins_third_party_logger_at_warning(
        self, configure: Callable[..., None], name: str, root_level: str
    ) -> None:
        configure(root_level, "text", stream=io.StringIO())

        assert logging.getLogger(name).getEffectiveLevel() == logging.WARNING

    def test_logs_configure_logging_silences_httpx_request_urls(
        self, configure: Callable[..., None]
    ) -> None:
        """httpx logs every request URL, query string and all, at INFO."""
        stream = io.StringIO()
        configure("DEBUG", "text", stream=stream)

        logging.getLogger("httpx").info(
            "HTTP Request: GET https://gmail.googleapis.com/x?q=alice%40example.com"
        )

        assert stream.getvalue() == ""

    def test_logs_configure_logging_silences_openai_debug_payloads(
        self, configure: Callable[..., None]
    ) -> None:
        """The OpenAI SDK logs whole request payloads (conversation content) at DEBUG."""
        stream = io.StringIO()
        configure("DEBUG", "json", stream=stream)

        logging.getLogger("openai._base_client").debug(
            "Request options: {'json_data': {'messages': [{'content': 'kestrel-secret-5521'}]}}"
        )

        assert stream.getvalue() == ""

    def test_logs_configure_logging_keeps_third_party_warnings(
        self, configure: Callable[..., None]
    ) -> None:
        stream = io.StringIO()
        configure("DEBUG", "text", stream=stream)

        logging.getLogger("httpx").warning("httpx pool warning 8812")

        assert "httpx pool warning 8812" in stream.getvalue()

    def test_logs_configure_logging_keeps_admino_debug_at_debug(
        self, configure: Callable[..., None]
    ) -> None:
        """The pin is specific to the third-party loggers: admino's DEBUG lines still show."""
        stream = io.StringIO()
        configure("DEBUG", "text", stream=stream)

        logging.getLogger("admino.probe").debug("admino debug 3391")

        assert "admino debug 3391" in stream.getvalue()


# ---------------------------------------------------------------------------
# 8. Static guards over src/admino
# ---------------------------------------------------------------------------

_LOG_METHODS: Final = frozenset(
    {"debug", "info", "warning", "error", "exception", "critical", "log"}
)
_LOGGER_NAMES: Final = frozenset({"logger", "_logger", "log", "_log", "logging", "LOGGER"})
# Identifiers that hold content (or credentials): never a log argument, except
# inside len(...) (a count is fine).
_CONTENT_IDENTIFIERS: Final = frozenset(
    {
        "email",
        "emails",
        "display_name",
        "recipient",
        "recipient_address",
        "subject",
        "title",
        "filename",
        "file_name",
        "body",
        "content",
        "query",
        "instructions",
        "password",
        "token",
        "message",
    }
)


def _source_files() -> list[Path]:
    """Every Python module under src/admino."""
    return sorted(p for p in _SRC_DIR.rglob("*.py") if "__pycache__" not in p.parts)


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _is_logger(node: ast.expr) -> bool:
    """True for ``logger``, ``self.logger``, ``logging`` and ``getLogger(...)`` receivers."""
    if isinstance(node, ast.Name):
        return node.id in _LOGGER_NAMES
    if isinstance(node, ast.Attribute):
        return node.attr in _LOGGER_NAMES
    if isinstance(node, ast.Call):
        func = node.func
        return (isinstance(func, ast.Attribute) and func.attr == "getLogger") or (
            isinstance(func, ast.Name) and func.id == "getLogger"
        )
    return False


def _log_calls(tree: ast.AST) -> Iterator[ast.Call]:
    """Every ``<logger>.<level>(...)`` call in ``tree``."""
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in _LOG_METHODS
            and _is_logger(node.func.value)
        ):
            yield node


def _content_references(node: ast.AST) -> list[str]:
    """Content identifiers (Name ids, Attribute attrs) in ``node``, skipping ``len(...)``."""
    found: list[str] = []
    stack: list[ast.AST] = [node]
    while stack:
        current = stack.pop()
        if (
            isinstance(current, ast.Call)
            and isinstance(current.func, ast.Name)
            and current.func.id == "len"
        ):
            continue
        if isinstance(current, ast.Name) and current.id in _CONTENT_IDENTIFIERS:
            found.append(current.id)
        elif isinstance(current, ast.Attribute) and current.attr in _CONTENT_IDENTIFIERS:
            found.append(current.attr)
        stack.extend(ast.iter_child_nodes(current))
    return found


def _content_offenders(tree: ast.AST, label: str) -> list[str]:
    """``label:line: identifiers`` for every log call that references content."""
    offenders: list[str] = []
    for call in _log_calls(tree):
        arguments = [*call.args, *(keyword.value for keyword in call.keywords)]
        hits = sorted({name for argument in arguments for name in _content_references(argument)})
        if hits:
            offenders.append(f"{label}:{call.lineno}: {', '.join(hits)}")
    return offenders


class TestLogsModuleIsolation:
    """admino/logs.py is standard-library only."""

    def test_logs_module_imports_only_the_standard_library(self) -> None:
        allowed = set(sys.stdlib_module_names) | {"__future__"}
        imported: list[str] = []
        for node in ast.walk(_parse(_LOGS_PATH)):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.append("." * node.level + (node.module or ""))

        assert [m for m in imported if m.split(".")[0] not in allowed] == []


class TestOneSafeLogHelper:
    """``admino.logs.safe_log`` is the one identifier sanitizer."""

    def test_logs_module_defines_safe_log(self) -> None:
        names = {
            node.name
            for node in ast.walk(_parse(_LOGS_PATH))
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        }

        assert {"safe_log", "safe_url"} <= names

    def test_logs_no_other_module_defines_a_safe_log(self) -> None:
        offenders: list[str] = []
        for path in _source_files():
            if path == _LOGS_PATH:
                continue
            for node in ast.walk(_parse(path)):
                defined: list[str] = []
                if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                    defined = [node.name]
                elif isinstance(node, ast.Assign):
                    defined = [t.id for t in node.targets if isinstance(t, ast.Name)]
                offenders.extend(
                    f"{path.relative_to(_SRC_DIR)}:{node.lineno}: {name}"
                    for name in defined
                    if name in {"safe_log", "_safe_log"}
                )

        assert offenders == []

    def test_logs_permissions_imports_safe_log_from_logs_module(self) -> None:
        imports = [
            alias.name
            for node in ast.walk(_parse(_SRC_DIR / "permissions.py"))
            if isinstance(node, ast.ImportFrom) and node.module == "admino.logs"
            for alias in node.names
        ]

        assert "safe_log" in imports

    def test_logs_permissions_private_safe_log_is_gone(self) -> None:
        import admino.permissions as permissions

        assert not hasattr(permissions, "_safe_log")


class TestNoContentInLogCalls:
    """No log call argument references a content identifier (counts via len() are fine)."""

    def test_logs_scanner_finds_the_log_calls(self) -> None:
        """The scan isn't vacuous: it sees the codebase's log calls."""
        calls = sum(len(list(_log_calls(_parse(path)))) for path in _source_files())

        assert calls >= 100

    @pytest.mark.parametrize(
        ("snippet", "flagged"),
        [
            ('logger.info("x %s", user.email)', True),
            ('logger.warning("x %s", display_name)', True),
            ('logger.error("x: %s", exc.message)', True),
            ('logger.info(f"sent {subject}")', True),
            ('logging.getLogger(__name__).info("x %s", body)', True),
            ('self.logger.debug("x %s", safe_log(title))', True),
            ('logger.info("x", extra={"q": query})', True),
            ('logger.info("x %d", len(body.messages))', False),
            ('logger.info("x %s", user_id)', False),
            ('logger.error("x %s", type(exc).__name__)', False),
            ('print("x", email)', False),
        ],
    )
    def test_logs_scanner_self_check(self, snippet: str, flagged: bool) -> None:
        assert bool(_content_offenders(ast.parse(snippet), "snippet")) is flagged

    def test_logs_no_log_call_references_content(self) -> None:
        offenders = [
            offender
            for path in _source_files()
            for offender in _content_offenders(_parse(path), str(path.relative_to(_SRC_DIR)))
        ]

        assert offenders == []

    def test_logs_no_logger_exception_calls(self) -> None:
        """``logger.exception`` writes a traceback (exception text) into the log."""
        offenders = [
            f"{path.relative_to(_SRC_DIR)}:{call.lineno}"
            for path in _source_files()
            for call in _log_calls(_parse(path))
            if isinstance(call.func, ast.Attribute) and call.func.attr == "exception"
        ]

        assert offenders == []

    def test_logs_no_exc_info_or_stack_info_on_log_calls(self) -> None:
        offenders = [
            f"{path.relative_to(_SRC_DIR)}:{call.lineno}: {keyword.arg}"
            for path in _source_files()
            for call in _log_calls(_parse(path))
            for keyword in call.keywords
            if keyword.arg in {"exc_info", "stack_info"}
        ]

        assert offenders == []


# ---------------------------------------------------------------------------
# 9. No third-party error tracking or analytics SDKs
# ---------------------------------------------------------------------------

# Name tokens (a package name split on - _ . / @) of error tracking, APM and
# analytics SDKs.
_DENIED_TOKENS: Final = frozenset(
    {
        "sentry",
        "raven",
        "rollbar",
        "bugsnag",
        "honeybadger",
        "airbrake",
        "pybrake",
        "raygun",
        "raygun4py",
        "raygun4js",
        "newrelic",
        "ddtrace",
        "datadog",
        "apm",
        "elasticapm",
        "appsignal",
        "trackjs",
        "posthog",
        "mixpanel",
        "segment",
        "amplitude",
        "logrocket",
        "hotjar",
        "heap",
        "gtag",
        "plausible",
        "analytics",
        "matomo",
        "fullstory",
    }
)
_DENIED_IMPORTS: Final = frozenset(
    {
        "sentry_sdk",
        "raven",
        "rollbar",
        "bugsnag",
        "honeybadger",
        "airbrake",
        "pybrake",
        "raygun4py",
        "newrelic",
        "ddtrace",
        "datadog",
        "elasticapm",
        "appsignal",
        "posthog",
        "mixpanel",
        "analytics",
        "segment",
        "amplitude",
    }
)
# SDK package names / script hosts in frontend code (word-bounded, case-insensitive).
_FRONTEND_SDK_PATTERN: Final = re.compile(
    r"@sentry/|\bsentry\b|\bposthog\b|\bmixpanel\b|\bgtag\b|googletagmanager|"
    r"google-analytics|googleAnalytics|\bplausible\.io\b|\blogrocket\b|\bhotjar\b|"
    r"@datadog/|\bdatadog\b|\bnewrelic\b|\bbugsnag\b|\brollbar\b|@amplitude/|"
    r"\bamplitude-js\b|cdn\.segment\.com|@segment/|heapanalytics|\braygun\b|"
    r"\bhoneybadger\b|\bairbrake\b|@elastic/apm|\bmatomo\b|\bfullstory\b",
    re.IGNORECASE,
)
_FRONTEND_SUFFIXES: Final = frozenset({".ts", ".js", ".mjs", ".vue", ".html", ".json", ".css"})
_REQUIREMENT_NAME: Final = re.compile(r"^\s*([A-Za-z0-9@][A-Za-z0-9._/@-]*)")


def _is_denied(package: str) -> bool:
    """True when a package name is an error tracking / analytics SDK."""
    tokens = {t for t in re.split(r"[-_./@]+", package.lower()) if t}
    return bool(tokens & _DENIED_TOKENS)


def _requirement_names(requirements: list[str]) -> list[str]:
    """The distribution names of PEP 508 requirement strings."""
    names: list[str] = []
    for requirement in requirements:
        match = _REQUIREMENT_NAME.match(requirement)
        if match:
            names.append(match.group(1))
    return names


def _frontend_files() -> list[Path]:
    """static-src's own source, entry HTML, build config and public assets."""
    static_src = _REPO_ROOT / "static-src"
    candidates = [
        *(static_src / "src").rglob("*"),
        *(static_src / "public").rglob("*"),
        static_src / "index.html",
        static_src / "vite.config.ts",
    ]
    return sorted(
        p
        for p in candidates
        if p.is_file()
        and p.suffix in _FRONTEND_SUFFIXES
        and not any(part.startswith(".") for part in p.relative_to(static_src).parts)
    )


class TestNoErrorTrackingOrAnalytics:
    """admino ships no third-party error tracking, APM or analytics SDK."""

    @pytest.mark.parametrize(
        ("package", "denied"),
        [
            ("sentry-sdk", True),
            ("@sentry/vue", True),
            ("posthog-js", True),
            ("vue-gtag", True),
            ("@google-analytics/data", True),
            ("elastic-apm", True),
            ("@datadog/browser-rum", True),
            ("analytics-python", True),
            ("httpx", False),
            ("google-api-python-client", False),
            ("vue-router", False),
            ("@vitejs/plugin-vue", False),
        ],
    )
    def test_logs_denylist_self_check(self, package: str, denied: bool) -> None:
        assert _is_denied(package) is denied

    def test_logs_pyproject_declares_no_tracking_sdk(self) -> None:
        project = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
            "project"
        ]
        requirements = list(project.get("dependencies", []))
        for extra in project.get("optional-dependencies", {}).values():
            requirements.extend(extra)
        names = _requirement_names(requirements)

        assert len(names) >= 5
        assert [n for n in names if _is_denied(n)] == []

    def test_logs_uv_lock_resolves_no_tracking_sdk(self) -> None:
        """No SDK arrives transitively either."""
        lock = tomllib.loads((_REPO_ROOT / "uv.lock").read_text(encoding="utf-8"))
        names = [str(package["name"]) for package in lock.get("package", [])]

        assert len(names) >= 10
        assert [n for n in names if _is_denied(n)] == []

    def test_logs_package_json_declares_no_tracking_sdk(self) -> None:
        package = json.loads((_REPO_ROOT / "static-src" / "package.json").read_text("utf-8"))
        names = [*package.get("dependencies", {}), *package.get("devDependencies", {})]

        assert len(names) >= 5
        assert [n for n in names if _is_denied(n)] == []

    def test_logs_backend_imports_no_tracking_sdk(self) -> None:
        offenders: list[str] = []
        for path in _source_files():
            for node in ast.walk(_parse(path)):
                modules: list[str] = []
                if isinstance(node, ast.Import):
                    modules = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                    modules = [node.module]
                offenders.extend(
                    f"{path.relative_to(_SRC_DIR)}:{node.lineno}: {m}"
                    for m in modules
                    if m.split(".")[0] in _DENIED_IMPORTS
                )

        assert offenders == []

    def test_logs_frontend_source_mentions_no_tracking_sdk(self) -> None:
        files = _frontend_files()
        offenders = [
            f"{path.relative_to(_REPO_ROOT)}: {match.group(0)}"
            for path in files
            for match in _FRONTEND_SDK_PATTERN.finditer(path.read_text("utf-8", errors="replace"))
        ]

        assert len(files) >= 10
        assert offenders == []

    def test_logs_no_tracking_sdk_policy_is_documented(self) -> None:
        """The AC says so: a doc states admino uses no error tracking or analytics SDK."""
        documents = [
            _REPO_ROOT / "SECURITY.md",
            _REPO_ROOT / "README.md",
            *sorted((_REPO_ROOT / "docs").glob("*.md")),
        ]
        paragraphs = [
            paragraph.lower()
            for document in documents
            if document.is_file()
            for paragraph in re.split(r"\n\s*\n", document.read_text(encoding="utf-8"))
        ]

        assert any(
            re.search(r"error[- ]tracking", paragraph) and "analytics" in paragraph
            for paragraph in paragraphs
        )


# ---------------------------------------------------------------------------
# 10. Operators can find the JSON switch
# ---------------------------------------------------------------------------


def test_logs_env_example_documents_log_format() -> None:
    """.env.example documents LOG_FORMAT (text or json) next to LOG_LEVEL."""
    env_text = (_REPO_ROOT / ".env.example").read_text(encoding="utf-8")

    assert re.search(r"(?m)^#?\s*LOG_FORMAT=(text|json)\s*$", env_text)
    assert "json" in env_text.lower()
