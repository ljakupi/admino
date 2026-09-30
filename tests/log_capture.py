"""Capture admino's configured log output for the log-hygiene tests (GH-158).

``main._configure_logging(level, log_format, stream=...)`` replaces the root
logger's handlers with ONE ``StreamHandler`` (a ``RequestIdFilter`` plus the
JSON or text formatter) and pins the chatty third-party loggers at WARNING.
Those are process-wide changes, so the tests use these context managers inside
the test body: they save the root handlers, the root level and the pinned
loggers' levels on entry and put them back on exit, before pytest's own
per-phase capture handlers are removed. (A fixture teardown would put back
the *setup* phase's capture handlers, which pytest has already detached, and
leak them onto the root logger.)

Inputs: a log level name and a log format ("json" or "text").
Outputs: a ``CapturedLogs`` with the formatted text (exactly what an operator
would see) and the raw ``LogRecord`` objects that reached the root handlers.

Security notes:
- Only in-memory streams are used; nothing is written to disk.
- ``admino.main`` is imported lazily, so a test module that uses these helpers
  still collects before GH-158 is implemented (each test then fails on the
  missing ``log_format`` / ``stream`` parameters).
"""

from __future__ import annotations

import io
import json
import logging
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from collections.abc import Iterator

# The third-party loggers _configure_logging pins at WARNING (they log request
# URLs with query strings at INFO, or whole request payloads at DEBUG).
PINNED_THIRD_PARTY_LOGGERS: Final[tuple[str, ...]] = (
    "httpx",
    "httpcore",
    "openai",
    "anthropic",
    "googleapiclient",
    "urllib3",
)


class RecordList(logging.Handler):
    """A handler that keeps every record it receives, unformatted."""

    def __init__(self) -> None:
        super().__init__(level=logging.NOTSET)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        """Keep the record."""
        self.records.append(record)


@dataclass
class CapturedLogs:
    """What the configured root handler wrote, plus the raw records."""

    stream: io.StringIO
    raw: RecordList = field(default_factory=RecordList)

    @property
    def text(self) -> str:
        """Everything the configured handler wrote so far."""
        return self.stream.getvalue()

    @property
    def records(self) -> list[logging.LogRecord]:
        """Every record that reached the root handlers."""
        return self.raw.records

    def lines(self) -> list[str]:
        """The non-empty output lines."""
        return [line for line in self.text.splitlines() if line]

    def json_lines(self) -> list[dict[str, Any]]:
        """The output lines parsed as JSON objects (log_format "json" only)."""
        return [json.loads(line) for line in self.lines()]


@contextmanager
def restored_logging() -> Iterator[None]:
    """Put the root handlers, root level and pinned logger levels back on exit."""
    root = logging.getLogger()
    saved_handlers = list(root.handlers)
    saved_level = root.level
    saved_levels = {name: logging.getLogger(name).level for name in PINNED_THIRD_PARTY_LOGGERS}
    try:
        yield
    finally:
        root.handlers = saved_handlers
        root.setLevel(saved_level)
        for name, level in saved_levels.items():
            logging.getLogger(name).setLevel(level)


@contextmanager
def configured_logging(level: str = "INFO", log_format: str = "json") -> Iterator[CapturedLogs]:
    """Configure logging the way main() does, into an in-memory stream.

    A ``RecordList`` is added to the root logger after the configured handler,
    so a test can also check the raw records (``exc_info``, ``stack_info``).
    """
    from admino import main

    with restored_logging():
        captured = CapturedLogs(stream=io.StringIO())
        main._configure_logging(level, log_format, stream=captured.stream)
        logging.getLogger().addHandler(captured.raw)
        yield captured
