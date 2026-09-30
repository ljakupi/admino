"""Log hygiene for admino: identifier sanitizing, URL redaction, request IDs, formatters.

Application logs carry IDs, counts, sizes, statuses and durations only (GH-158,
tracker #139 "No content in logs"). This module holds the pieces every log
line goes through:

- ``safe_log(value, max_len=64)``: THE sanitizer for identifiers in log
  arguments. ``str(value)`` cut to ``max_len`` characters, then every
  non-printable or Unicode format (``Cf``) character becomes ``\\uXXXX``.
- ``safe_url(url)``: ``scheme://host[:port]/path``; the query string, the
  fragment and any userinfo are dropped. An unparseable URL is the fixed
  ``"[invalid url]"``, never the input.
- ``request_id_var``: the current HTTP request's ID (set by the server's
  request-ID middleware, None outside a request), and ``RequestIdFilter``,
  which copies it onto every record as ``record.request_id``.
- ``JsonFormatter`` (one JSON object per line: ``ts``, ``level``, ``logger``,
  ``message``, ``request_id``, plus ``exc_type``) and ``TextFormatter``
  (``<asctime> <LEVEL> <logger> [<request_id or ->] — <message>``).

Security notes:
- Neither formatter ever writes a traceback, an exception message or
  ``stack_info``: an exception is named by its bare class name only
  (``exc_type``). ``extra=`` fields are never emitted, and a caller can't forge
  the request ID (the filter overwrites it).
- Both formatters cut the query string and fragment off every http(s) URL in
  the formatted message (%-arguments included), so an httpx "HTTP Request:"
  line or an OAuth callback URL never logs ``?q=`` or ``?code=``.
- One record is one line, free of terminal control sequences: JSON escapes
  control characters, and the text formatter escapes every non-printable or
  format character in the message (line breaks, ANSI escapes, bidi overrides,
  zero-width characters) as ``safe_log`` does, so a value can't forge a line
  or rewrite what an operator's terminal shows.
- Standard library only (tests/test_logs.py enforces it): it is imported by
  the isolated permission engine and must pull in nothing else.
"""

from __future__ import annotations

import json
import logging
import re
import unicodedata
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Final
from urllib.parse import urlsplit, urlunsplit

# The current HTTP request's ID (uuid4().hex), set by the server's request-ID
# middleware for the request's duration; None outside a request.
request_id_var: ContextVar[str | None] = ContextVar("admino_request_id", default=None)

_INVALID_URL: Final = "[invalid url]"
# An http(s) URL with a query string and/or fragment: group 1 is the part
# before the first "?" or "#"; the rest runs to the next space or quote.
_URL_WITH_QUERY: Final = re.compile(r"(https?://[^\s?#\"'<>]*)[?#][^\s\"'<>]*", re.IGNORECASE)
_TEXT_DATEFMT: Final = "%Y-%m-%dT%H:%M:%S%z"


def _escape(text: str) -> str:
    """Replace every non-printable or format (Cf) character with ``\\uXXXX``."""
    return "".join(
        c if c.isprintable() and unicodedata.category(c) != "Cf" else f"\\u{ord(c):04x}"
        for c in text
    )


def safe_log(value: object, max_len: int = 64) -> str:
    """Return ``value`` as a string that is safe to put in a log line.

    ``str(value)`` is cut to ``max_len`` characters first, then control,
    format (bidi overrides, zero-width) and other non-printable characters are
    escaped as ``\\uXXXX``, so an identifier can't inject ANSI sequences or a
    forged line. Use it for identifiers only: content never belongs in a log.

    Args:
        value: Any object (an id, a tool name, a status).
        max_len: The maximum number of input characters kept.

    Returns:
        The truncated, escaped string.
    """
    return _escape(str(value)[:max_len])


def safe_url(url: str) -> str:
    """Return ``url`` reduced to ``scheme://host[:port]/path`` for logging.

    The query string, the fragment and any userinfo (``user:pass@``) are
    dropped; non-printable characters are escaped as in ``safe_log``.

    Args:
        url: The URL to log.

    Returns:
        The reduced URL, or ``"[invalid url]"`` when it can't be parsed (the
        input itself is never returned).
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return _INVALID_URL
    host = parts.netloc.rpartition("@")[2]
    return _escape(urlunsplit((parts.scheme, host, parts.path, "", "")))


def _redact_urls(message: str) -> str:
    """Cut the query string and fragment off every http(s) URL in ``message``."""
    return _URL_WITH_QUERY.sub(r"\1", message)


def _exc_type(record: logging.LogRecord) -> str | None:
    """The bare class name of the record's exception, or None without one."""
    if record.exc_info and record.exc_info[0] is not None:
        return record.exc_info[0].__name__
    return None


class RequestIdFilter(logging.Filter):
    """Copy the current request's ID (or None) onto every record as ``request_id``.

    Overwrites any ``request_id`` a caller passed through ``extra=``, so a log
    call can't forge it. Never drops a record.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """Set ``record.request_id`` from ``request_id_var``; always keep the record."""
        record.request_id = request_id_var.get()
        return True


class JsonFormatter(logging.Formatter):
    """One JSON object per line: ts, level, logger, message, request_id (+ exc_type).

    ``ts`` is ISO-8601 in UTC. ``exc_type`` (the exception's bare class name) is
    present only when the record has exc_info. Nothing else is ever emitted:
    no traceback, exception message, stack_info or ``extra=`` field.
    """

    def format(self, record: logging.LogRecord) -> str:
        """Render ``record`` as one JSON line."""
        entry: dict[str, str | None] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": _redact_urls(record.getMessage()),
            "request_id": getattr(record, "request_id", None),
        }
        exc_type = _exc_type(record)
        if exc_type is not None:
            entry["exc_type"] = exc_type
        return json.dumps(entry)


class TextFormatter(logging.Formatter):
    """``<asctime> <LEVEL> <logger> [<request_id or ->] — <message>`` (+ exc_type).

    An exception adds `` [exc_type=<ClassName>]``; no traceback, exception
    message or stack_info is ever written. Non-printable and format characters
    in the message (line breaks, ANSI escapes, bidi overrides) are escaped as
    ``\\uXXXX``, so a record is always one line with no control sequences.
    """

    def format(self, record: logging.LogRecord) -> str:
        """Render ``record`` as one text line."""
        request_id = getattr(record, "request_id", None) or "-"
        message = _escape(_redact_urls(record.getMessage()))
        line = (
            f"{self.formatTime(record, _TEXT_DATEFMT)} {record.levelname:<8} {record.name} "
            f"[{request_id}] — {message}"
        )
        exc_type = _exc_type(record)
        if exc_type is not None:
            line += f" [exc_type={exc_type}]"
        return line
