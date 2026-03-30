"""Append-only NDJSON audit logger for conversation turns and tool calls.

Provides write-only access to the audit log file. Each entry is serialized
as a single JSON line (NDJSON format) and flushed immediately to disk.

Security notes:
- Write-only access pattern: no read API is exposed, preventing the agent
  from reading its own audit log.
- Append-only: the file is opened with mode="a" and never truncated or
  overwritten.
- Credential sanitization: callers must sanitize error messages before
  passing them to ToolCallAuditEntry. This module does not perform
  additional sanitization -- it trusts the Pydantic model constraints.
- Thread-safe: all writes are protected by a threading.Lock.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from io import TextIOWrapper
    from pathlib import Path
    from types import TracebackType

    from admino.models import ConversationAuditEntry, ToolCallAuditEntry


class AuditLogger:
    """Thread-safe, append-only NDJSON audit logger.

    Opens a log file in append mode and writes validated Pydantic audit
    entries as single JSON lines. Each write is flushed immediately.

    Usable as a context manager::

        with AuditLogger(log_path) as logger:
            logger.log_conversation(entry)
    """

    def __init__(self, log_path: Path) -> None:
        """Open the audit log file in append mode.

        Creates parent directories if they do not exist.

        Args:
            log_path: Path to the NDJSON audit log file.

        Raises:
            OSError: If the file or parent directories cannot be created/opened.
        """
        log_path.parent.mkdir(parents=True, exist_ok=True)
        self._file: TextIOWrapper = open(  # noqa: SIM115
            log_path, mode="a", encoding="utf-8"
        )
        self._lock: threading.Lock = threading.Lock()

    def log_conversation(self, entry: ConversationAuditEntry) -> None:
        """Append a conversation audit entry as a single NDJSON line.

        Args:
            entry: A validated ConversationAuditEntry to log.

        Raises:
            OSError: If the write or flush fails.
            ValueError: If the file handle is already closed.
        """
        self._write_entry(entry.model_dump_json())

    def log_tool_call(self, entry: ToolCallAuditEntry) -> None:
        """Append a tool call audit entry as a single NDJSON line.

        Args:
            entry: A validated ToolCallAuditEntry to log.

        Raises:
            OSError: If the write or flush fails.
            ValueError: If the file handle is already closed.
        """
        self._write_entry(entry.model_dump_json())

    def _write_entry(self, json_line: str) -> None:
        """Write a single JSON line to the audit log and flush.

        Thread-safe: acquires the lock before writing.

        Args:
            json_line: A complete JSON string (no trailing newline).

        Raises:
            OSError: If the write or flush fails.
            ValueError: If the file handle is already closed.
        """
        with self._lock:
            self._file.write(json_line + "\n")
            self._file.flush()

    def close(self) -> None:
        """Flush and close the underlying file handle.

        Safe to call multiple times -- subsequent calls are no-ops.
        """
        with self._lock:
            if not self._file.closed:
                self._file.flush()
                self._file.close()

    def __enter__(self) -> AuditLogger:
        """Enter the context manager, returning self."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Exit the context manager, closing the file handle.

        Does not suppress any exceptions.
        """
        self.close()


def open_audit_log(log_path: Path) -> AuditLogger:
    """Create and return an AuditLogger for the given path.

    Convenience factory function. Equivalent to ``AuditLogger(log_path)``.

    Args:
        log_path: Path to the NDJSON audit log file.

    Returns:
        An open AuditLogger instance ready for writing.

    Raises:
        OSError: If the file or parent directories cannot be created/opened.
    """
    return AuditLogger(log_path)
