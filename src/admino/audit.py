"""Append-only NDJSON audit logger for conversation turns and tool calls.

Provides write-only access to the audit log file. Each entry is serialized
as a single JSON line (NDJSON format) and flushed immediately to disk.

Security notes:
- Write-only access pattern: no read API is exposed, preventing the agent
  from reading its own audit log.
- Append-only: the file is opened with mode="a" and never truncated or
  overwritten.
- Path confinement: the log path is validated to reside under the expected
  base directory, preventing symlink/traversal attacks.
- Credential sanitization: audit entry models enforce automatic redaction
  of credential patterns via field validators. This module trusts those
  validators; entries constructed via model_construct() bypass all
  validation and must never be passed to log methods with untrusted data.
  See README.md "Architecture Decisions" for the threat model rationale.
- Thread-safe: all writes are protected by a threading.Lock.
- Write failures raise AuditWriteError so callers can handle them explicitly.
"""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path  # noqa: TC003 — runtime use required
from typing import TYPE_CHECKING

from admino.models import (  # noqa: TC001 — runtime import for call-boundary type safety
    ConversationAuditEntry,
    ToolCallAuditEntry,
)

if TYPE_CHECKING:
    from io import TextIOWrapper
    from types import TracebackType

logger = logging.getLogger(__name__)

# Cached at import time so it cannot be mutated between import and instantiation.
_IS_PRODUCTION: bool = os.environ.get("ADMINO_ENV", "").lower() == "production"


class AuditWriteError(Exception):
    """Raised when an audit log entry cannot be written to disk.

    Callers should catch this specifically to avoid silently dropping
    audit entries or crashing the server on transient I/O errors.
    """


class AuditLogger:
    """Thread-safe, append-only NDJSON audit logger.

    Opens a log file in append mode and writes validated Pydantic audit
    entries as single JSON lines. Each write is flushed immediately.

    Usable as a context manager::

        with AuditLogger(log_path, base_dir=data_dir) as audit:
            audit.log_conversation(entry)
    """

    def __init__(self, log_path: Path, *, base_dir: Path | None) -> None:
        """Open the audit log file in append mode.

        Creates parent directories if they do not exist.

        Args:
            log_path: Path to the NDJSON audit log file.
            base_dir: Expected parent directory. The resolved log_path must
                reside under this directory (prevents path traversal and
                symlink attacks). Pass None explicitly to disable confinement
                (not recommended in production; raises ValueError if
                ADMINO_ENV=production). Note: base_dir's own permissions are
                the caller's responsibility — only directories *under*
                base_dir are chmod'd to 0o700.

        Raises:
            AuditWriteError: If the file cannot be opened.
            ValueError: If log_path resolves outside base_dir.
        """
        resolved = log_path.resolve()
        resolved_base: Path | None = None
        if base_dir is None:
            # In production, base_dir=None disables all path confinement.
            # _IS_PRODUCTION is cached at import time to prevent runtime mutation.
            if _IS_PRODUCTION:
                msg = (
                    "base_dir=None is not allowed in production. "
                    "Set base_dir to enable path confinement."
                )
                raise ValueError(msg)
            logger.critical(
                "AuditLogger opened without base_dir — path confinement disabled. "
                "Pass base_dir in production to prevent path traversal attacks."
            )
        else:
            resolved_base = base_dir.resolve()
            if not resolved.is_relative_to(resolved_base):
                # Static message — do not include resolved paths in the
                # exception or any log output. The exception message may
                # propagate to HTTP responses or external loggers.
                msg = "Audit log path is outside the permitted base directory."
                raise ValueError(msg)
        try:
            resolved.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            # mkdir(mode=0o700, parents=True) may be reduced by the process
            # umask. Explicitly chmod all directories under base_dir to 0o700.
            # When resolved.parent == resolved_base, the loop body never
            # executes (zero iterations) — this is intentional: base_dir's
            # permissions are the caller's responsibility.
            if resolved_base is not None:
                cursor = resolved.parent
                while cursor != resolved_base and cursor != cursor.parent:
                    cursor.chmod(0o700)
                    cursor = cursor.parent
            else:
                # Even without base_dir, ensure the leaf dir is 0o700.
                resolved.parent.chmod(0o700)
            # Open the parent directory with O_DIRECTORY | O_NOFOLLOW to get
            # a trusted directory fd, then open the log file relative to it
            # via dir_fd. This narrows the TOCTOU window between resolve()
            # and os.open() — an attacker would need to replace the directory
            # itself (not just a path component) to redirect the open.
            # O_NOFOLLOW on the file refuses symlinks at the final component.
            # 0o600 restricts the file to the owning user, consistent with
            # the 0o700 directory above.
            # getattr fallback: O_DIRECTORY may be absent on some platforms.
            _o_directory = getattr(os, "O_DIRECTORY", 0)
            parent_fd = os.open(
                resolved.parent,
                os.O_RDONLY | _o_directory | os.O_NOFOLLOW,
            )
            try:
                fd = os.open(
                    resolved.name,
                    os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=parent_fd,
                )
            finally:
                os.close(parent_fd)
            try:
                self._file: TextIOWrapper = open(  # noqa: SIM115
                    fd,
                    mode="a",
                    encoding="utf-8",
                    errors="strict",
                )
            except Exception:
                os.close(fd)
                raise
        except OSError as exc:
            # Static message — do not interpolate exc into the log line because
            # OSError.__str__() includes the resolved filesystem path, which
            # could leak directory layout via the logging subsystem.
            logger.error("Cannot open audit log — see exception chain for details")
            raise AuditWriteError("Cannot open audit log — see server logs for details") from exc
        self._lock: threading.Lock = threading.Lock()

    def log_conversation(self, entry: ConversationAuditEntry) -> None:
        """Append a conversation audit entry as a single NDJSON line.

        Args:
            entry: A validated ConversationAuditEntry to log.

        Raises:
            AuditWriteError: If the write or flush fails.
        """
        # SECURITY: entry must be created via normal Pydantic construction,
        # not model_construct(), to ensure credential redaction runs.
        self.__write_entry(entry.model_dump_json())

    def log_tool_call(self, entry: ToolCallAuditEntry) -> None:
        """Append a tool call audit entry as a single NDJSON line.

        Args:
            entry: A validated ToolCallAuditEntry to log.

        Raises:
            AuditWriteError: If the write or flush fails.
        """
        # SECURITY: entry must be created via normal Pydantic construction,
        # not model_construct(), to ensure credential redaction runs.
        self.__write_entry(entry.model_dump_json())

    def __write_entry(self, json_line: str) -> None:
        """Write a single JSON line to the audit log and flush.

        INTERNAL — do not call directly. Use log_conversation() or
        log_tool_call() which enforce Pydantic model validation.

        Thread-safe: acquires the lock before writing.

        Args:
            json_line: A complete JSON string (no trailing newline).

        Raises:
            AuditWriteError: If the write or flush fails.
            ValueError: If json_line contains newlines (NDJSON corruption).
        """
        # IMPORTANT: This guard MUST remain OUTSIDE the try/except block below.
        # The except catches ValueError (from TextIOWrapper on closed file),
        # and moving this guard inside would silently wrap a programming error
        # into an opaque AuditWriteError, hiding the root cause.
        #
        # Defence-in-depth: Pydantic's model_dump_json() JSON-escapes
        # newlines in field values (e.g. \n -> \\n), so this guard should
        # never fire for entries created via log_conversation/log_tool_call.
        # It exists to catch any future misuse that bypasses Pydantic.
        if "\n" in json_line or "\r" in json_line:
            msg = "json_line must not contain newlines (NDJSON corruption risk)"
            raise ValueError(msg)
        try:
            with self._lock:
                self._file.write(json_line + "\n")
                self._file.flush()
        except (OSError, ValueError) as exc:
            # Static message only — never include json_line or entry content
            # in the log to prevent accidental credential leakage.
            logger.error("Audit write failed (I/O error)")
            raise AuditWriteError("Audit write failed — see server logs for details") from exc

    def close(self) -> None:
        """Close the underlying file handle.

        Safe to call multiple times -- subsequent calls are no-ops.
        TextIOWrapper.close() calls flush() internally, so no
        explicit pre-flush is needed.

        Known limitation: the lock is held during close(), which calls
        flush() (a blocking I/O operation). If flush blocks (e.g. NFS
        stall, disk full), concurrent __write_entry calls will block on
        the lock. This is an intentional tradeoff — releasing the lock
        before close() would allow writes to a closing file handle.
        """
        # IMPORTANT: the lock must be held for the entire check-and-close
        # sequence. Do not call self._file.close() outside this lock —
        # concurrent __write_entry calls depend on the lock to prevent
        # writes to a closing/closed file handle.
        with self._lock:
            if not self._file.closed:
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


def open_audit_log(log_path: Path, *, base_dir: Path | None) -> AuditLogger:
    """Create and return an AuditLogger for the given path.

    Convenience factory function.

    Args:
        log_path: Path to the NDJSON audit log file.
        base_dir: Expected parent directory for path confinement.
            Pass None explicitly to disable confinement (not recommended
            in production).

    Returns:
        An open AuditLogger instance ready for writing.

    Raises:
        AuditWriteError: If the file or parent directories cannot be created/opened.
        ValueError: If log_path resolves outside base_dir.
    """
    return AuditLogger(log_path, base_dir=base_dir)
