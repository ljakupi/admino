"""Tests for the append-only NDJSON audit logger.

Covers basic write behavior, append-only guarantees, schema validation,
credential leakage prevention, context manager protocol, close behavior,
file creation, concurrent writes, and the write-only API surface.
"""

from __future__ import annotations

import json
import threading
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from admino.audit import AuditLogger, open_audit_log
from admino.models import ConversationAuditEntry, ToolCallAuditEntry

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_conversation_entry(
    session_id: str = "sess-001",
    role: str = "user",
    content: str = "Hello, agent",
    model: str = "llama3",
    tool_calls_count: int = 0,
) -> ConversationAuditEntry:
    """Build a ConversationAuditEntry with sensible defaults."""
    return ConversationAuditEntry(
        session_id=session_id,
        role=role,  # type: ignore[arg-type]
        content=content,
        model=model,
        tool_calls_count=tool_calls_count,
    )


def _make_tool_call_entry(
    session_id: str = "sess-001",
    tool: str = "gmail",
    action: str = "read",
    permission: str = "allow",
    args_summary: str = "message_id=abc123",
    success: bool = True,
    error: str | None = None,
) -> ToolCallAuditEntry:
    """Build a ToolCallAuditEntry with sensible defaults."""
    return ToolCallAuditEntry(
        session_id=session_id,
        tool=tool,
        action=action,
        permission=permission,  # type: ignore[arg-type]
        args_summary=args_summary,
        success=success,
        error=error,
    )


def _read_ndjson_lines(path: Path) -> list[dict[str, object]]:
    """Read an NDJSON file and return a list of parsed dicts."""
    text = path.read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if line.strip()]
    return [json.loads(line) for line in lines]


# ---------------------------------------------------------------------------
# 1-3: Basic write behavior
# ---------------------------------------------------------------------------


class TestBasicWriteBehavior:
    """Tests for basic entry writing."""

    def test_conversation_entry_write(self, tmp_path: Path) -> None:
        """Log a ConversationAuditEntry, verify one valid JSON line with correct fields."""
        log_path = tmp_path / "audit.ndjson"
        entry = _make_conversation_entry()

        with AuditLogger(log_path) as logger:
            logger.log_conversation(entry)

        records = _read_ndjson_lines(log_path)
        assert len(records) == 1
        rec = records[0]
        assert rec["entry_type"] == "conversation"
        assert rec["session_id"] == "sess-001"
        assert rec["role"] == "user"
        assert rec["content"] == "Hello, agent"
        assert rec["model"] == "llama3"
        assert rec["tool_calls_count"] == 0

    def test_tool_call_entry_write(self, tmp_path: Path) -> None:
        """Log a ToolCallAuditEntry, verify JSON line with correct fields."""
        log_path = tmp_path / "audit.ndjson"
        entry = _make_tool_call_entry()

        with AuditLogger(log_path) as logger:
            logger.log_tool_call(entry)

        records = _read_ndjson_lines(log_path)
        assert len(records) == 1
        rec = records[0]
        assert rec["entry_type"] == "tool_call"
        assert rec["session_id"] == "sess-001"
        assert rec["tool"] == "gmail"
        assert rec["action"] == "read"
        assert rec["permission"] == "allow"
        assert rec["args_summary"] == "message_id=abc123"
        assert rec["success"] is True
        assert rec["error"] is None

    def test_multiple_entries_ndjson(self, tmp_path: Path) -> None:
        """Log several mixed entries, verify NDJSON format and correct count."""
        log_path = tmp_path / "audit.ndjson"
        entries_conv = [_make_conversation_entry(session_id=f"s{i}") for i in range(3)]
        entries_tool = [_make_tool_call_entry(session_id=f"t{i}") for i in range(2)]

        with AuditLogger(log_path) as logger:
            for e in entries_conv:
                logger.log_conversation(e)
            for e in entries_tool:
                logger.log_tool_call(e)

        records = _read_ndjson_lines(log_path)
        assert len(records) == 5
        assert sum(1 for r in records if r["entry_type"] == "conversation") == 3
        assert sum(1 for r in records if r["entry_type"] == "tool_call") == 2


# ---------------------------------------------------------------------------
# 4-5: Append-only behavior
# ---------------------------------------------------------------------------


class TestAppendOnlyBehavior:
    """Tests for append-only guarantees."""

    def test_append_mode_reopen(self, tmp_path: Path) -> None:
        """Close logger, reopen same file, verify old entries preserved."""
        log_path = tmp_path / "audit.ndjson"

        with AuditLogger(log_path) as logger:
            logger.log_conversation(_make_conversation_entry(session_id="first"))

        with AuditLogger(log_path) as logger:
            logger.log_conversation(_make_conversation_entry(session_id="second"))

        records = _read_ndjson_lines(log_path)
        assert len(records) == 2
        assert records[0]["session_id"] == "first"
        assert records[1]["session_id"] == "second"

    def test_no_truncation_of_preexisting_content(self, tmp_path: Path) -> None:
        """Pre-populate file with content, open AuditLogger, verify preserved."""
        log_path = tmp_path / "audit.ndjson"
        pre_existing = '{"pre": "existing"}\n'
        log_path.write_text(pre_existing, encoding="utf-8")

        with AuditLogger(log_path) as logger:
            logger.log_conversation(_make_conversation_entry())

        text = log_path.read_text(encoding="utf-8")
        assert text.startswith('{"pre": "existing"}')
        records = _read_ndjson_lines(log_path)
        assert len(records) == 2


# ---------------------------------------------------------------------------
# 6-8: Schema validation
# ---------------------------------------------------------------------------


class TestSchemaValidation:
    """Tests for serialized entry schema correctness."""

    @pytest.mark.parametrize(
        ("entry_factory", "expected_type"),
        [
            (_make_conversation_entry, "conversation"),
            (_make_tool_call_entry, "tool_call"),
        ],
        ids=["conversation", "tool_call"],
    )
    def test_entry_type_field(
        self,
        tmp_path: Path,
        entry_factory: object,
        expected_type: str,
    ) -> None:
        """Verify entry_type discriminator serializes correctly."""
        log_path = tmp_path / "audit.ndjson"
        entry = entry_factory()  # type: ignore[operator]

        with AuditLogger(log_path) as logger:
            if expected_type == "conversation":
                logger.log_conversation(entry)
            else:
                logger.log_tool_call(entry)

        records = _read_ndjson_lines(log_path)
        assert records[0]["entry_type"] == expected_type

    def test_timestamp_is_utc_iso8601(self, tmp_path: Path) -> None:
        """Verify timestamp contains UTC timezone marker."""
        log_path = tmp_path / "audit.ndjson"
        with AuditLogger(log_path) as logger:
            logger.log_conversation(_make_conversation_entry())

        records = _read_ndjson_lines(log_path)
        ts = str(records[0]["timestamp"])
        # Pydantic v2 serializes datetimes with UTC as +00:00 or Z
        assert "+00:00" in ts or ts.endswith("Z"), f"Timestamp not UTC: {ts}"

    def test_round_trip_conversation(self, tmp_path: Path) -> None:
        """Deserialize a written ConversationAuditEntry back to the model."""
        log_path = tmp_path / "audit.ndjson"
        original = _make_conversation_entry()

        with AuditLogger(log_path) as logger:
            logger.log_conversation(original)

        records = _read_ndjson_lines(log_path)
        restored = ConversationAuditEntry.model_validate(records[0])
        assert restored.session_id == original.session_id
        assert restored.role == original.role
        assert restored.content == original.content
        assert restored.model == original.model
        assert restored.entry_type == "conversation"

    def test_round_trip_tool_call(self, tmp_path: Path) -> None:
        """Deserialize a written ToolCallAuditEntry back to the model."""
        log_path = tmp_path / "audit.ndjson"
        original = _make_tool_call_entry(error="something failed")

        with AuditLogger(log_path) as logger:
            logger.log_tool_call(original)

        records = _read_ndjson_lines(log_path)
        restored = ToolCallAuditEntry.model_validate(records[0])
        assert restored.tool == original.tool
        assert restored.action == original.action
        assert restored.error == "something failed"


# ---------------------------------------------------------------------------
# 9-11: No credential leakage
# ---------------------------------------------------------------------------


class TestNoCredentialLeakage:
    """Tests ensuring no credentials appear in serialized output."""

    def test_args_summary_written_exactly(self, tmp_path: Path) -> None:
        """args_summary without credentials is written exactly as provided."""
        log_path = tmp_path / "audit.ndjson"
        entry = _make_tool_call_entry(args_summary="query=meeting notes, limit=10")

        with AuditLogger(log_path) as logger:
            logger.log_tool_call(entry)

        records = _read_ndjson_lines(log_path)
        assert records[0]["args_summary"] == "query=meeting notes, limit=10"

    def test_error_field_preserved(self, tmp_path: Path) -> None:
        """Error string is written as-is, including sanitized messages."""
        log_path = tmp_path / "audit.ndjson"
        sanitized_error = "Google API error: [CREDENTIAL_REDACTED]"
        entry = _make_tool_call_entry(error=sanitized_error)

        with AuditLogger(log_path) as logger:
            logger.log_tool_call(entry)

        records = _read_ndjson_lines(log_path)
        assert records[0]["error"] == sanitized_error

    @pytest.mark.parametrize(
        "forbidden_key",
        ["token", "password", "secret", "api_key", "Bearer"],
        ids=["token", "password", "secret", "api_key", "Bearer"],
    )
    def test_no_credential_keys_in_output(self, tmp_path: Path, forbidden_key: str) -> None:
        """Serialized JSON keys must not include credential-like field names."""
        log_path = tmp_path / "audit.ndjson"
        with AuditLogger(log_path) as logger:
            logger.log_conversation(_make_conversation_entry())
            logger.log_tool_call(_make_tool_call_entry())

        records = _read_ndjson_lines(log_path)
        for rec in records:
            assert forbidden_key not in rec, (
                f"Found forbidden key '{forbidden_key}' in audit output keys"
            )


# ---------------------------------------------------------------------------
# 12-13: Context manager
# ---------------------------------------------------------------------------


class TestContextManager:
    """Tests for context manager protocol."""

    def test_context_manager_closes_file(self, tmp_path: Path) -> None:
        """File is closed after exiting the with block."""
        log_path = tmp_path / "audit.ndjson"

        with AuditLogger(log_path) as logger:
            logger.log_conversation(_make_conversation_entry())

        # After exiting, the underlying file should be closed
        assert logger._file.closed

    def test_context_manager_on_exception(self, tmp_path: Path) -> None:
        """File is closed even if an exception is raised inside the with block."""
        log_path = tmp_path / "audit.ndjson"

        with pytest.raises(RuntimeError, match="boom"), AuditLogger(log_path) as logger:
            logger.log_conversation(_make_conversation_entry())
            msg = "boom"
            raise RuntimeError(msg)

        assert logger._file.closed
        # The entry before the exception should be persisted
        records = _read_ndjson_lines(log_path)
        assert len(records) == 1


# ---------------------------------------------------------------------------
# 14-15: Close behavior
# ---------------------------------------------------------------------------


class TestCloseBehavior:
    """Tests for close() semantics."""

    def test_close_is_idempotent(self, tmp_path: Path) -> None:
        """Calling close() twice does not raise."""
        log_path = tmp_path / "audit.ndjson"
        logger = AuditLogger(log_path)
        logger.close()
        logger.close()  # Should not raise

    def test_write_after_close_raises(self, tmp_path: Path) -> None:
        """Writing after close() raises ValueError."""
        log_path = tmp_path / "audit.ndjson"
        logger = AuditLogger(log_path)
        logger.close()

        with pytest.raises(ValueError):
            logger.log_conversation(_make_conversation_entry())

    def test_write_tool_call_after_close_raises(self, tmp_path: Path) -> None:
        """Writing a tool call after close() raises ValueError."""
        log_path = tmp_path / "audit.ndjson"
        logger = AuditLogger(log_path)
        logger.close()

        with pytest.raises(ValueError):
            logger.log_tool_call(_make_tool_call_entry())


# ---------------------------------------------------------------------------
# 16-17: File creation
# ---------------------------------------------------------------------------


class TestFileCreation:
    """Tests for automatic directory and file creation."""

    def test_parent_directories_created(self, tmp_path: Path) -> None:
        """Non-existent nested parent directories are created automatically."""
        log_path = tmp_path / "a" / "b" / "c" / "audit.ndjson"
        assert not log_path.parent.exists()

        with AuditLogger(log_path) as logger:
            logger.log_conversation(_make_conversation_entry())

        assert log_path.exists()
        records = _read_ndjson_lines(log_path)
        assert len(records) == 1

    def test_open_audit_log_factory(self, tmp_path: Path) -> None:
        """open_audit_log() returns a working AuditLogger."""
        log_path = tmp_path / "audit.ndjson"
        logger = open_audit_log(log_path)

        try:
            logger.log_conversation(_make_conversation_entry())
            logger.log_tool_call(_make_tool_call_entry())
        finally:
            logger.close()

        records = _read_ndjson_lines(log_path)
        assert len(records) == 2
        assert records[0]["entry_type"] == "conversation"
        assert records[1]["entry_type"] == "tool_call"


# ---------------------------------------------------------------------------
# 18: Concurrent writes (thread safety)
# ---------------------------------------------------------------------------


class TestConcurrentWrites:
    """Tests for thread-safe writing."""

    def test_concurrent_writes_no_interleaving(self, tmp_path: Path) -> None:
        """10 threads x 10 entries = 100 valid NDJSON lines, no interleaving."""
        log_path = tmp_path / "audit.ndjson"
        num_threads = 10
        entries_per_thread = 10

        with AuditLogger(log_path) as logger:
            barrier = threading.Barrier(num_threads)

            def writer(thread_id: int) -> None:
                barrier.wait()
                for i in range(entries_per_thread):
                    entry = _make_conversation_entry(
                        session_id=f"t{thread_id}-e{i}",
                    )
                    logger.log_conversation(entry)

            threads = [threading.Thread(target=writer, args=(tid,)) for tid in range(num_threads)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        records = _read_ndjson_lines(log_path)
        assert len(records) == num_threads * entries_per_thread

        # Every line must be independently valid JSON
        raw_lines = [
            line for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()
        ]
        for i, line in enumerate(raw_lines):
            try:
                json.loads(line)
            except json.JSONDecodeError:
                pytest.fail(f"Line {i} is not valid JSON (possible interleaving): {line!r}")


# ---------------------------------------------------------------------------
# 19: No read API
# ---------------------------------------------------------------------------


class TestNoReadAPI:
    """Tests verifying the write-only API surface."""

    @pytest.mark.parametrize(
        "method_name",
        ["read", "readlines", "get", "fetch", "query"],
        ids=["read", "readlines", "get", "fetch", "query"],
    )
    def test_no_read_methods(self, method_name: str) -> None:
        """AuditLogger must not expose any read-like methods."""
        assert not hasattr(AuditLogger, method_name), (
            f"AuditLogger should not have a '{method_name}' method"
        )
