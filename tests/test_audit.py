"""Tests for the append-only NDJSON audit logger.

Covers basic write behavior, append-only guarantees, schema validation,
credential leakage prevention, context manager protocol, close behavior,
file creation, concurrent writes, and the write-only API surface.
"""

from __future__ import annotations

import json
import logging
import os
import stat
import threading
from typing import TYPE_CHECKING, ClassVar

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from admino.audit import AuditLogger, AuditWriteError, open_audit_log
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

        with AuditLogger(log_path, base_dir=tmp_path) as logger:
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

        with AuditLogger(log_path, base_dir=tmp_path) as logger:
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

        with AuditLogger(log_path, base_dir=tmp_path) as logger:
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

        with AuditLogger(log_path, base_dir=tmp_path) as logger:
            logger.log_conversation(_make_conversation_entry(session_id="first"))

        with AuditLogger(log_path, base_dir=tmp_path) as logger:
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

        with AuditLogger(log_path, base_dir=tmp_path) as logger:
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

        with AuditLogger(log_path, base_dir=tmp_path) as logger:
            if expected_type == "conversation":
                logger.log_conversation(entry)
            else:
                logger.log_tool_call(entry)

        records = _read_ndjson_lines(log_path)
        assert records[0]["entry_type"] == expected_type

    def test_timestamp_is_utc_iso8601(self, tmp_path: Path) -> None:
        """Verify timestamp contains UTC timezone marker."""
        log_path = tmp_path / "audit.ndjson"
        with AuditLogger(log_path, base_dir=tmp_path) as logger:
            logger.log_conversation(_make_conversation_entry())

        records = _read_ndjson_lines(log_path)
        ts = str(records[0]["timestamp"])
        # Pydantic v2 may use +00:00 or Z depending on version/platform
        assert "+00:00" in ts or ts.endswith("Z"), f"Timestamp not UTC: {ts}"

    def test_round_trip_conversation(self, tmp_path: Path) -> None:
        """Deserialize a written ConversationAuditEntry back to the model."""
        log_path = tmp_path / "audit.ndjson"
        original = _make_conversation_entry()

        with AuditLogger(log_path, base_dir=tmp_path) as logger:
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

        with AuditLogger(log_path, base_dir=tmp_path) as logger:
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

        with AuditLogger(log_path, base_dir=tmp_path) as logger:
            logger.log_tool_call(entry)

        records = _read_ndjson_lines(log_path)
        assert records[0]["args_summary"] == "query=meeting notes, limit=10"

    def test_error_field_preserved(self, tmp_path: Path) -> None:
        """Error string is written as-is, including sanitized messages."""
        log_path = tmp_path / "audit.ndjson"
        sanitized_error = "Google API error: [CREDENTIAL_REDACTED]"
        entry = _make_tool_call_entry(error=sanitized_error)

        with AuditLogger(log_path, base_dir=tmp_path) as logger:
            logger.log_tool_call(entry)

        records = _read_ndjson_lines(log_path)
        assert records[0]["error"] == sanitized_error

    @pytest.mark.parametrize(
        "forbidden_key",
        ["token", "password", "secret", "api_key", "Bearer"],
        ids=["token", "password", "secret", "api_key", "Bearer"],
    )
    def test_no_credential_keys_in_output(self, tmp_path: Path, forbidden_key: str) -> None:
        """Serialized JSON must not include credential-like field names as keys."""
        log_path = tmp_path / "audit.ndjson"
        with AuditLogger(log_path, base_dir=tmp_path) as logger:
            logger.log_conversation(_make_conversation_entry())
            logger.log_tool_call(_make_tool_call_entry())

        records = _read_ndjson_lines(log_path)
        for rec in records:
            assert forbidden_key not in rec, (
                f"Found forbidden key '{forbidden_key}' in audit output keys"
            )

    @pytest.mark.parametrize(
        ("label", "credential"),
        [
            ("bearer_value", "Bearer " + "sk-proj-" + "a1b2c3d4e5" * 2),  # gitleaks:allow
            ("oauth_value", "ya29." + "x" * 40),  # gitleaks:allow
            ("github_pat_value", "ghp_" + "B" * 40),  # gitleaks:allow
        ],
        ids=["bearer_value", "oauth_value", "github_pat_value"],
    )
    def test_no_credential_values_in_output(
        self, tmp_path: Path, label: str, credential: str
    ) -> None:
        """Credential patterns in field values must be redacted before reaching disk."""
        log_path = tmp_path / "audit.ndjson"
        with AuditLogger(log_path, base_dir=tmp_path) as logger:
            logger.log_conversation(_make_conversation_entry(content=f"leaked {credential}"))
            logger.log_tool_call(_make_tool_call_entry(args_summary=f"key={credential}"))

        raw = log_path.read_text(encoding="utf-8")
        assert credential not in raw, f"{label}: credential pattern survived redaction"
        assert "[CREDENTIAL_REDACTED]" in raw, f"{label}: redaction placeholder missing"


# ---------------------------------------------------------------------------
# 12-13: Context manager
# ---------------------------------------------------------------------------


class TestContextManager:
    """Tests for context manager protocol."""

    def test_context_manager_closes_file(self, tmp_path: Path) -> None:
        """File is closed after exiting the with block."""
        log_path = tmp_path / "audit.ndjson"

        with AuditLogger(log_path, base_dir=tmp_path) as logger:
            logger.log_conversation(_make_conversation_entry())

        # Test-only: accessing private member to verify internal state
        assert logger._file.closed

    def test_context_manager_on_exception(self, tmp_path: Path) -> None:
        """File is closed even if an exception is raised inside the with block."""
        log_path = tmp_path / "audit.ndjson"

        with (
            pytest.raises(RuntimeError, match="boom"),
            AuditLogger(log_path, base_dir=tmp_path) as logger,
        ):
            logger.log_conversation(_make_conversation_entry())
            msg = "boom"
            raise RuntimeError(msg)

        assert logger._file.closed  # Test-only: private member access
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
        logger = AuditLogger(log_path, base_dir=tmp_path)
        logger.close()
        logger.close()  # Should not raise

    def test_write_after_close_raises(self, tmp_path: Path) -> None:
        """Writing after close() raises AuditWriteError."""
        log_path = tmp_path / "audit.ndjson"
        logger = AuditLogger(log_path, base_dir=tmp_path)
        logger.close()

        with pytest.raises(AuditWriteError):
            logger.log_conversation(_make_conversation_entry())

    def test_write_tool_call_after_close_raises(self, tmp_path: Path) -> None:
        """Writing a tool call after close() raises AuditWriteError."""
        log_path = tmp_path / "audit.ndjson"
        logger = AuditLogger(log_path, base_dir=tmp_path)
        logger.close()

        with pytest.raises(AuditWriteError):
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

        with AuditLogger(log_path, base_dir=tmp_path) as logger:
            logger.log_conversation(_make_conversation_entry())

        assert log_path.exists()
        records = _read_ndjson_lines(log_path)
        assert len(records) == 1

    def test_open_audit_log_factory(self, tmp_path: Path) -> None:
        """open_audit_log() returns a working AuditLogger."""
        log_path = tmp_path / "audit.ndjson"
        logger = open_audit_log(log_path, base_dir=tmp_path)

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

        with AuditLogger(log_path, base_dir=tmp_path) as logger:
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

    def test_concurrent_write_and_close_race(self, tmp_path: Path) -> None:
        """Concurrent write + close must not deadlock or panic.

        Either the write succeeds (entry on disk) or AuditWriteError is raised.
        The process must not hang or crash.
        """
        log_path = tmp_path / "audit.ndjson"
        audit_logger = AuditLogger(log_path, base_dir=tmp_path)
        barrier = threading.Barrier(2)
        write_error: BaseException | None = None

        def writer() -> None:
            nonlocal write_error
            barrier.wait()
            try:
                for i in range(20):
                    audit_logger.log_conversation(_make_conversation_entry(session_id=f"race-{i}"))
            except AuditWriteError:
                pass  # Expected if close() won the race
            except Exception as exc:
                write_error = exc

        def closer() -> None:
            barrier.wait()
            audit_logger.close()

        t_write = threading.Thread(target=writer)
        t_close = threading.Thread(target=closer)
        t_write.start()
        t_close.start()
        # Use generous timeout to avoid flakiness in slow CI containers
        t_write.join(timeout=30)
        t_close.join(timeout=30)

        # Must not hang
        assert not t_write.is_alive(), "Writer thread deadlocked"
        assert not t_close.is_alive(), "Closer thread deadlocked"

        # No unexpected exceptions
        assert write_error is None, f"Unexpected error in writer: {write_error}"

        # Whatever was written must be valid NDJSON
        raw = log_path.read_text(encoding="utf-8")
        for line in raw.splitlines():
            if line.strip():
                json.loads(line)  # Raises on corrupt line


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

    def test_public_api_surface_allowlist(self) -> None:
        """Only the allowed public methods may exist on AuditLogger.

        Any new public method requires an explicit allowlist update,
        preventing accidental exposure of read or export APIs.

        Note: this covers class methods only. The module-level factory
        open_audit_log() is not covered here. Dunder methods outside
        the allowlist (e.g. __repr__, __del__) are excluded by design —
        adding __del__ would require an allowlist update since it could
        introduce read-on-finalize behavior.
        """
        import inspect

        allowed = {
            "log_conversation",
            "log_tool_call",
            "close",
            "__init__",
            "__enter__",
            "__exit__",
        }
        public_methods = {
            name
            for name, _ in inspect.getmembers(AuditLogger, predicate=inspect.isfunction)
            if not name.startswith("_") or name in ("__init__", "__enter__", "__exit__")
        }
        unexpected = public_methods - allowed
        assert not unexpected, (
            f"Unexpected public methods on AuditLogger: {unexpected}. "
            "If intentional, add them to the allowlist in this test."
        )


# ---------------------------------------------------------------------------
# Path confinement
# ---------------------------------------------------------------------------


class TestPathConfinement:
    """Verify log_path is confined to the expected base directory."""

    def test_path_inside_base_dir_accepted(self, tmp_path: Path) -> None:
        log_path = tmp_path / "logs" / "audit.jsonl"
        logger = AuditLogger(log_path, base_dir=tmp_path)
        logger.close()
        assert log_path.exists()

    def test_path_outside_base_dir_rejected(self, tmp_path: Path) -> None:
        base = tmp_path / "allowed"
        base.mkdir()
        outside = tmp_path / "outside" / "audit.jsonl"
        with pytest.raises(ValueError, match="outside the permitted base"):
            AuditLogger(outside, base_dir=base)

    def test_symlink_escape_rejected(self, tmp_path: Path) -> None:
        base = tmp_path / "allowed"
        base.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        link = base / "escape"
        link.symlink_to(outside)
        with pytest.raises(ValueError, match="outside the permitted base"):
            AuditLogger(link / "audit.jsonl", base_dir=base)

    def test_no_base_dir_skips_check(
        self,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When base_dir is explicitly None, any path is accepted but CRITICAL is emitted."""
        import admino.audit

        monkeypatch.delenv("ADMINO_ENV", raising=False)
        monkeypatch.setattr(admino.audit, "_IS_PRODUCTION", False)
        log_path = tmp_path / "audit.jsonl"
        with caplog.at_level(logging.CRITICAL, logger="admino.audit"):
            logger = AuditLogger(log_path, base_dir=None)
            logger.close()

        # Ensure the CRITICAL warning is still present (regression guard)
        assert any("path confinement disabled" in r.message for r in caplog.records)

    def test_open_audit_log_with_base_dir(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        logger = open_audit_log(log_path, base_dir=tmp_path)
        logger.close()


# ---------------------------------------------------------------------------
# Newline injection guard
# ---------------------------------------------------------------------------


class TestNewlineGuard:
    """__write_entry rejects json_line containing newlines.

    These are white-box tests that access the name-mangled __write_entry
    method directly. If the internal method is renamed, these tests must
    be updated to match.
    """

    def test_newline_in_json_line_raises(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        with (
            AuditLogger(log_path, base_dir=tmp_path) as logger,
            pytest.raises(ValueError, match="newlines"),
        ):
            # Test-only: accessing name-mangled private method
            logger._AuditLogger__write_entry('{"a":"b"}\n{"injected":true}')  # type: ignore[attr-defined]

    def test_carriage_return_raises(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        with (
            AuditLogger(log_path, base_dir=tmp_path) as logger,
            pytest.raises(ValueError, match="newlines"),
        ):
            # Test-only: accessing name-mangled private method
            logger._AuditLogger__write_entry('{"a":"b"}\r{"injected":true}')  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# AuditWriteError on I/O failure
# ---------------------------------------------------------------------------


class TestAuditWriteError:
    """Write failures raise AuditWriteError, not raw OSError."""

    def test_write_to_closed_file_raises_audit_error(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path, base_dir=tmp_path)
        logger.close()
        with pytest.raises(AuditWriteError):
            # Test-only: accessing name-mangled private method
            logger._AuditLogger__write_entry('{"test": true}')  # type: ignore[attr-defined]

    def test_open_failure_raises_audit_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Opening a log at an invalid path raises AuditWriteError."""
        import admino.audit

        # Ensure _IS_PRODUCTION is False (base_dir=None would raise otherwise)
        monkeypatch.delenv("ADMINO_ENV", raising=False)
        monkeypatch.setattr(admino.audit, "_IS_PRODUCTION", False)
        # Create a file where a directory is expected, causing mkdir to fail
        blocker = tmp_path / "not_a_dir"
        blocker.write_text("", encoding="utf-8")
        log_path = blocker / "sub" / "audit.jsonl"

        with pytest.raises(AuditWriteError):
            AuditLogger(log_path, base_dir=None)


# ---------------------------------------------------------------------------
# End-to-end credential redaction through AuditLogger to disk (Finding 8)
# ---------------------------------------------------------------------------


class TestCredentialRedactionEndToEnd:
    """Verify credential patterns are redacted in the NDJSON file on disk.

    These tests exercise the full pipeline: model construction (with
    field validators) → model_dump_json() → _write_entry → file.
    Assertions are on raw file text, not parsed JSON, to catch escaping tricks.
    """

    _REDACTED: ClassVar[str] = "[CREDENTIAL_REDACTED]"

    # Each tuple: (description, raw_credential_string)
    # These are synthetic test patterns, not real credentials.
    # gitleaks:allow — suppress secret scanner false positives on these lines.
    _CREDENTIAL_SAMPLES: ClassVar[list[tuple[str, str]]] = [
        ("google_oauth", "ya29." + "a1b2c3d4e5" * 8),  # gitleaks:allow
        ("google_refresh", "1//" + "abcDEF123456" * 5),  # gitleaks:allow
        (  # gitleaks:allow
            "jwt",
            "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        ),
        ("bearer", "Bearer " + "sk-proj-" + "a1b2c3d4e5" * 2),  # gitleaks:allow
        ("github_pat", "ghp_" + "A" * 40),  # gitleaks:allow
        ("aws_key", "AKIA" + "A" * 16),  # gitleaks:allow
        ("slack", "xoxb-" + "a1b2c3d4e5" * 5),  # gitleaks:allow
    ]

    @pytest.mark.parametrize(
        ("label", "credential"),
        _CREDENTIAL_SAMPLES,
        ids=[s[0] for s in _CREDENTIAL_SAMPLES],
    )
    def test_content_field_redacted_on_disk(
        self, tmp_path: Path, label: str, credential: str
    ) -> None:
        """Credential in content must not appear in the raw file bytes."""
        log_path = tmp_path / "audit.ndjson"
        entry = _make_conversation_entry(content=f"leaked {credential} here")

        with AuditLogger(log_path, base_dir=tmp_path) as audit_log:
            audit_log.log_conversation(entry)

        raw = log_path.read_text(encoding="utf-8")
        assert credential not in raw, f"{label}: credential pattern survived redaction in content"
        assert self._REDACTED in raw

    @pytest.mark.parametrize(
        ("label", "credential"),
        _CREDENTIAL_SAMPLES,
        ids=[s[0] for s in _CREDENTIAL_SAMPLES],
    )
    def test_args_summary_field_redacted_on_disk(
        self, tmp_path: Path, label: str, credential: str
    ) -> None:
        """Credential in args_summary must not appear in the raw file bytes."""
        log_path = tmp_path / "audit.ndjson"
        entry = _make_tool_call_entry(args_summary=f"key={credential}")

        with AuditLogger(log_path, base_dir=tmp_path) as audit_log:
            audit_log.log_tool_call(entry)

        raw = log_path.read_text(encoding="utf-8")
        assert credential not in raw, (
            f"{label}: credential pattern survived redaction in args_summary"
        )
        assert self._REDACTED in raw, f"{label}: redaction placeholder missing in args_summary"

    @pytest.mark.parametrize(
        ("label", "credential"),
        _CREDENTIAL_SAMPLES,
        ids=[s[0] for s in _CREDENTIAL_SAMPLES],
    )
    def test_error_field_redacted_on_disk(
        self, tmp_path: Path, label: str, credential: str
    ) -> None:
        """Credential in error must not appear in the raw file bytes."""
        log_path = tmp_path / "audit.ndjson"
        entry = _make_tool_call_entry(success=False, error=f"failed with {credential}")

        with AuditLogger(log_path, base_dir=tmp_path) as audit_log:
            audit_log.log_tool_call(entry)

        raw = log_path.read_text(encoding="utf-8")
        assert credential not in raw, f"{label}: credential pattern survived redaction in error"
        assert self._REDACTED in raw, f"{label}: redaction placeholder missing in error"


# ---------------------------------------------------------------------------
# base_dir=None emits CRITICAL warning (Finding 9)
# ---------------------------------------------------------------------------


class TestBaseDirectoryWarning:
    """base_dir=None must emit a CRITICAL log so it cannot be silently ignored."""

    def test_base_dir_none_emits_critical_warning(
        self,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Passing base_dir=None must produce a CRITICAL log message."""
        import admino.audit

        monkeypatch.delenv("ADMINO_ENV", raising=False)
        monkeypatch.setattr(admino.audit, "_IS_PRODUCTION", False)
        log_path = tmp_path / "audit.jsonl"
        with caplog.at_level(logging.CRITICAL, logger="admino.audit"):
            logger = AuditLogger(log_path, base_dir=None)
            logger.close()

        assert any("path confinement disabled" in r.message for r in caplog.records)
        assert any(r.levelno == logging.CRITICAL for r in caplog.records)

    def test_base_dir_none_rejected_in_production(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """base_dir=None must raise ValueError when _IS_PRODUCTION is True."""
        import admino.audit

        monkeypatch.setattr(admino.audit, "_IS_PRODUCTION", True)
        log_path = tmp_path / "audit.jsonl"
        with pytest.raises(ValueError, match="not allowed in production"):
            AuditLogger(log_path, base_dir=None)

    def test_base_dir_provided_no_warning(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Passing a valid base_dir must not produce any confinement warning."""
        log_path = tmp_path / "audit.jsonl"
        with caplog.at_level(logging.DEBUG, logger="admino.audit"):
            logger = AuditLogger(log_path, base_dir=tmp_path)
            logger.close()

        assert not any("path confinement disabled" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# model_construct() bypass awareness (Finding 10)
# ---------------------------------------------------------------------------


class TestModelConstructBypass:
    """Demonstrate that model_construct() bypasses field validators.

    This test documents the trust boundary: audit.py trusts that entries
    are constructed via normal Pydantic validation. Entries built with
    model_construct() skip all validators including credential redaction.
    """

    def test_model_construct_bypasses_redaction_known_risk(self, tmp_path: Path) -> None:
        """SECURITY: model_construct() bypasses redaction — documents a known limitation.

        This test exists to document the trust boundary, NOT to validate
        acceptable behavior. If a future guard causes this test to fail,
        that is a security improvement — update the assertion accordingly.
        See: audit.py module docstring, "model_construct() bypass" section.

        Uses a synthetic token (not a real credential format) to avoid
        leaking realistic patterns in CI logs if the assertion fails.
        """
        from datetime import UTC, datetime

        log_path = tmp_path / "audit.ndjson"
        # Synthetic unique marker — not a real credential format, safe for CI logs.
        credential = "SYNTHETIC_TEST_TOKEN_DO_NOT_USE_" + "x" * 20

        # model_construct() skips all validators — this is the known risk.
        # SECURITY: Never use model_construct() with untrusted data.
        entry = ConversationAuditEntry.model_construct(
            entry_type="conversation",
            timestamp=datetime.now(UTC),
            session_id="sess-001",
            role="user",
            content=f"leaked {credential}",
            model="llama3",
            tool_calls_count=0,
        )

        with AuditLogger(log_path, base_dir=tmp_path) as audit_log:
            audit_log.log_conversation(entry)

        raw = log_path.read_text(encoding="utf-8")
        # This PASSES — proving model_construct() bypasses redaction.
        # If this assertion fails, a guard was added (security improvement).
        assert credential in raw, "If this fails, a guard was added — update this test accordingly"


# ---------------------------------------------------------------------------
# File and directory permission bits (Finding 11)
# ---------------------------------------------------------------------------


class TestFilePermissions:
    """Verify restrictive permission bits on created files and directories."""

    def test_log_file_permissions_0o600(self, tmp_path: Path) -> None:
        """The audit log file must be created with mode 0o600 (owner rw only)."""
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path, base_dir=tmp_path)
        logger.close()

        file_mode = stat.S_IMODE(os.stat(log_path).st_mode)
        assert file_mode == 0o600, f"Expected 0o600, got {oct(file_mode)}"

    def test_leaf_directory_permissions_0o700(self, tmp_path: Path) -> None:
        """Newly created leaf directory must have mode 0o700 (owner rwx only)."""
        log_path = tmp_path / "newdir" / "audit.jsonl"
        logger = AuditLogger(log_path, base_dir=tmp_path)
        logger.close()

        dir_mode = stat.S_IMODE(os.stat(log_path.parent).st_mode)
        assert dir_mode == 0o700, f"Expected 0o700, got {oct(dir_mode)}"

    def test_base_dir_permissions_not_modified(self, tmp_path: Path) -> None:
        """base_dir's own permissions must not be altered by AuditLogger."""
        base = tmp_path / "base"
        base.mkdir(mode=0o755)
        original_mode = stat.S_IMODE(os.stat(base).st_mode)
        log_path = base / "sub" / "audit.jsonl"
        logger = AuditLogger(log_path, base_dir=base)
        logger.close()

        after_mode = stat.S_IMODE(os.stat(base).st_mode)
        assert after_mode == original_mode, (
            f"base_dir mode changed from {oct(original_mode)} to {oct(after_mode)}"
        )

    def test_direct_child_of_base_dir_permissions(self, tmp_path: Path) -> None:
        """Log file as direct child of base_dir — zero chmod loop iterations.

        When resolved.parent == resolved_base, the chmod loop body never
        executes. base_dir's permissions must not be altered.
        """
        log_path = tmp_path / "audit.jsonl"  # direct child of base_dir
        original_mode = stat.S_IMODE(os.stat(tmp_path).st_mode)
        logger = AuditLogger(log_path, base_dir=tmp_path)
        logger.close()

        assert log_path.exists()
        # base_dir itself must not have been chmod'd
        after_mode = stat.S_IMODE(os.stat(tmp_path).st_mode)
        assert after_mode == original_mode
        # File permissions still enforced
        file_mode = stat.S_IMODE(os.stat(log_path).st_mode)
        assert file_mode == 0o600

    def test_intermediate_directory_permissions_0o700(self, tmp_path: Path) -> None:
        """Intermediate directories created by mkdir(parents=True) get chmod'd to 0o700."""
        log_path = tmp_path / "a" / "b" / "c" / "audit.jsonl"
        logger = AuditLogger(log_path, base_dir=tmp_path)
        logger.close()

        # Check each intermediate dir under base
        for subdir in ["a", "a/b", "a/b/c"]:
            dir_path = tmp_path / subdir
            dir_mode = stat.S_IMODE(os.stat(dir_path).st_mode)
            assert dir_mode == 0o700, f"Expected 0o700 for {subdir}, got {oct(dir_mode)}"


# ---------------------------------------------------------------------------
# File-level symlink rejection via O_NOFOLLOW (Finding 12)
# ---------------------------------------------------------------------------


class TestFileSymlinkRejection:
    """O_NOFOLLOW rejects opening a symlink at the final path component.

    AuditLogger calls resolve() before os.open(), so pre-existing symlinks
    are followed during resolution and O_NOFOLLOW fires only if a symlink
    is placed at the resolved path between resolve() and os.open() (a TOCTOU
    race). This cannot be deterministically unit-tested, so we verify the
    OS-level O_NOFOLLOW behavior directly to ensure the defence works.
    """

    def test_os_nofollow_rejects_symlink(self, tmp_path: Path) -> None:
        """Verify that os.open with O_NOFOLLOW raises on a symlink."""
        real_file = tmp_path / "real.txt"
        real_file.write_text("target", encoding="utf-8")
        symlink = tmp_path / "link.txt"
        symlink.symlink_to(real_file)

        # O_NOFOLLOW must raise OSError (ELOOP) on the symlink
        with pytest.raises(OSError):
            os.open(
                symlink,
                os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW,
                0o600,
            )

    def test_directory_symlink_caught_by_path_confinement(self, tmp_path: Path) -> None:
        """A symlink escaping base_dir is caught by resolve() + is_relative_to."""
        base = tmp_path / "allowed"
        base.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        link = base / "escape"
        link.symlink_to(outside)
        with pytest.raises(ValueError, match="outside the permitted base"):
            AuditLogger(link / "audit.jsonl", base_dir=base)
