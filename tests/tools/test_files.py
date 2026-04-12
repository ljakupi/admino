"""Tests for the files tool (admino.tools.files).

Covers configuration, path validation (traversal, symlink, read-only, extension
denylist), TOCTOU defence, symlink safety in list/search, and all async tool
handlers (read, list, search, write, move).
"""

from __future__ import annotations

from pathlib import Path  # noqa: TC003 — used at runtime in fixtures and tests
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Generator

from admino.models import (
    FileListArgs,
    FileMoveArgs,
    FileReadArgs,
    FileSearchArgs,
    FileWriteArgs,
)
from admino.tools import files
from admino.tools.registry import clear_registry

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_registry() -> Generator[None, None, None]:
    """Ensure the registry is clean before and after every test."""
    clear_registry()
    # Re-import to trigger registration (module-level decorators)
    import importlib

    importlib.reload(files)
    yield
    clear_registry()


@pytest.fixture()
def allowed_dir(tmp_path: Path) -> Path:
    """Create and return a temporary allowed directory."""
    d = tmp_path / "allowed"
    d.mkdir()
    return d


@pytest.fixture()
def readonly_dir(tmp_path: Path) -> Path:
    """Create and return a temporary read-only directory."""
    d = tmp_path / "readonly"
    d.mkdir()
    return d


@pytest.fixture()
def writable_dir(tmp_path: Path) -> Path:
    """Create and return a temporary writable directory."""
    d = tmp_path / "writable"
    d.mkdir()
    return d


@pytest.fixture()
def configured_files(
    allowed_dir: Path,
    readonly_dir: Path,
    writable_dir: Path,
) -> None:
    """Configure the files tool with read-only and readwrite dirs."""
    files.configure(
        allowed_paths=[
            {"path": str(readonly_dir), "label": "readonly", "access": "read"},
            {"path": str(writable_dir), "label": "writable", "access": "readwrite"},
            {"path": str(allowed_dir), "label": "allowed", "access": "read"},
        ],
        max_read_chars=500,
    )


# ---------------------------------------------------------------------------
# 1. Configuration Tests
# ---------------------------------------------------------------------------


class TestConfigure:
    """Tests for files.configure()."""

    def test_configure_sets_allowed_paths(self, tmp_path: Path) -> None:
        """configure() populates _allowed_paths with resolved entries."""
        d = tmp_path / "data"
        d.mkdir()
        files.configure(
            allowed_paths=[{"path": str(d), "label": "test", "access": "readwrite"}],
            max_read_chars=1000,
        )
        assert len(files._allowed_paths) == 1
        assert files._allowed_paths[0].path == d.resolve()
        assert files._allowed_paths[0].writable is True

    def test_configure_sets_max_read_chars(self, tmp_path: Path) -> None:
        """configure() correctly sets the module-level max_read_chars."""
        d = tmp_path / "data"
        d.mkdir()
        files.configure(
            allowed_paths=[{"path": str(d), "label": "test", "access": "read"}],
            max_read_chars=42,
        )
        assert files._max_read_chars == 42

    def test_configure_empty_list(self) -> None:
        """configure() with empty list results in no allowed paths."""
        files.configure(allowed_paths=[], max_read_chars=100)
        assert files._allowed_paths == []


# ---------------------------------------------------------------------------
# 2. Path Validation Tests
# ---------------------------------------------------------------------------


class TestValidatePath:
    """Tests for files._validate_path()."""

    def test_valid_path_within_allowed_dir(self, configured_files: None, allowed_dir: Path) -> None:
        """A path inside an allowed directory succeeds."""
        target = allowed_dir / "test.txt"
        target.touch()
        result = files._validate_path(str(target))
        assert result == target.resolve()

    def test_path_outside_all_allowed_dirs(self, configured_files: None, tmp_path: Path) -> None:
        """A path outside all allowed directories raises PermissionError."""
        outside = tmp_path / "outside" / "secret.txt"
        with pytest.raises(PermissionError, match="outside all allowed"):
            files._validate_path(str(outside))

    def test_path_traversal_caught(
        self, configured_files: None, allowed_dir: Path, tmp_path: Path
    ) -> None:
        """Path traversal via ../ is caught after resolution."""
        # ../outside escapes the allowed_dir
        traversal = str(allowed_dir / ".." / "outside" / "secret.txt")
        with pytest.raises(PermissionError, match="outside all allowed"):
            files._validate_path(traversal)

    def test_symlink_outside_allowed_dir_caught(
        self, configured_files: None, allowed_dir: Path, tmp_path: Path
    ) -> None:
        """A symlink pointing outside the allowed dir is caught."""
        secret = tmp_path / "secret.txt"
        secret.write_text("secret data")
        link = allowed_dir / "escape_link"
        link.symlink_to(secret)
        with pytest.raises(PermissionError, match="outside all allowed"):
            files._validate_path(str(link))

    def test_no_allowed_paths_raises_value_error(self) -> None:
        """No allowed paths configured raises ValueError."""
        files.configure(allowed_paths=[], max_read_chars=100)
        with pytest.raises(ValueError, match="No allowed file paths configured"):
            files._validate_path("/some/path")

    def test_readonly_path_rejects_write(self, configured_files: None, readonly_dir: Path) -> None:
        """Read-only path rejects require_write=True."""
        target = readonly_dir / "file.txt"
        target.touch()
        with pytest.raises(PermissionError, match="read-only"):
            files._validate_path(str(target), require_write=True)

    def test_writable_path_allows_write(self, configured_files: None, writable_dir: Path) -> None:
        """Writable path allows require_write=True."""
        target = writable_dir / "file.txt"
        result = files._validate_path(str(target), require_write=True)
        assert result == target.resolve()

    @pytest.mark.parametrize(
        "ext",
        [".sh", ".py", ".bat", ".exe", ".ps1", ".bash", ".dll", ".so"],
    )
    def test_denied_extensions_rejected_on_write(
        self, configured_files: None, writable_dir: Path, ext: str
    ) -> None:
        """Denied file extensions are rejected on write."""
        target = writable_dir / f"script{ext}"
        with pytest.raises(PermissionError, match="extension"):
            files._validate_path(str(target), require_write=True)

    @pytest.mark.parametrize("ext", [".txt", ".md", ".json", ".csv"])
    def test_allowed_extensions_accepted_on_write(
        self, configured_files: None, writable_dir: Path, ext: str
    ) -> None:
        """Allowed extensions are accepted on write."""
        target = writable_dir / f"doc{ext}"
        result = files._validate_path(str(target), require_write=True)
        assert result == target.resolve()


# ---------------------------------------------------------------------------
# 3. TOCTOU Defence Tests
# ---------------------------------------------------------------------------


class TestRevalidateResolved:
    """Tests for files._revalidate_resolved()."""

    def test_unchanged_path_passes(self, configured_files: None, allowed_dir: Path) -> None:
        """A path that hasn't changed passes revalidation."""
        target = allowed_dir / "stable.txt"
        target.touch()
        resolved = target.resolve()
        # Should not raise
        files._revalidate_resolved(resolved)

    def test_path_changed_raises_permission_error(
        self, configured_files: None, allowed_dir: Path, tmp_path: Path
    ) -> None:
        """A path resolving differently raises PermissionError."""
        # Create a file in allowed dir, get its resolved path
        target = allowed_dir / "file.txt"
        target.touch()
        resolved = target.resolve()
        # Remove the file and create a symlink to an outside location
        target.unlink()
        outside = tmp_path / "outside_secret.txt"
        outside.write_text("secret")
        target.symlink_to(outside)
        # Now the path resolves differently
        with pytest.raises(PermissionError):
            files._revalidate_resolved(resolved)


# ---------------------------------------------------------------------------
# 4. Symlink Safety in List/Search
# ---------------------------------------------------------------------------


class TestSymlinkSafety:
    """Tests for symlink filtering in _sync_list_dir and _sync_search_files."""

    def test_list_dir_skips_external_symlinks(
        self, configured_files: None, allowed_dir: Path, tmp_path: Path
    ) -> None:
        """_sync_list_dir skips symlinks pointing outside the root."""
        # Create a real file inside
        real_file = allowed_dir / "real.txt"
        real_file.write_text("hello")
        # Create a symlink to an outside file
        outside = tmp_path / "outside.txt"
        outside.write_text("secret")
        link = allowed_dir / "escape_link.txt"
        link.symlink_to(outside)

        entries = files._sync_list_dir(allowed_dir, max_depth=1)
        names = [e.split(" ", 1)[1] for e in entries]
        assert "real.txt" in names
        assert "escape_link.txt" not in names

    def test_search_files_skips_external_files(
        self, configured_files: None, allowed_dir: Path, tmp_path: Path
    ) -> None:
        """_sync_search_files skips files that resolve outside root."""
        real_file = allowed_dir / "match.txt"
        real_file.write_text("content")
        outside = tmp_path / "match.txt"
        outside.write_text("secret content")
        link = allowed_dir / "linked_match.txt"
        link.symlink_to(outside)

        results = files._sync_search_files(
            allowed_dir, "*.txt", content_search=False, max_results=50
        )
        assert "match.txt" in results
        assert "linked_match.txt" not in results

    def test_search_prunes_escaped_subdirs(
        self, configured_files: None, allowed_dir: Path, tmp_path: Path
    ) -> None:
        """_sync_search_files prunes subdirectories that escape root."""
        outside_dir = tmp_path / "outside_subdir"
        outside_dir.mkdir()
        (outside_dir / "secret.txt").write_text("secret")
        link_dir = allowed_dir / "escape_dir"
        link_dir.symlink_to(outside_dir)

        results = files._sync_search_files(
            allowed_dir, "*.txt", content_search=False, max_results=50
        )
        assert not any("secret.txt" in r for r in results)


# ---------------------------------------------------------------------------
# 5. Async Tool Handler Tests
# ---------------------------------------------------------------------------


class TestFilesRead:
    """Tests for the files_read handler."""

    @pytest.mark.asyncio
    async def test_reads_file_content(self, configured_files: None, allowed_dir: Path) -> None:
        """files_read returns file contents."""
        target = allowed_dir / "hello.txt"
        target.write_text("Hello, world!")
        result = await files.files_read(FileReadArgs(path=str(target)))
        assert result == "Hello, world!"

    @pytest.mark.asyncio
    async def test_truncation_at_max_read_chars(
        self, configured_files: None, allowed_dir: Path
    ) -> None:
        """files_read truncates at max_read_chars (configured to 500)."""
        target = allowed_dir / "big.txt"
        target.write_text("x" * 1000)
        result = await files.files_read(FileReadArgs(path=str(target)))
        assert "[Truncated at 500 characters]" in result
        # Content before truncation marker should be 500 chars
        content_before = result.split("\n\n[Truncated")[0]
        assert len(content_before) == 500

    @pytest.mark.asyncio
    async def test_nonexistent_file_returns_message(
        self, configured_files: None, allowed_dir: Path
    ) -> None:
        """files_read returns not-found message for missing file."""
        target = allowed_dir / "nonexistent.txt"
        result = await files.files_read(FileReadArgs(path=str(target)))
        assert "Not a file or does not exist" in result


class TestFilesList:
    """Tests for the files_list handler."""

    @pytest.mark.asyncio
    async def test_lists_directory_contents(
        self, configured_files: None, allowed_dir: Path
    ) -> None:
        """files_list lists directory contents."""
        (allowed_dir / "a.txt").touch()
        (allowed_dir / "b.txt").touch()
        sub = allowed_dir / "subdir"
        sub.mkdir()
        result = await files.files_list(FileListArgs(path=str(allowed_dir), max_depth=1))
        assert "a.txt" in result
        assert "b.txt" in result
        assert "subdir" in result

    @pytest.mark.asyncio
    async def test_depth_control(self, configured_files: None, allowed_dir: Path) -> None:
        """files_list respects max_depth."""
        sub = allowed_dir / "sub"
        sub.mkdir()
        (sub / "deep.txt").touch()
        # depth=1 should show sub but not its contents
        result_d1 = await files.files_list(FileListArgs(path=str(allowed_dir), max_depth=1))
        assert "sub" in result_d1
        assert "deep.txt" not in result_d1
        # depth=2 should show sub and its contents
        result_d2 = await files.files_list(FileListArgs(path=str(allowed_dir), max_depth=2))
        assert "deep.txt" in result_d2

    @pytest.mark.asyncio
    async def test_non_directory_returns_error(
        self, configured_files: None, allowed_dir: Path
    ) -> None:
        """files_list returns error for non-directory path."""
        target = allowed_dir / "file.txt"
        target.touch()
        result = await files.files_list(FileListArgs(path=str(target), max_depth=1))
        assert "Not a directory" in result


class TestFilesSearch:
    """Tests for the files_search handler."""

    @pytest.mark.asyncio
    async def test_glob_search_finds_matching(
        self, configured_files: None, allowed_dir: Path
    ) -> None:
        """files_search finds files matching a glob pattern."""
        (allowed_dir / "notes.txt").write_text("content")
        (allowed_dir / "data.csv").write_text("data")
        result = await files.files_search(FileSearchArgs(path=str(allowed_dir), pattern="*.txt"))
        assert "notes.txt" in result
        assert "data.csv" not in result

    @pytest.mark.asyncio
    async def test_content_search_finds_matching(
        self, configured_files: None, allowed_dir: Path
    ) -> None:
        """files_search content search finds files containing text."""
        (allowed_dir / "match.txt").write_text("The secret keyword here")
        (allowed_dir / "nomatch.txt").write_text("Nothing special")
        result = await files.files_search(
            FileSearchArgs(
                path=str(allowed_dir),
                pattern="secret keyword",
                content_search=True,
            )
        )
        assert "match.txt" in result
        assert "nomatch.txt" not in result

    @pytest.mark.asyncio
    async def test_no_matches_returns_message(
        self, configured_files: None, allowed_dir: Path
    ) -> None:
        """files_search returns appropriate message when nothing matches."""
        result = await files.files_search(FileSearchArgs(path=str(allowed_dir), pattern="*.xyz"))
        assert "No files found" in result


class TestFilesWrite:
    """Tests for the files_write handler."""

    @pytest.mark.asyncio
    async def test_writes_content(self, configured_files: None, writable_dir: Path) -> None:
        """files_write writes content and returns canonical path."""
        target = writable_dir / "output.txt"
        result = await files.files_write(FileWriteArgs(path=str(target), content="Hello!"))
        assert "Written 6 characters" in result
        assert str(target.resolve()) in result
        assert target.read_text() == "Hello!"

    @pytest.mark.asyncio
    async def test_creates_parent_directories(
        self, configured_files: None, writable_dir: Path
    ) -> None:
        """files_write creates parent directories if needed."""
        target = writable_dir / "sub" / "deep" / "file.txt"
        await files.files_write(FileWriteArgs(path=str(target), content="nested"))
        assert target.exists()
        assert target.read_text() == "nested"

    @pytest.mark.asyncio
    async def test_rejects_symlink_targets(
        self, configured_files: None, writable_dir: Path, tmp_path: Path
    ) -> None:
        """files_write rejects writing through a symlink."""
        outside = tmp_path / "outside.txt"
        outside.write_text("original")
        link = writable_dir / "link.txt"
        link.symlink_to(outside)
        with pytest.raises(PermissionError):
            await files.files_write(FileWriteArgs(path=str(link), content="overwrite"))

    @pytest.mark.asyncio
    async def test_uses_resolved_canonical_path_in_result(
        self, configured_files: None, writable_dir: Path
    ) -> None:
        """files_write returns the resolved canonical path."""
        target = writable_dir / "output.md"
        result = await files.files_write(FileWriteArgs(path=str(target), content="data"))
        # The result should use the resolved path, not raw user input
        assert str(target.resolve()) in result

    @pytest.mark.asyncio
    async def test_files_write_refuses_to_overwrite_existing_file_preserves_content(
        self, configured_files: None, writable_dir: Path
    ) -> None:
        """files_write refuses overwrite; original content is preserved.

        Overwriting silently deletes prior content, which would bypass the
        ``files.delete`` hardcoded denial. The handler must refuse the call
        and leave the existing file untouched.
        """
        target = writable_dir / "existing.txt"
        target.write_text("original content")
        result = await files.files_write(
            FileWriteArgs(path=str(target), content="malicious replacement")
        )
        # Refusal guides toward renaming, NOT toward files.move workaround.
        assert "Cannot write" in result
        assert "already exists" in result
        assert "different filename" in result
        assert target.read_text() == "original content"

    @pytest.mark.asyncio
    async def test_files_write_refuses_overwrite_of_existing_directory(
        self, configured_files: None, writable_dir: Path
    ) -> None:
        """files_write refuses when the target path is an existing directory."""
        target = writable_dir / "subdir"
        target.mkdir()
        result = await files.files_write(FileWriteArgs(path=str(target) + "/", content="data"))
        # Either the refusal message or a PermissionError from validation;
        # the critical guarantee is that the directory is not replaced.
        assert "Cannot write" in result or target.is_dir()
        assert target.is_dir()

    @pytest.mark.asyncio
    async def test_files_write_refusal_does_not_recommend_move_workaround(
        self, configured_files: None, writable_dir: Path
    ) -> None:
        """Refusal must NOT instruct the LLM to chain files.move.

        Regression guard for the prior behaviour where the tool description
        suggested "move the old file aside, then write the new one", which
        caused the LLM to request a confusing ``files.move`` confirmation
        instead of surfacing the name collision to the user.
        """
        target = writable_dir / "existing.txt"
        target.write_text("original")
        result = await files.files_write(FileWriteArgs(path=str(target), content="new content"))
        assert "files.move" not in result
        assert "move the old" not in result.lower()

    def test_sync_write_file_uses_o_excl_flag(self) -> None:
        """Verify O_EXCL is used in _sync_write_file (code inspection).

        Regression guard for the create-only invariant: if a future refactor
        replaces O_EXCL with O_TRUNC, overwrites would silently succeed.
        """
        import inspect

        source = inspect.getsource(files._sync_write_file)
        assert "O_EXCL" in source
        assert "O_TRUNC" not in source


class TestFilesMove:
    """Tests for the files_move handler."""

    @pytest.mark.asyncio
    async def test_moves_file(self, configured_files: None, writable_dir: Path) -> None:
        """files_move moves a file between writable directories."""
        src = writable_dir / "source.txt"
        src.write_text("move me")
        dest = writable_dir / "dest.txt"
        result = await files.files_move(FileMoveArgs(source=str(src), destination=str(dest)))
        assert "Moved" in result
        assert not src.exists()
        assert dest.read_text() == "move me"

    @pytest.mark.asyncio
    async def test_rejects_move_from_readonly(
        self, configured_files: None, readonly_dir: Path, writable_dir: Path
    ) -> None:
        """files_move rejects move from read-only directory."""
        src = readonly_dir / "protected.txt"
        src.write_text("protected")
        dest = writable_dir / "stolen.txt"
        with pytest.raises(PermissionError, match="read-only"):
            await files.files_move(FileMoveArgs(source=str(src), destination=str(dest)))

    def test_sync_move_rejects_symlink_source(
        self, configured_files: None, writable_dir: Path
    ) -> None:
        """_sync_move_file rejects a symlink source directly.

        Note: files_move calls _validate_path which resolves symlinks,
        so at the handler level the symlink is already resolved. The
        symlink check in _sync_move_file is a TOCTOU defence for when
        a symlink appears between validation and I/O. We test the sync
        helper directly.
        """
        real = writable_dir / "real.txt"
        real.write_text("content")
        link = writable_dir / "link.txt"
        link.symlink_to(real)
        dest = writable_dir / "moved.txt"
        with pytest.raises(PermissionError, match="symlink"):
            files._sync_move_file(link, dest)


# ---------------------------------------------------------------------------
# 6. Extension Denylist Tests (L1)
# ---------------------------------------------------------------------------


class TestExtensionDenylist:
    """Tests for L1 extension denylist enforcement."""

    @pytest.mark.parametrize(
        "ext",
        [".sh", ".py", ".bat", ".exe", ".ps1"],
    )
    @pytest.mark.asyncio
    async def test_writing_denied_extension_raises(
        self, configured_files: None, writable_dir: Path, ext: str
    ) -> None:
        """Writing executable extensions raises PermissionError."""
        target = writable_dir / f"script{ext}"
        with pytest.raises(PermissionError, match="extension"):
            await files.files_write(FileWriteArgs(path=str(target), content="#!/bin/bash\necho hi"))

    @pytest.mark.parametrize("ext", [".txt", ".md", ".json", ".csv"])
    @pytest.mark.asyncio
    async def test_writing_allowed_extension_succeeds(
        self, configured_files: None, writable_dir: Path, ext: str
    ) -> None:
        """Writing safe extensions succeeds."""
        target = writable_dir / f"doc{ext}"
        result = await files.files_write(FileWriteArgs(path=str(target), content="safe content"))
        assert "Written" in result


# ---------------------------------------------------------------------------
# 7. Pydantic Model Validation Tests
# ---------------------------------------------------------------------------


class TestFileModelValidation:
    """Tests for Pydantic model constraints on file arg models."""

    def test_file_write_args_max_content_length(self) -> None:
        """FileWriteArgs rejects content exceeding max_length."""
        with pytest.raises(Exception):  # noqa: B017
            FileWriteArgs(path="/some/path", content="x" * 50001)

    def test_file_read_args_max_path_length(self) -> None:
        """FileReadArgs rejects paths exceeding max_length."""
        with pytest.raises(Exception):  # noqa: B017
            FileReadArgs(path="x" * 501)

    def test_file_list_args_depth_bounds(self) -> None:
        """FileListArgs rejects out-of-range max_depth."""
        with pytest.raises(Exception):  # noqa: B017
            FileListArgs(path="/some/path", max_depth=0)
        with pytest.raises(Exception):  # noqa: B017
            FileListArgs(path="/some/path", max_depth=4)

    def test_file_search_args_max_results_bounds(self) -> None:
        """FileSearchArgs rejects out-of-range max_results."""
        with pytest.raises(Exception):  # noqa: B017
            FileSearchArgs(path="/some/path", pattern="*", max_results=0)
        with pytest.raises(Exception):  # noqa: B017
            FileSearchArgs(path="/some/path", pattern="*", max_results=101)

    def test_file_write_args_o_nofollow_flag(
        self,
    ) -> None:
        """Verify O_NOFOLLOW is used in _sync_write_file (code inspection)."""
        import inspect

        source = inspect.getsource(files._sync_write_file)
        assert "O_NOFOLLOW" in source
