"""Local file access tool with strict path validation.

Provides read, list, search, write, and move actions for files within
operator-configured allowed paths. All paths are canonicalized and validated
before any I/O operation.

Security notes:
- All paths are resolved to absolute paths and checked against allowed_paths
  BEFORE any filesystem I/O.
- Path traversal via ``../`` and symlinks is detected and rejected.
- Read-only paths reject write and move operations.
- File content is truncated to max_read_chars before returning to the LLM.
- No DELETE capability. files.delete is a hardcoded deny in permissions.py.
- No OVERWRITE capability. ``files.write`` is create-only: if the destination
  already exists, the call is refused. Overwriting a file is a silent delete
  of its prior content and would bypass the ``files.delete`` hardcoded denial.
  The ``files.overwrite`` action is also modelled as a first-class permission
  and is itself hardcoded-denied in permissions.py — there is no registered
  handler for it; the permission engine rejects the call before dispatch so
  the audit log records the attempt explicitly.
  Create-only enforcement on ``files.write`` is defence-in-depth: a pre-check
  in the handler (for a friendly error message) plus ``O_EXCL`` on the sync
  open (kernel-level TOCTOU defence). If a destination already exists, the
  caller is guided to ask the user for a different filename — NOT to move
  the old file aside, which would still be a destructive workaround.
- No eval, exec, shell=True, or importlib.
- Does not import from agent.py, llm.py, or server.py.
"""

from __future__ import annotations

import asyncio
import fnmatch
import logging
import os
import shutil
from pathlib import Path
from typing import Final

from admino.models import (
    FileListArgs,
    FileMoveArgs,
    FileReadArgs,
    FileSearchArgs,
    FileWriteArgs,
)
from admino.tools.registry import register_tool

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level configuration
# ---------------------------------------------------------------------------

_MAX_LIST_ENTRIES: Final[int] = 500
_MAX_SEARCH_CONTENT_READ: Final[int] = 100_000  # bytes read per file during content search

# Extensions that are denied for write operations to prevent the LLM from
# writing executable scripts via prompt injection.  The check is case-insensitive.
_DENIED_WRITE_EXTENSIONS: Final[frozenset[str]] = frozenset(
    {
        ".sh",
        ".bash",
        ".zsh",
        ".fish",
        ".csh",
        ".ksh",  # shell scripts
        ".py",
        ".pyw",  # Python
        ".rb",
        ".pl",
        ".pm",  # Ruby, Perl
        ".bat",
        ".cmd",
        ".ps1",  # Windows
        ".exe",
        ".com",
        ".msi",  # Windows binaries
        ".so",
        ".dylib",
        ".dll",  # shared libraries
    }
)


class _AllowedPath:
    """An operator-configured allowed path entry."""

    __slots__ = ("label", "path", "writable")

    def __init__(self, path: str, label: str, access: str) -> None:
        self.path: Path = Path(path).resolve()
        self.label: str = label
        self.writable: bool = access == "readwrite"


_allowed_paths: list[_AllowedPath] = []
_max_read_chars: int = 10_000


def configure(
    allowed_paths: list[dict[str, str]],
    max_read_chars: int = 10_000,
) -> None:
    """Configure the files tool with operator-defined allowed paths.

    Called by main.py during startup with values from AppConfig.

    Args:
        allowed_paths: List of dicts with keys 'path', 'label', 'access'.
            access is 'read' or 'readwrite'.
        max_read_chars: Maximum characters to return when reading a file.
    """
    global _allowed_paths, _max_read_chars
    _allowed_paths = [
        _AllowedPath(
            path=entry["path"],
            label=entry.get("label", entry["path"]),
            access=entry.get("access", "read"),
        )
        for entry in allowed_paths
    ]
    _max_read_chars = max_read_chars


# ---------------------------------------------------------------------------
# Path validation
# ---------------------------------------------------------------------------


def _validate_path(path_str: str, *, require_write: bool = False) -> Path:
    """Resolve and validate a path against the allowed paths list.

    Canonicalizes the path (resolving symlinks and ``..`` segments),
    then checks that it falls under at least one configured allowed path.
    If ``require_write`` is True, the matching allowed path must have
    readwrite access and the file extension must not be in the denylist.

    Args:
        path_str: The raw path string from the LLM.
        require_write: If True, require the path to be in a writable allowed path.

    Returns:
        The resolved, validated Path.

    Raises:
        PermissionError: If the path is outside allowed paths, in a read-only path
            when write is required, or has a denied extension for writes.
        ValueError: If no allowed paths are configured.
    """
    if not _allowed_paths:
        msg = "No allowed file paths configured."
        raise ValueError(msg)

    # Resolve to absolute, following symlinks. This catches ../  traversal
    # and symlink-based escapes.
    resolved = Path(path_str).resolve()

    for entry in _allowed_paths:
        # Check if resolved path is equal to or a child of the allowed path.
        try:
            resolved.relative_to(entry.path)
        except ValueError:
            continue

        # Found a matching allowed path.
        if require_write and not entry.writable:
            msg = f"Path is in a read-only directory: {entry.label}"
            raise PermissionError(msg)

        # L1 fix: reject writes to executable file extensions.
        if require_write and resolved.suffix.lower() in _DENIED_WRITE_EXTENSIONS:
            msg = f"Writing files with extension '{resolved.suffix}' is not allowed."
            raise PermissionError(msg)

        return resolved

    msg = "Path is outside all allowed directories."
    raise PermissionError(msg)


def _revalidate_resolved(resolved: Path) -> None:
    """Re-resolve a path inside a sync thread and verify it hasn't changed.

    TOCTOU defence: between the initial ``_validate_path`` call (in the async
    context) and the actual I/O (in ``asyncio.to_thread``), a symlink could
    have been created or changed.  Re-resolving inside the thread and comparing
    with the originally validated path catches this race.

    Args:
        resolved: The path returned by ``_validate_path``.

    Raises:
        PermissionError: If re-resolution produces a different path (symlink swap)
            or the path is no longer under an allowed directory.
    """
    # Residual TOCTOU window (documented, accepted for current threat model):
    # There is still a gap between the async `_validate_path` call and this
    # re-resolution inside `asyncio.to_thread`. An attacker who can atomically
    # rename a directory component during that window would cause re-resolution
    # to yield a different path -- which THIS check detects and rejects, so the
    # window is closed defensively rather than left exploitable. Fully eliminating
    # the window would require opening each path component with
    # os.open(O_PATH | O_NOFOLLOW), which is not warranted for the current
    # threat model (single-user, trusted local filesystem).
    current = Path(str(resolved)).resolve()
    if current != resolved:
        msg = "Path changed between validation and I/O (possible symlink attack)."
        raise PermissionError(msg)
    # Also verify it's still under an allowed path (belt-and-suspenders).
    for entry in _allowed_paths:
        try:
            current.relative_to(entry.path)
            return
        except ValueError:
            continue
    msg = "Path is outside all allowed directories."
    raise PermissionError(msg)


def _is_within_root(child: Path, root: Path) -> bool:
    """Check if child's resolved path is within root's resolved path."""
    try:
        child.resolve().relative_to(root)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Synchronous helpers (run via asyncio.to_thread)
# ---------------------------------------------------------------------------


def _sync_read_file(path: Path, max_chars: int) -> str:
    """Read a file and truncate to max_chars.

    Re-validates the resolved path inside the thread to defend against
    TOCTOU symlink races (H1 fix).
    """
    _revalidate_resolved(path)
    text = path.read_text(encoding="utf-8", errors="replace")
    if len(text) > max_chars:
        return text[:max_chars] + f"\n\n[Truncated at {max_chars} characters]"
    return text


def _sync_list_dir(path: Path, max_depth: int) -> list[str]:
    """List directory contents up to max_depth levels deep.

    Skips symlinks whose resolved targets fall outside the root path
    to prevent directory listing escapes (M2 fix).
    """
    root_resolved = path.resolve()
    entries: list[str] = []

    def _walk(current: Path, depth: int) -> None:
        if depth > max_depth or len(entries) >= _MAX_LIST_ENTRIES:
            return
        try:
            items = sorted(current.iterdir(), key=lambda p: (not p.is_dir(), p.name))
        except PermissionError:
            return
        for item in items:
            if len(entries) >= _MAX_LIST_ENTRIES:
                return
            # M2 fix: skip symlinks that resolve outside the allowed root.
            if item.is_symlink() and not _is_within_root(item, root_resolved):
                continue
            # Show path relative to the original requested path
            try:
                rel = item.relative_to(path)
            except ValueError:
                rel = item
            prefix = "d " if item.is_dir() else "f "
            entries.append(prefix + str(rel))
            if item.is_dir() and depth < max_depth:
                _walk(item, depth + 1)

    _walk(path, 1)
    return entries


def _sync_search_files(
    root: Path,
    pattern: str,
    content_search: bool,
    max_results: int,
) -> list[str]:
    """Search for files by name glob or content.

    Re-validates each file path inside the walk to ensure symlinks within
    the allowed directory cannot escape to out-of-bounds files (H2 fix).
    Explicitly passes followlinks=False to os.walk.
    """
    root_resolved = root.resolve()
    results: list[str] = []

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        if len(results) >= max_results:
            break

        # H2 fix: prune subdirectories whose resolved paths escape the root.
        # Modifying dirnames in-place controls which subdirs os.walk descends into.
        dirnames[:] = [d for d in dirnames if _is_within_root(Path(dirpath) / d, root_resolved)]

        for fname in filenames:
            if len(results) >= max_results:
                break
            full_path = Path(dirpath) / fname

            # H2 fix: skip files that resolve outside the root.
            if not _is_within_root(full_path, root_resolved):
                continue

            if content_search:
                # Search file contents for the pattern string.
                try:
                    raw = full_path.read_bytes()[:_MAX_SEARCH_CONTENT_READ]
                    text = raw.decode("utf-8", errors="replace")
                except (PermissionError, OSError):
                    continue
                if pattern.lower() in text.lower():
                    try:
                        rel = full_path.relative_to(root)
                    except ValueError:
                        rel = full_path
                    results.append(str(rel))
            else:
                # Match filename against glob pattern.
                if fnmatch.fnmatch(fname, pattern):
                    try:
                        rel = full_path.relative_to(root)
                    except ValueError:
                        rel = full_path
                    results.append(str(rel))

    return results


def _sync_write_file(path: Path, content: str) -> None:
    """Write content to a NEW file, creating parent directories if needed.

    Create-only: if the file already exists, ``os.open`` with ``O_EXCL``
    raises ``FileExistsError``. This is the kernel-level TOCTOU defence
    paired with the handler's pre-check — even if another process creates
    the file in the window between the pre-check and this open, the open
    itself refuses to clobber it.

    Uses O_NOFOLLOW via os.open to prevent writing through symlinks (H1 fix).
    Re-validates the resolved path inside the thread.
    """
    _revalidate_resolved(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # O_NOFOLLOW: refuse to open if path is a symlink.  This prevents a race
    # where a symlink is planted between validation and open.
    # O_EXCL:     refuse to open if the file already exists — create-only.
    #             We never destroy existing content via this handler.
    fd = os.open(
        str(path),
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o644,
    )
    try:
        os.write(fd, content.encode("utf-8"))
    finally:
        os.close(fd)


def _sync_move_file(source: Path, destination: Path) -> None:
    """Move a file from source to destination.

    Re-validates both paths inside the thread (H1 fix).
    Rejects moves if either path is a symlink.
    """
    _revalidate_resolved(source)
    _revalidate_resolved(destination)
    # Reject if source is a symlink — shutil.move follows symlinks.
    if source.is_symlink():
        msg = "Refusing to move a symlink."
        raise PermissionError(msg)
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Refuse to overwrite existing files — consistent with files.write and
    # download actions. This prevents move from acting as a de-facto delete.
    if os.path.lexists(str(destination)):
        if destination.is_symlink():
            msg = "Refusing to move to a symlink destination."
            raise PermissionError(msg)
        msg = "Destination already exists. Choose a different path."
        raise FileExistsError(msg)
    shutil.move(str(source), str(destination))


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------


@register_tool(
    tool="files",
    action="read",
    description="Read file contents, truncated to the configured character limit.",
    args_schema=FileReadArgs,
)
async def files_read(args: FileReadArgs, **kwargs: object) -> str:
    """Read a file within an allowed path.

    Args:
        args: Validated read arguments (path).

    Returns:
        The file contents, truncated to max_read_chars.
    """
    validated_path = _validate_path(args.path, require_write=False)
    if not validated_path.is_file():
        return f"Not a file or does not exist: {validated_path}"
    return await asyncio.to_thread(_sync_read_file, validated_path, _max_read_chars)


@register_tool(
    tool="files",
    action="list",
    description="List files and directories at a given path, with configurable depth.",
    args_schema=FileListArgs,
)
async def files_list(args: FileListArgs, **kwargs: object) -> str:
    """List directory contents within an allowed path.

    Args:
        args: Validated list arguments (path, max_depth).

    Returns:
        A newline-separated listing of files and directories.
    """
    validated_path = _validate_path(args.path, require_write=False)
    if not validated_path.is_dir():
        return f"Not a directory or does not exist: {validated_path}"
    entries = await asyncio.to_thread(_sync_list_dir, validated_path, args.max_depth)
    if not entries:
        return "Directory is empty."
    return "\n".join(entries)


@register_tool(
    tool="files",
    action="search",
    description="Search for files by name pattern or content within an allowed directory.",
    args_schema=FileSearchArgs,
)
async def files_search(args: FileSearchArgs, **kwargs: object) -> str:
    """Search for files by filename glob or content within an allowed path.

    Args:
        args: Validated search arguments (path, pattern, content_search, max_results).

    Returns:
        A newline-separated list of matching file paths relative to the search root.
    """
    validated_path = _validate_path(args.path, require_write=False)
    if not validated_path.is_dir():
        return f"Not a directory or does not exist: {validated_path}"
    results = await asyncio.to_thread(
        _sync_search_files,
        validated_path,
        args.pattern,
        args.content_search,
        args.max_results,
    )
    if not results:
        return "No files found matching the search criteria."
    return "\n".join(results)


@register_tool(
    tool="files",
    action="write",
    description=(
        "Create a NEW file with the given content. The path must be in a "
        "readwrite-allowed directory and must NOT already exist. Overwriting "
        "existing files is permanently disabled (files.overwrite is hardcoded-"
        "denied, equivalent to files.delete). If the destination already "
        "exists, do NOT attempt to move the old file aside — instead, stop "
        "and ask the user to choose a different filename."
    ),
    args_schema=FileWriteArgs,
)
async def files_write(args: FileWriteArgs, **kwargs: object) -> str:
    """Create a new file within a writable allowed path.

    This action is strictly create-only. If the destination already exists
    (as a regular file, directory, or symlink — anything ``os.path.lexists``
    reports), the call is refused with a descriptive message so the LLM can
    surface the situation to the user and ask them for a different filename.

    The existence check here is for a friendly error message. The
    authoritative defence is ``O_EXCL`` inside ``_sync_write_file``, which
    catches the TOCTOU race where another process creates the file
    between this check and the open.

    Args:
        args: Validated write arguments (path, content).

    Returns:
        A confirmation message on success, or a refusal message if the
        destination already exists.
    """
    validated_path = _validate_path(args.path, require_write=True)
    # Pre-check: refuse if the target already exists. ``lexists`` catches
    # symlinks (even broken ones) and directories in addition to regular
    # files — all of which we refuse to clobber.
    if os.path.lexists(str(validated_path)):
        return (
            f"Cannot write to {validated_path}: a file or directory already "
            "exists at that path. Overwriting existing files is not permitted "
            "— it would destroy the prior content, which is equivalent to "
            "deletion. Please ask the user to choose a different filename."
        )
    try:
        await asyncio.to_thread(_sync_write_file, validated_path, args.content)
    except FileExistsError:
        # TOCTOU race: the file was created between the lexists check and
        # the O_EXCL open. Surface the same refusal message so the behaviour
        # is consistent regardless of which layer catches it.
        return (
            f"Cannot write to {validated_path}: a file was created at that "
            "path concurrently. Overwriting is not permitted. Please ask the "
            "user to choose a different filename."
        )
    return f"Written {len(args.content)} characters to {validated_path}"


@register_tool(
    tool="files",
    action="move",
    description="Move a file. Both source and destination must be in readwrite directories.",
    args_schema=FileMoveArgs,
)
async def files_move(args: FileMoveArgs, **kwargs: object) -> str:
    """Move a file between writable allowed paths.

    Args:
        args: Validated move arguments (source, destination).

    Returns:
        A confirmation message.
    """
    source_path = _validate_path(args.source, require_write=True)
    dest_path = _validate_path(args.destination, require_write=True)
    if not source_path.is_file():
        return f"Source file does not exist: {source_path}"
    await asyncio.to_thread(_sync_move_file, source_path, dest_path)
    return f"Moved {source_path} to {dest_path}"
