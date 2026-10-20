"""Private, executable placement for verified native compiler bytes.

The verified compiler bytes are written to a fresh 0700 directory and run from
there, so the bytes that run are exactly the bytes that were verified. The
system temporary directory comes first. A host that mounts it noexec, such as
a container on a default tmpfs, runs them from a private folder in the Guard
home instead. That folder is used only while it, the Guard home and every
directory above the Guard home are closed to other accounts, so no second
account can swap the bytes between the write and the exec.
"""

from __future__ import annotations

import os
import stat
import tempfile
from collections.abc import Generator
from contextlib import contextmanager, suppress
from pathlib import Path

_PRIVATE_ROOT_NAME = "native-exec"
_EXECUTABLE_NAME = "hol-guard-runtime.exe" if os.name == "nt" else "hol-guard-runtime"
# Every Guard home this process has opened, most recent first, so a store for
# one home never takes the fallback away from a store for another.
_private_roots: list[Path] = []


class ExecutableMaterializationError(OSError):
    """No private directory could run the verified compiler bytes."""


def use_guard_home(guard_home: Path) -> None:
    """Add a Guard home whose private folder can back a noexec temporary directory."""
    root = Path(guard_home) / _PRIVATE_ROOT_NAME
    with suppress(ValueError):
        _private_roots.remove(root)
    _private_roots.insert(0, root)


def _closed_directory(metadata: os.stat_result, *, open_bits: int) -> bool:
    return stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.geteuid() and not metadata.st_mode & open_bits


def _replaceable_by_another_account(directory: Path) -> bool:
    """Whether another account could rename a directory above this one away.

    Both the path as named and the path its links resolve to are checked. A
    link is only as safe as the directory holding it, which is checked as the
    next ancestor, so links are judged by owner alone.
    """
    resolved = Path(os.path.realpath(directory))
    for ancestor in (*directory.parents, *resolved.parents):
        metadata = ancestor.lstat()
        if metadata.st_uid not in (0, os.geteuid()):
            return True
        if stat.S_ISLNK(metadata.st_mode):
            continue
        if not stat.S_ISDIR(metadata.st_mode):
            return True
        # The sticky bit limits renames to the entry's owner, as on /tmp.
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH) and not metadata.st_mode & stat.S_ISVTX:
            return True
    return False


def _private_root_directory(root: Path) -> Path | None:
    try:
        # Another account that can write the Guard home, or any directory
        # above it, could rename the private folder or the home away and put
        # its own in its place.
        if not _closed_directory(root.parent.lstat(), open_bits=stat.S_IWGRP | stat.S_IWOTH):
            return None
        if _replaceable_by_another_account(root.parent):
            return None
        with suppress(FileExistsError):
            root.mkdir(mode=0o700)
        if not _closed_directory(root.lstat(), open_bits=0o077):
            return None
    except OSError:
        return None
    return root


def _write(directory: Path, raw: bytes) -> Path:
    path = directory / _EXECUTABLE_NAME
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags, 0o700)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            _ = handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if os.name != "nt":
        path.chmod(0o700)
    return path


def _candidate(raw: bytes, parent: Path | None) -> tuple[tempfile.TemporaryDirectory[str], Path] | None:
    try:
        directory = tempfile.TemporaryDirectory(
            prefix="hol-guard-source-compiler-", dir=parent, ignore_cleanup_errors=True
        )
    except OSError:
        return None
    try:
        path = _write(Path(directory.name), raw)
    except OSError:
        directory.cleanup()
        return None
    # Linux answers X_OK with EACCES for a file on a noexec mount.
    if os.name != "nt" and not os.access(path, os.X_OK):
        directory.cleanup()
        return None
    return directory, path


@contextmanager
def verified_executable(raw: bytes) -> Generator[Path]:
    """Materialize exactly the verified bytes in a private execution directory."""
    candidate = _candidate(raw, None)
    if os.name != "nt":
        for root in tuple(_private_roots):
            if candidate is not None:
                break
            if (directory := _private_root_directory(root)) is not None:
                candidate = _candidate(raw, directory)
    if candidate is None:
        raise ExecutableMaterializationError("no private directory can run the verified source compiler")
    directory, path = candidate
    with directory:
        yield path
