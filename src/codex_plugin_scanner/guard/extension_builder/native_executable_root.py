"""Private, executable placement for verified native compiler bytes.

The verified compiler bytes are written to a fresh 0700 directory and run from
there, so the bytes that run are exactly the bytes that were verified. The
system temporary directory comes first. A host that mounts it noexec, such as
a container on a default tmpfs, runs them from a private folder in the Guard
home instead. That folder is used only while it, the Guard home and every
directory above the Guard home are closed to other accounts, so no second
account can swap the bytes between the write and the exec.

The copy is kept for the life of the process. Writing and first running a
new executable of over 100 MB takes seconds on Windows, where every new image
is scanned, and one control change asks native several times. Before each
run the copy is compared byte for byte with the freshly verified bytes; a copy
that differs, is missing or sits in a directory that is no longer private is
replaced, never run.

Windows keeps an executable's image locked for a moment after its process
exits, so each directory is removed at exit with a short backoff once that
lock is released. A single attempt left directories behind on Windows until
the disk filled.
"""

from __future__ import annotations

import atexit
import logging
import os
import shutil
import stat
import tempfile
import threading
import time
from collections.abc import Generator
from contextlib import contextmanager, suppress
from pathlib import Path

_PRIVATE_ROOT_NAME = "native-exec"
_LOGGER = logging.getLogger(__name__)
_EXECUTABLE_NAME = "hol-guard-runtime.exe" if os.name == "nt" else "hol-guard-runtime"
# Every Guard home this process has opened, most recent first, so a store for
# one home never takes the fallback away from a store for another.
_private_roots: list[Path] = []
# Seconds to wait between removal attempts while Windows still holds the image.
_REMOVAL_BACKOFF = (0.05, 0.1, 0.2, 0.4, 0.8, 1.6)
_COMPARE_CHUNK = 1024 * 1024
_copies_lock = threading.Lock()
# The copy runs reuse, and copies already replaced. A replaced copy may still
# be running in another thread, so it is removed with the rest at exit.
_current: tuple[tempfile.TemporaryDirectory[str], Path] | None = None
_retired: list[tempfile.TemporaryDirectory[str]] = []


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


def _remove_released(directory: Path) -> None:
    """Remove a directory whose executable may still be locked by the system."""
    for delay in (*_REMOVAL_BACKOFF, None):
        if not directory.exists():
            return
        try:
            shutil.rmtree(directory)
        except FileNotFoundError:
            return
        except OSError as exc:
            if delay is None:
                _LOGGER.warning("could not remove the source compiler directory %s: %s", directory, exc)
                return
            time.sleep(delay)
        else:
            return


def _holds_exactly(path: Path, raw: bytes) -> bool:
    """Whether a private copy is still a regular file holding exactly the verified bytes."""
    try:
        if os.name != "nt" and not _closed_directory(path.parent.lstat(), open_bits=0o077):
            return False
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(path, flags), "rb") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != len(raw):
                return False
            view = memoryview(raw)
            offset = 0
            while chunk := handle.read(_COMPARE_CHUNK):
                if view[offset : offset + len(chunk)] != chunk:
                    return False
                offset += len(chunk)
            return offset == len(raw)
    except OSError:
        return False


def _materialize(raw: bytes) -> tuple[tempfile.TemporaryDirectory[str], Path]:
    candidate = _candidate(raw, None)
    if os.name != "nt":
        for root in tuple(_private_roots):
            if candidate is not None:
                break
            if (directory := _private_root_directory(root)) is not None:
                candidate = _candidate(raw, directory)
    if candidate is None:
        raise ExecutableMaterializationError("no private directory can run the verified source compiler")
    return candidate


def release_copies() -> None:
    """Remove every private copy this process made. Runs at exit."""
    global _current
    with _copies_lock:
        directories = [*_retired, *([_current[0]] if _current is not None else [])]
        _retired.clear()
        _current = None
    for directory in directories:
        directory.cleanup()
        _remove_released(Path(directory.name))


atexit.register(release_copies)


@contextmanager
def verified_executable(raw: bytes) -> Generator[Path]:
    """Yield a private copy holding exactly the verified bytes."""
    global _current
    with _copies_lock:
        if _current is None or not _holds_exactly(_current[1], raw):
            replacement = _materialize(raw)
            if _current is not None:
                _retired.append(_current[0])
            _current = replacement
        path = _current[1]
    yield path
