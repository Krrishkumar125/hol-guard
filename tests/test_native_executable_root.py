"""Verified compiler bytes still run when the system temporary directory is noexec."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.extension_builder import native_executable_root as root_module
from codex_plugin_scanner.guard.extension_builder import native_source_compiler

pytestmark = pytest.mark.skipif(os.name == "nt", reason="noexec mounts and POSIX modes are POSIX-only")

_SCRIPT = b"#!/bin/sh\necho verified\n"


def _deny_exec_in_system_temp(monkeypatch: pytest.MonkeyPatch) -> None:
    """Answer X_OK the way Linux does for a file on a noexec /tmp mount."""
    system_temp = Path(tempfile.gettempdir()).resolve()
    real_access = os.access

    def access(path: Path, mode: int) -> bool:
        if mode == os.X_OK and path.resolve().parent.parent == system_temp:
            return False
        return real_access(path, mode)

    monkeypatch.setattr(root_module.os, "access", access)


@pytest.fixture
def guard_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "guard-home"
    home.mkdir(mode=0o700)
    home.chmod(0o700)
    monkeypatch.setattr(root_module, "_private_roots", [])
    root_module.use_guard_home(home)
    return home


def test_an_executable_system_temp_is_used_without_touching_the_guard_home(guard_home: Path) -> None:
    with root_module.verified_executable(_SCRIPT) as path:
        assert path.parent.parent == Path(tempfile.gettempdir())
        assert path.read_bytes() == _SCRIPT
    assert not path.exists()
    assert not (guard_home / "native-exec").exists()


def test_a_noexec_system_temp_runs_the_verified_bytes_from_the_private_guard_home_folder(
    guard_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _deny_exec_in_system_temp(monkeypatch)
    with root_module.verified_executable(_SCRIPT) as path:
        private = guard_home / "native-exec"
        assert path.parent.parent == private
        assert stat.S_IMODE(private.lstat().st_mode) == 0o700
        assert stat.S_IMODE(path.parent.lstat().st_mode) == 0o700
        assert path.read_bytes() == _SCRIPT
        completed = subprocess.run([str(path)], capture_output=True, check=True)
        assert completed.stdout == b"verified\n"
    assert not path.parent.exists()


@pytest.mark.parametrize("weakness", ["group-writable-home", "open-private-folder", "symlinked-private-folder"])
def test_a_private_folder_another_account_could_swap_is_never_used(
    guard_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, weakness: str
) -> None:
    _deny_exec_in_system_temp(monkeypatch)
    private = guard_home / "native-exec"
    if weakness == "group-writable-home":
        guard_home.chmod(0o770)
    elif weakness == "open-private-folder":
        private.mkdir()
        private.chmod(0o755)
    else:
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir(mode=0o700)
        private.symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(root_module.ExecutableMaterializationError), root_module.verified_executable(_SCRIPT):
        pytest.fail("verified bytes were placed where another account could swap them")


def test_no_executable_folder_reports_that_the_compiler_cannot_start(
    guard_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(root_module.os, "access", lambda path, mode: mode != os.X_OK)
    with (
        pytest.raises(native_source_compiler.NativeSourceCompilerError, match="could not be started"),
        native_source_compiler._verified_executable(_SCRIPT),
    ):
        pytest.fail("a compiler was yielded from a noexec folder")


def test_a_caller_error_inside_the_materialized_compiler_propagates_unchanged(guard_home: Path) -> None:
    with pytest.raises(OSError, match="caller failure"), native_source_compiler._verified_executable(_SCRIPT):
        raise OSError("caller failure")


def test_guard_store_names_its_home_as_the_private_execution_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.store import GuardStore

    monkeypatch.setattr(root_module, "_private_roots", [])
    store = GuardStore(tmp_path / "guard-home")
    assert root_module._private_roots == [store.guard_home / "native-exec"]


@pytest.mark.parametrize(("parent_mode", "usable"), [(0o770, False), (0o1770, True)])
def test_a_guard_home_another_account_could_rename_away_is_never_used(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, parent_mode: int, usable: bool
) -> None:
    _deny_exec_in_system_temp(monkeypatch)
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(parent_mode)
    home = shared / "guard-home"
    home.mkdir(mode=0o700)
    monkeypatch.setattr(root_module, "_private_roots", [])
    root_module.use_guard_home(home)
    if usable:
        with root_module.verified_executable(_SCRIPT) as path:
            assert path.parent.parent == home / "native-exec"
        return
    with pytest.raises(root_module.ExecutableMaterializationError), root_module.verified_executable(_SCRIPT):
        pytest.fail("verified bytes were placed under a home another account could rename away")
    assert not (home / "native-exec").exists()


def test_a_second_guard_home_does_not_take_the_fallback_from_the_first(
    guard_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _deny_exec_in_system_temp(monkeypatch)
    unusable = tmp_path / "second-home"
    unusable.mkdir(mode=0o700)
    unusable.chmod(0o770)
    root_module.use_guard_home(unusable)
    with root_module.verified_executable(_SCRIPT) as path:
        assert path.parent.parent == guard_home / "native-exec"


def _hold_the_image(monkeypatch: pytest.MonkeyPatch, attempts: int) -> list[float]:
    """Fail the next removals the way Windows does while an exited executable's image is still mapped."""
    real_rmtree = shutil.rmtree
    held = {"left": attempts}
    sleeps: list[float] = []

    def rmtree(path, *args, **kwargs):  # type: ignore[no-untyped-def]
        if held["left"] > 0:
            held["left"] -= 1
            if "onexc" in kwargs or "onerror" in kwargs:
                return None  # TemporaryDirectory(ignore_cleanup_errors=True) swallows it
            raise PermissionError(13, "The process cannot access the file", str(path))
        return real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(shutil, "rmtree", rmtree)
    monkeypatch.setattr(root_module.time, "sleep", sleeps.append)
    return sleeps


def test_a_directory_held_briefly_after_the_compiler_exits_is_still_removed(
    guard_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sleeps = _hold_the_image(monkeypatch, attempts=3)
    with root_module.verified_executable(_SCRIPT) as path:
        assert path.exists()
    assert not path.parent.exists()
    assert sleeps == [0.05, 0.1]


def test_a_directory_that_stays_held_is_given_up_after_a_bounded_wait_and_reported(
    guard_home: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    sleeps = _hold_the_image(monkeypatch, attempts=100)
    with root_module.verified_executable(_SCRIPT) as path:
        pass
    assert path.parent.exists()
    assert sleeps == list(root_module._REMOVAL_BACKOFF)
    assert "could not remove the source compiler directory" in caplog.text
    monkeypatch.undo()
    shutil.rmtree(path.parent)
