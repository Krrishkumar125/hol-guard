"""Installed Python implementation bytes are part of an exact code version."""

from __future__ import annotations

import importlib.util
import marshal
import os
import shlex
import shutil
import subprocess
import sys
import sysconfig
import tempfile
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.hook_native_exact_action import native_exact_action
from tests.test_native_review_exact_action_always import _token, _verdict

pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="isolated macOS CPython layout fixture")


def _copy_runtime(project: Path) -> tuple[Path, Path]:
    executable = Path(sys.executable).resolve()
    library = Path(sysconfig.get_path("stdlib"))
    version = f"python{sys.version_info.major}.{sys.version_info.minor}"
    dylib = library.parent / f"lib{version}.dylib"
    assert executable.is_file() and dylib.is_file(), "select the test CPython distribution"
    installed = project / "runtime" / "lib" / version
    installed.mkdir(parents=True)
    interpreter = project / "runtime" / "bin" / version
    interpreter.parent.mkdir()
    shutil.copy2(executable, interpreter)
    shutil.copy2(dylib, installed.parent / dylib.name)
    # CPython's path landmark and the actual UTF-8 startup implementation.
    shutil.copy2(library / "os.py", installed / "os.py")
    (installed / "encodings").mkdir()
    for name in ("__init__.py", "aliases.py", "utf_8.py"):
        shutil.copy2(library / "encodings" / name, installed / "encodings" / name)
    return interpreter, installed


def _environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    parent = Path(__file__).resolve().parents[1] / "rust" / "target" / "python-wire-tests"
    parent.mkdir(parents=True, exist_ok=True)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    for name in tuple(os.environ):
        if name.startswith("PYTHON"):
            monkeypatch.delenv(name)
    return parent, home


def _execute(argv: list[str], project: Path, home: Path) -> str:
    completed = subprocess.run(
        argv,
        cwd=project,
        env={"HOME": str(home), "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout


def _unchecked_bytecode(source: str, filename: Path) -> bytes:
    header = importlib.util.MAGIC_NUMBER + (1).to_bytes(4, "little") + bytes(8)
    return header + marshal.dumps(compile(source, str(filename), "exec"))


@pytest.mark.parametrize("changed", ["source", "transitive", "bytecode"])
def test_installed_python_standard_module_mutation_changes_reusable_identity(
    native_context_digest: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, changed: str
) -> None:
    del native_context_digest
    parent, home = _environment(tmp_path, monkeypatch)
    with tempfile.TemporaryDirectory(prefix="stdlib-", dir=parent) as directory:
        project = Path(directory).resolve()
        interpreter, installed = _copy_runtime(project)
        module = installed / "colorsys.py"
        library = Path(sysconfig.get_path("stdlib"))
        module.write_bytes((library / "colorsys.py").read_bytes() + b"\nfixture_marker = 'safe'\n")
        selected = module
        if changed == "transitive":
            selected = installed / "calendar.py"
            selected.write_text("fixture_marker = 'safe'\n")
            module.write_text(module.read_text() + "\nfrom calendar import fixture_marker\n")
        elif changed == "bytecode":
            selected = Path(importlib.util.cache_from_source(str(module)))
            selected.parent.mkdir()
            selected.write_bytes(_unchecked_bytecode(module.read_text(), module))
        script = project / "report.py"
        script.write_text("import colorsys\nprint(colorsys.fixture_marker)\n")
        argv = [str(interpreter), "-I", "-S", "-B", str(script)]

        assert _execute(argv, project, home) == "safe\n"
        command = shlex.join(argv)
        before = _token(command, project)
        assert before is not None, "the resolved standard implementation must retain an identity"
        module.touch()
        (project / "unrelated.txt").write_text("ordinary data")
        assert _token(command, project) == before
        metadata = selected.stat()
        body = selected.read_bytes()
        replacement = body.replace(b"fixture_marker = 'safe'", b"fixture_marker = 'evil'")
        if changed == "bytecode":
            replacement = _unchecked_bytecode(module.read_text().replace("'safe'", "'evil'"), module)
        assert len(replacement) == len(body)
        selected.write_bytes(replacement)
        os.utime(selected, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
        assert _execute(argv, project, home) == "evil\n", "the interpreter must load the changed installed body"
        after = _token(command, project)
        assert after is not None and after != before, "Python consent ignored changed installed standard code"
        # A compiled alternative is not silently treated as this source file.
        (installed / "colorsys.so").write_bytes(b"unproven native implementation")
        result, receipt = _verdict()
        assert native_exact_action(
            harness="claude-code",
            tool_name="Bash",
            payload={"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(project)},
            native_result=result,
            native_receipt=receipt,
            workspace=project,
            home_dir=project.parent / "home",
        ) == (None, "python_runtime_module_unproven")


@pytest.mark.parametrize("changed", ["source", "bytecode"])
def test_real_python_local_module_and_active_bytecode_are_content_bound(
    native_context_digest: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, changed: str
) -> None:
    del native_context_digest
    parent, home = _environment(tmp_path, monkeypatch)
    with tempfile.TemporaryDirectory(prefix="local-", dir=parent) as directory:
        project = Path(directory).resolve()
        interpreter, _ = _copy_runtime(project)
        script = project / "report.py"
        script.write_text("import helper\nprint(helper.value)\n")
        helper = project / "helper.py"
        helper.write_text("value = 'safe'\n")
        selected = helper
        if changed == "bytecode":
            selected = Path(importlib.util.cache_from_source(str(helper)))
            selected.parent.mkdir()

        def bytecode(value: str) -> bytes:
            # CPython's unchecked hash cache really executes instead of the
            # unchanged source. This is test-owned code, not analyzer probing.
            return _unchecked_bytecode(f"value = '{value}'\n", helper)

        if changed == "bytecode":
            selected.write_bytes(bytecode("safe"))
        argv = [str(interpreter), "-S", "-B", str(script)]
        assert _execute(argv, project, home) == "safe\n"
        command = shlex.join(argv)
        before = _token(command, project)
        assert before is not None, "a local module proof must remain eligible"
        metadata = selected.stat()
        selected.write_bytes(b"value = 'evil'\n" if changed == "source" else bytecode("evil"))
        os.utime(selected, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
        assert _execute(argv, project, home) == "evil\n"
        assert _token(command, project) not in {None, before}
