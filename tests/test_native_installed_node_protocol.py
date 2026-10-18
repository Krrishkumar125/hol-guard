"""Stronger code identity must not silently use a manifest-only runtime."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_resident_decision
from codex_plugin_scanner.guard.daemon import hook_native_exact_action as bridge


def test_manifest_only_runtime_is_refused_by_the_real_transport_gate(tmp_path, monkeypatch):
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=object(),
        capabilities=SimpleNamespace(features={"resident-protocol-v2", "native-exact-action-v1"}),
    )
    monkeypatch.setattr(native_resident_decision, "native_runtime_status", lambda: status)
    monkeypatch.setattr(native_resident_decision, "ensure_resident_prerequisite", lambda _home: True)
    with pytest.raises(bridge.NativeExactActionError, match="native_exact_action_unavailable"):
        bridge._answer({"kind": "exact_action"}, tmp_path)
    assert list(tmp_path.iterdir()) == [], "unsupported identity cannot write a grant or start a resident"


@pytest.mark.parametrize(
    "reason",
    [
        "node_package_manifest_unproven",
        "node_package_entrypoint_unproven",
        "node_package_exports_unproven",
        "node_package_native_addon_unproven",
        "node_runtime_package_mutation_unproven",
    ],
)
def test_specific_installed_code_uncertainty_is_preserved_without_accepting_arbitrary_reasons(reason):
    bridge._validate_exact_action({"token": None, "once_only_reason": reason})
    with pytest.raises(bridge.NativeExactActionError, match="native_exact_action_payload_invalid"):
        bridge._validate_exact_action({"token": None, "once_only_reason": reason + "_allow"})


def test_real_resident_binds_installed_node_code_and_preserves_specific_uncertainty(
    native_context_digest,
    tmp_path,
    monkeypatch,
):
    del native_context_digest
    node = os.environ.get("HOL_GUARD_TEST_NODE_BINARY")
    if node is None:
        pytest.skip("select a real Node executable for the native identity integration lane")
    assert Path(node).is_absolute() and Path(node).is_file()
    from tests.test_native_review_exact_action_always import _verdict

    parent = Path(__file__).resolve().parents[1] / "rust" / "target" / "node-wire-tests"
    parent.mkdir(parents=True, exist_ok=True)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("NODE_OPTIONS", raising=False)
    monkeypatch.delenv("NODE_PATH", raising=False)
    with tempfile.TemporaryDirectory(prefix="installed-", dir=parent) as directory:
        project = Path(directory).resolve()
        (project / "package.json").write_text('{"type":"module"}')
        (project / "report.mjs").write_text("import value from 'fixture-package'; console.log(value);\n")
        package = project / "node_modules" / "fixture-package"
        package.mkdir(parents=True)
        manifest = package / "package.json"
        manifest.write_text('{"name":"fixture-package","type":"module","exports":"./entry.js"}')
        entry = package / "entry.js"
        entry.write_text("export default 'safe';\n")
        result, receipt = _verdict()
        command = f"{shlex.quote(node)} report.mjs"

        def identity():
            return bridge.native_exact_action(
                harness="claude-code",
                tool_name="Bash",
                payload={"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(project)},
                native_result=result,
                native_receipt=receipt,
                workspace=project,
                home_dir=home,
            )

        before, reason = identity()
        assert before is not None and reason is None
        metadata = entry.stat()
        entry.write_text("export default 'evil';\n")
        os.utime(entry, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
        after, reason = identity()
        assert after is not None and after != before and reason is None
        manifest.write_text(
            json.dumps(
                {
                    "name": "fixture-package",
                    "exports": {
                        "import": "./entry.js",
                        "require": "./other.js",
                    },
                }
            )
        )
        assert identity() == (None, "node_package_exports_unproven")


def test_actual_previous_runtime_cannot_supply_manifest_only_identity(tmp_path):
    previous = os.environ.get("HOL_GUARD_TEST_PREVIOUS_NATIVE_BINARY")
    if previous is None:
        pytest.skip("select the previous native executable for capability compatibility")
    assert Path(previous).is_absolute() and Path(previous).is_file()
    child = r"""
import sys
from pathlib import Path
from codex_plugin_scanner.guard.daemon.hook_native_exact_action import _answer, NativeExactActionError
from codex_plugin_scanner.guard.native_runtime import native_runtime_status
from codex_plugin_scanner.guard.native_resident_client import close_native_residents
home = Path(sys.argv[1])
status = native_runtime_status()
assert status.available and status.compatible and status.capabilities is not None
assert 'native-exact-action-v1' in status.capabilities.features
assert 'native-exact-action-v2' not in status.capabilities.features
try:
    try:
        _answer({'kind':'exact_action'}, home)
    except NativeExactActionError as error:
        assert str(error) == 'native_exact_action_unavailable'
    else:
        raise AssertionError('manifest-only runtime supplied a stronger identity')
finally:
    assert close_native_residents(guard_home=home)
print('previous runtime withheld exact identity')
"""
    environment = {**os.environ, "HOL_GUARD_NATIVE": "force", "HOL_GUARD_NATIVE_BINARY": previous}
    completed = subprocess.run(
        [sys.executable, "-c", child, str(tmp_path / "old-native")],
        env=environment,
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    assert completed.stdout.strip() == "previous runtime withheld exact identity"
