"""Source-built CLI-sink/resident proof; separate from installed OMP evidence."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.cli.commands_dispatch_local import _run_guard_execute_bound_bash_command
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.native_bash_protocol import NativeBashError, runtime_status
from codex_plugin_scanner.guard.native_resident_client import close_native_residents
from codex_plugin_scanner.guard.runtime.bound_bash_sink import run_bound_bash
from codex_plugin_scanner.guard.store import GuardStore


class _Secrets:
    def __init__(self):
        self.values = {}

    def get_secret(self, key):
        return self.values.get(key)

    def set_secret(self, key, value):
        self.values[key] = value

    def delete_secret(self, key):
        self.values.pop(key, None)


@pytest.mark.skipif(sys.platform != "darwin", reason="native immutable Bash owner currently supports macOS")
@pytest.mark.parametrize("home_in_workspace", [True, False])
def test_real_sink_quiet_replay_and_current_persistence_review(
    native_context_digest, tmp_path, monkeypatch, home_in_workspace,
):
    del native_context_digest
    runtime_status()  # A lane with an old binary must fail, not count a skipped proof.
    original_prepare = HookWorker.prepare_workspace_policy

    def checked_prepare(worker, *args, **kwargs):
        result = original_prepare(worker, *args, **kwargs)
        assert result is not None, worker.policy_snapshot_publisher.last_error
        return result

    monkeypatch.setattr(HookWorker, "prepare_workspace_policy", checked_prepare)
    project, guard = tmp_path / "project", tmp_path / "guard"
    home = (project if home_in_workspace else tmp_path) / "home"
    project.mkdir()
    home.mkdir()
    fixtures = Path(__file__).parent / "fixtures" / "script_approvals"
    for name in ("maintenance.sh", "fixture-registry"):
        target = project / name
        target.write_bytes((fixtures / name).read_bytes())
        target.chmod(0o700)
    monkeypatch.chdir(project)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PATH", f"{project}:/usr/bin:/bin")
    store = GuardStore(guard, prime_policy_integrity=False)
    store._policy_integrity_secret_store = _Secrets()
    payload = {
        "hook_event_name": "PreToolUse", "tool_name": "bash",
        "tool_input": {"command": f"/bin/bash '{project / 'maintenance.sh'}' dry"}, "cwd": str(project),
    }
    output, errors = io.StringIO(), io.StringIO()
    try:
        if not home_in_workspace:
            with pytest.raises(NativeBashError, match="native_bash_consent_required"):
                run_bound_bash(payload, store=store, workspace=project, harness="omp",
                               operation_id="sink-fixture-operation-1", output=output, errors=errors)
            assert not (home / "maintenance-report.tsv").exists()
            with store._connect() as connection:
                assert connection.execute("select count(*) from guard_bash_operations").fetchone()[0] == 0
            return
        request_directory = tmp_path / "hol-guard-contained-test-sink-fixture"
        request_directory.mkdir(mode=0o700)
        request_file = request_directory / "request.json"
        raw = json.dumps({"schema": "guard-contained-test-request.v1", "workspace": str(project), "payload": payload})
        request_file.write_text(raw)
        request_file.chmod(0o600)
        args = argparse.Namespace(
            harness="omp", operation_id="sink-fixture-operation-1", timeout_seconds=120,
            request_file=str(request_file), request_sha256=hashlib.sha256(raw.encode()).hexdigest(),
        )
        assert _run_guard_execute_bound_bash_command(
            args, guard_home=guard, workspace=project, store=store, context=SimpleNamespace(home_dir=home),
        ) == 0
        assert not request_file.exists() and not request_directory.exists()
        report = home / "maintenance-report.tsv"
        assert report.is_file()
        assert output.getvalue() == ""
        assert "alpha/current" in report.read_text() and "local metadata" in report.read_text()
        report.write_text("preserved after lost reply")
        assert run_bound_bash(payload, store=store, workspace=project, harness="omp",
                              operation_id="sink-fixture-operation-1", output=output, errors=errors) == 0
        assert report.read_text() == "preserved after lost reply"
        assert "output_not_retained" in errors.getvalue()
        with store._connect() as connection:
            assert connection.execute("select count(*) from guard_local_once_approvals").fetchone()[0] == 0
            assert connection.execute("select count(*) from guard_bash_operations").fetchone()[0] == 1
    finally:
        assert close_native_residents(guard_home=guard)
