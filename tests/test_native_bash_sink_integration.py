"""Source-built CLI-sink/resident proof; separate from installed OMP evidence."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.cli.commands_dispatch_local import _run_guard_execute_bound_bash_command
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.native_bash_protocol import runtime_status
from codex_plugin_scanner.guard.native_resident_client import close_native_residents
from codex_plugin_scanner.guard.runtime import bound_bash_sink
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
@pytest.mark.parametrize("duration,home_in_workspace", [("quiet", True), ("once", False), ("persistent", False)])
def test_real_sink_quiet_replay_and_current_persistence_review(
    native_context_digest, tmp_path, monkeypatch, home_in_workspace, duration,
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
            assert run_bound_bash(payload, store=store, workspace=project, harness="omp",
                                  operation_id="sink-fixture-operation-1", output=output, errors=errors) == 125
            assert "native_bash_consent_required" in errors.getvalue()
            assert not (home / "maintenance-report.tsv").exists()
            with store._connect() as connection:
                assert connection.execute("select count(*) from guard_bash_operations").fetchone()[0] == 0
            native_prepare = bound_bash_sink.prepare
            minted = []

            def lane_prepare(*args, **kwargs):
                prepared = native_prepare(*args, **kwargs)
                assert prepared["consent_required"]
                if not minted:
                    # Lane-owned test consent, scoped solely to this disposable
                    # store and the native-prepared subject. No approval endpoint
                    # or operator's live Guard request is accessed.
                    now = datetime.now(timezone.utc)
                    if duration == "once":
                        approval = store.record_local_once_approval(
                            request_id="sink-once-fixture-request", harness="omp", publisher=None,
                            artifact_id=prepared["artifact_id"], artifact_hash=prepared["artifact_hash"],
                            workspace=str(project), action="allow", created_at=now.isoformat(),
                            expires_at=(now + timedelta(minutes=5)).isoformat(),
                        )
                    else:
                        store.ensure_policy_integrity_ready_for_write(now=now.isoformat())
                        store.upsert_policy(PolicyDecision(
                            harness="omp", scope="artifact", action="allow", workspace=str(project),
                            artifact_id=prepared["artifact_id"], artifact_hash=prepared["artifact_hash"],
                            reason="Lane-owned exact version consent", source="approval-gate",
                        ), now.isoformat())
                        approval = "persistent-fixture"
                    assert approval is not None
                    minted.append(approval)
                return prepared

            monkeypatch.setattr(bound_bash_sink, "prepare", lane_prepare)
            assert run_bound_bash(payload, store=store, workspace=project, harness="omp",
                                  operation_id="sink-fixture-operation-1", output=output, errors=errors) == 0
            report = home / "maintenance-report.tsv"
            assert "local metadata" in report.read_text()
            if duration == "persistent":
                monkeypatch.setattr(bound_bash_sink, "prepare", native_prepare)
                for iteration in range(2, 11):
                    if iteration in {2, 6, 10}:
                        assert close_native_residents(guard_home=guard)
                    (project / "maintenance.sh").touch()
                    (project / "unrelated.txt").write_text(str(iteration))
                    assert run_bound_bash(payload, store=store, workspace=project, harness="omp",
                                          operation_id=f"sink-fixture-operation-{iteration}",
                                          output=output, errors=errors) == 0
                assert len(minted) == 1
                report.write_text("preserved after persistent runs")
                helper = project / "fixture-registry"
                helper.write_text(helper.read_text() + "\nprintf changed\n")
                assert run_bound_bash(payload, store=store, workspace=project, harness="omp",
                                      operation_id="sink-fixture-operation-changed",
                                      output=output, errors=errors) == 125
                assert report.read_text() == "preserved after persistent runs"
                with store._connect() as connection:
                    assert connection.execute("select count(*) from guard_local_once_approvals").fetchone()[0] == 0
                    assert connection.execute("select count(*) from guard_bash_operations").fetchone()[0] == 10
                return
            with store._connect() as connection:
                row = connection.execute("select claimed_at from guard_local_once_approvals").fetchone()
                assert row[0] is not None
            report.write_text("preserved once report")
            assert close_native_residents(guard_home=guard)
            assert run_bound_bash(payload, store=store, workspace=project, harness="omp",
                                  operation_id="sink-fixture-operation-1", output=output, errors=errors) == 0
            assert "output_not_retained" in errors.getvalue()
            assert run_bound_bash(payload, store=store, workspace=project, harness="omp",
                                  operation_id="sink-fixture-operation-2", output=output, errors=errors) == 125
            assert report.read_text() == "preserved once report"
            assert len(minted) == 1
            with store._connect() as connection:
                assert connection.execute("select count(*) from guard_bash_operations").fetchone()[0] == 1
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
