"""Pinned real SDK tool delivery, separate from model/full-wheel qualification."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.pi_extension_bound_bash_source import _ENVIRONMENT_NAMES
from codex_plugin_scanner.guard.adapters.pi_extension_contained_tests_source import CONTAINED_TEST_HELPERS_SOURCE
from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.config import update_guard_settings
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.hook_execution_environment import (
    HOOK_EXECUTION_ENVIRONMENT_KEY,
    collect_hook_execution_environment,
)
from codex_plugin_scanner.guard.native_bash_protocol import runtime_status
from codex_plugin_scanner.guard.native_resident_client import close_native_residents
from codex_plugin_scanner.guard.store import GuardStore
from tests.omp_bound_bash_lifecycle import assert_sdk_host_death_cancels, pause_native_execute_source

pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="native Bash owner is macOS-only")


@pytest.mark.parametrize(
    "duration",
    ["once", "persistent", "persistent-same-intent", "persistent-nonzero", "keep-blocked", "host-parent-death"],
)
@pytest.mark.parametrize("harness", ["omp", "pi"])
def test_pinned_sdk_bash_tool_delivers_consent_and_preserves_execution_cwd(
    native_context_digest,
    tmp_path,
    monkeypatch,
    duration,
    harness,
):
    del native_context_digest
    repo = Path(__file__).resolve().parents[1]
    sdk_root = repo / "ci" / "pi-exact-continuation"
    package_name = "@earendil-works/pi-coding-agent" if harness == "pi" else "@oh-my-pi/pi-coding-agent"
    package = sdk_root / "node_modules" / package_name / "package.json"
    if not package.is_file():
        pytest.skip("install the locked ci/pi-exact-continuation SDK dependencies to run this lane")
    bun = shutil.which("bun")
    if bun is None:
        pytest.skip("requires the pinned SDK's Bun runtime")
    expected = json.loads((sdk_root / "package.json").read_text())["dependencies"][package_name]
    assert json.loads(package.read_text())["version"] == expected
    status = runtime_status()
    assert status.identity is not None
    workspace, home, guard = tmp_path / "project", tmp_path / "home", tmp_path / "guard"
    execution_cwd = workspace / "subproject"
    execution_cwd.mkdir(parents=True)
    home.mkdir()
    fixtures = Path(__file__).parent / "fixtures" / "script_approvals"
    for name in ("maintenance.sh", "fixture-registry"):
        target = execution_cwd / name
        target.write_bytes((fixtures / name).read_bytes())
        target.chmod(0o700)
    if duration == "persistent-nonzero":
        script = execution_cwd / "maintenance.sh"
        script.write_text(script.read_text() + "\nexit 7\n")
    monkeypatch.chdir(workspace)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("LANG", "C")
    monkeypatch.setenv("PATH", f"{execution_cwd}:/usr/bin:/bin:{Path(bun).parent}")
    update_guard_settings(guard, {"blocked_request_mode": "ask"})
    store = GuardStore(guard)
    command = f"/bin/bash {shlex.quote(str(execution_cwd / 'maintenance.sh'))} dry"
    original_input = {"command": command, "timeout": 45}
    session_cwd = workspace if harness == "omp" else execution_cwd
    if harness == "omp":
        original_input["cwd"] = "subproject"
    worker = HookWorker(store=store, workspace=session_cwd, home_dir=home, wait_for_native_policy=False)
    try:
        assert worker.prepare_workspace_policy(session_cwd, deadline=time.monotonic() + 25) is not None
        response = worker.review_http_payload(
            payload={
                "hook_event_name": "PreToolUse",
                "tool_name": "bash",
                "tool_input": original_input,
                "session_id": "bound-bash-sdk-fixture",
                "tool_call_id": "initial-call",
                HOOK_EXECUTION_ENVIRONMENT_KEY: collect_hook_execution_environment(),
                "guard_bound_bash_host": {
                    "schema": "guard-native-bash-host-delivery.v2",
                    "owner_pid": os.getpid(),
                    "host": "omp-input-rewrite-v1" if harness == "omp" else "pi-input-mutation-v1",
                    "environment": {name: os.environ[name] for name in _ENVIRONMENT_NAMES if os.environ.get(name)},
                    "file_creation_mask": 0o022,
                },
            },
            params={},
            default_harness=harness,
            workspace=session_cwd,
            home_dir=home,
            guard_home=guard,
        )
        assert response["required_execution_profile"] == "native-bash-owner-v1"
    finally:
        worker.close()
    wrapper = tmp_path / "guard-cli"
    ready_marker, resume_marker = tmp_path / "cli-ready", tmp_path / "cli-resume"
    pause_source = pause_native_execute_source(ready_marker, resume_marker) if duration == "host-parent-death" else ""
    wrapper.write_text(
        f"#!{sys.executable}\nimport os, sys\nsys.path.insert(0, {str(repo / 'src')!r})\n"
        "os.environ['HOL_GUARD_NATIVE'] = 'force'\n"
        f"os.environ['HOL_GUARD_NATIVE_BINARY'] = {str(status.identity.path)!r}\n"
        + pause_source
        + "from codex_plugin_scanner.cli import main\nraise SystemExit(main())\n"
    )
    wrapper.chmod(0o700)
    routing = tmp_path / "routing.ts"
    routing.write_text(
        """
import { createHash, randomBytes } from 'node:crypto';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
export const handlers = new Map();
const pi = { on(name, callback) {
  const list = handlers.get(name) ?? []; list.push(callback); handlers.set(name, list);
} };
export function bindSession(manager) {
  pi.appendEntry = (kind, data) => manager.appendCustomEntry(kind, data);
}
export function bindExec(exec) { pi.exec = exec; }
const toolCallIdKey = (value) => typeof value === 'string' ? value : null;
const GUARD_CLI_WRAPPER_ACCEPTS_JSON_ARGS = false;
const GUARD_HOME_DIR_IS_DEFAULT = true;
const GUARD_HOME_DIR = "";
const GUARD_CONTAINED_SINK_COMMAND = [];
const GUARD_CONTAINED_REQUEST_ROOT = "";
"""
        + f"const GUARD_CLI_WRAPPER_COMMAND = {json.dumps(str(wrapper))};\n"
        + f"const GUARD_HOME = {json.dumps(str(guard))};\n"
        + CONTAINED_TEST_HELPERS_SOURCE.replace(
            'const boundBashHarness = "omp";', f'const boundBashHarness = "{harness}";'
        )
        + f"const response = {json.dumps(response)};\n"
        + """
pi.on("tool_call", async (event, ctx) => {
  const snapshot = { cwd: ctx.sessionManager.getCwd(), payload: {
    hook_event_name: "PreToolUse", tool_name: event.toolName, tool_call_id: event.toolCallId,
    session_id: ctx.sessionManager.getSessionId(), tool_input: structuredClone(event.input),
  } };
  const input = prepareContainedTestInput(response, snapshot, ctx);
  if (!input) return { block: true, reason: "missing protected owner delivery" };
  ROUTE_INPUT_RESULT
});
""".replace(
            "ROUTE_INPUT_RESULT",
            "Object.assign(event.input, input); return undefined;" if harness == "pi" else "return { input };",
        )
    )
    environment = {
        "HOME": str(home),
        "PATH": os.environ["PATH"],
        "LANG": "C",
        "TERM": "dumb",
        "PI_CODING_AGENT_DIR": str(tmp_path / "sdk-agent"),
        "PYTHONPATH": str(repo / "src"),
        "HOL_GUARD_NATIVE": "force",
        "HOL_GUARD_NATIVE_BINARY": str(status.identity.path),
    }
    configuration = tmp_path / "sdk.json"

    def configure(call_id):
        configuration.write_text(
            json.dumps(
                {
                    "expectedVersion": expected,
                    "routingModule": str(routing),
                    "workspace": str(session_cwd),
                    "callId": call_id,
                    "input": original_input,
                    "harness": harness,
                    "sessionFile": str(tmp_path / "sdk-session.jsonl"),
                    "newIntent": (
                        call_id in {"fresh-operation", "current-policy-denied", "new-user-intent"}
                        or (
                            call_id.startswith("persistent-")
                            and duration not in {"persistent-same-intent", "persistent-nonzero"}
                        )
                    ),
                }
            )
        )

    def run(call_id):
        configure(call_id)
        completed = subprocess.run(
            [bun, str(fixtures / "pi_family_bound_bash_sdk.ts"), str(sdk_root), str(configuration)],
            cwd=workspace,
            env=environment,
            text=True,
            capture_output=True,
            timeout=60,
        )
        assert completed.returncode == 0, completed.stderr[-2000:]
        decoded = json.loads(completed.stdout)
        assert decoded["version"] == expected and decoded["originalInput"] == original_input
        if call_id == "approved-retry":
            assert decoded.get("acknowledgements") == [{"code": 0, "stderr": ""}], decoded
        return decoded.get("result"), decoded.get("sdkError")

    def refused(call_id, code):
        result, error = run(call_id)
        if error is not None:
            assert code in error, error
        else:
            assert result["details"]["exitCode"] == 125, result

    try:
        refused("initial-call", "native_bash_consent_required")
        report = home / "maintenance-report.tsv"
        assert not report.exists()
        pending = store.list_approval_requests()
        assert len(pending) == 1
        request = pending[0]
        subject = request["action_envelope_json"]["native_bash"]["subject"]
        assert subject["context"]["cwd"] == str(execution_cwd)
        if duration == "keep-blocked":
            apply_approval_resolution(
                store=store,
                request_id=request["request_id"],
                action="block",
                scope="artifact",
                persist_policy=False,
                workspace=str(session_cwd),
                reason="Lane-owned SDK Keep blocked",
                scope_contract_version=request["scope_contract_version"],
                scope_contract_digest=request["scope_contract_digest"],
            )
            for iteration in range(2):
                assert close_native_residents(guard_home=guard)
                refused(f"same-user-intent-reissue-{iteration}", "native_bash_operation_kept_blocked")
                assert store.list_approval_requests() == []
            assert not report.exists()
            refused("new-user-intent", "native_bash_consent_required")
            new_pending = store.list_approval_requests()
            assert len(new_pending) == 1 and new_pending[0]["request_id"] != request["request_id"]
            with store._connect() as connection:
                assert connection.execute("select count(*) from guard_bash_operations").fetchone()[0] == 0
                assert connection.execute("select count(*) from policy_decisions").fetchone()[0] == 0
            return
        apply_approval_resolution(
            store=store,
            request_id=request["request_id"],
            action="allow",
            scope="artifact",
            persist_policy=duration in {"persistent", "persistent-same-intent", "persistent-nonzero"},
            workspace=str(session_cwd),
            reason="Lane-owned SDK consent",
            scope_contract_version=request["scope_contract_version"],
            scope_contract_digest=request["scope_contract_digest"],
        )
        if duration == "host-parent-death":
            configure("host-parent-death-retry")
            assert_sdk_host_death_cancels(
                store=store,
                operation_id=request["action_envelope_json"]["native_bash"]["review_lineage"]["operation_id"],
                command=[bun, str(fixtures / "pi_family_bound_bash_sdk.ts"), str(sdk_root), str(configuration)],
                environment=environment,
                workspace=workspace,
                ready=ready_marker,
                resume=resume_marker,
                report=report,
            )
        if duration == "persistent-nonzero":
            for iteration in range(1, 4):
                report.write_text(f"must refresh after exit 7, invocation {iteration}")
                result, error = run("approved-retry" if iteration == 1 else f"persistent-{iteration}")
                if harness == "pi":
                    assert error is not None and error.endswith("Command exited with code 7"), error
                else:
                    assert error is None and result["details"]["exitCode"] == 7, result
                assert "local metadata" in report.read_text(), "a completed failed call must not replay forever"
            assert store.list_approval_requests() == []
            with store._connect() as connection:
                assert connection.execute("select count(*) from guard_bash_operations").fetchone()[0] == 3
            return
        approved, error = run("approved-retry")
        assert error is None, error
        assert not approved.get("isError", False)
        assert approved.get("details", {}).get("exitCode", 0) == 0
        assert "local metadata" in report.read_text()
        if duration in {"persistent", "persistent-same-intent"}:
            for iteration in range(2, 11):
                (execution_cwd / "maintenance.sh").touch()
                (execution_cwd / "unrelated.txt").write_text(str(iteration))
                report.write_text(f"must refresh for invocation {iteration}")
                result, error = run(f"persistent-{iteration}")
                assert error is None, error
                assert not result.get("isError", False), result
                assert "local metadata" in report.read_text(), "a distinct invocation must execute rather than replay"
            assert store.list_approval_requests() == []
            report.write_text("preserve persistent SDK report")
            update_guard_settings(guard, {"subprocess_action": "block"})
            refused("current-policy-denied", "bash_current_policy_denied")
            assert report.read_text() == "preserve persistent SDK report"
            with store._connect() as connection:
                assert connection.execute("select count(*) from guard_bash_operations").fetchone()[0] == 10
                assert connection.execute("select count(*) from guard_local_once_approvals").fetchone()[0] == 0
            return
        report.write_text("preserve SDK report")
        replay, error = run("approved-retry")
        assert error is None, error
        assert not replay.get("isError", False)
        assert replay.get("details", {}).get("exitCode", 0) == 0
        assert report.read_text() == "preserve SDK report"
        refused("fresh-operation", "native_bash_consent_required")
        assert report.read_text() == "preserve SDK report"
    finally:
        assert close_native_residents(guard_home=guard)
