"""Execute generated Bash-owner routing and host observation helpers."""

from __future__ import annotations

import json
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.pi_extension_bound_bash_source import with_bound_bash_host_observation
from codex_plugin_scanner.guard.adapters.pi_extension_contained_tests_source import CONTAINED_TEST_HELPERS_SOURCE
from codex_plugin_scanner.guard.adapters.pi_extension_previous_source import previous_managed_extension_source
from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source

pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="native Bash owner is macOS-only")


@pytest.mark.parametrize("harness", ["omp", "pi"])
def test_bound_bash_rewrite_keeps_original_context_and_stable_operation(tmp_path, harness):
    bun = shutil.which("bun")
    if bun is None:
        pytest.skip("requires the OMP Bun runtime")
    helpers = CONTAINED_TEST_HELPERS_SOURCE.replace('const boundBashHarness = "omp";',
                                                   f'const boundBashHarness = "{harness}";')
    script = tmp_path / "bound-bash.ts"
    script.write_text("""
import { createHash } from 'node:crypto';
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
const pi = { on() {} };
const GUARD_CLI_WRAPPER_COMMAND = "/tmp/guard path'quoted";
const GUARD_CLI_WRAPPER_ACCEPTS_JSON_ARGS = false;
const GUARD_HOME = "/tmp/guard-home 'quoted";
const GUARD_HOME_DIR_IS_DEFAULT = true;
const GUARD_HOME_DIR = "/home/fixture";
const GUARD_CONTAINED_SINK_COMMAND = [];
const GUARD_CONTAINED_REQUEST_ROOT = "";
const toolCallIdKey = (value) => typeof value === 'string' ? value : null;
""" + helpers + """
const snapshot = { cwd: "/project with 'quote", payload: {
  hook_event_name: "PreToolUse", tool_name: "bash", tool_call_id: "bash-call", session_id: "session-1",
  tool_input: { command: "/bin/bash maintenance.sh dry", cwd: "subproject", timeout: 45 },
} };
const required = { decision: "deny", policy_action: "sandbox-required",
  reason_code: "native_bash_owner_required", required_execution_profile: "native-bash-owner-v1" };
const rejected = [
  prepareContainedTestInput({ ...required, decision: "allow" }, snapshot),
  prepareContainedTestInput({ ...required, reason_code: "native_workspace_containment_required" }, snapshot),
  prepareContainedTestInput(required, { ...snapshot, payload: { ...snapshot.payload, session_id: "" } }),
];
const first = prepareContainedTestInput(required, snapshot);
if (!first) throw Error("missing Bash owner route");
const directory = containedTestRequests.get("bash-call");
const raw = readFileSync(join(directory, "request.json"), "utf8");
const duplicate = prepareContainedTestInput(required, snapshot);
cleanupContainedTestRequest("bash-call");
const second = prepareContainedTestInput(required, snapshot);
cleanupContainedTestRequest("bash-call");
console.log(JSON.stringify({ first, second, duplicate, rejected, raw, original: snapshot.payload.tool_input }));
""")
    result = subprocess.run([bun, str(script)], text=True, capture_output=True, check=True, timeout=15)
    decoded = json.loads(result.stdout)
    assert decoded["rejected"] == [None, None, None] and decoded["duplicate"] is None
    first, second = (shlex.split(decoded[key]["command"]) for key in ("first", "second"))
    assert first[:2] == ["/tmp/guard path'quoted", "execute-bound-bash"]
    assert first[first.index("--harness") + 1] == harness
    operation = first[first.index("--operation-id") + 1]
    assert operation.startswith("bash-operation:") and len(operation) == 79
    assert second[second.index("--operation-id") + 1] == operation
    assert first[first.index("--timeout-seconds") + 1] == "45"
    assert decoded["first"]["cwd"] == "subproject"
    assert json.loads(decoded["raw"])["payload"]["tool_input"] == decoded["original"]
    assert decoded["original"]["command"] == "/bin/bash maintenance.sh dry"


@pytest.mark.parametrize("harness", ["omp", "pi"])
def test_host_observation_is_active_only_and_withholds_unselected_values(tmp_path: Path, harness: str):
    bun = shutil.which("bun")
    if bun is None:
        pytest.skip("requires the OMP Bun runtime")
    arguments = {"guard_home": tmp_path / "guard", "home_dir": tmp_path / "home",
                 "settings_path": tmp_path / "settings.json", "harness": harness}
    assert "guard_bound_bash_host" in managed_extension_source(**arguments)
    assert "guard_bound_bash_host" not in previous_managed_extension_source(**arguments)
    source = """
const GUARD_CLI_WRAPPER_ACCEPTS_JSON_ARGS = false;
const GUARD_CLI_WRAPPER_COMMAND = "/path/to/guard";
const activeEnvironment = { LANG: "C", UNSELECTED_FIXTURE_VALUE: "withhold-this-value" };
function observe(payload) {
  let payloadToSend = {
    ...payload,
    guard_execution_environment: {},
  };
  return payloadToSend;
}
const mask = process.umask();
const result = observe({ hook_event_name: "PreToolUse", tool_name: "bash" });
if (process.umask() !== mask) throw Error("mask changed");
console.log(JSON.stringify({ result, mask }));
"""
    script = tmp_path / "host-observation.ts"
    script.write_text(with_bound_bash_host_observation(source, harness=harness))
    result = subprocess.run([bun, str(script)], text=True, capture_output=True, check=True, timeout=15)
    decoded = json.loads(result.stdout)
    stamp = decoded["result"]["guard_bound_bash_host"]
    assert stamp["environment"] == {"LANG": "C"}
    assert stamp["file_creation_mask"] == decoded["mask"]
    assert stamp["host"] == ("omp-input-rewrite-v1" if harness == "omp" else "pi-input-mutation-v1")
    assert "withhold-this-value" not in result.stdout
