"""The Python facts projection reproduces the recorded configured-action queries."""

from __future__ import annotations

import gzip
import importlib.util
import json
from pathlib import Path

import codex_plugin_scanner.guard.cli.commands  # noqa: F401  (wires the shared command namespace)
from codex_plugin_scanner.guard.cli.commands_support_runtime_artifact_policy import (
    _runtime_artifact_policy_action,
    runtime_policy_artifact_facts,
    runtime_policy_config_facts,
)

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "rust/crates/guard-runtime/tests/fixtures/config_action_vectors.json.gz"
RECORDER = ROOT / "scripts/ci/record_config_action_vectors.py"


def _recorder():
    spec = importlib.util.spec_from_file_location("record_config_action_vectors", RECORDER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _vectors() -> list[dict]:
    return json.loads(gzip.decompress(VECTORS.read_bytes()))


def test_facts_projection_reproduces_recorded_queries(tmp_path: Path) -> None:
    recorder = _recorder()
    vectors = _vectors()
    assert len(vectors) >= 900
    for vector in vectors:
        config = recorder.build_config(vector["spec"]["config"], tmp_path)
        artifact = recorder.build_artifact(vector["spec"]["artifact"])
        assert {
            "policy_config": runtime_policy_config_facts(config, recorder.HARNESS),
            "artifact": runtime_policy_artifact_facts(config, artifact, recorder.HARNESS),
        } == vector["query"], vector["name"]


def test_recorded_actions_cover_every_action_and_auto_stops() -> None:
    vectors = _vectors()
    assert {item["expected"]["action"] for item in vectors} >= {
        "allow",
        "warn",
        "review",
        "require-reapproval",
        "sandbox-required",
        "block",
    }
    assert any(item["expected"]["auto_stop_events"] for item in vectors)


def test_native_action_matches_recorded_python_actions(native_approval_reuse_runtime: Path) -> None:
    recorder = _recorder()
    for vector in _vectors()[:60]:
        config = recorder.build_config(vector["spec"]["config"], native_approval_reuse_runtime)
        artifact = recorder.build_artifact(vector["spec"]["artifact"])
        assert (
            _runtime_artifact_policy_action(
                config, artifact, recorder.HARNESS, guard_home=native_approval_reuse_runtime
            )
            == vector["expected"]["action"]
        ), vector["name"]


def test_a_prompts_classes_travel_instead_of_a_python_hard_block(native_approval_reuse_runtime: Path) -> None:
    recorder = _recorder()
    home = native_approval_reuse_runtime
    config = recorder.build_config(_vectors()[0]["spec"]["config"], home)
    spec: dict[str, object] = {
        "artifact_id": "omp:prompt:1",
        "artifact_type": "prompt_request",
        "metadata": {"prompt_request_classes": ["guard_bypass_intent", "secret_read"]},
    }
    facts = runtime_policy_artifact_facts(config, recorder.build_artifact(spec), recorder.HARNESS)
    # Python stops answering the hard block and hands the classes it read over.
    assert facts["hard_block"] is False
    assert facts["prompt_request_classes"] == ["guard_bypass_intent", "secret_read"]
    # The resident still stops the request, so the decision only changed hands.
    action = _runtime_artifact_policy_action(config, recorder.build_artifact(spec), recorder.HARNESS, guard_home=home)
    assert action == "block"

    spec["metadata"] = {"prompt_request_classes": ["secret_read"]}
    ordinary = runtime_policy_artifact_facts(config, recorder.build_artifact(spec), recorder.HARNESS)
    assert ordinary["prompt_request_classes"] == ["secret_read"]

    spec["metadata"] = {}
    plain = runtime_policy_artifact_facts(config, recorder.build_artifact(spec), recorder.HARNESS)
    # An artifact with no classes sends no key, so an older resident answers for it.
    assert "prompt_request_classes" not in plain


def test_a_reason_code_travels_instead_of_the_two_facts_python_read_off_it(
    native_approval_reuse_runtime: Path,
) -> None:
    recorder = _recorder()
    home = native_approval_reuse_runtime
    config = recorder.build_config(_vectors()[0]["spec"]["config"], home)
    spec: dict[str, object] = {
        "artifact_id": "omp:native-pretool:bash",
        "artifact_type": "tool_call",
        "metadata": {
            "action_class": "pytest repository-code execution",
            "reason_code": "pytest_restricted_profile_required",
            "restricted_profile_version": "2",
        },
    }
    facts = runtime_policy_artifact_facts(config, recorder.build_artifact(spec), recorder.HARNESS)
    # Python stops answering both facts and hands over the metadata they were read off.
    assert facts["pytest_restricted_sandbox"] is False
    assert facts["shell_local_script_review"] is False
    assert facts["reason_code"] == "pytest_restricted_profile_required"
    assert facts["restricted_profile_version"] == "2"

    spec["metadata"] = {"reason_code": "shell_local_script_execution_review"}
    shell = runtime_policy_artifact_facts(config, recorder.build_artifact(spec), recorder.HARNESS)
    assert shell["shell_local_script_review"] is False
    assert shell["reason_code"] == "shell_local_script_execution_review"
    # The version only travels beside a reason code, and only as text.
    assert "restricted_profile_version" not in shell

    spec["metadata"] = {"restricted_profile_version": "2"}
    plain = runtime_policy_artifact_facts(config, recorder.build_artifact(spec), recorder.HARNESS)
    # An artifact that names no reason code sends no key, so an older resident
    # answers for it, where both facts are false for every caller anyway.
    assert "reason_code" not in plain
    assert "restricted_profile_version" not in plain
