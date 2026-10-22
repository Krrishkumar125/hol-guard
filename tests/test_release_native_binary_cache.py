"""Exact release reuse must preserve source, build-profile and binary bindings."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.ci.prune_superseded_caches import cache_family
from scripts.release.native_cache_key import build_id
from scripts.release.prepared_native import transfer
from tests.release_workflow_helpers import load_workflow

ROOT = Path(__file__).resolve().parents[1]


def environment() -> dict[str, str]:
    return {
        "SOURCE_SHA": "a" * 40,
        "VERSION": "3.54.0",
        "RUST_TARGET": "aarch64-apple-darwin",
        "RUNNER_OS": "macOS",
        "RUNNER_ARCH": "ARM64",
        "ImageOS": "macos15",
        "ImageVersion": "20261020.1",
        "FAST_CODEGEN": "false",
        "HOL_GUARD_APPROVAL_ENROLLMENT_ROOT_HEX": "public-root",
        "HOL_GUARD_APPROVAL_ENROLLMENT_ROOT_FINGERPRINT_HEX": "public-fingerprint",
    }


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("SOURCE_SHA", "b" * 40),
        ("VERSION", "3.54.1"),
        ("RUST_TARGET", "x86_64-apple-darwin"),
        ("RUNNER_ARCH", "X64"),
        ("ImageVersion", "20261021.1"),
        ("FAST_CODEGEN", "true"),
        ("RUSTFLAGS", "-C link-arg=/Brepro"),
        ("CARGO_ENCODED_RUSTFLAGS", "-C\x1fopt-level=1"),
        ("RUSTUP_TOOLCHAIN", "1.89.0"),
        ("CARGO_PROFILE_RELEASE_LTO", "false"),
        ("CARGO_PROFILE_RELEASE_CODEGEN_UNITS", "16"),
        ("HOL_GUARD_APPROVAL_ENROLLMENT_ROOT_HEX", "different-root"),
        ("HOL_GUARD_APPROVAL_ENROLLMENT_ROOT_FINGERPRINT_HEX", "different-fingerprint"),
    ],
)
def test_binary_reuse_rejects_each_changed_build_input(name, value):
    original = environment()
    assert build_id({**original, name: value}) != build_id(original)


def test_alpha_workspace_optimization_is_bound_only_when_used():
    original = {**environment(), "FAST_CODEGEN": "true", "ALPHA_WORKSPACE_OPT_LEVEL": "1"}
    assert build_id(original) != build_id({**original, "ALPHA_WORKSPACE_OPT_LEVEL": "2"})
    stable = environment()
    assert build_id(stable) == build_id({**stable, "ALPHA_WORKSPACE_OPT_LEVEL": "1"})


def test_cache_identity_ignores_scheduling_and_environment_order():
    original = environment()
    reordered = dict(reversed(list(original.items())))
    assert build_id(original) == build_id({**reordered, "GITHUB_RUN_ID": "987", "CI_PYTEST_COVERAGE_SHARDS": "128"})


@pytest.mark.parametrize(
    "name", ["SOURCE_SHA", "VERSION", "RUST_TARGET", "RUNNER_OS", "RUNNER_ARCH", "ImageOS", "ImageVersion"]
)
def test_incomplete_identity_cannot_select_a_shared_binary(name):
    inputs = environment()
    del inputs[name]
    with pytest.raises(ValueError, match="complete"):
        build_id(inputs)


@pytest.mark.parametrize(("name", "value"), [("SOURCE_SHA", "abc123"), ("FAST_CODEGEN", "yes")])
def test_ambiguous_identity_is_refused(name, value):
    with pytest.raises(ValueError):
        build_id({**environment(), name: value})


@pytest.mark.parametrize("change", ["build_id", "missing_id", "version", "source", "runtime", "compiler"])
def test_restored_identity_and_hashes_are_verified_before_install(tmp_path, monkeypatch, change):
    for name, value in environment().items():
        monkeypatch.setenv(name, value)
    paths = {}
    for name, filename in (("RUNTIME", "runtime"), ("SOURCE_COMPILER", "compiler")):
        paths[name] = tmp_path / filename
        paths[name].write_bytes(filename.encode())
        monkeypatch.setenv(name, str(paths[name]))
    monkeypatch.setenv("PREPARED_NATIVE_BUILD_ID", build_id(environment()))
    packed = tmp_path / "packed"
    transfer(packed, install=False)
    manifest_path = packed / "identity.json"
    manifest = json.loads(manifest_path.read_text())
    if change == "build_id":
        manifest["build_id"] = "0" * 64
    elif change == "missing_id":
        del manifest["build_id"]
    elif change == "version":
        manifest["version"] = "3.54.1"
    elif change == "source":
        manifest["source_sha"] = "b" * 40
    else:
        (packed / change).write_bytes(b"tampered")
    manifest_path.write_text(json.dumps(manifest))
    for destination in paths.values():
        destination.write_bytes(b"existing")
    with pytest.raises(ValueError, match="mismatch"):
        transfer(packed, install=True)
    assert all(path.read_bytes() == b"existing" for path in paths.values())


def test_exact_cache_reuse_restores_both_executables(tmp_path, monkeypatch):
    monkeypatch.setenv("SOURCE_SHA", "a" * 40)
    monkeypatch.setenv("VERSION", "3.54.0")
    monkeypatch.setenv("PREPARED_NATIVE_BUILD_ID", build_id(environment()))
    runtime, compiler = tmp_path / "runtime", tmp_path / "compiler"
    for key, path in (("RUNTIME", runtime), ("SOURCE_COMPILER", compiler)):
        path.write_bytes(path.name.encode())
        monkeypatch.setenv(key, str(path))
    packed = tmp_path / "packed"
    transfer(packed, install=False)
    runtime.unlink()
    compiler.unlink()
    transfer(packed, install=True)
    assert runtime.read_bytes() == b"runtime"
    assert compiler.read_bytes() == b"compiler"
    assert runtime.stat().st_mode & 0o111
    assert compiler.stat().st_mode & 0o111


def test_binary_cache_preserves_verification_and_has_no_partial_fallback():
    job = load_workflow(ROOT / ".github/workflows/release-native-prepare.yml")["jobs"]["compile"]
    steps = {step.get("name"): step for step in job["steps"]}
    restore = steps["Restore exact release binaries"]
    assert "restore-keys" not in restore["with"]
    assert "steps.native-identity.outputs.build-id" in restore["with"]["key"]
    assert "matrix.target" in restore["with"]["key"]
    assert "fast" in restore["with"]["key"]
    verify = steps["Verify restored native release inputs"]
    assert "cache-hit == 'true'" in verify["if"]
    assert verify["run"].index("prepared_native.py install") < verify["run"].index("build_native_command_program.py")
    assert '"$RUNTIME" self-test --json' in verify["run"]
    for name in (
        "Install pinned Rust target",
        "Cache trusted release compilation",
        "Install content-addressed compiler cache",
        "Compile canonical release inputs",
    ):
        assert "cache-hit != 'true'" in steps[name]["if"]
    save = steps["Save verified release binaries"]
    assert "github.ref == 'refs/heads/main'" in save["if"]
    assert "github.event_name == 'push' || inputs.fast_codegen == true" in save["if"]
    assert list(steps).index("Save verified release binaries") > list(steps).index("Compile canonical release inputs")
    assert steps["Upload exact-run binaries"]["with"]["path"] == "prepared-native/*"
    family = "release-native-binaries-v1-aarch64-apple-darwin-release"
    assert cache_family(family + "-" + "a" * 64) == family


def test_duplicate_sources_wait_without_canceling_publish_calls():
    job = load_workflow(ROOT / ".github/workflows/release-native-prepare.yml")["jobs"]["compile"]
    concurrency = job["concurrency"]
    assert concurrency["cancel-in-progress"] is False
    assert concurrency["queue"] == "max"
    group = concurrency["group"]
    assert "inputs.source_sha || github.sha" in group
    assert "matrix.target" in group
    assert "inputs.version" in group
    assert "github.run_id" not in group
