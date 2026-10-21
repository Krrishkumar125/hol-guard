"""Bind the checked-in command-source input manifest to the real dependency closure."""

from __future__ import annotations

import json
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT / "rust"
MANIFEST_PATH = WORKSPACE / "build_support/command_source_inputs.v1.json"
# The fingerprint exists to identify the command compiler implementation: the
# target facade plus the excluded host package that compiles catalog inputs.
COMPILER_ROOTS = ("guard-command", "guard-command-build")


def _manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def _crate_manifest(crate: str) -> dict:
    path = WORKSPACE / "crates" / crate / "Cargo.toml"
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _production_closure() -> set[str]:
    """Normal and build path-dependency closure; dev-only crates stay out."""
    seen: set[str] = set()
    stack = list(COMPILER_ROOTS)
    while stack:
        crate = stack.pop()
        if crate in seen:
            continue
        seen.add(crate)
        manifest = _crate_manifest(crate)
        for section in ("dependencies", "build-dependencies"):
            for spec in manifest.get(section, {}).values():
                path = spec.get("path") if isinstance(spec, dict) else None
                if not path:
                    continue
                target = (WORKSPACE / "crates" / crate / path).resolve()
                crates_root = (WORKSPACE / "crates").resolve()
                assert crates_root == target.parent, f"path dependency escapes crates/: {target}"
                stack.append(target.name)
    return seen


def test_manifest_schema_and_identity_domain() -> None:
    """The manifest keeps the reviewed schema and its versioned identity domain."""
    manifest = _manifest()
    assert manifest["schema"] == "guard.command-source-inputs.v1"
    assert manifest["identity_domain"] == "hol-guard.native-source-implementation.v2"


def test_manifest_files_exist_and_stay_inside_the_workspace() -> None:
    """Every explicit file input exists at its declared workspace path."""
    for relative in _manifest()["files"]:
        assert not relative.startswith(("/", "\\"))
        assert all(part not in ("", ".", "..") for part in relative.split("/"))
        path = WORKSPACE / relative
        assert path.is_file(), relative
        assert not path.is_symlink(), relative


def test_build_support_files_are_all_classified() -> None:
    """No unclassified Rust/JSON input may sit beside the identity implementation."""
    declared = set(_manifest()["files"])
    present = {
        f"build_support/{path.name}"
        for path in (WORKSPACE / "build_support").iterdir()
        if path.is_file() and path.suffix in (".rs", ".json")
    }
    assert present == declared


def test_manifest_crates_match_the_production_closure() -> None:
    """A newly reachable or newly unreachable crate fails until classified."""
    declared = set(_manifest()["crates"])
    assert declared == _production_closure()
    for crate in declared:
        assert (WORKSPACE / "crates" / crate / "Cargo.toml").is_file(), crate


def test_runtime_only_crates_stay_outside_the_fingerprint() -> None:
    """Runtime domains must not re-enter the broad sweep this manifest replaces."""
    declared = set(_manifest()["crates"])
    excluded = {
        "guard-runtime",
        "guard-contained-process",
        "guard-archive",
        "guard-hook-core",
        "guard-pack-compiler",
        "guard-policy-snapshot",
        "guard-rule-contract",
        "guard-google-identity",
        "guard-seatbelt",
        "guard-alloc-probe",
    }
    assert declared.isdisjoint(excluded)


def _path_dependencies(crate: str) -> set[str]:
    manifest = _crate_manifest(crate)
    names = set()
    for section in ("dependencies", "build-dependencies", "dev-dependencies"):
        for dep_name, spec in manifest.get(section, {}).items():
            if isinstance(spec, dict) and "path" in spec:
                names.add(dep_name)
    return names


def test_catalog_data_crate_has_no_path_back_to_the_facade() -> None:
    """The data leaf must not reintroduce a crate-level cycle."""
    assert "guard-command-catalog-data" in _path_dependencies("guard-command")
    assert "guard-command" not in _path_dependencies("guard-command-catalog-data")
    host_paths = _path_dependencies("guard-command-build")
    assert "guard-command" not in host_paths
    assert "guard-command-catalog-data" not in host_paths


def test_python_mirror_follows_the_manifest(tmp_path) -> None:
    """The maintainer-side digest mirror consumes the same checked-in manifest."""
    from scripts.core_command_build_inputs import implementation_digest

    digest = implementation_digest(ROOT)
    assert len(digest) == 64 and all(c in "0123456789abcdef" for c in digest)
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    manifest["identity_domain"] = "hol-guard.native-source-implementation.mutated"
    fake = tmp_path / "rust"
    fake.mkdir()
    (fake / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
    (fake / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
    for relative in manifest["files"]:
        source = WORKSPACE / relative
        target = fake / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    (fake / "build_support" / "command_source_inputs.v1.json").write_text(json.dumps(manifest), encoding="utf-8")
    for crate in manifest["crates"]:
        (fake / "crates" / crate).mkdir(parents=True)
        (fake / "crates" / crate / "Cargo.toml").write_text("[package]\n", encoding="utf-8")
    assert implementation_digest(tmp_path) != digest
