"""Cached package decisions must be reconstructed by the resident authority."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.local_supply_chain import evaluate_package_request_artifact
from codex_plugin_scanner.guard.native_resident_client import (
    close_native_residents,
    native_resident_client_failure_code,
)
from codex_plugin_scanner.guard.native_resident_prerequisite_reason import prerequisite_failure_for_home
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_native_supply_chain_cloud_vectors import VECTORS, _artifact, _seed_rows
from tests.test_native_supply_chain_cloud_vectors import pytestmark as pytestmark


@pytest.mark.parametrize(
    "variant", ["control", "changed-cache", "expired", "payload-hash", "revoked-key", "foreign-workspace"]
)
def test_native_cache_reconstructs_current_authority(native_context_digest, tmp_path: Path, variant: str) -> None:
    del native_context_digest
    case = copy.deepcopy(next(case for case in VECTORS["cases"] if case["name"] == "offline_eval_cache_hit"))
    workspace = tmp_path / "ws"
    workspace.mkdir()
    for name, spec in case["files"].items():
        (workspace / name).write_text(spec["text"], encoding="utf-8")
    home = tmp_path / "home"
    store = GuardStore(home)
    cache_row = case["rows"]["guard_supply_chain_eval_cache"][0]
    if variant != "control":
        cached = json.loads(cache_row["decision_json"])
        cached.update(
            decision="allow", policy_action="allow", packages=[], reasons=[], risk_summary="unverified cached text"
        )
        cache_row["decision_json"] = json.dumps(cached)
    bundle_row = case["rows"]["guard_supply_chain_bundle_cache"][0]
    bundle = json.loads(bundle_row["response_json"])
    if variant == "payload-hash":
        bundle["payloadHash"] = "0" * 64
    elif variant == "revoked-key":
        key = next(key for key in bundle["verificationKeys"] if key["keyId"] == bundle["bundle"]["keyId"])
        key["state"] = "revoked"
    elif variant == "foreign-workspace":
        bundle_row["workspace_id"] = cache_row["workspace_id"] = "other-fixture-workspace"
        credentials_row = next(
            row for row in case["rows"]["sync_state"] if row["state_key"] == "oauth_local_credentials"
        )
        credentials = json.loads(credentials_row["payload_json"])
        credentials["workspace_id"] = "other-fixture-workspace"
        credentials_row["payload_json"] = json.dumps(credentials)
    bundle_row["response_json"] = json.dumps(bundle)
    _seed_rows(home / "guard.db", case["rows"])
    try:
        result = evaluate_package_request_artifact(
            artifact=_artifact(case["targets"], case["lockfile_paths"]),
            store=store,
            workspace_dir=workspace,
            now="2100-01-01T00:00:00Z" if variant == "expired" else VECTORS["now"],
        )
        assert not any(reason["code"] == "native_supply_chain_eval_unavailable" for reason in result.reasons), (
            native_resident_client_failure_code(),
            prerequisite_failure_for_home(home),
        )
        assert result.decision != "allow"
        assert result.policy_action != "allow"
        assert result.risk_summary != "unverified cached text"
        if variant in {"control", "changed-cache"}:
            assert result.decision == "block"
            assert result.cache_status == "hit"
            assert result.entitlement_state == "unknown"
            assert any(reason["code"] == "known_malware_or_kev" for reason in result.reasons)
        else:
            assert result.cache_status != "hit"
        if variant == "foreign-workspace":
            assert result.bundle_version is None
            assert result.enforcement != "offline_cached"
    finally:
        close_native_residents(guard_home=home)
