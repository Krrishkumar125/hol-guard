"""Tests for package-firewall entitlement helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard import package_firewall_entitlement as entitlement_module
from codex_plugin_scanner.guard.native_hook_artifact_compose import (
    NativeHookComposeError,
    NativeHookComposeValidationError,
)
from codex_plugin_scanner.guard.package_firewall_entitlement import (
    PACKAGE_FIREWALL_RUNTIME_UNAVAILABLE_REASON,
    build_oauth_package_firewall_entitlement,
    package_firewall_action_states,
    package_firewall_available_actions,
    package_firewall_block_details,
    package_firewall_entitlement_or_denied,
    package_firewall_operation_allowed,
    reconcile_connect_state_with_oauth_entitlement,
)
from codex_plugin_scanner.guard.store import GuardStore


@pytest.mark.parametrize(
    "allowed,installed,can_repair",
    [(True, False, True), (True, True, True), (False, False, False), (False, True, True)],
)
def test_repair_access_supports_paid_first_activation_and_existing_local_recovery(
    allowed: bool,
    installed: bool,
    can_repair: bool,
) -> None:
    entitlement = {"allowed": allowed, "reason": "paid_entitlement_active" if allowed else "paid_guard_cloud_required"}
    assert package_firewall_operation_allowed(entitlement, "repair", has_installed_managers=installed) is can_repair
    states = package_firewall_action_states(entitlement, has_installed_managers=installed)
    assert (states["repair"] == "available") is can_repair
    assert package_firewall_operation_allowed(entitlement, "install", has_installed_managers=installed) is allowed
    assert package_firewall_operation_allowed(entitlement, "remove", has_installed_managers=installed) is installed


def test_build_oauth_package_firewall_entitlement_preserves_team_tier() -> None:
    entitlement = build_oauth_package_firewall_entitlement(
        {
            "guard_local_entitlement": {
                "plan_id": "team",
                "tier": "team",
                "supply_chain_firewall": True,
                "expires_at": "2026-06-30T00:00:00.000Z",
            }
        },
        now=datetime(2026, 5, 31, tzinfo=timezone.utc),
    )

    assert entitlement == {
        "plan_id": "team",
        "supply_chain_entitlement_expires_at": "2026-06-30T00:00:00.000Z",
        "supply_chain_firewall": True,
        "supply_chain_plan_id": "team",
    }


def test_build_oauth_package_firewall_entitlement_consumes_solo_plan_identity() -> None:
    entitlement = build_oauth_package_firewall_entitlement(
        {
            "guard_local_entitlement": {
                "plan_id": "solo",
                "tier": "solo",
                "supply_chain_firewall": False,
                "expires_at": "2026-09-07T00:00:00.000Z",
            }
        },
        now=datetime(2026, 8, 7, tzinfo=timezone.utc),
    )

    assert entitlement == {
        "plan_id": "solo",
        "supply_chain_entitlement_expires_at": "2026-09-07T00:00:00.000Z",
        "supply_chain_firewall": False,
        "supply_chain_plan_id": "solo",
    }


def test_build_oauth_package_firewall_entitlement_keeps_legacy_paid_alias_compatible() -> None:
    entitlement = build_oauth_package_firewall_entitlement(
        {
            "guard_local_entitlement": {
                "plan_id": "paid",
                "tier": "paid",
                "expires_at": "2026-09-07T00:00:00.000Z",
            }
        },
        now=datetime(2026, 8, 7, tzinfo=timezone.utc),
    )

    assert entitlement == {
        "plan_id": "paid",
        "supply_chain_entitlement_expires_at": "2026-09-07T00:00:00.000Z",
        "supply_chain_firewall": True,
        "supply_chain_plan_id": "paid",
    }


def test_reconcile_connect_state_clears_stale_sync_not_available_for_paid_oauth(
    tmp_path: Path,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    now = "2026-05-31T09:00:00.000Z"
    store.record_guard_connect_pairing_completed(
        sync_url="https://hol.org/api/guard/receipts/sync",
        allowed_origin="https://hol.org",
        now=now,
    )
    store.record_latest_guard_connect_sync_result(
        status="connected",
        milestone="sync_not_available",
        now=now,
        reason="Guard sync requires a Pro or Team plan.",
    )
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-token",
        dpop_private_key_pem=(
            "-----BEGIN " + "PRIVATE KEY-----\nMC4CAQAwBQYDK2VuBCIEIA==\n-----END PRIVATE KEY-----\n"
        ),
        dpop_public_jwk={"kty": "OKP", "crv": "Ed25519", "x": "test"},
        dpop_public_jwk_thumbprint="thumbprint-1",
        supply_chain_plan_id="team",
        supply_chain_firewall=True,
        supply_chain_entitlement_expires_at="2026-06-30T00:00:00.000Z",
        workspace_id="workspace-1",
        now=now,
    )

    reconciled = reconcile_connect_state_with_oauth_entitlement(store, now=now)

    assert reconciled is not None
    assert reconciled.get("milestone") == "first_sync_pending"
    effective = store.get_effective_guard_connect_state(now=now)
    assert isinstance(effective, dict)
    assert effective.get("milestone") == "first_sync_pending"


def test_reconcile_connect_state_ignores_non_sync_not_available_milestones(
    tmp_path: Path,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    now = "2026-05-31T09:00:00.000Z"
    store.record_guard_connect_pairing_completed(
        sync_url="https://hol.org/api/guard/receipts/sync",
        allowed_origin="https://hol.org",
        now=now,
    )

    assert reconcile_connect_state_with_oauth_entitlement(store, now=now) is None


def test_reconcile_connect_state_ignores_missing_oauth_credentials(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    now = "2026-05-31T09:00:00.000Z"
    store.record_guard_connect_pairing_completed(
        sync_url="https://hol.org/api/guard/receipts/sync",
        allowed_origin="https://hol.org",
        now=now,
    )
    store.record_latest_guard_connect_sync_result(
        status="connected",
        milestone="sync_not_available",
        now=now,
        reason="Guard sync requires a Pro or Team plan.",
    )

    assert reconcile_connect_state_with_oauth_entitlement(store, now=now) is None


def test_reconcile_connect_state_ignores_free_oauth_plan(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    now = "2026-05-31T09:00:00.000Z"
    store.record_guard_connect_pairing_completed(
        sync_url="https://hol.org/api/guard/receipts/sync",
        allowed_origin="https://hol.org",
        now=now,
    )
    store.record_latest_guard_connect_sync_result(
        status="connected",
        milestone="sync_not_available",
        now=now,
        reason="Guard sync requires a Pro or Team plan.",
    )
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-token",
        dpop_private_key_pem=(
            "-----BEGIN " + "PRIVATE KEY-----\nMC4CAQAwBQYDK2VuBCIEIA==\n-----END PRIVATE KEY-----\n"
        ),
        dpop_public_jwk={"kty": "OKP", "crv": "Ed25519", "x": "test"},
        dpop_public_jwk_thumbprint="thumbprint-1",
        supply_chain_plan_id="free",
        supply_chain_firewall=False,
        supply_chain_entitlement_expires_at="2026-06-30T00:00:00.000Z",
        workspace_id="workspace-1",
        now=now,
    )

    assert reconcile_connect_state_with_oauth_entitlement(store, now=now) is None


@pytest.mark.parametrize("error", [NativeHookComposeError("unavailable"), NativeHookComposeValidationError("bad")])
def test_a_runtime_that_cannot_answer_entitles_nothing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
) -> None:
    """A gating caller reads a denial, never an allow it worked out itself."""

    class _Rows:
        """The rows the question is built from, with no runtime behind them."""

        guard_home = str(tmp_path)

        def get_sync_payload(self, name: str) -> None:
            return None

        def get_effective_guard_connect_state(self, *, now: str) -> None:
            return None

        def get_cloud_sync_profile(self) -> None:
            return None

        def get_oauth_local_credential_health(self) -> None:
            return None

    def refuse(*args: object, **kwargs: object) -> dict[str, object]:
        raise error

    monkeypatch.setattr(entitlement_module, "native_hook_compose", refuse)
    entitlement = package_firewall_entitlement_or_denied(cast("GuardStore", _Rows()))

    assert entitlement["allowed"] is False
    assert entitlement["reason"] == PACKAGE_FIREWALL_RUNTIME_UNAVAILABLE_REASON
    assert package_firewall_operation_allowed(entitlement, "install", has_installed_managers=True) is False
    assert package_firewall_action_states(entitlement, has_installed_managers=False)["install"] != "available"
    assert "connect" not in package_firewall_available_actions(entitlement, has_installed_managers=False)


def test_an_unanswerable_runtime_is_not_reported_as_an_unpaid_account() -> None:
    """The block says the runtime could not answer rather than naming a plan."""

    status, code, message = package_firewall_block_details(
        {"allowed": False, "reason": PACKAGE_FIREWALL_RUNTIME_UNAVAILABLE_REASON}
    )

    assert status == 503
    assert code == PACKAGE_FIREWALL_RUNTIME_UNAVAILABLE_REASON
    assert "paid" not in message.lower()
