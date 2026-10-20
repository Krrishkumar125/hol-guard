"""Package-firewall entitlement helpers shared by CLI and daemon flows."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .cloud_entitlements import parse_guard_cloud_entitlements
from .native_hook_artifact_compose import (
    NativeHookComposeError,
    NativeHookComposeValidationError,
    native_hook_compose,
)
from .package_firewall_defaults import (
    PACKAGE_FIREWALL_PAID_TIERS,
    build_guard_local_entitlement_defaults,
)
from .store import GuardStore


def _dict_or_none(value: object) -> dict[str, object] | None:
    return value if isinstance(value, dict) else None


def _optional_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def build_oauth_package_firewall_entitlement(
    payload: dict[str, object],
    *,
    now: datetime | None = None,
) -> dict[str, object] | None:
    record = payload.get("guard_local_entitlement")
    if not isinstance(record, dict):
        return None
    defaults = build_guard_local_entitlement_defaults(record, now=now)
    if defaults is None:
        return None

    # The typed Cloud parser is the authoritative path for canonical Guard
    # plan IDs. Retain the legacy defaults path for older paid-tier aliases so
    # existing OAuth grants are not invalidated during rollout.
    parsed = parse_guard_cloud_entitlements(payload)
    if parsed is None:
        return defaults
    defaults["plan_id"] = parsed.plan_id
    defaults["supply_chain_plan_id"] = parsed.plan_id
    firewall = parsed.features.get("guard.cloud.supply_chain_firewall")
    if isinstance(firewall, bool):
        defaults["supply_chain_firewall"] = firewall
    return defaults


def _oauth_entitlement_fields_from_sync_payload(payload: object) -> dict[str, object] | None:
    if not isinstance(payload, dict):
        return None
    fields: dict[str, object] = {}
    for key in (
        "supply_chain_plan_id",
        "supply_chain_firewall",
        "supply_chain_entitlement_expires_at",
        "workspace_id",
    ):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            fields[key] = value.strip()
        elif key == "supply_chain_firewall" and isinstance(value, bool):
            fields[key] = value
    if _optional_string(fields.get("supply_chain_plan_id")) is None:
        return None
    return fields


def reconcile_connect_state_with_oauth_entitlement(
    store: GuardStore,
    *,
    now: str,
) -> dict[str, object] | None:
    """Clear stale sync_not_available when OAuth credentials reflect a paid plan."""
    latest_state = store.get_effective_guard_connect_state(now=now)
    if not isinstance(latest_state, dict):
        return None
    milestone = _optional_string(latest_state.get("milestone"))
    if milestone != "sync_not_available":
        return None
    oauth_payload = store.get_sync_payload("oauth_local_credentials")
    oauth_fields = _oauth_entitlement_fields_from_sync_payload(oauth_payload)
    if not isinstance(oauth_fields, dict):
        return None
    plan_id = _optional_string(oauth_fields.get("supply_chain_plan_id"))
    if plan_id is None or plan_id.lower() not in PACKAGE_FIREWALL_PAID_TIERS:
        return None
    return store.record_latest_guard_connect_sync_result(
        status="connected",
        milestone="first_sync_pending",
        now=now,
        reason=None,
    )


def resolve_package_firewall_entitlement(
    store: GuardStore,
    *,
    now: datetime | None = None,
) -> dict[str, object]:
    """What package-firewall access this home has proven, per the resident.

    The store rows are read here; which entitlement they add up to — a proven
    paid plan, a connect or reconnect that must happen first, or an unpaid
    account — is decided by the resident, which runs the same resolver the
    package authority edge runs. An unreachable resident raises rather than
    letting this side read an allow out of the rows it just gathered.
    """

    resolved_now = now or datetime.now(timezone.utc)
    answer = native_hook_compose(
        "package_firewall_entitlement",
        {
            "bundle_payload": _dict_or_none(store.get_sync_payload("supply_chain_bundle_entitlement")),
            "connect_state": _dict_or_none(store.get_effective_guard_connect_state(now=resolved_now.isoformat())),
            "has_cloud_sync_profile": store.get_cloud_sync_profile() is not None,
            "now": resolved_now.isoformat(),
            "oauth_health": _dict_or_none(store.get_oauth_local_credential_health()),
            "oauth_payload": _dict_or_none(store.get_sync_payload("oauth_local_credentials")),
        },
        guard_home=Path(store.guard_home),
    )
    return answer


# What the entitlement says when the resident cannot answer. Nothing is
# entitled on a machine whose runtime will not say what it has proven, and no
# caller reads an allow out of the rows it gathered for the question.
PACKAGE_FIREWALL_RUNTIME_UNAVAILABLE_REASON = "guard_runtime_unavailable"


def package_firewall_entitlement_or_denied(
    store: GuardStore,
    *,
    now: datetime | None = None,
) -> dict[str, object]:
    """The resolved entitlement, or the denial an unanswerable runtime means.

    Callers that only need to know whether this home is entitled -- a settings
    write recording ``cloud_sync_entitled``, a status page describing what is
    offered -- have work of their own that an unreachable, unprovisioned or
    too-old resident must not take down. They ask through here and read a
    denial instead of a crash. The resident stays the only thing that can grant
    access: this answers no, never yes.
    """

    try:
        return resolve_package_firewall_entitlement(store, now=now)
    except (NativeHookComposeError, NativeHookComposeValidationError):
        return {
            "allowed": False,
            "reason": PACKAGE_FIREWALL_RUNTIME_UNAVAILABLE_REASON,
            "tier": "unknown",
            "upgrade_cta": None,
        }


def package_firewall_action_states(
    entitlement: dict[str, object],
    *,
    has_installed_managers: bool,
) -> dict[str, str]:
    allowed = bool(entitlement.get("allowed"))
    reason = str(entitlement.get("reason") or "").strip().lower()
    if allowed:
        blocked_state = "available"
    elif reason == "guard_cloud_connect_required":
        blocked_state = "connect_required"
    elif reason == "guard_cloud_reconnect_required":
        blocked_state = "reconnect_required"
    else:
        blocked_state = "paid_required"
    local_recovery_state = "available" if has_installed_managers else "disabled"
    return {
        "install": blocked_state,
        "repair": "available" if allowed or has_installed_managers else blocked_state,
        "test": blocked_state,
        "audit": blocked_state,
        "sync": blocked_state,
        "remove": local_recovery_state,
    }


def package_firewall_available_actions(
    entitlement: dict[str, object],
    *,
    has_installed_managers: bool,
) -> list[str]:
    reason = str(entitlement.get("reason") or "").strip().lower()
    actions = ["status"]
    if reason in {"guard_cloud_connect_required", "guard_cloud_reconnect_required"}:
        actions.append("connect")
    if has_installed_managers:
        actions.extend(["repair", "remove"])
    actions.extend(["education", "cli_fallback"])
    return actions


def package_firewall_operation_allowed(
    entitlement: dict[str, object],
    operation: str,
    *,
    has_installed_managers: bool,
) -> bool:
    normalized_operation = operation.strip().lower()
    if normalized_operation in {"status", "connect", "open-shell"}:
        return True
    # Existing local protection must remain repairable even when Cloud access
    # needs reconnecting or the paid entitlement cannot currently be proven.
    # This does not authorize new installs, tests, audits, or policy sync.
    if normalized_operation == "repair":
        return bool(entitlement.get("allowed")) or has_installed_managers
    if normalized_operation == "remove":
        return has_installed_managers
    reason = str(entitlement.get("reason") or "").strip().lower()
    if reason == "guard_cloud_reconnect_required":
        return False
    return bool(entitlement.get("allowed"))


def package_firewall_block_details(entitlement: dict[str, object]) -> tuple[int, str, str]:
    if entitlement.get("reason") == PACKAGE_FIREWALL_RUNTIME_UNAVAILABLE_REASON:
        # Not an unpaid account and not a connect that has to happen: the
        # runtime could not say, so nothing is offered and the copy says why.
        return (
            503,
            PACKAGE_FIREWALL_RUNTIME_UNAVAILABLE_REASON,
            "The HOL Guard runtime could not report package firewall access on this machine.",
        )
    if entitlement.get("reason") == "guard_cloud_connect_required":
        return (
            403,
            "guard_cloud_connect_required",
            "Connect HOL Guard Cloud on this machine before running package firewall actions.",
        )
    if entitlement.get("reason") == "guard_cloud_reconnect_required":
        return (
            403,
            "guard_cloud_reconnect_required",
            "Reconnect HOL Guard Cloud to refresh package firewall access.",
        )
    return (
        402,
        "paid_guard_cloud_required",
        "HOL Guard Cloud paid access is required to run package firewall actions.",
    )
