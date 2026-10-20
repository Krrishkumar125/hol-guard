"""Shared extension-control daemon API errors.

Kept separate from the API service so helper evaluators can raise the same
public error type without creating an import cycle.
"""

from __future__ import annotations

_RECOVERY_ACTIONS = {
    "approval_required": "provide_local_approval",
    "authority_apply_failed": "refresh_effective_controls",
    "authority_conflict": "refresh_effective_controls",
    "authority_unavailable": "enroll_or_repair_authority",
    "authority_unread": "refresh_effective_controls",
    "catalog_conflict": "refresh_catalog",
    "immutable_extension": "remove_local_override",
    "immutable_permission": "remove_local_override",
    "managed_layer_mutation": "managed_policy_read_only",
    "pack_preparation_unavailable": "retry_pack_preparation",
    "proof_invalid": "request_new_proof",
    "proof_mismatch": "request_new_proof",
    "proof_not_found": "request_new_proof",
    "revision_conflict": "refresh_effective_controls",
}

# A classified, non-sensitive cause narrows a generic failure code to the step
# that actually failed. It never carries a path, a URL or an exception message.
_CAUSE_RECOVERY_ACTIONS = {
    "authority_unavailable": "enroll_or_repair_authority",
    "installed_runtime_incomplete": "repair_guard_installation",
    "local_storage": "repair_local_cache",
    "offline": "retry_when_reachable",
    "release_unavailable": "retry_when_reachable",
}


class ExtensionControlApiError(Exception):
    """Stable error envelope shared by inspection, Test Lab, and mutation APIs."""

    def __init__(self, status: int, code: str, *, cause: str | None = None) -> None:
        super().__init__(status, code)
        self.status = status
        self.code = code
        self.cause = cause

    def to_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {"error": self.code}
        if self.cause is not None:
            payload["cause"] = self.cause
        action = _CAUSE_RECOVERY_ACTIONS.get(self.cause or "") or _RECOVERY_ACTIONS.get(self.code)
        if action is not None:
            payload["recovery"] = {"action": action}
        return payload
