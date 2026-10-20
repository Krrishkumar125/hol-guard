"""The approval resolution gate asks the resident and never decides locally."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard import approval_resolution
from codex_plugin_scanner.guard.native_approval_resolution_eligibility import (
    ApprovalResolutionEligibilityUnavailableError,
)


def test_a_block_reason_is_whatever_the_resident_answered(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[list[dict[str, object]]] = []

    def fake(requests, *, guard_home=None):  # type: ignore[no-untyped-def]
        captured.append([dict(request) for request in requests])
        return ["terminal_policy_action_not_resolvable"]

    monkeypatch.setattr(approval_resolution, "native_approval_resolution_block_reasons", fake)
    request = {"policy_action": "block", "decision_contract_error": None}
    assert approval_resolution.approval_resolution_block_reason(request) == "terminal_policy_action_not_resolvable"
    assert captured == [[request]]


def test_a_batch_keeps_the_callers_order(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake(requests, *, guard_home=None):  # type: ignore[no-untyped-def]
        return [None, "authoritative_decision_inconsistent", None]

    monkeypatch.setattr(approval_resolution, "native_approval_resolution_block_reasons", fake)
    assert approval_resolution.approval_resolution_block_reasons(
        [{"policy_action": "review"}, {"policy_action": "nonsense"}, {"policy_action": "warn"}]
    ) == [None, "authoritative_decision_inconsistent", None]


def test_a_refusal_raises_at_the_mutation_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        approval_resolution,
        "native_approval_resolution_block_reasons",
        lambda requests, *, guard_home=None: ["terminal_policy_action_not_resolvable"],
    )
    with pytest.raises(ValueError, match="terminal_policy_action_not_resolvable"):
        approval_resolution.require_resolvable_approval_request({"policy_action": "block"})


def test_a_resolvable_row_passes_the_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        approval_resolution,
        "native_approval_resolution_block_reasons",
        lambda requests, *, guard_home=None: [None],
    )
    approval_resolution.require_resolvable_approval_request({"policy_action": "review"})


def test_an_unavailable_resident_never_reads_as_resolvable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(requests, *, guard_home=None):  # type: ignore[no-untyped-def]
        raise ApprovalResolutionEligibilityUnavailableError

    monkeypatch.setattr(approval_resolution, "native_approval_resolution_block_reasons", unavailable)
    with pytest.raises(ApprovalResolutionEligibilityUnavailableError):
        approval_resolution.require_resolvable_approval_request({"policy_action": "review"})
    with pytest.raises(ApprovalResolutionEligibilityUnavailableError):
        approval_resolution.approval_resolution_block_reason({"policy_action": "block"})


def test_an_empty_batch_asks_the_resident_nothing() -> None:
    assert approval_resolution.approval_resolution_block_reasons([]) == []
