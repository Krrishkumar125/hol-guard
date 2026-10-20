"""A selection-only request keeps the wire shape an older resident accepts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_approval_scope_select as select

ITEM: dict[str, object] = {
    "request_id": "11111111111111111111111111111111",
    "harness": "omp",
    "artifact_id": "omp:native-pretool:bash",
    "artifact_name": "bash",
    "artifact_type": "tool_call",
    "artifact_hash": "11111111111111111111111111111111",
    "policy_action": "review",
}


def _capture(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str | None, dict[str, Any]]]:
    seen: list[tuple[str | None, dict[str, Any]]] = []
    monkeypatch.setattr(select, "_resolve_digest_home", lambda _home: Path("/tmp/scope-select-home"))
    monkeypatch.setattr(select, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(select, "_payload", lambda _response, _request, _home: {"status": "ok"})

    def fake(*, request: dict[str, Any], required_feature: str | None = None, **_kwargs: object) -> dict[str, object]:
        seen.append((required_feature, request))
        return {}

    monkeypatch.setattr(select, "_resident_request", fake)
    return seen


def _select(**overrides: object) -> None:
    select.native_approval_scope_selection(
        ITEM,
        action="allow",
        requested_scope="artifact",
        contract_version=None,
        contract_digest=None,
        **overrides,  # type: ignore[arg-type]
    )


def test_resolving_a_scope_alone_asks_for_the_capability_it_always_had(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = _capture(monkeypatch)
    _select()
    feature, request = seen[0]
    assert feature == select.APPROVAL_SCOPE_SELECT_FEATURE == "approval-scope-select-v1"
    # The key is absent, not null: a resident that predates the block refuses
    # an unknown field, so a selection-only caller must not grow one.
    assert "persistence" not in request


def test_deferring_the_persistence_leg_asks_for_the_newer_capability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = _capture(monkeypatch)
    _select(decide_persistence=True, persist_policy=False)
    feature, request = seen[0]
    assert feature == select.APPROVAL_SCOPE_SELECT_PERSISTENCE_FEATURE == "approval-scope-select-v2"
    assert request["persistence"] == {"persist_policy": False}
