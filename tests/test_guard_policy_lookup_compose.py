"""The Python side of the `policy_lookup_compose` op.

Ordering saved decisions is the resident's verdict; these tests cover what the
translator in `store_policy` is still responsible for: shipping the probes it
resolved, refusing an empty list, and refusing a reply it cannot read rather
than inventing a composition of its own.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_policy_lookup_compose as bridge
from codex_plugin_scanner.guard import store_policy
from codex_plugin_scanner.guard.native_policy_lookup_compose import (
    PolicyLookupComposeUnavailableError,
    native_policy_lookup_compose,
)


def _probe(action: str | None, revision: int = 3) -> dict[str, Any]:
    return {
        "decision": None if action is None else {"action": action, "artifact_id": "a"},
        "ignored_local_integrity": None,
        "trust_status": {"status": "verified"},
        "authority_revision": revision,
    }


def _answer(**overrides: Any) -> dict[str, Any]:
    composed = {
        "decision": {"action": "review", "_approval_authority_revision": 3},
        "ignored_local_integrity": None,
        "trust_status": {"status": "verified"},
        "authority_revision": 3,
    }
    composed.update(overrides)
    return composed


def test_the_resident_answer_is_the_composition(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[list[dict[str, Any]]] = []
    homes: list[Path] = []

    def _compose(candidates: list[dict[str, Any]], *, guard_home: Path) -> dict[str, Any]:
        seen.append(candidates)
        homes.append(guard_home)
        return _answer()

    monkeypatch.setattr(store_policy, "native_policy_lookup_compose", _compose)
    composed = store_policy._most_restrictive_policy_lookup(
        [_probe("allow"), _probe("review")], guard_home=Path("/store-home")
    )
    assert composed == _answer()
    assert [probe["decision"] for probe in seen[0]] == [
        {"action": "allow", "artifact_id": "a"},
        {"action": "review", "artifact_id": "a"},
    ]
    # The composition must reach the same resident the probes did.
    assert homes == [Path("/store-home")]


def test_every_resolved_probe_is_shipped_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[list[dict[str, Any]]] = []

    def _compose(candidates: list[dict[str, Any]], *, guard_home: Path) -> dict[str, Any]:
        seen.append(candidates)
        return _answer()

    monkeypatch.setattr(store_policy, "native_policy_lookup_compose", _compose)
    store_policy._most_restrictive_policy_lookup(
        [_probe("allow", revision=3), _probe(None, revision=4), _probe("block", revision=3)],
        guard_home=Path("/store-home"),
    )
    assert [probe["authority_revision"] for probe in seen[0]] == [3, 4, 3]


def test_no_probe_at_all_is_a_caller_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def _unreachable(candidates: list[dict[str, Any]], *, guard_home: Path) -> dict[str, Any]:
        raise AssertionError("an empty lookup must not reach the resident")

    monkeypatch.setattr(store_policy, "native_policy_lookup_compose", _unreachable)
    with pytest.raises(ValueError):
        store_policy._most_restrictive_policy_lookup([], guard_home=Path("/store-home"))


def _bridge_answering(monkeypatch: pytest.MonkeyPatch, payload: object) -> list[str]:
    """Run the bridge against ``payload`` and record resident health records."""

    failures: list[str] = []
    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda home: True)
    monkeypatch.setattr(bridge, "_resident_request", lambda **kwargs: {"status": "ok"})
    monkeypatch.setattr(bridge, "_payload", lambda response, wire, home: payload)
    monkeypatch.setattr(
        bridge,
        "native_runtime_status",
        lambda: SimpleNamespace(identity=SimpleNamespace(sha256="runtime-sha")),
    )
    monkeypatch.setattr(
        bridge,
        "native_record_resident_failure",
        lambda sha256, home, *, reason: failures.append(reason),
    )
    return failures


@pytest.mark.parametrize(
    "composed",
    [
        _answer(trust_status=None),
        _answer(trust_status="verified"),
        _answer(authority_revision="3"),
        _answer(authority_revision=True),
        _answer(decision="allow"),
        _answer(ignored_local_integrity="bad"),
        {},
    ],
    ids=[
        "no-trust-status",
        "unreadable-trust-status",
        "unreadable-revision",
        "boolean-revision",
        "unreadable-decision",
        "unreadable-ignored-integrity",
        "empty-reply",
    ],
)
def test_an_unreadable_composition_is_refused(monkeypatch: pytest.MonkeyPatch, composed: dict[str, Any]) -> None:
    # A reply the translator cannot read must fail closed: returning a partial
    # composition here would drop whichever saved rule the resident picked.
    failures = _bridge_answering(monkeypatch, composed)
    with pytest.raises(PolicyLookupComposeUnavailableError):
        native_policy_lookup_compose([_probe("allow")], guard_home=Path("/store-home"))
    # A reply nobody can read is not a healthy answer, whatever ``_payload``
    # made of its binding.
    assert failures == ["native_policy_lookup_compose_bad_payload"]


def test_a_readable_composition_is_returned_without_a_failure_record(monkeypatch: pytest.MonkeyPatch) -> None:
    failures = _bridge_answering(monkeypatch, _answer())
    assert native_policy_lookup_compose([_probe("allow")], guard_home=Path("/store-home")) == _answer()
    assert failures == []


def test_an_unreachable_resident_is_not_answered_locally(monkeypatch: pytest.MonkeyPatch) -> None:
    def _unavailable(candidates: list[dict[str, Any]], *, guard_home: Path) -> dict[str, Any]:
        raise PolicyLookupComposeUnavailableError

    monkeypatch.setattr(store_policy, "native_policy_lookup_compose", _unavailable)
    with pytest.raises(PolicyLookupComposeUnavailableError):
        store_policy._most_restrictive_policy_lookup([_probe("allow"), _probe("block")], guard_home=Path("/store-home"))
