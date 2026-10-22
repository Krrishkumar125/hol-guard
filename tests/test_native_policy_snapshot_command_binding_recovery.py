"""A command binding this runtime cannot admit must not stop every prompt.

The resident rejects a policy push whose command binding names a program it
cannot build from its packaged program or its pack cache. Rejecting the whole
snapshot leaves the resident with no policy, so the hook fails closed on every
request for as long as the activated catalog and the installed runtime
disagree. The publisher drops the binding and republishes instead.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot_publisher_transport as transport
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError

BINDING = {
    "schema": "guard.native-command-control-binding.v1",
    "program_digest": "a" * 64,
    "catalog_digest": "b" * 64,
    "trust_digest": "c" * 64,
}


def _capabilities() -> SimpleNamespace:
    # Catalog and trust digests differ from the binding, which is what makes
    # the publisher ship the activated catalog's program unchanged.
    return SimpleNamespace(
        rule_digest="d" * 64,
        program_digest="e" * 64,
        catalog_digest="f" * 64,
        trust_digest="0" * 64,
        features=(),
    )


def _publisher(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        guard_home=tmp_path,
        _wall_clock=lambda: 1_700_000_000.0,
        _snapshot=None,
        _resident_startup_required=False,
        _command_binding_unusable=None,
    )


@pytest.fixture
def stubbed(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    """Record the binding each publication carries and skip real encoding."""

    carried: list[object] = []

    def snapshot(**kwargs: object) -> dict[str, object]:
        carried.append(kwargs["command_extensions"])
        return {
            "generation": len(carried),
            "policy_digest": f"{len(carried):064d}",
            "mode": "enforce",
        }

    monkeypatch.setattr(transport, "native_policy_snapshot_v3", snapshot)
    monkeypatch.setattr(transport, "_policy_snapshot_push_bytes_v3", lambda *a, **k: b"{}")
    return carried


def _accepted(generation: int, policy_digest: str) -> bytes:
    return json.dumps(
        {
            "status": "accepted",
            "generation": generation,
            "policy_digest": policy_digest,
            "idempotent": False,
            "resident_generation": 7,
        }
    ).encode()


def _publish(publisher: SimpleNamespace, client: object) -> tuple[dict[str, object], int]:
    return transport._publish_snapshot_v3(
        publisher=publisher,
        identity=SimpleNamespace(path=publisher.guard_home / "runtime", sha256="9" * 64),
        capabilities=_capabilities(),
        config={"mode": "prompt"},
        command_extensions=BINDING,
        master_key=b"k" * 32,
        client=client,
        renew_after_generation=None,
    )


@pytest.mark.parametrize("code", sorted(transport.COMMAND_BINDING_UNUSABLE_CODES))
def test_unusable_command_binding_is_dropped_and_the_snapshot_still_publishes(
    tmp_path: Path, stubbed: list[object], code: str
) -> None:
    publisher = _publisher(tmp_path)
    responses = [
        json.dumps({"error": code, "retryable": False}).encode(),
        _accepted(2, f"{2:064d}"),
    ]

    def client(**_: object) -> bytes:
        return responses.pop(0)

    snapshot, resident_generation = _publish(publisher, client)

    assert resident_generation == 7
    assert snapshot["generation"] == 2
    # The first publication carries the activated catalog's binding; only the
    # retry drops it, so a usable binding is never discarded pre-emptively.
    assert stubbed == [BINDING, None]
    assert publisher._command_binding_unusable == code


def test_a_rejection_without_a_binding_is_reported_as_itself(tmp_path: Path, stubbed: list[object]) -> None:
    publisher = _publisher(tmp_path)

    def client(**_: object) -> bytes:
        return json.dumps({"error": "native_command_pack_cache_invalid", "retryable": False}).encode()

    with pytest.raises(NativePolicySnapshotError) as failure:
        _publish(publisher, client)

    assert str(failure.value) == "native_command_pack_cache_invalid"
    assert stubbed == [BINDING, None]


def test_an_unrelated_rejection_keeps_the_command_binding(tmp_path: Path, stubbed: list[object]) -> None:
    publisher = _publisher(tmp_path)

    def client(**_: object) -> bytes:
        return json.dumps({"error": "native_policy_snapshot_not_current", "retryable": False}).encode()

    with pytest.raises(NativePolicySnapshotError) as failure:
        _publish(publisher, client)

    assert str(failure.value) == "native_policy_snapshot_not_current"
    assert stubbed == [BINDING]
    assert publisher._command_binding_unusable is None


def test_every_recovery_code_is_a_declared_native_failure_identity() -> None:
    from codex_plugin_scanner.guard.native_approval_errors import FINITE_FAILURE_CODES

    assert transport.COMMAND_BINDING_UNUSABLE_CODES <= FINITE_FAILURE_CODES
