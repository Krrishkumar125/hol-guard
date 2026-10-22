"""A rejected command binding must not stop every prompt at the hook barrier.

`prepare_native_hook_policy` turns a `None` from `prepare_workspace_policy`
into the `native_policy_not_ready` fail-safe the user sees instead of a
reviewed prompt. A guard home whose activated catalog names a command program
the installed runtime cannot build makes the resident reject every push that
carries the binding, so without recovery that barrier never opens again.

These exercise the real publisher and the real hook worker against a resident
that rejects exactly those pushes, which is what a drifted catalog does.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.native_policy_snapshot import (
    NativePolicySnapshotPublisher,
    get_native_policy_snapshot_publisher,
)
from codex_plugin_scanner.guard.native_policy_snapshot_publisher_transport import (
    COMMAND_BINDING_UNUSABLE_CODES,
)
from codex_plugin_scanner.guard.store import GuardStore

from .native_policy_snapshot_test_fixtures import _ack, _status


class _RejectsTheBinding:
    """Answer every push that carries a command binding with one failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        self.carried: list[bool] = []

    def __call__(self, **kwargs: object) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        carried = b'"command_extensions"' in payload
        self.carried.append(carried)
        if carried:
            return json.dumps({"error": self.code, "retryable": False}).encode()
        return _ack(payload, guard_home=kwargs.get("guard_home"))


def _store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> GuardStore:
    store = GuardStore(tmp_path / "guard-home")
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (b"w" * 32, "master-id"))
    return store


# `native_request_invalid_json` is what a resident built before the admission
# codes were declared reports for every one of them, so a publisher meeting an
# older runtime recovers on the same terms.
@pytest.mark.parametrize("code", ["native_command_pack_cache_invalid", "native_request_invalid_json"])
def test_a_rejected_binding_still_leaves_the_publisher_holding_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: str
) -> None:
    resident = _RejectsTheBinding(code)
    publisher = NativePolicySnapshotPublisher(
        store=_store(tmp_path, monkeypatch),
        status_provider=_status,
        client_request=resident,
        poll_interval_seconds=0.05,
    )
    publisher._publish_once()

    snapshot = publisher.current_snapshot_binding()
    assert snapshot is not None
    # The catalog's binding is tried first and only dropped once refused.
    assert resident.carried == [True, False]
    assert snapshot.get("command_extensions") is None
    # Dropping the binding costs command extensions, never enforcement.
    assert snapshot.get("mode") == "enforce"
    assert publisher.last_error is None


def test_the_hook_barrier_opens_on_the_recovered_snapshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _store(tmp_path, monkeypatch)
    publisher = get_native_policy_snapshot_publisher(store)
    publisher._client_request = _RejectsTheBinding("native_command_pack_cache_invalid")
    monkeypatch.setattr(publisher, "_status_provider", _status)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    worker = HookWorker(store=store, workspace=workspace, home_dir=tmp_path / "home")
    try:
        prepared = worker.prepare_workspace_policy(workspace, deadline=time.monotonic() + 30.0)
    finally:
        worker.close(deadline_monotonic=time.monotonic() + 10.0)

    # A `None` here is the `native_policy_not_ready` fail-safe on every prompt.
    assert prepared is not None
    assert prepared.get("mode") == "enforce"


def test_a_rejection_that_is_not_about_the_binding_still_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Recovery is for admission failures only, never a blanket retry."""

    unrelated = "native_policy_snapshot_not_current"
    assert unrelated not in COMMAND_BINDING_UNUSABLE_CODES
    resident = _RejectsTheBinding(unrelated)
    publisher = NativePolicySnapshotPublisher(
        store=_store(tmp_path, monkeypatch),
        status_provider=_status,
        client_request=resident,
        poll_interval_seconds=0.05,
    )
    publisher._publish_once()

    assert publisher.current_snapshot_binding() is None
    assert publisher.last_error == unrelated
    assert resident.carried == [True]
