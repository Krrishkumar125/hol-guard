"""A decision wait observes one row and leaves approval reuse to the retry."""

import argparse
import json
from threading import Thread

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.blocked_request_mode import approval_wait_hint
from codex_plugin_scanner.guard.cli.approval_wait import run_approval_wait_command
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_codex_resume_commands import _request


@pytest.mark.parametrize("action, expected_code", [("allow", 0), ("block", 1)])
def test_wait_observes_external_decision_without_consuming_it(tmp_path, action, expected_code):
    store = GuardStore(tmp_path / "guard")
    store.add_approval_request(_request("req-1"), "2026-10-22T11:00:00Z")
    store.add_approval_request(_request("unrelated"), "2026-10-22T11:00:00Z")

    def decide():
        # Simulate a separately authenticated UI decision at the store boundary.
        store.resolve_approval_request(
            "req-1",
            resolution_action=action,
            resolution_scope="artifact",
            reason="test",
            resolved_at="2026-10-22T12:00:00Z",
        )

    thread = Thread(target=decide)
    thread.start()
    payload, code = run_approval_wait_command(argparse.Namespace(request_id="req-1", timeout=2), store=store)
    thread.join()
    assert code == expected_code
    assert payload["resolution_action"] == action
    assert store.get_approval_request("unrelated")["status"] == "pending"
    assert store.get_approval_request("req-1")["status"] == "resolved"
    # Observing a decision repeatedly neither consumes nor changes it.
    assert run_approval_wait_command(argparse.Namespace(request_id="req-1", timeout=0), store=store) == (payload, code)


def test_wait_timeout_and_missing_id_are_not_approval(tmp_path, capsys):
    home = tmp_path / "guard"
    store = GuardStore(home)
    store.add_approval_request(_request("req-1"), "2026-10-22T11:00:00Z")
    assert main(["guard", "approvals", "wait", "req-1", "--timeout", "0", "--home", str(home), "--json"]) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "approval_wait_timeout"
    assert store.get_approval_request("req-1")["status"] == "pending"
    payload, code = run_approval_wait_command(argparse.Namespace(request_id="missing", timeout=0), store=store)
    assert (payload["error"], code) == ("not_found", 1)


@pytest.mark.parametrize("timeout", ["-1", "601", "abc"])
def test_wait_rejects_unbounded_timeout(timeout):
    with pytest.raises(SystemExit):
        main(["guard", "approvals", "wait", "req-1", "--timeout", timeout])


@pytest.mark.parametrize("request_id", ["", "-x", "req;id", "$(id)", "req/1", "réq"])
def test_wait_hint_never_interpolates_shell_syntax(request_id):
    assert approval_wait_hint(request_id) == ""
