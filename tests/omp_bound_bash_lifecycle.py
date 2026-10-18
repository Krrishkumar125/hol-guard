"""Synchronization and cleanup for isolated real SDK-host death tests."""

from __future__ import annotations

import sqlite3
import subprocess
import time
from pathlib import Path

from codex_plugin_scanner.guard.native_bash_protocol import activity, request_id, runtime_status
from codex_plugin_scanner.guard.native_execution import _resident_request
from codex_plugin_scanner.guard.native_resident_client import close_native_residents
from tests.test_native_bash_process_lifecycle import _wait_activity


def pause_native_execute_source(ready: Path, resume: Path) -> str:
    """Pause only after the real sink has looked up saved authorization."""
    return f"""
from pathlib import Path
import time
from codex_plugin_scanner.guard.runtime import bound_bash_sink
original_execute = bound_bash_sink.execute
def synchronized_execute(request, **options):
    if request['authorization']['kind'] == 'saved_grant':
        Path({str(ready)!r}).write_text('ready')
        deadline = time.monotonic() + 25
        while not Path({str(resume)!r}).is_file():
            if time.monotonic() >= deadline:
                raise RuntimeError('fixture resume deadline')
            time.sleep(0.01)
    return original_execute(request, **options)
bound_bash_sink.execute = synchronized_execute
"""


def _cancel_owned_fixture(guard_home: Path, operation_id: str) -> None:
    reply = _resident_request(
        operation="native_bash_cancel",
        request={
            "schema": "guard-native-bash-cancel-request.v1",
            "request_id": request_id(),
            "guard_home": str(guard_home),
            "operation_id": operation_id,
        },
        guard_home=guard_home,
        timeout_seconds=2,
        required_feature="native-bash-owner-protocol-v1",
        response_schema="guard-native-bash-cancel-result.v1",
        status=runtime_status(),
        record_success=False,
    )
    assert isinstance(reply, dict) and reply.get("status") == "ok"
    _wait_activity(operation_id, guard_home, lambda item: item["cancellation_requested"] or not item["active"])


def assert_sdk_host_death_cancels(
    *,
    store,
    operation_id: str,
    command: list[str],
    environment: dict[str, str],
    workspace: Path,
    ready: Path,
    resume: Path,
    report: Path,
) -> None:
    """Kill the spawned SDK host, retaining a database barrier until cancellation."""
    process = subprocess.Popen(
        command,
        cwd=workspace,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    blocker = sqlite3.connect(store.path, timeout=5, isolation_level=None)
    owner_stopped = False
    try:
        deadline = time.monotonic() + 20
        while not ready.is_file():
            assert process.poll() is None, "SDK ended before its real CLI prepared authorization"
            assert time.monotonic() < deadline, "SDK did not reach the pre-execution barrier"
            time.sleep(0.02)
        blocker.execute("BEGIN IMMEDIATE")
        resume.write_text("dispatch")
        observed = _wait_activity(operation_id, store.guard_home, lambda item: item["active"])
        assert observed["cancellation_requested"] is False
        assert not report.exists()
        process.kill()
        assert process.wait(timeout=3) < 0
        _wait_activity(operation_id, store.guard_home, lambda item: item["cancellation_requested"])
    finally:
        if blocker.in_transaction:
            # A failed assertion must not release an orphan to spend consent.
            try:
                observed = activity(operation_id, guard_home=store.guard_home)
                if observed["active"] and not observed["cancellation_requested"]:
                    _cancel_owned_fixture(store.guard_home, operation_id)
            except (AssertionError, RuntimeError, ValueError):
                assert close_native_residents(guard_home=store.guard_home)
                owner_stopped = True
            blocker.execute("ROLLBACK")
        blocker.close()
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)
        if not owner_stopped:
            _wait_activity(operation_id, store.guard_home, lambda item: not item["active"])
        assert not report.exists()
        with store._connect() as connection:
            assert connection.execute("select claimed_at from guard_local_once_approvals").fetchone()[0] is None
            assert connection.execute("select count(*) from guard_bash_operations").fetchone()[0] == 0
