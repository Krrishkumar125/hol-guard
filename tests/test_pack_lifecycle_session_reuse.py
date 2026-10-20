from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.catalog_delivery import active_security, lifecycle

transport = lifecycle.transport


@pytest.fixture
def native(monkeypatch, tmp_path):
    calls = {"verify": 0, "copies": 0, "runs": 0}

    def verify_compiler(path, manifest):
        calls["verify"] += 1
        return b"runtime"

    @contextmanager
    def verified_executable(raw):
        calls["copies"] += 1
        yield Path(tmp_path / "runtime")

    def run_bounded(argv, request, timeout):
        calls["runs"] += 1
        return 0, b"{}", b""

    monkeypatch.setattr(transport, "_verify_manifest", lambda path: {})
    monkeypatch.setattr(transport, "_verify_compiler", verify_compiler)
    monkeypatch.setattr(transport, "_verified_executable", verified_executable)
    monkeypatch.setattr(transport, "_run_bounded", run_bounded)
    monkeypatch.setattr(transport, "_decode_output", lambda stdout, returncode, stderr: {})
    return calls


def test_session_verifies_once_and_only_when_native_is_used(native):
    with lifecycle.session():
        pass
    assert native["verify"] == 0

    with lifecycle.session():
        lifecycle.invoke("offline", operation="one")
        with lifecycle.session():
            lifecycle.invoke("offline", operation="two")
    assert native == {"verify": 1, "copies": 1, "runs": 2}

    lifecycle.invoke("offline", operation="three")
    lifecycle.invoke("offline", operation="four")
    assert native == {"verify": 3, "copies": 3, "runs": 4}


@pytest.fixture
def answers(monkeypatch):
    requests = []
    monkeypatch.setattr(active_security, "_key", lambda store: b"k" * 32)
    monkeypatch.setattr(active_security, "_ANSWERS", type(active_security._ANSWERS)())

    def invoke(kind, **fields):
        requests.append(fields)
        if fields.get("record") == "bad":
            raise ValueError("active_security_invalid")
        return {"active_matches": True, "publication": {"epoch": len(requests)}}

    monkeypatch.setattr(lifecycle, "invoke", invoke)
    return requests


def test_pure_answers_are_reused_for_identical_requests(answers):
    first = active_security.invoke("resume", object(), record="r", activation_digest="a")
    first["publication"]["epoch"] = 99
    second = active_security.invoke("resume", object(), record="r", activation_digest="a")
    assert second == {"active_matches": True, "publication": {"epoch": 1}}
    assert len(answers) == 1

    active_security.invoke("resume", object(), record="r", activation_digest="b")
    active_security.invoke("binding", object(), record="r", binding={})
    assert len(answers) == 3


def test_stateful_operations_and_failures_are_never_reused(answers):
    for _ in range(2):
        active_security.invoke("begin", object(), record="r", publication="p")
    assert len(answers) == 2

    for _ in range(2):
        with pytest.raises(ValueError, match="active_security_invalid"):
            active_security.invoke("read", object(), record="bad")
    assert len(answers) == 4


def test_answers_stay_bounded(answers):
    for index in range(active_security._ANSWERS_LIMIT + 5):
        active_security.invoke("read", object(), record=str(index))
    assert len(active_security._ANSWERS) == active_security._ANSWERS_LIMIT
    active_security.invoke("read", object(), record="0")
    assert len(answers) == active_security._ANSWERS_LIMIT + 6
