"""The artifact hook applies the resident's final-action settle as Python decided it.

``scripts/ci/record_artifact_finalize_vectors.py`` recorded the retired Python
settle (``set_native_artifact_hook_final_action`` and the browser-outcome
section of ``finalize_native_artifact_hook``) with its two rendering
collaborators stubbed. The Rust suite replays the facts to the answers; this
suite hands each recorded answer to the new executor and checks that it sends
the same facts and leaves the same state, the same persisted receipt bytes and
the same effects. It also pins the approval invariant on the recorded answers
and the fail-closed ordering: the resident is asked before anything is
persisted, and a resident that cannot answer leaves no receipt or inbox record.
"""

from __future__ import annotations

import contextlib
import copy
import gzip
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import codex_plugin_scanner.guard.cli.commands  # noqa: F401  (wires the shared command namespace)
from codex_plugin_scanner.guard import native_hook_artifact_finalize as finalize
from codex_plugin_scanner.guard import native_hook_decision as decision
from codex_plugin_scanner.guard import native_resident_decision as shared
from codex_plugin_scanner.guard.cli import commands_hook_native_finish as finish
from codex_plugin_scanner.guard.cli import commands_hook_native_review as review
from codex_plugin_scanner.guard.cli import commands_hook_native_silent_review as silent_review
from codex_plugin_scanner.guard.cli import commands_hook_native_state as state_module

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "rust/crates/guard-runtime/tests/fixtures/artifact_finalize_vectors.json.gz"
RECORDER = ROOT / "scripts/ci/record_artifact_finalize_vectors.py"
FEATURE = finalize.HOOK_DECISION_ARTIFACT_FINALIZE_FEATURE
SETTLING = {"allow", "block", "sandbox-required"}


def _recorder() -> Any:
    spec = importlib.util.spec_from_file_location("record_artifact_finalize_vectors", RECORDER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load() -> dict[str, Any]:
    return json.loads(gzip.decompress(VECTORS.read_bytes()))


def _key(facts: object) -> str:
    return json.dumps(facts, sort_keys=True)


def _settle_reply(vector: dict[str, Any]) -> dict[str, Any]:
    """The resident's payload: the objects whose key order is persisted are rebuilt from their wire text."""

    payload = copy.deepcopy(vector["answer"])
    payload["evidence_patch"]["fields"] = json.loads(vector["wire"]["fields"])
    if vector["wire"]["resolution"] is not None:
        payload["receipt"]["appended_evidence"] = [json.loads(vector["wire"]["resolution"])]
    return {"kind": "artifact_finalize", **payload}


def _resident_stub(monkeypatch: pytest.MonkeyPatch, answer: Any) -> list[dict[str, Any]]:
    """Stand in for the resident behind the wrapper's real shape validation."""

    asked: list[dict[str, Any]] = []

    def decide(query: dict[str, Any], guard_home: object, validate: Any, feature: str = "") -> dict[str, Any]:
        assert feature == FEATURE
        asked.append(query)
        payload = answer(query)
        validate(payload)
        return payload

    monkeypatch.setattr(finalize, "_decide", decide)
    return asked


def _stub_renderers(monkeypatch: pytest.MonkeyPatch, recorder: Any) -> None:
    monkeypatch.setattr(state_module, "build_decision_v2", recorder.stub_decision_v2)
    monkeypatch.setattr(state_module, "build_incident_context", recorder.stub_incident_context)


def test_executor_reproduces_the_recorded_python_settle(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = _recorder()
    data = _load()
    vectors = {_key(vector["facts"]): vector for vector in data["settle"]}
    assert len(vectors) > 2_500
    _stub_renderers(monkeypatch, recorder)
    asked = _resident_stub(monkeypatch, lambda query: _settle_reply(vectors[_key(query["inputs"])]))

    def run(case: Any) -> SimpleNamespace:
        state = case.state()
        state_module.set_native_artifact_hook_final_action(
            state,  # type: ignore[arg-type]
            case.policy_action,
            approval_request_id=case.approval_request_id,
            approval_source=case.approval_source,
            observed_policy_action=case.observed_policy_action,
            queued_request_id=case.queued_request_id,
        )
        return state

    failures: list[str] = []
    replayed = 0
    for case in recorder.settle_cases():
        replayed += 1
        expected = vectors[_key(case.facts())]
        asked.clear()
        actual = recorder.record_settle(case, run=run)
        if [query["inputs"] for query in asked] != [case.facts()]:
            failures.append(f"{case.facts()}: asked {asked}")
        for key in ("facts", "answer", "receipt", "wire"):
            if actual[key] != expected[key]:
                failures.append(f"{case.facts()}: {key} {actual[key]!r} != {expected[key]!r}")
        observed = json.dumps(actual["outcome"], sort_keys=True, separators=(",", ":"))
        if observed != data["outcomes"][expected["outcome"]]:
            failures.append(f"{case.facts()}: outcome {observed} != {data['outcomes'][expected['outcome']]}")
        if len(failures) > 10:
            break
    assert failures == []
    assert replayed == len(data["settle"])


def test_the_persisted_receipt_is_pinned_byte_for_byte(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = _recorder()
    data = _load()
    vectors = {_key(vector["facts"]): vector for vector in data["settle"]}
    _stub_renderers(monkeypatch, recorder)
    _resident_stub(monkeypatch, lambda query: _settle_reply(vectors[_key(query["inputs"])]))
    browser = 0
    for case in recorder.settle_cases():
        state = case.state()
        state_module.set_native_artifact_hook_final_action(
            state,  # type: ignore[arg-type]
            case.policy_action,
            approval_request_id=case.approval_request_id,
            approval_source=case.approval_source,
            observed_policy_action=case.observed_policy_action,
            queued_request_id=case.queued_request_id,
        )
        pinned = vectors[_key(case.facts())]["receipt"]
        receipt = state.receipt
        assert receipt.policy_decision == pinned["policy_decision"]
        assert receipt.approval_source == pinned["approval_source"]
        assert receipt.approval_request_id == pinned["approval_request_id"]
        assert receipt.user_override == pinned["user_override"]
        assert json.dumps(list(receipt.scanner_evidence), separators=(",", ":")) == pinned["scanner_evidence"]
        if case.approval_source == "browser":
            browser += 1
            assert receipt.user_override == "browser-approval"
            assert json.loads(pinned["scanner_evidence"])[-1]["source"] == "browser_approval_resolution"
    assert browser > 700


def test_the_settle_leaves_the_approval_choice_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = _recorder()
    data = _load()
    vectors = {_key(vector["facts"]): vector for vector in data["settle"]}
    _stub_renderers(monkeypatch, recorder)
    _resident_stub(monkeypatch, lambda query: _settle_reply(vectors[_key(query["inputs"])]))
    kept = {
        "approval_requests": [{"request_id": "queued-1"}],
        "approval_url": "http://127.0.0.1:4455/requests/queued-1",
        "approval_wait": {"timeout": 30},
        "review_hint": "Approve it.",
        "browser_resolution_request_id": "req-1",
    }
    for case in recorder.settle_cases():
        state = case.state()
        state.response_payload.update(copy.deepcopy(kept))
        state_module.set_native_artifact_hook_final_action(
            state,  # type: ignore[arg-type]
            case.policy_action,
            approval_request_id=case.approval_request_id,
            approval_source=case.approval_source,
            observed_policy_action=case.observed_policy_action,
            queued_request_id=case.queued_request_id,
        )
        for key, value in kept.items():
            assert state.response_payload[key] == value, case.facts()


class _StopError(Exception):
    """The resident was asked; nothing more is needed."""


def _stop(_query: object) -> dict[str, Any]:
    raise _StopError


def _supply_state(raw: object, cloud: object = None) -> SimpleNamespace:
    state = _recorder().SettleCase(previous_action="review", policy_action="allow").state()
    state.response_payload.pop("supply_chain_evaluation", None)
    if raw is not _ABSENT:
        state.response_payload["supply_chain_evaluation"] = raw
    state.decision_v2_payload = {} if cloud is None else {"package_review_cloud_reason_code": cloud}
    return state


_ABSENT = object()


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (_ABSENT, (False, None)),
        ("not a mapping", (False, None)),
        ({}, (True, None)),
        ({"decision": "block"}, (True, "block")),
        ({"policy_action": "review", "decision": "block"}, (True, "review")),
        ({"policy_action": None, "decision": "block"}, (True, None)),
        ({"policy_action": 5, "decision": "block"}, (True, None)),
        ({"decision": ["block"]}, (True, None)),
    ],
)
def test_package_evaluation_facts_are_read_as_the_old_settle_read_them(
    monkeypatch: pytest.MonkeyPatch, raw: object, expected: tuple[bool, str | None]
) -> None:
    asked = _resident_stub(monkeypatch, _stop)
    state = _supply_state(raw)
    with pytest.raises(_StopError):
        state_module.plan_native_artifact_hook_final_action(state, "allow")  # type: ignore[arg-type]
    inputs = asked[0]["inputs"]
    assert (inputs["supply_chain_present"], inputs["supply_chain_action"]) == expected


@pytest.mark.parametrize(
    ("cloud", "expected"), [(None, None), ("cloud_timeout", "cloud_timeout"), (5, None), ([], None)]
)
def test_the_cloud_reason_code_is_sent_only_as_text(
    monkeypatch: pytest.MonkeyPatch, cloud: object, expected: str | None
) -> None:
    asked = _resident_stub(monkeypatch, _stop)
    with pytest.raises(_StopError):
        state_module.plan_native_artifact_hook_final_action(_supply_state(_ABSENT, cloud), "allow")  # type: ignore[arg-type]
    assert asked[0]["inputs"]["package_review_cloud_reason_code"] == expected


def test_planning_changes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = _recorder()
    case = recorder.SettleCase(previous_action="review", policy_action="block", approval_source="browser")
    data = _load()
    vectors = {_key(vector["facts"]): vector for vector in data["settle"]}
    _resident_stub(monkeypatch, lambda query: _settle_reply(vectors[_key(query["inputs"])]))
    state, untouched = case.state(), case.state()
    state_module.plan_native_artifact_hook_final_action(
        state,  # type: ignore[arg-type]
        "block",
        approval_source="browser",
    )
    assert recorder.outcome_of(state) == recorder.outcome_of(untouched)


# ---- the browser outcome ---------------------------------------------------


class _RenderedError(Exception):
    """The browser section handed the verdict to the directive."""


def test_executor_reproduces_the_recorded_browser_outcome_section(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = _recorder()
    data = _load()
    vectors = {_key(vector["facts"]): vector for vector in data["browser"]}
    assert len(vectors) == len(data["browser"]) > 60
    trace: list[list[object]] = []
    current: list[tuple[str, str]] = []
    asked = _resident_stub(
        monkeypatch,
        lambda query: {"kind": "artifact_browser_outcome", **vectors[_key(query["inputs"])]["answer"]},
    )

    def fresh_state(event: str) -> SimpleNamespace:
        return SimpleNamespace(
            action_envelope=None,
            artifact_id="artifact",
            event_name=event,
            initial_policy_action="stale",
            policy_action="review",
            response_payload={},
            runtime_artifact=SimpleNamespace(artifact_type="tool_action_request"),
            runtime_artifact_hash="hash",
            browser_approval_daemon_client=None,
        )

    fresh: list[SimpleNamespace] = []

    def decide(*_args: object, fresh_context_provider: Any, **_kwargs: object) -> str:
        fresh_context_provider()
        return current[-1][0]

    def settle(state: SimpleNamespace, action: str, **kwargs: Any) -> None:
        if state is fresh[-1]:
            trace.append(["adopt"])
        assert kwargs["queued_request_id"] == "queued-1"
        assert kwargs["approval_request_id"] == "req-1"
        trace.append(["settle", action, kwargs["approval_source"]])
        state.policy_action = action

    def directive(*_args: object, **_kwargs: object) -> dict[str, object]:
        trace.append(["render"])
        raise _RenderedError

    monkeypatch.setattr(finish, "_browser_approval_decision", decide)
    monkeypatch.setattr(finish, "set_native_artifact_hook_final_action", settle)
    monkeypatch.setattr(finish, "live_hook_approval_context", lambda *_a, **_k: None)
    monkeypatch.setattr(finish, "native_artifact_directive", directive)
    monkeypatch.setattr(finish, "record_native_artifact_hook_receipt", lambda *_a, **_k: trace.append(["receipt"]))
    monkeypatch.setattr(
        finish,
        "_record_harness_usage_for_hook",
        lambda **kwargs: trace.append(["usage", kwargs["policy_action"]]),
    )
    monkeypatch.setattr(
        finish,
        "_emit_native_hook_response",
        lambda **kwargs: trace.append(["native_allow", kwargs["event_name"], kwargs["reason"]]),
    )

    def run(decision_text: str, event: str) -> list[list[object]]:
        trace.clear()
        asked.clear()
        current.append((decision_text, event))
        fresh.append(fresh_state(event))
        state = SimpleNamespace(
            action_envelope=None,
            artifact_id="artifact",
            event_name=event,
            initial_policy_action="review",
            policy_action="review",
            response_payload={
                "approval_requests": [{"request_id": "queued-1"}],
                "browser_resolution_request_id": "req-1",
            },
            runtime_artifact=SimpleNamespace(artifact_type="tool_action_request"),
            runtime_artifact_hash="hash",
            browser_approval_daemon_client="client",
        )
        try:
            rc = finish.finalize_native_artifact_hook(
                state,  # type: ignore[arg-type]
                SimpleNamespace(harness="codex", json=False),  # type: ignore[arg-type]
                config=None,  # type: ignore[arg-type]
                payload={},
                store=SimpleNamespace(guard_home=None),  # type: ignore[arg-type]
                post_wait_revalidator=lambda: fresh[-1],  # type: ignore[arg-type,return-value]
            )
        except _RenderedError:
            pass
        else:
            trace.append(["return", rc])
        finally:
            current.pop()
        assert [query["inputs"] for query in asked] == [{"decision": decision_text, "event": event}]
        return [list(entry) for entry in trace]

    failures: list[str] = []
    for decision_text, event in recorder.browser_cases():
        expected = vectors[_key({"decision": decision_text, "event": event})]
        actual = recorder.record_browser(decision_text, event, run=run)
        for key in ("facts", "trace", "answer"):
            if actual[key] != expected[key]:
                failures.append(f"{decision_text!r} {event!r}: {key} {actual[key]!r} != {expected[key]!r}")
    assert failures == []


_REQUEST_FACTS = [
    ({"browser_resolution_request_id": "req-1"}, ("req-1", None)),
    ({"browser_resolution_request_id": ""}, ("", None)),
    ({"browser_resolution_request_id": 5}, (None, None)),
    ({}, (None, None)),
    ({"approval_requests": [{"request_id": "queued-1"}, {"request_id": "queued-2"}]}, (None, "queued-1")),
    ({"approval_requests": [{"request_id": 5}]}, (None, None)),
    ({"approval_requests": ["queued-1"]}, (None, None)),
    ({"approval_requests": []}, (None, None)),
    ({"approval_requests": "queued-1"}, (None, None)),
    (
        {"browser_resolution_request_id": "req-1", "approval_requests": [{"request_id": "queued-1"}]},
        ("req-1", "queued-1"),
    ),
]


@pytest.mark.parametrize(("response", "expected"), _REQUEST_FACTS)
@pytest.mark.parametrize("browser_decision", ["allow", "block", "sandbox-required"])
def test_request_ids_reach_the_resident_as_facts(
    monkeypatch: pytest.MonkeyPatch,
    response: dict[str, object],
    expected: tuple[str | None, str | None],
    browser_decision: str,
) -> None:
    seen: list[dict[str, object]] = []
    monkeypatch.setattr(finish, "_browser_approval_decision", lambda *_a, **_k: browser_decision)
    monkeypatch.setattr(
        finish,
        "native_artifact_browser_outcome",
        lambda inputs, **_k: {
            "settle": True,
            "action": inputs["decision"],
            "approval_source": "browser",
            "emit_native_allow": False,
            "finish_without_render": inputs["decision"] == "allow",
        },
    )
    monkeypatch.setattr(finish, "set_native_artifact_hook_final_action", lambda _state, _action, **kw: seen.append(kw))
    monkeypatch.setattr(finish, "record_native_artifact_hook_receipt", lambda *_a, **_k: None)
    monkeypatch.setattr(finish, "_record_harness_usage_for_hook", lambda **_k: None)
    monkeypatch.setattr(finish, "live_hook_approval_context", lambda *_a, **_k: None)
    monkeypatch.setattr(finish, "native_artifact_directive", lambda *_a, **_k: (_ for _ in ()).throw(_RenderedError()))
    state = SimpleNamespace(
        action_envelope=None,
        event_name="PreToolUse",
        policy_action="review",
        response_payload=dict(response),
        runtime_artifact=SimpleNamespace(artifact_type="tool_action_request"),
    )
    with contextlib.suppress(_RenderedError):
        finish.finalize_native_artifact_hook(
            state,  # type: ignore[arg-type]
            SimpleNamespace(harness="codex", json=False),  # type: ignore[arg-type]
            config=None,  # type: ignore[arg-type]
            payload={},
            store=SimpleNamespace(guard_home=None),  # type: ignore[arg-type]
        )
    assert len(seen) == 1
    assert (seen[0]["approval_request_id"], seen[0]["queued_request_id"]) == expected
    assert seen[0]["approval_source"] == "browser"


def test_a_missing_browser_decision_asks_the_resident_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[object] = []
    monkeypatch.setattr(finish, "_browser_approval_decision", lambda *_a, **_k: None)
    monkeypatch.setattr(finish, "native_artifact_browser_outcome", lambda *_a, **_k: asked.append("outcome"))
    monkeypatch.setattr(finish, "live_hook_approval_context", lambda *_a, **_k: None)
    monkeypatch.setattr(finish, "native_artifact_directive", lambda *_a, **_k: (_ for _ in ()).throw(_RenderedError()))
    state = SimpleNamespace(
        action_envelope=None,
        event_name="PreToolUse",
        policy_action="review",
        response_payload={},
        runtime_artifact=SimpleNamespace(artifact_type="tool_action_request"),
    )
    with pytest.raises(_RenderedError):
        finish.finalize_native_artifact_hook(
            state,  # type: ignore[arg-type]
            SimpleNamespace(harness="codex", json=False),  # type: ignore[arg-type]
            config=None,  # type: ignore[arg-type]
            payload={},
            store=SimpleNamespace(guard_home=None),  # type: ignore[arg-type]
        )
    assert asked == []


# ---- fail closed: nothing is persisted for a verdict the harness never got ----


def _unavailable(*_args: object, **_kwargs: object) -> dict[str, Any]:
    raise decision.NativeHookDecisionError("native_hook_decision_unavailable")


def test_a_browser_approval_the_resident_cannot_settle_leaves_no_receipt(monkeypatch: pytest.MonkeyPatch) -> None:
    effects: list[str] = []
    monkeypatch.setattr(finish, "_browser_approval_decision", lambda *_a, **_k: "allow")
    monkeypatch.setattr(
        finish,
        "native_artifact_browser_outcome",
        lambda *_a, **_k: {
            "settle": True,
            "action": "allow",
            "approval_source": "browser",
            "emit_native_allow": True,
            "finish_without_render": True,
        },
    )
    monkeypatch.setattr(state_module, "native_artifact_finalize", _unavailable)
    monkeypatch.setattr(finish, "record_native_artifact_hook_receipt", lambda *_a, **_k: effects.append("receipt"))
    monkeypatch.setattr(finish, "_record_harness_usage_for_hook", lambda **_k: effects.append("usage"))
    monkeypatch.setattr(finish, "_emit_native_hook_response", lambda **_k: effects.append("native_allow"))
    state = _plan_state()
    with pytest.raises(decision.NativeHookDecisionError):
        finish.finalize_native_artifact_hook(
            state,  # type: ignore[arg-type]
            SimpleNamespace(harness="codex", json=False),  # type: ignore[arg-type]
            config=None,  # type: ignore[arg-type]
            payload={},
            store=SimpleNamespace(guard_home=None),  # type: ignore[arg-type]
        )
    assert effects == []
    assert state.policy_action == "review"


def test_a_browser_outcome_the_resident_cannot_judge_settles_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    effects: list[str] = []
    monkeypatch.setattr(finish, "_browser_approval_decision", lambda *_a, **_k: "allow")
    monkeypatch.setattr(finish, "native_artifact_browser_outcome", _unavailable)
    monkeypatch.setattr(finish, "set_native_artifact_hook_final_action", lambda *_a, **_k: effects.append("settle"))
    monkeypatch.setattr(finish, "record_native_artifact_hook_receipt", lambda *_a, **_k: effects.append("receipt"))
    monkeypatch.setattr(finish, "_emit_native_hook_response", lambda **_k: effects.append("native_allow"))
    with pytest.raises(decision.NativeHookDecisionError):
        finish.finalize_native_artifact_hook(
            _plan_state(),  # type: ignore[arg-type]
            SimpleNamespace(harness="codex", json=False),  # type: ignore[arg-type]
            config=None,  # type: ignore[arg-type]
            payload={},
            store=SimpleNamespace(guard_home=None),  # type: ignore[arg-type]
        )
    assert effects == []


def _plan_state() -> SimpleNamespace:
    state = _recorder().SettleCase(previous_action="review", policy_action="block").state()
    state.event_name = "PreToolUse"
    state.runtime_artifact = SimpleNamespace(artifact_type="tool_action_request", source_scope="s", config_path="c")
    return state


def test_a_watch_mode_settle_the_resident_cannot_give_queues_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    effects: list[str] = []
    monkeypatch.setattr(review, "_observe_mode_executable_action", lambda _state: "allow")
    monkeypatch.setattr(review, "queue_observe_mode_request", lambda **_k: effects.append("queue"))
    monkeypatch.setattr(state_module, "native_artifact_finalize", _unavailable)
    state = _plan_state()
    state.browser_approval_daemon_client = "client"
    with pytest.raises(decision.NativeHookDecisionError):
        review._record_observed_review(
            state,  # type: ignore[arg-type]
            config=SimpleNamespace(receipt_redaction_level="summary"),  # type: ignore[arg-type]
            store=None,  # type: ignore[arg-type]
        )
    assert effects == []
    assert state.policy_action == "review"
    assert state.browser_approval_daemon_client == "client"


def test_a_watch_mode_settle_is_planned_before_the_record_and_applied_after(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = _recorder()
    order: list[str] = []
    _stub_renderers(monkeypatch, recorder)
    monkeypatch.setattr(review, "_observe_mode_executable_action", lambda _state: "allow")
    monkeypatch.setattr(review, "queue_observe_mode_request", lambda **_k: order.append("queue"))
    plan = review.plan_native_artifact_hook_final_action
    apply = review.apply_native_artifact_hook_final_action
    monkeypatch.setattr(
        review, "plan_native_artifact_hook_final_action", lambda *a, **k: order.append("plan") or plan(*a, **k)
    )
    monkeypatch.setattr(
        review, "apply_native_artifact_hook_final_action", lambda *a, **k: order.append("apply") or apply(*a, **k)
    )
    data = _load()
    vectors = {_key(vector["facts"]): vector for vector in data["settle"]}
    _resident_stub(monkeypatch, lambda query: _settle_reply(vectors[_key(query["inputs"])]))
    state = recorder.SettleCase(
        previous_action="review", policy_action="allow", observed_policy_action="review"
    ).state()
    state.browser_approval_daemon_client = "client"
    state.runtime_artifact_hash = "hash"
    review._record_observed_review(
        state,  # type: ignore[arg-type]
        config=SimpleNamespace(receipt_redaction_level="summary"),  # type: ignore[arg-type]
        store=None,  # type: ignore[arg-type]
    )
    assert order == ["plan", "queue", "apply"]
    assert state.policy_action == "allow"
    assert state.response_payload["observed_policy_action"] == "review"
    assert state.browser_approval_daemon_client is None


@pytest.mark.parametrize("kind", ["silent_review", "silent_block"])
def test_a_silent_denial_the_resident_cannot_settle_leaves_nothing_on_file(
    monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    recorded: list[str] = []
    monkeypatch.setattr(silent_review, "record_unprompted_review", lambda **_k: recorded.append("inbox"))
    monkeypatch.setattr(silent_review, "_runtime_detection", lambda *_a: SimpleNamespace())
    monkeypatch.setattr(silent_review, "_runtime_request_summary", lambda _artifact: "summary")
    monkeypatch.setattr(silent_review, "_action_envelope_json", lambda _envelope: None)
    monkeypatch.setattr(state_module, "native_artifact_finalize", _unavailable)
    state = _plan_state()
    state.approval_prompted = None
    with pytest.raises(decision.NativeHookDecisionError):
        silent_review.apply_unprompted_native_review(
            state,  # type: ignore[arg-type]
            SimpleNamespace(harness="codex"),  # type: ignore[arg-type]
            None,  # type: ignore[arg-type]
            SimpleNamespace(receipt_redaction_level="summary"),  # type: ignore[arg-type]
            {"route": kind, "silent_review": {"action": "review", "reason": "Lead."}},
        )
    assert recorded == []
    assert state.policy_action == "review"
    assert state.approval_prompted is None


# ---- the wrapper's decoding ------------------------------------------------

_FACTS = {
    "previous_action": "review",
    "policy_action": "allow",
    "observed_policy_action": None,
    "approval_source": "browser",
    "approval_request_id": "req-1",
    "queued_request_id": None,
    "initial_policy_action": "review",
    "receipt_approval_source": None,
    "receipt_approval_request_id": None,
    "receipt_user_override": None,
    "package_review_cloud_reason_code": None,
    "supply_chain_present": False,
    "supply_chain_action": None,
}
_FINALIZE = {
    "kind": "artifact_finalize",
    "action": "allow",
    "observed_action": None,
    "decision_reason": "browser-approval",
    "cloud_reason_code": None,
    "refresh_copy": True,
    "observed_supply_chain_action": None,
    "drop_terminal_action": False,
    "evidence_patch": {"source": "policy_composition", "fields": {"authoritative_action": "allow"}},
    "receipt": {
        "policy_decision": "allow",
        "approval_source": "browser",
        "approval_request_id": "req-1",
        "user_override": "browser-approval",
        "appended_evidence": [
            {
                "source": "browser_approval_resolution",
                "initial_action": "review",
                "authoritative_action": "allow",
                "approval_request_id": "req-1",
            }
        ],
    },
}
_OUTCOME_FACTS = {"decision": "allow", "event": "PostToolUse"}
_OUTCOME = {
    "kind": "artifact_browser_outcome",
    "settle": True,
    "action": "allow",
    "approval_source": "browser",
    "emit_native_allow": True,
    "finish_without_render": True,
}


def _resident_answering(monkeypatch: pytest.MonkeyPatch, query: dict[str, Any], payload: dict[str, Any]) -> list[str]:
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=object(),
        capabilities=SimpleNamespace(features={"resident-protocol-v2", FEATURE}),
    )
    monkeypatch.setattr(shared, "native_runtime_status", lambda: status)
    monkeypatch.setattr(shared, "record_resident", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(shared, "_resolve_digest_home", lambda _home: Path("/tmp/hook-decision-home"))
    monkeypatch.setattr(shared, "ensure_resident_prerequisite", lambda _home: True)
    asked: list[str] = []

    def transport(*, request: dict[str, Any], required_feature: str, **_kwargs: object) -> dict[str, Any]:
        asked.append(required_feature)
        assert request["query"] == query
        return {
            "schema": "guard-hook-decision-result.v1",
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + shared._canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "payload": payload,
        }

    monkeypatch.setattr(decision, "_resident_request", transport)
    return asked


def test_a_bound_settle_is_decoded_behind_its_capability(monkeypatch: pytest.MonkeyPatch) -> None:
    asked = _resident_answering(monkeypatch, {"kind": "artifact_finalize", "inputs": _FACTS}, _FINALIZE)
    answer = finalize.native_artifact_finalize(_FACTS)
    assert answer == {key: value for key, value in _FINALIZE.items() if key != "kind"}
    assert asked == [FEATURE]


def test_a_bound_outcome_is_decoded_behind_its_capability(monkeypatch: pytest.MonkeyPatch) -> None:
    asked = _resident_answering(monkeypatch, {"kind": "artifact_browser_outcome", "inputs": _OUTCOME_FACTS}, _OUTCOME)
    answer = finalize.native_artifact_browser_outcome(_OUTCOME_FACTS)
    assert answer == {key: value for key, value in _OUTCOME.items() if key != "kind"}
    assert asked == [FEATURE]


def _with(base: dict[str, Any], dotted: str, value: object) -> dict[str, Any]:
    changed = copy.deepcopy(base)
    target = changed
    *path, last = dotted.split(".")
    for part in path:
        target = target[int(part)] if isinstance(target, list) else target[part]
    if isinstance(target, list):
        target[int(last)] = value
    else:
        target[last] = value
    return changed


@pytest.mark.parametrize(
    "payload",
    [
        _with(_FINALIZE, "action", "permit"),
        _with(_FINALIZE, "action", "block"),
        _with(_FINALIZE, "action", 5),
        _with(_FINALIZE, "observed_action", "review"),
        _with(_FINALIZE, "drop_terminal_action", True),
        _with(_FINALIZE, "refresh_copy", "yes"),
        _with(_FINALIZE, "cloud_reason_code", 5),
        _with(_FINALIZE, "observed_supply_chain_action", "maybe"),
        _with(_FINALIZE, "evidence_patch.source", None),
        _with(_FINALIZE, "evidence_patch.fields", {}),
        _with(_FINALIZE, "evidence_patch.fields", {"authoritative_action": "block"}),
        _with(_FINALIZE, "evidence_patch.fields", {"authoritative_action": "allow", "observed_policy_action": "x"}),
        _with(_FINALIZE, "receipt.policy_decision", "block"),
        _with(_FINALIZE, "receipt.user_override", 1),
        _with(_FINALIZE, "receipt.appended_evidence", ["browser"]),
        _with(_FINALIZE, "receipt.appended_evidence", [{"source": "browser_approval_resolution"}]),
        _with(_FINALIZE, "receipt.appended_evidence.0.authoritative_action", "block"),
        {**_FINALIZE, "extra": True},
        {key: value for key, value in _FINALIZE.items() if key != "receipt"},
    ],
)
def test_a_malformed_settle_fails_closed(monkeypatch: pytest.MonkeyPatch, payload: dict[str, Any]) -> None:
    _resident_answering(monkeypatch, {"kind": "artifact_finalize", "inputs": _FACTS}, payload)
    with pytest.raises(decision.NativeHookDecisionError):
        finalize.native_artifact_finalize(_FACTS)


@pytest.mark.parametrize(
    "payload",
    [
        {**_OUTCOME, "action": "block"},
        {**_OUTCOME, "action": "review"},
        {**_OUTCOME, "approval_source": "daemon"},
        {**_OUTCOME, "approval_source": None},
        {**_OUTCOME, "settle": False},
        {**_OUTCOME, "emit_native_allow": "yes"},
        {**_OUTCOME, "finish_without_render": False},
        {**_OUTCOME, "extra": 1},
        {
            "kind": "artifact_browser_outcome",
            "settle": False,
            "action": "allow",
            "approval_source": None,
            "emit_native_allow": False,
            "finish_without_render": False,
        },
        {
            "kind": "artifact_browser_outcome",
            "settle": False,
            "action": None,
            "approval_source": None,
            "emit_native_allow": True,
            "finish_without_render": False,
        },
    ],
)
def test_a_malformed_outcome_fails_closed(monkeypatch: pytest.MonkeyPatch, payload: dict[str, Any]) -> None:
    _resident_answering(monkeypatch, {"kind": "artifact_browser_outcome", "inputs": _OUTCOME_FACTS}, payload)
    with pytest.raises(decision.NativeHookDecisionError):
        finalize.native_artifact_browser_outcome(_OUTCOME_FACTS)


def test_a_terminal_outcome_may_not_end_the_hook_unrendered(monkeypatch: pytest.MonkeyPatch) -> None:
    facts = {"decision": "block", "event": "PreToolUse"}
    terminal = {**_OUTCOME, "action": "block", "emit_native_allow": False, "finish_without_render": False}
    _resident_answering(monkeypatch, {"kind": "artifact_browser_outcome", "inputs": facts}, terminal)
    assert finalize.native_artifact_browser_outcome(facts)["action"] == "block"
    unrendered = {**terminal, "finish_without_render": True}
    _resident_answering(monkeypatch, {"kind": "artifact_browser_outcome", "inputs": facts}, unrendered)
    with pytest.raises(decision.NativeHookDecisionError):
        finalize.native_artifact_browser_outcome(facts)


def test_incomplete_inputs_are_refused_before_the_resident_is_asked(monkeypatch: pytest.MonkeyPatch) -> None:
    asked = _resident_answering(monkeypatch, {"kind": "artifact_finalize", "inputs": _FACTS}, _FINALIZE)
    with pytest.raises(decision.NativeHookDecisionError):
        finalize.native_artifact_finalize({key: value for key, value in _FACTS.items() if key != "supply_chain_action"})
    with pytest.raises(decision.NativeHookDecisionError):
        finalize.native_artifact_finalize({**_FACTS, "extra": 1})
    with pytest.raises(decision.NativeHookDecisionError):
        finalize.native_artifact_browser_outcome({"decision": "allow"})
    assert asked == []


# ---- the real resident (CI) ------------------------------------------------


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_resident_answers_the_recorded_settles() -> None:
    failures: list[str] = []
    for vector in _load()["settle"][::37]:
        answer = finalize.native_artifact_finalize(vector["facts"])
        expected = _settle_reply(vector)
        failures.extend(
            f"{vector['facts']}: {key} {answer[key]!r} != {value!r}"
            for key, value in expected.items()
            if key != "kind" and answer[key] != value
        )
        # Key order is persisted: the objects the resident writes keep Python's.
        if json.dumps(answer["evidence_patch"]["fields"], separators=(",", ":")) != vector["wire"]["fields"]:
            failures.append(f"{vector['facts']}: evidence fields reordered")
    assert failures == []


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_resident_answers_the_recorded_browser_outcomes() -> None:
    failures: list[str] = []
    for vector in _load()["browser"]:
        answer = finalize.native_artifact_browser_outcome(vector["facts"])
        failures.extend(
            f"{vector['facts']}: {key} {answer[key]!r} != {value!r}"
            for key, value in vector["answer"].items()
            if answer[key] != value
        )
    assert failures == []
