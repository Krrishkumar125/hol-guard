#!/usr/bin/env python3
"""Record artifact-hook final-action vectors from the Python settle.

After the artifact hook has a verdict, three paths can still change it: a
Watch-mode record that executes the policy it observed, a silent denial, and a
browser approval that resolved the review. Each path called
``set_native_artifact_hook_final_action`` (``commands_hook_native_state.py``),
and the browser path first decided in ``finalize_native_artifact_hook``
(``commands_hook_native_finish.py``) whether the outcome settled the hook at
all. The resident decides all of that now: ``artifact_finalize`` and
``artifact_browser_outcome`` in ``hook_decision_artifact_finalize.rs``.

``_recorded_settle`` and ``_recorded_browser_outcome`` below are that Python
code as it stood at 3b8ac2e848, kept here so the oracle never calls the code it
checks. The two collaborators that only render (``build_decision_v2`` and
``build_incident_context``) are stubs that echo their arguments, so a vector
records which arguments the settle chose. Regenerate with:

    PYTHONPATH=src .venv/bin/python scripts/ci/record_artifact_finalize_vectors.py

A ``settle`` vector holds the resident's inputs (``facts``), the answer the
recorded behaviour exhibits (``answer``), the receipt the settle persists
(``receipt``: the fields and the exact text of its ``scanner_evidence``), the
text of the two ordered objects the resident must write in Python's key order
(``wire``) and the whole observable outcome (``outcome``, an index into
``outcomes``). A ``browser`` vector holds the outcome facts, the effects the
old section ran and the answer they exhibit.

The Rust ``hook_decision_artifact_finalize_tests`` replays facts to answers and
pins the wire text; ``tests/test_artifact_finalize_parity.py`` runs the new
executor with the resident stubbed from the vectors and checks that it leaves
the same state, receipt bytes and effects.
"""

from __future__ import annotations

import copy
import gzip
import itertools
import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from codex_plugin_scanner.guard.action_lattice import normalize_guard_action

OUTPUT = Path("rust/crates/guard-runtime/tests/fixtures/artifact_finalize_vectors.json.gz")

ACTIONS = ("allow", "warn", "review", "require-reapproval", "sandbox-required", "block", "ask", "unrecognized")
OBSERVED = (None, *ACTIONS)
CLOUD_CODES = (
    None,
    "cloud_auth_error",
    "cloud_http_error",
    "cloud_timeout",
    "cloud_validation_error",
    "cloud_unrelated",
    "",
)
INITIAL_ACTIONS = ("review", "require-reapproval", "block")
RISK0 = "RISK0"
TERMINAL0 = "TERMINAL0"
CLOUD_CODE_SET = {"cloud_auth_error", "cloud_http_error", "cloud_timeout", "cloud_validation_error"}


@dataclass(frozen=True)
class Receipt:
    """The receipt fields the settle reads and writes."""

    policy_decision: str
    approval_source: str | None
    approval_request_id: str | None
    user_override: str | None
    scanner_evidence: tuple[dict[str, object], ...]
    harness: str = "codex"


@dataclass(frozen=True)
class Envelope:
    """Stands in for the action envelope: remembers the result it was given."""

    result: str | None = None

    def with_pre_execution_result(self, action: str) -> Envelope:
        return Envelope(action)


def stub_decision_v2(action: str, *, reason: str, signals: object) -> SimpleNamespace:
    """Echo the arguments the settle chose; the real builder only renders them."""

    assert signals == ("signal",)
    payload = {
        "action": action,
        "reason": reason,
        "dashboard_primary_detail": f"detail:{action}:{reason}",
        "user_title": f"title:{action}:{reason}",
        "user_body": f"body:{action}:{reason}",
        "retry_instruction": "" if action == "block" else f"retry:{action}:{reason}",
        "harness_message": f"message:{action}:{reason}",
    }
    return SimpleNamespace(to_dict=lambda: payload)


def stub_incident_context(**kwargs: Any) -> dict[str, str]:
    """Echo the arguments the settle passed to the incident builder."""

    action, risk = kwargs["policy_action"], kwargs["risk_summary"]
    assert kwargs["harness"] == "codex" and kwargs["launch_target"] is None
    return {
        "trigger_summary": f"trigger:{action}:{risk}",
        "why_now": f"why:{action}:{risk}",
        "risk_headline": f"headline:{action}:{risk}",
    }


@dataclass(frozen=True)
class SettleCase:
    """One enumerated fact combination for the final-action settle."""

    previous_action: str
    policy_action: str
    observed_policy_action: str | None = None
    approval_source: str | None = None
    approval_request_id: str | None = None
    queued_request_id: str | None = None
    initial_policy_action: str = "review"
    receipt_approval_source: str | None = None
    receipt_approval_request_id: str | None = None
    receipt_user_override: str | None = None
    package_review_cloud_reason_code: str | None = None
    supply_chain_present: bool = False
    supply_chain_action: str | None = None

    def facts(self) -> dict[str, object]:
        return {
            "previous_action": self.previous_action,
            "policy_action": self.policy_action,
            "observed_policy_action": self.observed_policy_action,
            "approval_source": self.approval_source,
            "approval_request_id": self.approval_request_id,
            "queued_request_id": self.queued_request_id,
            "initial_policy_action": self.initial_policy_action,
            "receipt_approval_source": self.receipt_approval_source,
            "receipt_approval_request_id": self.receipt_approval_request_id,
            "receipt_user_override": self.receipt_user_override,
            "package_review_cloud_reason_code": self.package_review_cloud_reason_code,
            "supply_chain_present": self.supply_chain_present,
            "supply_chain_action": self.supply_chain_action,
        }

    def state(self) -> SimpleNamespace:
        """The hook state the facts describe, before the settle."""

        response: dict[str, object] = {
            "policy_action": self.previous_action,
            "resolved_policy_action": "stale",
            "terminal_action": TERMINAL0,
            "risk_summary": RISK0,
            "policy_composition": {"current_composed_action": "review", "authoritative_action": "stale"},
            "decision_v2_json": {"stale": True},
        }
        if self.supply_chain_present:
            response["supply_chain_evaluation"] = {
                "policy_action": self.supply_chain_action,
                "decision": "allow",
                "risk_summary": "package risk",
                "user_copy": {"title": "t0", "kept": "kept"},
            }
        evidence = _evidence()
        decision_v2: dict[str, object] = {"action": self.previous_action}
        if self.package_review_cloud_reason_code is not None:
            decision_v2["package_review_cloud_reason_code"] = self.package_review_cloud_reason_code
        return SimpleNamespace(
            action_envelope=Envelope(),
            artifact_id="artifact",
            artifact_name="name",
            changed_capabilities=["cap"],
            decision_signals=("signal",),
            decision_v2_payload=decision_v2,
            guard_home=None,
            initial_policy_action=self.initial_policy_action,
            policy_action=self.previous_action,
            receipt=Receipt(
                policy_decision="stale",
                approval_source=self.receipt_approval_source,
                approval_request_id=self.receipt_approval_request_id,
                user_override=self.receipt_user_override,
                scanner_evidence=tuple(copy.deepcopy(evidence)),
            ),
            response_payload=response,
            risk_summary=RISK0,
            runtime_artifact=SimpleNamespace(artifact_type="tool_action_request", source_scope="s", config_path="c"),
            scanner_evidence_payload=evidence,
        )


def _evidence() -> list[dict[str, object]]:
    """Evidence entries: one that already carries the key, a bare probe, others."""

    return [
        {"source": "policy_composition", "authoritative_action": "stale", "note": "kept"},
        {"source": "policy_composition"},
        {"source": "scanner", "authoritative_action": "untouched"},
    ]


def _recorded_settle(
    state: SimpleNamespace,
    policy_action: str,
    *,
    approval_request_id: str | None = None,
    approval_source: str | None = None,
    observed_policy_action: str | None = None,
) -> None:
    """``set_native_artifact_hook_final_action`` as it stood at 3b8ac2e848."""

    previous_action = normalize_guard_action(state.policy_action, unknown_action="block")
    normalized_action = normalize_guard_action(policy_action, unknown_action="block")
    state.policy_action = normalized_action
    state.response_payload["policy_action"] = normalized_action
    state.response_payload["resolved_policy_action"] = normalized_action
    normalized_observed_action = (
        normalize_guard_action(observed_policy_action, unknown_action="block")
        if observed_policy_action is not None
        else None
    )
    if normalized_observed_action is not None:
        state.response_payload["observed_policy_action"] = normalized_observed_action
        state.response_payload.pop("terminal_action", None)
    if state.action_envelope is not None:
        state.action_envelope = state.action_envelope.with_pre_execution_result(normalized_action)

    decision_v2_payload = stub_decision_v2(
        normalized_action,
        reason=("browser-approval" if approval_source == "browser" else normalized_action),
        signals=state.decision_signals,
    ).to_dict()
    package_review_cloud_reason_code = state.decision_v2_payload.get("package_review_cloud_reason_code")
    if package_review_cloud_reason_code in {
        "cloud_auth_error",
        "cloud_http_error",
        "cloud_timeout",
        "cloud_validation_error",
    }:
        decision_v2_payload["package_review_cloud_reason_code"] = package_review_cloud_reason_code
    state.decision_v2_payload = decision_v2_payload
    state.response_payload["decision_v2_json"] = decision_v2_payload

    if previous_action != normalized_action:
        final_risk_summary = str(decision_v2_payload["dashboard_primary_detail"])
        state.risk_summary = final_risk_summary
        state.response_payload["risk_summary"] = final_risk_summary
        raw_supply_chain = state.response_payload.get("supply_chain_evaluation")
        if isinstance(raw_supply_chain, dict):
            observed_supply_chain = dict(raw_supply_chain)
            raw_user_copy = raw_supply_chain.get("user_copy")
            user_copy = dict(raw_user_copy) if isinstance(raw_user_copy, dict) else {}
            if normalized_observed_action is not None:
                raw_package_action = observed_supply_chain.get(
                    "policy_action",
                    observed_supply_chain.get("decision"),
                )
                observed_package_action = (
                    normalize_guard_action(raw_package_action, unknown_action="block")
                    if isinstance(raw_package_action, str)
                    else normalized_observed_action
                )
                raw_supply_chain["observed_policy_action"] = observed_package_action
                raw_supply_chain["observed_risk_summary"] = observed_supply_chain.get("risk_summary")
                raw_supply_chain["observed_user_copy"] = observed_supply_chain.get("user_copy")
            user_copy.update(
                {
                    "title": decision_v2_payload["user_title"],
                    "summary": decision_v2_payload["user_body"],
                    "next_step": decision_v2_payload["retry_instruction"] or decision_v2_payload["user_body"],
                    "harness_message": decision_v2_payload["harness_message"],
                }
            )
            raw_supply_chain.update(
                {
                    "decision": decision_v2_payload["action"],
                    "policy_action": normalized_action,
                    "risk_summary": final_risk_summary,
                    "user_copy": user_copy,
                }
            )

    incident = stub_incident_context(
        harness=state.receipt.harness,
        artifact=state.runtime_artifact,
        artifact_id=state.artifact_id,
        artifact_name=state.artifact_name,
        artifact_type=state.runtime_artifact.artifact_type,
        source_scope=state.runtime_artifact.source_scope,
        config_path=state.runtime_artifact.config_path,
        changed_fields=state.changed_capabilities,
        policy_action=normalized_action,
        launch_target=None,
        risk_summary=state.risk_summary,
        guard_home=state.guard_home,
    )
    for key in ("trigger_summary", "why_now", "risk_headline"):
        state.response_payload[key] = incident[key]

    policy_composition = state.response_payload.get("policy_composition")
    if isinstance(policy_composition, dict):
        policy_composition["authoritative_action"] = normalized_action
        if normalized_observed_action is not None:
            policy_composition["observed_policy_action"] = normalized_observed_action
    for evidence in state.scanner_evidence_payload:
        if evidence.get("source") == "policy_composition":
            evidence["authoritative_action"] = normalized_action
            if normalized_observed_action is not None:
                evidence["observed_policy_action"] = normalized_observed_action

    receipt_evidence = tuple(
        {
            **evidence,
            "authoritative_action": normalized_action,
            **(
                {"observed_policy_action": normalized_observed_action} if normalized_observed_action is not None else {}
            ),
        }
        if evidence.get("source") == "policy_composition"
        else evidence
        for evidence in state.receipt.scanner_evidence
    )
    if approval_source == "browser":
        receipt_evidence = (
            *receipt_evidence,
            {
                "source": "browser_approval_resolution",
                "initial_action": state.initial_policy_action,
                "authoritative_action": normalized_action,
                "approval_request_id": approval_request_id,
            },
        )
    state.receipt = replace(
        state.receipt,
        policy_decision=normalized_action,
        approval_source=approval_source or state.receipt.approval_source,
        approval_request_id=approval_request_id or state.receipt.approval_request_id,
        user_override=("browser-approval" if approval_source == "browser" else state.receipt.user_override),
        scanner_evidence=receipt_evidence,
    )


def _recorded_settle_call(case: SettleCase) -> SimpleNamespace:
    """The call each path made.

    The browser paths resolved the request id first, in
    ``finalize_native_artifact_hook``: the allow path passed the resolution's
    request id only, a terminal outcome fell back to the first queued request
    when the resolution named none, and an id that is not text became ``None``.
    The other paths passed no source and no request id.
    """

    state = case.state()
    request_id = case.approval_request_id
    if case.approval_source == "browser":
        assert case.policy_action in {"allow", "block", "sandbox-required"}, "the browser decides one of three"
        if case.policy_action != "allow" and request_id is None:
            request_id = case.queued_request_id
    _recorded_settle(
        state,
        case.policy_action,
        approval_request_id=request_id,
        approval_source=case.approval_source,
        observed_policy_action=case.observed_policy_action,
    )
    return state


def _evidence_text(entries: object) -> str:
    """The exact persisted text: key order is observable, so nothing is sorted."""

    return json.dumps(list(entries), separators=(",", ":"))  # type: ignore[call-overload]


def outcome_of(state: SimpleNamespace) -> dict[str, Any]:
    """Everything the settle leaves observable on the state."""

    return {
        "policy_action": state.policy_action,
        "envelope": state.action_envelope.result,
        "response_payload": state.response_payload,
        "decision_v2_payload": state.decision_v2_payload,
        "risk_summary": state.risk_summary,
        "scanner_evidence_text": _evidence_text(state.scanner_evidence_payload),
        "receipt": receipt_pins(state.receipt),
    }


def receipt_pins(receipt: Receipt) -> dict[str, Any]:
    """The persisted receipt fields, with the evidence as exact text."""

    return {
        "policy_decision": receipt.policy_decision,
        "approval_source": receipt.approval_source,
        "approval_request_id": receipt.approval_request_id,
        "user_override": receipt.user_override,
        "scanner_evidence": _evidence_text(receipt.scanner_evidence),
    }


def observed_answer(case: SettleCase, after: SimpleNamespace) -> tuple[dict[str, Any], dict[str, str | None]]:
    """The resident's answer the recorded behaviour exhibits, and its wire text."""

    pre = case.state()
    response = after.response_payload
    observed = response.get("observed_policy_action")
    detail_refreshed = after.risk_summary != RISK0
    carried = after.decision_v2_payload.get("package_review_cloud_reason_code")
    supply_chain = response.get("supply_chain_evaluation")
    observed_supply_chain = supply_chain.get("observed_policy_action") if isinstance(supply_chain, dict) else None
    reason = str(after.decision_v2_payload["reason"])
    probe = after.scanner_evidence_payload[1]
    fields = {key: value for key, value in probe.items() if key != "source"}
    fields_text = json.dumps(fields, separators=(",", ":"))
    pre_receipt = pre.receipt
    appended = after.receipt.scanner_evidence[len(pre_receipt.scanner_evidence) :]
    assert len(appended) <= 1
    answer = {
        "action": after.policy_action,
        "observed_action": observed,
        "decision_reason": reason,
        "cloud_reason_code": carried,
        "refresh_copy": detail_refreshed,
        "observed_supply_chain_action": observed_supply_chain,
        "drop_terminal_action": "terminal_action" not in response,
        "evidence_patch": {"source": "policy_composition", "fields": json.loads(fields_text)},
        "receipt": {
            "policy_decision": after.receipt.policy_decision,
            "approval_source": after.receipt.approval_source,
            "approval_request_id": after.receipt.approval_request_id,
            "user_override": after.receipt.user_override,
            "appended_evidence": [dict(entry) for entry in appended],
        },
    }
    wire = {
        "fields": fields_text,
        "resolution": json.dumps(appended[0], separators=(",", ":")) if appended else None,
    }
    return answer, wire


def record_settle(
    case: SettleCase,
    run: Callable[[SettleCase], SimpleNamespace] = _recorded_settle_call,
) -> dict[str, Any]:
    after = run(case)
    answer, wire = observed_answer(case, after)
    return {
        "facts": case.facts(),
        "answer": answer,
        "receipt": receipt_pins(after.receipt),
        "wire": wire,
        "outcome": outcome_of(after),
    }


def settle_cases() -> Iterator[SettleCase]:
    """Every fact combination the settle can observe, in four sweeps.

    Each sweep varies the facts that interact with each other and holds the
    rest at a representative value. A browser resolution decides ``allow``,
    ``block`` or ``sandbox-required`` and never observes a policy, so the
    browser sweeps stay on those; the other paths pass no source or request.
    """

    browser_actions = ("allow", "block", "sandbox-required")
    # Action normalization: previous, final and observed actions.
    for previous, action, observed in itertools.product(ACTIONS, ACTIONS, OBSERVED):
        yield SettleCase(previous_action=previous, policy_action=action, observed_policy_action=observed)
    for previous, action, request, queued in itertools.product(
        ACTIONS, browser_actions, (None, "req-1"), (None, "queued-1")
    ):
        yield SettleCase(
            previous_action=previous,
            policy_action=action,
            approval_source="browser",
            approval_request_id=request,
            queued_request_id=queued,
        )
    # The receipt: who resolved it, with which request, over which prior values.
    priors = list(itertools.product((None, "cli"), (None, "prior-1"), (None, "user")))
    for action, request, queued, initial, (prior_source, prior_request, prior_override) in itertools.product(
        browser_actions, (None, "", "req-1"), (None, "", "queued-1"), INITIAL_ACTIONS, priors
    ):
        yield SettleCase(
            previous_action="review",
            policy_action=action,
            approval_source="browser",
            approval_request_id=request,
            queued_request_id=queued,
            initial_policy_action=initial,
            receipt_approval_source=prior_source,
            receipt_approval_request_id=prior_request,
            receipt_user_override=prior_override,
        )
    for action, observed, source, request, (prior_source, prior_request, prior_override) in itertools.product(
        ("allow", "block", "review"), (None, "allow"), (None, "", "daemon"), (None, "", "req-1"), priors
    ):
        yield SettleCase(
            previous_action="review",
            policy_action=action,
            observed_policy_action=observed,
            approval_source=source,
            approval_request_id=request,
            queued_request_id="queued-1",
            receipt_approval_source=prior_source,
            receipt_approval_request_id=prior_request,
            receipt_user_override=prior_override,
        )
    # The package evaluation and the cloud reason code the new decision keeps.
    supply_chains = [(False, None), (True, None), *((True, action) for action in ACTIONS)]
    for previous, action, observed, code, (present, package_action) in itertools.product(
        ("review", "allow"), ("allow", "block"), (None, "review"), CLOUD_CODES, supply_chains
    ):
        yield SettleCase(
            previous_action=previous,
            policy_action=action,
            observed_policy_action=observed,
            package_review_cloud_reason_code=code,
            supply_chain_present=present,
            supply_chain_action=package_action,
        )
    # The package evaluation under every final and observed action.
    for action, observed, (present, package_action) in itertools.product(ACTIONS, OBSERVED, supply_chains):
        yield SettleCase(
            previous_action="review",
            policy_action=action,
            observed_policy_action=observed,
            supply_chain_present=present,
            supply_chain_action=package_action,
        )


# ---- the browser outcome ---------------------------------------------------

DECISIONS = ("allow", "block", "sandbox-required", "review", "require-reapproval", "timeout", "", "ALLOW", "Block")
EVENTS = ("PreToolUse", "PostToolUse", "UserPromptSubmit", "PermissionRequest", "Stop", "", "pretooluse")


def _recorded_browser_outcome(decision: str, event_name: str) -> list[list[object]]:
    """The browser-outcome section of ``finalize_native_artifact_hook`` at 3b8ac2e848.

    Every effect is a trace entry; ``render`` is where the section handed the
    settled verdict to the directive.
    """

    trace: list[list[object]] = []
    if decision == "allow":
        trace.append(["adopt"])
        trace.append(["settle", "allow", "browser"])
        if event_name != "PreToolUse":
            trace.append(["native_allow", event_name, ""])
        trace.append(["receipt"])
        trace.append(["usage", "allow"])
        trace.append(["return", 0])
        return trace
    if decision in {"block", "sandbox-required"}:
        trace.append(["adopt"])
        trace.append(["settle", decision, "browser"])
    trace.append(["render"])
    return trace


def observed_outcome(trace: list[list[object]]) -> dict[str, Any]:
    """The outcome fields the recorded trace exhibits."""

    outcome: dict[str, Any] = {
        "settle": False,
        "action": None,
        "approval_source": None,
        "emit_native_allow": False,
        "finish_without_render": False,
    }
    for entry in trace:
        if entry[0] == "settle":
            outcome.update(settle=True, action=entry[1], approval_source=entry[2])
        elif entry[0] == "native_allow":
            outcome["emit_native_allow"] = True
        elif entry[0] == "return":
            outcome["finish_without_render"] = True
    return outcome


def record_browser(
    decision: str,
    event: str,
    run: Callable[[str, str], list[list[object]]] = _recorded_browser_outcome,
) -> dict[str, Any]:
    trace = run(decision, event)
    return {
        "facts": {"decision": decision, "event": event},
        "trace": trace,
        "answer": observed_outcome(trace),
    }


def browser_cases() -> Iterator[tuple[str, str]]:
    yield from itertools.product(DECISIONS, EVENTS)


def build() -> dict[str, Any]:
    pool: dict[str, int] = {}
    outcomes: list[str] = []
    settle: list[dict[str, Any]] = []
    for case in settle_cases():
        vector = record_settle(case)
        text = json.dumps(vector["outcome"], sort_keys=True, separators=(",", ":"))
        if text not in pool:
            pool[text] = len(outcomes)
            outcomes.append(text)
        vector["outcome"] = pool[text]
        settle.append(vector)
    browser = [record_browser(decision, event) for decision, event in browser_cases()]
    return {"settle": settle, "browser": browser, "outcomes": outcomes}


def main() -> int:
    vectors = build()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(vectors, sort_keys=True, separators=(",", ":")).encode()
    OUTPUT.write_bytes(gzip.compress(body, compresslevel=9, mtime=0))
    print(
        f"wrote {len(vectors['settle'])} settle and {len(vectors['browser'])} browser vectors "
        f"({len(vectors['outcomes'])} outcomes) to {OUTPUT}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
