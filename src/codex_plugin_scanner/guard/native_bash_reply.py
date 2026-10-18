"""Shape checks for native-owned Bash results, independent of risk policy."""

from __future__ import annotations

import re

from .native_bash_protocol import NativeBashError


def _require(condition: bool) -> None:
    if not condition:
        raise NativeBashError("native_bash_response_invalid")


def validate_prepared(payload: object) -> dict[str, object]:
    _require(isinstance(payload, dict))
    assert isinstance(payload, dict)
    _require(set(payload) == {"subject", "artifact_id", "artifact_hash", "assessment", "consent_required", "review"})
    _require(payload["artifact_id"] == "native-bash-launch:v1")
    _require(_token(payload["artifact_hash"]))
    _require(type(payload["consent_required"]) is bool and isinstance(payload["assessment"], list))
    review = payload["review"]
    _require(isinstance(review, dict))
    assert isinstance(review, dict)
    _require(set(review) == {"decision", "receipt"})
    _require(isinstance(review["decision"], dict) and isinstance(review["receipt"], dict))
    subject = payload["subject"]
    _require(isinstance(subject, dict))
    assert isinstance(subject, dict)
    _require(subject.get("schema") == "guard.bash-subject.v1")
    _require(subject.get("execution_assurance") == "macos-readonly-root-framed-outputs-v1")
    return payload


def _token(value: object) -> bool:
    return isinstance(value, str) and value.startswith("guard-approval-context:v1:")


def _completion(value: object, *, summary: bool) -> None:
    _require(isinstance(value, dict))
    assert isinstance(value, dict)
    suffix = {"stdout_sha256", "stderr_sha256"} if summary else {"stdout", "stderr"}
    _require(set(value) == {"exit_code", "output_limited", "timed_out", "cancelled"} | suffix)
    _require(value["exit_code"] is None or (type(value["exit_code"]) is int and -(2**31) <= value["exit_code"] < 2**31))
    _require(all(type(value[key]) is bool for key in ("output_limited", "timed_out", "cancelled")))
    _require(all(isinstance(value[key], str) for key in suffix))
    if summary:
        _require(all(re.fullmatch(r"[0-9a-f]{64}", value[key]) is not None for key in suffix))


def validate_executed(result: dict[str, object], request: dict[str, object]) -> None:
    _require(all(type(result[key]) is bool for key in ("grant_claimed", "dispatch_acknowledged", "replayed")))
    operation = result["operation"]
    if operation is not None:
        _require(isinstance(operation, dict))
        assert isinstance(operation, dict)
        _require(set(operation) == {
            "operation_id", "artifact_hash", "authorization", "state", "dispatch_acknowledged", "completion",
        })
        _require(operation["operation_id"] == request["operation_id"])
        authorization = request["authorization"]
        _require(isinstance(authorization, dict))
        assert isinstance(authorization, dict)
        _require(isinstance(operation["authorization"], str)
                 and operation["authorization"] in {"saved_grant", "current_policy"})
        if result["replayed"]:
            _require(result["grant_claimed"] == (operation["authorization"] == "saved_grant"))
        else:
            _require(operation["authorization"] == authorization["kind"])
        _require(isinstance(operation["state"], str)
                 and operation["state"] in {"claimed", "dispatched", "completed", "uncertain"})
        _require(type(operation["dispatch_acknowledged"]) is bool)
        _require(operation["dispatch_acknowledged"] == result["dispatch_acknowledged"])
        _require(_token(operation["artifact_hash"]))
        if operation["completion"] is not None:
            _completion(operation["completion"], summary=True)
        _require((operation["state"] == "completed") == (operation["completion"] is not None))
    if result["payload"] is not None:
        _completion(result["payload"], summary=False)
    if result["status"] == "ok":
        _require(result["dispatch_acknowledged"] is True and result["replayed"] is False)
        _require(isinstance(operation, dict) and operation["state"] == "completed" and result["payload"] is not None)
    elif result["status"] == "recorded":
        _require(result["replayed"] is True and operation is not None and result["payload"] is None)
        _require(result["code"] in {
            "native_bash_already_completed_output_not_retained", "native_bash_operation_in_progress_or_uncertain",
        })
    else:
        _require(result["replayed"] is False)
