"""Shape checks for native-owned Bash results, independent of risk policy."""

from __future__ import annotations

import re

from .native_bash_protocol import ARTIFACT_ID, NativeBashError


def supported_execution_assurance(value: object) -> bool:
    return isinstance(value, str) and value in {
        "macos-readonly-root-framed-outputs-v1",
        "macos-readonly-root-http-read-v1",
        "macos-hardened-broker-v1",
    }


def _require(condition: bool) -> None:
    if not condition:
        raise NativeBashError("native_bash_response_invalid")


def validate_prepared(payload: object) -> dict[str, object]:
    _require(isinstance(payload, dict))
    assert isinstance(payload, dict)
    required = {"subject", "artifact_id", "artifact_hash", "assessment", "consent_required", "review"}
    _require(required <= set(payload) <= required | {"dependency_artifact"})
    _require(payload["artifact_id"] == ARTIFACT_ID)
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
    _require(supported_execution_assurance(subject.get("execution_assurance")))
    if "dependency_artifact" in payload:
        artifact = payload["dependency_artifact"]
        _require(isinstance(artifact, dict))
        assert isinstance(artifact, dict)
        metadata = artifact.get("metadata")
        _require(artifact.get("artifact_type") == "package_request" and isinstance(metadata, dict))
        assert isinstance(metadata, dict)
        _require(metadata.get("assessment_only") is True)
        harness = artifact.get("harness")
        _require(isinstance(harness, str) and harness in {"omp", "pi"})
        assert isinstance(harness, str)
        context = subject.get("context")
        _require(isinstance(context, dict))
        assert isinstance(context, dict)
        _require(context.get("host") == {"omp": "omp-input-rewrite-v1", "pi": "pi-input-mutation-v1"}[harness])
        _require(isinstance(subject.get("package_bindings"), list) and bool(subject["package_bindings"]))
        digest = metadata.get("captured_subject_sha256")
        _require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None)
        _require(artifact.get("artifact_id") == f"{artifact.get('harness')}:project:package-request:{digest}")
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


def validate_review_lineage(lineage: object) -> dict[str, object]:
    _require(isinstance(lineage, dict))
    assert isinstance(lineage, dict)
    _require(
        set(lineage)
        == {
            "schema",
            "lineage_id",
            "operation_id",
            "artifact_hash",
            "created_at_ms",
            "expires_at_ms",
        }
    )
    _require(lineage["schema"] == "guard-native-bash-review-lineage.v1")
    _require(
        isinstance(lineage["lineage_id"], str) and re.fullmatch(r"[0-9a-f]{64}", lineage["lineage_id"]) is not None
    )
    _require(
        isinstance(lineage["operation_id"], str)
        and re.fullmatch(r"[A-Za-z0-9_.:-]{16,128}", lineage["operation_id"]) is not None
    )
    _require(_token(lineage["artifact_hash"]))
    _require(
        type(lineage["created_at_ms"]) is int
        and type(lineage["expires_at_ms"]) is int
        and lineage["created_at_ms"] >= 0
        and lineage["expires_at_ms"] - lineage["created_at_ms"] == 86_400_000
    )
    return lineage


def validate_executed(result: dict[str, object], request: dict[str, object]) -> None:
    def operation_matches(value: object) -> bool:
        if request.get("tool_call_id") is not None:
            # Native allocation is part of the request-bound reply. This digest
            # names an invocation; it is not client permission or a grant.
            return isinstance(value, str) and re.fullmatch(r"bash-invocation:[0-9a-f]{64}", value) is not None
        return value == request["operation_id"]

    _require(all(type(result[key]) is bool for key in ("grant_claimed", "dispatch_acknowledged", "replayed")))
    lineage = result["review_lineage"]
    if lineage is not None:
        lineage = validate_review_lineage(lineage)
        _require(operation_matches(lineage["operation_id"]))
        _require(
            result["status"] == "error"
            and result["code"] == "native_bash_consent_required"
            and not result["grant_claimed"]
            and not result["dispatch_acknowledged"]
            and not result["replayed"]
            and result["operation"] is None
            and result["payload"] is None
        )
    elif result["code"] == "native_bash_consent_required":
        _require(False)
    operation = result["operation"]
    if operation is not None:
        _require(isinstance(operation, dict))
        assert isinstance(operation, dict)
        _require(
            set(operation)
            == {
                "operation_id",
                "artifact_hash",
                "authorization",
                "state",
                "dispatch_acknowledged",
                "completion",
            }
        )
        _require(operation_matches(operation["operation_id"]))
        authorization = request["authorization"]
        _require(isinstance(authorization, dict))
        assert isinstance(authorization, dict)
        _require(
            isinstance(operation["authorization"], str)
            and operation["authorization"] in {"saved_grant", "current_policy"}
        )
        if result["replayed"]:
            _require(result["grant_claimed"] == (operation["authorization"] == "saved_grant"))
        else:
            _require(operation["authorization"] == authorization["kind"])
        _require(
            isinstance(operation["state"], str)
            and operation["state"] in {"claimed", "dispatched", "completed", "uncertain"}
        )
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
        _require(
            result["code"]
            in {
                "native_bash_already_completed_output_not_retained",
                "native_bash_operation_in_progress_or_uncertain",
            }
        )
    else:
        _require(result["replayed"] is False)
