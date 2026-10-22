"""Extension allow-hint decided by the native resident.

Which configurable extension permissions would let a reviewed command run is
decided by the resident (``extension_allow_hint``): it re-runs the command
evaluation the ``command_effect_decide`` op uses, under its own admitted control
snapshot, with hypothetical enabled permissions, and keeps only the permissions
the allow needs. Python builds the query from the evidence the review already
holds and shape-checks the answer; there is no Python evaluator and no fallback.
A reply that is not a bound, strictly decoded ``ok`` means no hint.
"""

from __future__ import annotations

import threading
import time
from dataclasses import replace
from pathlib import Path
from typing import Any, Final

from .native_daemon_route import _decide
from .native_resident_decision import ResidentOperation, shape_fields
from .runtime.command_evaluation import (
    CommandEvaluationInput,
    _resolve_home,  # pyright: ignore[reportPrivateUsage]
    _wire_item,  # pyright: ignore[reportPrivateUsage]
)
from .runtime.native_command_extension_evidence import NativeCommandExtensionEvidenceError

EXTENSION_ALLOW_HINT_FEATURE: Final = "extension-allow-hint-v1"
_TIMEOUT_SECONDS: Final = 5.0
# A bounded reduction pass is answered after its budget, so the ask outlives
# the budget by the time the resident needs to finish the verified full set.
_RESPONSE_SLACK_SECONDS: Final = 2.0
_MAX_BUDGET_MS: Final = 60_000
# The resident bounds the canonical request to 1 MiB; the envelope adds a little.
_MAX_REQUEST_BYTES: Final = 1024 * 1024 + 64 * 1024
_MAX_CONCURRENT_ASKS: Final = 4
_SLOTS: Final = threading.BoundedSemaphore(_MAX_CONCURRENT_ASKS)
_HINT_FIELDS: Final = {
    "schema": str,
    "permission_ids": list,
    "rule_ids": list,
    "extension_ids": list,
    "relied_permission_ids": list,
    "catalog_digest": str,
}


class NativeExtensionAllowHintError(RuntimeError):
    """No authoritative answer; ``code`` says why, for diagnostics only."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


_OPERATION: Final = ResidentOperation(
    operation="extension_allow_hint",
    feature=EXTENSION_ALLOW_HINT_FEATURE,
    prefix="native_extension_allow_hint",
    request_schema="guard-extension-allow-hint-request.v1",
    request_id_prefix="extension-allow-hint",
    result_schema="guard-extension-allow-hint-result.v1",
    timeout_seconds=_TIMEOUT_SECONDS,
    error=NativeExtensionAllowHintError,
)


def _timing(deadline: float | None) -> tuple[float, int | None]:
    """The ask's timeout and the resident's reduction budget for ``deadline``."""

    if deadline is None:
        return _TIMEOUT_SECONDS, None
    remaining = max(0.0, deadline - time.monotonic())
    return min(_TIMEOUT_SECONDS, remaining + _RESPONSE_SLACK_SECONDS), min(int(remaining * 1000), _MAX_BUDGET_MS)


def _query(entry: CommandEvaluationInput, budget_ms: int | None) -> dict[str, object]:
    item, _evidence = _wire_item(entry)
    query: dict[str, object] = {
        "kind": "allow_hint",
        "command_text": item.command_text,
        "canonical_command": dict(item.canonical_command),
        "native_extension_evidence": dict(item.native_extension_evidence),
        "control_snapshot": dict(item.control_snapshot),
    }
    if item.cwd is not None:
        query["cwd"] = str(item.cwd)
    if item.home_dir is not None:
        query["home_dir"] = str(item.home_dir)
    if budget_ms is not None:
        query["reduction_budget_ms"] = budget_ms
    return query


def native_extension_allow_hint(
    entry: CommandEvaluationInput,
    *,
    guard_home: Path | None = None,
    deadline: float | None = None,
) -> dict[str, object] | None:
    """Permission ids whose Allow state would let ``entry``'s command run, or None.

    ``deadline`` (``time.monotonic()``) bounds the resident's optional reduction
    pass: once it has passed, the already verified full permission set is
    answered as it is. ``None`` also covers an unavailable resident.
    """

    timeout_seconds, budget_ms = _timing(deadline)
    parsed: list[dict[str, object] | None] = []

    def validate(payload: dict[str, Any]) -> None:
        from .runtime.extension_allow_hint import validated_extension_allow_hint

        hint = payload["hint"]
        if hint is None:
            parsed.append(None)
            return
        shape_fields(hint, _HINT_FIELDS, lambda: _OPERATION.fail(_OPERATION.invalid))
        checked = validated_extension_allow_hint(hint)
        if checked is None:
            raise _OPERATION.fail(_OPERATION.invalid)
        parsed.append(checked)

    try:
        _decide(
            _query(entry, budget_ms),
            _resolve_home(guard_home),
            {"hint": (dict, type(None))},
            validate,
            operation=replace(_OPERATION, timeout_seconds=timeout_seconds),
            max_request_bytes=_MAX_REQUEST_BYTES,
            slots=_SLOTS,
        )
    except (NativeCommandExtensionEvidenceError, RuntimeError, ValueError):
        return None
    return parsed[0]
