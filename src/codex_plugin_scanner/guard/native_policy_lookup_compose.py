"""Resident bridge for the ``policy_lookup_compose`` op.

Rust owns which saved decision a multi-probe lookup returns: the artifact's
own rule, an exact command the memory pattern names, and the pattern's
artifact each answer separately, and the one the hook acts on is the most
restrictive of them. This module only ships the probes that were already
resolved and hands the answer back. Nothing is ordered here, so an
unreachable resident raises instead of letting a looser saved rule stand in
for a stricter one.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from uuid import uuid4

from .native_context import _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_runtime import native_runtime_status
from .native_runtime_resilience import native_record_resident_failure
from .native_store_policy import _payload
from .store_base import PolicyDecisionLookupResult

POLICY_LOOKUP_COMPOSE_FEATURE = "policy-lookup-compose-v1"
_REQUEST_SCHEMA = "guard-policy-lookup-compose-request.v1"
_RESULT_SCHEMA = "guard-policy-lookup-compose-result.v1"
_TIMEOUT_SECONDS = 10.0
_MAX_REQUEST_BYTES = 4 * 1024 * 1024


class PolicyLookupComposeUnavailableError(RuntimeError):
    """Raised when the resident cannot say which saved decision wins."""


def _composed(payload: dict[str, object]) -> PolicyDecisionLookupResult | None:
    """The reply read as a lookup result, or ``None`` when it is unreadable."""

    decision = payload.get("decision")
    ignored = payload.get("ignored_local_integrity")
    trust_status = payload.get("trust_status")
    revision = payload.get("authority_revision")
    if not isinstance(trust_status, dict) or not isinstance(revision, int) or isinstance(revision, bool):
        return None
    if not (decision is None or isinstance(decision, dict)) or not (ignored is None or isinstance(ignored, dict)):
        return None
    return {
        "decision": decision,
        "ignored_local_integrity": ignored,
        "trust_status": trust_status,
        "authority_revision": revision,
    }


def native_policy_lookup_compose(
    candidates: Sequence[PolicyDecisionLookupResult],
    *,
    guard_home: Path | None = None,
) -> PolicyDecisionLookupResult:
    """Compose the resolved probes in the resident; raise when it cannot.

    ``candidates`` are ``PolicyDecisionLookupResult`` mappings in the order
    the probes ran, the direct artifact lookup first. ``guard_home`` is the
    home of the store that resolved them: the composition must reach the same
    resident the probes did.
    """

    home = Path(_resolve_digest_home(guard_home))
    if not ensure_resident_prerequisite(home):
        raise PolicyLookupComposeUnavailableError
    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"policy-lookup-compose-{uuid4().hex}",
        "candidates": [
            {
                "decision": candidate.get("decision"),
                "ignored_local_integrity": candidate.get("ignored_local_integrity"),
                "trust_status": candidate.get("trust_status"),
                "authority_revision": candidate.get("authority_revision"),
            }
            for candidate in candidates
        ],
    }
    try:
        response = _resident_request(
            operation="policy_lookup_compose",
            request=wire,
            guard_home=home,
            timeout_seconds=_TIMEOUT_SECONDS,
            required_feature=POLICY_LOOKUP_COMPOSE_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError, OSError, RuntimeError):
        raise PolicyLookupComposeUnavailableError from None
    payload = _payload(response, wire, home)
    if not isinstance(payload, dict):
        raise PolicyLookupComposeUnavailableError
    composed = _composed(payload)
    if composed is None:
        # ``_payload`` counted the bound ``ok`` reply as a healthy answer. A
        # payload the caller cannot read is not one, so the resident's
        # consecutive-failure count hears about it before the raise.
        identity = native_runtime_status().identity
        if identity is not None:
            native_record_resident_failure(identity.sha256, home, reason="native_policy_lookup_compose_bad_payload")
        raise PolicyLookupComposeUnavailableError
    return composed
