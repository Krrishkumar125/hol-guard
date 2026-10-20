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
from typing import Any
from uuid import uuid4

from .native_context import _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_store_policy import _payload

POLICY_LOOKUP_COMPOSE_FEATURE = "policy-lookup-compose-v1"
_REQUEST_SCHEMA = "guard-policy-lookup-compose-request.v1"
_RESULT_SCHEMA = "guard-policy-lookup-compose-result.v1"
_TIMEOUT_SECONDS = 10.0
_MAX_REQUEST_BYTES = 4 * 1024 * 1024


class PolicyLookupComposeUnavailableError(RuntimeError):
    """Raised when the resident cannot say which saved decision wins."""


def native_policy_lookup_compose(
    candidates: Sequence[dict[str, Any]],
    *,
    guard_home: Path | None = None,
) -> dict[str, object]:
    """Compose the resolved probes in the resident; raise when it cannot.

    ``candidates`` are ``PolicyDecisionLookupResult`` mappings in the order
    the probes ran, the direct artifact lookup first.
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
    return payload
