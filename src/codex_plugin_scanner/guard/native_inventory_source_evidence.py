"""Resident bridge for the ``inventory_source_evidence`` op.

An inventory item carries two pieces of filesystem evidence: the source of
truth behind a symlinked config path, and the content hash of the artifact's
primary document. Both read the filesystem, follow links and decide what a
path is allowed to reach, so the resident derives them and this module only
ships the artifact's identity across and hands the answer back. Nothing is
computed here: an unavailable resident cannot soften a blocked link into a
hash, and a snapshot built without the resident carries no evidence at all.

The whole artifact set is asked for at once. One request per artifact would
put the resident on the critical path of every inventory item an AIBOM run
walks, which is the cost the native cutover exists to remove.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast
from uuid import uuid4

from .native_context import _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_store_policy import _payload

INVENTORY_SOURCE_EVIDENCE_FEATURE = "inventory-source-evidence-v1"
_REQUEST_SCHEMA = "guard-inventory-source-evidence-request.v1"
_RESULT_SCHEMA = "guard-inventory-source-evidence-result.v1"
_TIMEOUT_SECONDS = 10.0
# Mirrors ``INVENTORY_SOURCE_EVIDENCE_MAX_ENTRIES``: the resident refuses a
# request carrying more entries than this.
_MAX_ENTRIES = 512
_MAX_REQUEST_BYTES = 4 * 1024 * 1024


class InventorySourceEvidenceUnavailableError(RuntimeError):
    """The resident could not derive the inventory source evidence."""

    code = "native_inventory_source_evidence_unavailable"


def native_inventory_source_evidence(
    entries: Sequence[Mapping[str, object]],
    *,
    home_dir: Path,
    workspace_dir: Path | None = None,
    include_symlinks: bool = True,
    follow_unsafe_symlinks: bool = False,
    guard_home: Path | None = None,
) -> list[dict[str, object]]:
    """Return one evidence mapping per entry, in order.

    Each answer carries ``source_of_truth`` (the metadata block for a symlinked
    config path, or ``None``) and ``primary_content_hash`` (``sha256:…`` for a
    document the artifact is allowed to hash, or ``None``).

    Raises ``InventorySourceEvidenceUnavailableError`` when the resident cannot
    answer, so a caller fails closed rather than publishing a snapshot whose
    evidence was never derived.
    """

    if not entries:
        return []
    try:
        home = Path(_resolve_digest_home(guard_home))
    except (OSError, RuntimeError, ValueError):
        raise InventorySourceEvidenceUnavailableError from None
    if not ensure_resident_prerequisite(home):
        raise InventorySourceEvidenceUnavailableError
    answers: list[dict[str, object]] = []
    for start in range(0, len(entries), _MAX_ENTRIES):
        answers.extend(
            _evidence_for_batch(
                entries[start : start + _MAX_ENTRIES],
                home,
                home_dir=home_dir,
                workspace_dir=workspace_dir,
                include_symlinks=include_symlinks,
                follow_unsafe_symlinks=follow_unsafe_symlinks,
            )
        )
    return answers


def _evidence_for_batch(
    entries: Sequence[Mapping[str, object]],
    home: Path,
    *,
    home_dir: Path,
    workspace_dir: Path | None,
    include_symlinks: bool,
    follow_unsafe_symlinks: bool,
) -> list[dict[str, object]]:
    """Ask the resident about one batch the contract is willing to accept."""

    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"inventory-source-evidence-{uuid4().hex}",
        "home_dir": str(home_dir),
        "include_symlinks": include_symlinks,
        "follow_unsafe_symlinks": follow_unsafe_symlinks,
        "entries": [_entry_wire(entry) for entry in entries],
    }
    if workspace_dir is not None:
        wire["workspace_dir"] = str(workspace_dir)
    try:
        response = _resident_request(
            operation="inventory_source_evidence",
            request=wire,
            guard_home=home,
            timeout_seconds=_TIMEOUT_SECONDS,
            required_feature=INVENTORY_SOURCE_EVIDENCE_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError, OSError, RuntimeError):
        raise InventorySourceEvidenceUnavailableError from None
    payload = _payload(response, wire, home)
    if not isinstance(payload, dict):
        raise InventorySourceEvidenceUnavailableError
    evidence = payload.get("evidence")
    if not isinstance(evidence, list) or len(evidence) != len(entries):
        raise InventorySourceEvidenceUnavailableError
    if not all(isinstance(item, dict) for item in evidence):
        raise InventorySourceEvidenceUnavailableError
    return cast("list[dict[str, object]]", evidence)


def _entry_wire(entry: Mapping[str, object]) -> dict[str, object]:
    """Ship an entry's identity, leaving out a config path it does not carry."""

    wire: dict[str, object] = {
        "harness": str(entry.get("harness", "")),
        "item_kind": str(entry.get("item_kind", "")),
        "artifact_type": str(entry.get("artifact_type", "")),
    }
    config_path = entry.get("config_path")
    if isinstance(config_path, str) and config_path:
        wire["config_path"] = config_path
    return wire
