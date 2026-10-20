"""AIBOM-detected items as fleet posture inventory rows.

Guard writes a row to its local inventory table only when it scans an artifact
itself: a launch through ``hol-guard run``, an install or a consumer scan. Machines
protected through hooks rarely take those paths, so their inventory table stays
empty while the AIBOM collection sees every skill, MCP server, plugin and hook on
the machine. Each AIBOM collection stores a compact copy of what it found here,
and fleet posture reports the union of both sources.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import TYPE_CHECKING, Any

from .fleet_posture_common import HARNESS_IDS, normalized_timestamp
from .fleet_posture_inventory import inventory_item_kind

if TYPE_CHECKING:
    from ..store import GuardStore

AIBOM_ITEMS_STATE_KEY = "fleet_posture_aibom_items"
# One machine rarely carries more than a few hundred items; the cap bounds the stored row.
MAX_AIBOM_ROWS = 5_000


def _row_key(row: Mapping[str, object]) -> str:
    return "\0".join(str(row.get(part) or "") for part in ("harness", "artifact_type", "artifact_name", "config_path"))


def _stored_rows(store: GuardStore) -> list[dict[str, object]]:
    raw = store.get_sync_payload(AIBOM_ITEMS_STATE_KEY)
    rows = raw.get("rows") if isinstance(raw, dict) else None
    if not isinstance(rows, list):
        return []
    return [dict(row) for row in rows if isinstance(row, dict)]


def _item_rows(snapshot: Any) -> Iterable[dict[str, object]]:
    harness = str(getattr(snapshot, "agent_type", "") or "")
    seen_at = normalized_timestamp(getattr(snapshot, "generated_at", None))
    if harness not in HARNESS_IDS or seen_at is None:
        return
    for item in getattr(snapshot, "items", ()) or ():
        metadata = item.metadata if isinstance(getattr(item, "metadata", None), dict) else {}
        artifact_type = str(metadata.get("artifactType") or "")
        if inventory_item_kind(artifact_type) is None:
            artifact_type = str(getattr(item, "item_kind", "") or "")
        name = str(getattr(item, "display_name", "") or "").strip()
        if inventory_item_kind(artifact_type) is None or not name:
            continue
        config_path = metadata.get("configPath")
        # Item ids read ``<harness>:<scope>:<name>``; the scope maps to the contract source.
        id_parts = str(getattr(item, "item_id", "") or "").split(":")
        yield {
            "artifact_type": artifact_type,
            "harness": harness,
            "artifact_name": name,
            "artifact_hash": getattr(item, "content_hash", None),
            "source_scope": id_parts[1] if len(id_parts) >= 3 else None,
            "config_path": config_path if isinstance(config_path, str) and config_path else None,
            "first_seen_at": seen_at,
            "last_seen_at": seen_at,
            "present": True,
        }


def remember_aibom_items(store: GuardStore, snapshots: Iterable[Any], *, now: str) -> int:
    """Store the reportable items of one AIBOM collection, keeping when each was first seen.

    The collection replaces the previous one, so an item it no longer finds leaves
    the next fleet posture as a removal.
    """

    first_seen = {_row_key(row): row.get("first_seen_at") for row in _stored_rows(store)}
    rows: dict[str, dict[str, object]] = {}
    for snapshot in snapshots:
        for row in _item_rows(snapshot):
            key = _row_key(row)
            if key in rows:
                continue
            earlier = normalized_timestamp(first_seen.get(key))
            if earlier is not None:
                row["first_seen_at"] = earlier
            rows[key] = row
            if len(rows) >= MAX_AIBOM_ROWS:
                break
    store.set_sync_payload(AIBOM_ITEMS_STATE_KEY, {"collectedAt": now, "rows": list(rows.values())}, now)
    return len(rows)


def fleet_inventory_rows(store: GuardStore) -> list[dict[str, object]]:
    """Local inventory rows followed by AIBOM-detected rows; selection keeps the first of a duplicate."""

    return [*store.list_inventory(), *_stored_rows(store)]
