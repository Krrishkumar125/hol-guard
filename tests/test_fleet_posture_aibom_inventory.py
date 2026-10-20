"""Fleet posture reports what the AIBOM collection found, and machines carry their host name."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.inventory_contract import GuardAgentInventoryItem, GuardAgentInventorySnapshot
from codex_plugin_scanner.guard.runtime import fleet_posture as fp
from codex_plugin_scanner.guard.runtime import fleet_posture_tools as tools
from codex_plugin_scanner.guard.runtime.fleet_posture_aibom import (
    AIBOM_ITEMS_STATE_KEY,
    fleet_inventory_rows,
    remember_aibom_items,
)
from codex_plugin_scanner.guard.store import GuardStore

NOW = datetime(2026, 10, 20, 12, 0, 0, tzinfo=timezone.utc)
HASH = "sha256:" + "b" * 64


def _item(item_id: str, kind: str, name: str, *, artifact_type: str | None = None) -> GuardAgentInventoryItem:
    metadata: dict[str, object] = {"configPath": f"{{home}}/.codex/{name}"}
    if artifact_type is not None:
        metadata["artifactType"] = artifact_type
    return GuardAgentInventoryItem(
        item_id=item_id,
        item_kind=kind,  # type: ignore[arg-type]
        display_name=name,
        description="",
        source_fingerprint="f",
        content_hash=HASH,
        capability_categories=(),
        metadata=metadata,
    )


def _snapshot(harness: str, generated_at: str, *items: GuardAgentInventoryItem) -> GuardAgentInventorySnapshot:
    return GuardAgentInventorySnapshot(f"{harness}:1", f"{harness}:agent", harness, generated_at, items=items)  # type: ignore[arg-type]


@pytest.fixture
def store(tmp_path: Path) -> GuardStore:
    return GuardStore(tmp_path / "guard")


def test_aibom_items_reach_fleet_posture_when_the_inventory_table_is_empty(
    store: GuardStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store, "list_inventory", lambda harness=None: [])
    remember_aibom_items(
        store,
        [
            _snapshot(
                "codex",
                "2026-10-20T11:00:00Z",
                _item("codex:global:chrome-devtools", "mcp_server", "chrome-devtools"),
                _item("codex:project:review", "skill", "review", artifact_type="skill_file"),
                # Kinds fleet posture does not report stay out.
                _item("codex:global:agents", "prompt_pack", "AGENTS.md"),
            ),
            # Harnesses outside the contract stay out.
            _snapshot("not-a-harness", "2026-10-20T11:00:00Z", _item("x:global:y", "skill", "y")),
        ],
        now="2026-10-20T11:00:00Z",
    )
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard")
    config = SimpleNamespace(install_owner="user", harness_postures={}, protection_posture="protected", mode="enforce")
    built = fp.build_fleet_posture_state(
        store, [], fp.FleetPostureSettings(context=context, guard_config=config, now=NOW)
    )
    items = {(item["kind"], item["name"], item["source"]) for item in built.payload["inventory"]["items"]}  # type: ignore[index]
    assert items == {("mcp_server", "chrome-devtools", "user"), ("skill", "review", "project")}


def test_inventory_table_rows_win_over_the_same_aibom_item(store: GuardStore, monkeypatch: pytest.MonkeyPatch) -> None:
    table_row = {
        "artifact_name": "chrome-devtools",
        "artifact_type": "mcp_server",
        "harness": "codex",
        "config_path": "{home}/.codex/chrome-devtools",
        "last_policy_action": "allow",
    }
    monkeypatch.setattr(store, "list_inventory", lambda harness=None: [table_row])
    remember_aibom_items(
        store,
        [
            _snapshot(
                "codex", "2026-10-20T11:00:00Z", _item("codex:global:chrome-devtools", "mcp_server", "chrome-devtools")
            )
        ],
        now="2026-10-20T11:00:00Z",
    )
    rows = fleet_inventory_rows(store)
    assert rows[0] is table_row
    assert len(rows) == 2


def test_a_later_collection_keeps_first_seen_and_drops_items_it_no_longer_finds(store: GuardStore) -> None:
    first = _item("codex:global:one", "skill", "one")
    second = _item("codex:global:two", "skill", "two")
    remember_aibom_items(store, [_snapshot("codex", "2026-10-19T00:00:00Z", first, second)], now="2026-10-19T00:00:00Z")
    remember_aibom_items(store, [_snapshot("codex", "2026-10-20T00:00:00Z", first)], now="2026-10-20T00:00:00Z")
    stored = store.get_sync_payload(AIBOM_ITEMS_STATE_KEY)
    assert isinstance(stored, dict)
    rows = stored["rows"]
    assert [row["artifact_name"] for row in rows] == ["one"]
    assert rows[0]["first_seen_at"] == "2026-10-19T00:00:00Z"
    assert rows[0]["last_seen_at"] == "2026-10-20T00:00:00Z"


@pytest.mark.parametrize("label", ["Local machine", "local-device", "This machine", "  "])
def test_generic_labels_are_sent_as_the_host_name(label: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tools.platform, "node", lambda: "Ada-MacBook-Pro.local")
    assert tools.effective_device_label(label) == "Ada-MacBook-Pro"


def test_a_chosen_label_is_kept(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tools.platform, "node", lambda: "Ada-MacBook-Pro.local")
    assert tools.effective_device_label("Build server 3") == "Build server 3"


def test_a_generic_label_stays_when_the_host_has_no_usable_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tools.platform, "node", lambda: "localhost")
    assert tools.effective_device_label("Local machine") == "Local machine"
