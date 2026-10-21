"""The authority memo serves a settled reply only while the database is unchanged."""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_extension_control_authority_memo as memo

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="the memo keeps nothing on Windows")


def _store(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "guard.db"
    with sqlite3.connect(path) as connection:
        connection.execute("create table t (v integer)")
    return path


def _wire(store: Path, *, op: str = "read", allow_migration: bool = False, request_id: str = "r1") -> dict[str, object]:
    return {
        "store_path": str(store),
        "op": op,
        "request_id": request_id,
        "allow_migration": allow_migration,
        "catalog_digest": "c" * 64,
    }


def _keep(wire: dict[str, object], payload: dict[str, object]) -> None:
    key, kept = memo.lookup(wire)
    assert kept is None
    memo.keep(key, payload)


def test_settled_reply_is_served_until_another_connection_commits(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _keep(_wire(store), {"view": {"health": "protected"}})

    _key, kept = memo.lookup(_wire(store, request_id="r2"))
    assert kept == {"view": {"health": "protected"}}
    kept["view"]["health"] = "mutated"
    assert memo.lookup(_wire(store))[1] == {"view": {"health": "protected"}}

    with sqlite3.connect(store) as connection:
        connection.execute("insert into t values (1)")
    assert memo.lookup(_wire(store))[1] is None


def test_replaced_database_is_not_served_from_the_memo(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _keep(_wire(store), {"view": {"health": "protected"}})
    _store(tmp_path / "next").replace(store)
    assert memo.lookup(_wire(store))[1] is None


@pytest.mark.parametrize(
    "payload",
    [
        {"fault": "tampered"},
        {"view": {}, "action": {"kind": "rollback"}},
        {"need": "manifest"},
        {"view": {}, "events": [{"kind": "migrated"}]},
        {"view": {}, "manifest_write": {"sha256": "m"}},
    ],
)
def test_unsettled_replies_always_go_back_to_the_resident(tmp_path: Path, payload: dict[str, object]) -> None:
    store = _store(tmp_path)
    _keep(_wire(store), payload)
    assert memo.lookup(_wire(store))[1] is None


def test_migrating_reply_serves_a_read_only_caller_but_not_the_converse(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _keep(_wire(store, allow_migration=True), {"view": {"health": "protected"}})
    assert memo.lookup(_wire(store, allow_migration=False))[1] == {"view": {"health": "protected"}}

    other = _store(tmp_path / "other")
    _keep(_wire(other, allow_migration=False), {"view": {"health": "protected"}})
    assert memo.lookup(_wire(other, allow_migration=True))[1] is None


def test_missing_database_is_never_memoized(tmp_path: Path) -> None:
    key, kept = memo.lookup(_wire(tmp_path / "absent.db"))
    assert key is None
    assert kept is None
