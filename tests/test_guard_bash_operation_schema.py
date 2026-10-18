from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.store_bash_operation_schema import (
    BASH_OPERATION_MIGRATION_VERSION,
    bash_operation_schema_statement,
    ensure_bash_operation_schema,
)
from codex_plugin_scanner.guard.store_connection_schema import _REQUIRED_SCHEMA_MIGRATION_VERSIONS


def database(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.execute("create table schema_migrations(version integer primary key, applied_at text not null)")
    return connection


def test_bash_operation_upgrade_preserves_reservations_across_reopen(tmp_path: Path) -> None:
    path = tmp_path / "guard.db"
    with database(path) as connection:
        # The native owner can reserve before the Python store next initializes.
        connection.execute(bash_operation_schema_statement())
        connection.execute("insert into guard_bash_operations values ('operation-00000001', '{}', '{}')")
        ensure_bash_operation_schema(connection, applied_at="2026-10-18T00:00:00Z")
    with sqlite3.connect(path) as connection:
        ensure_bash_operation_schema(connection, applied_at="2026-10-18T00:01:00Z")
        assert connection.execute("select * from guard_bash_operations").fetchall() == [
            ("operation-00000001", "{}", "{}")
        ]
        assert connection.execute("select version from schema_migrations").fetchall() == [
            (BASH_OPERATION_MIGRATION_VERSION,)
        ]
        assert BASH_OPERATION_MIGRATION_VERSION in _REQUIRED_SCHEMA_MIGRATION_VERSIONS


def test_bash_operation_upgrade_rejects_incompatible_schema_without_marking_current(tmp_path: Path) -> None:
    with database(tmp_path / "guard.db") as connection:
        connection.execute("create table guard_bash_operations(operation_id text, payload text, integrity text)")
        connection.execute("insert into guard_bash_operations values ('existing', 'preserve', 'preserve')")
        with pytest.raises(RuntimeError, match=r"incompatible.*schema object"):
            ensure_bash_operation_schema(connection, applied_at="2026-10-18T00:00:00Z")
        assert connection.execute("select * from schema_migrations").fetchall() == []
        assert connection.execute("select payload from guard_bash_operations").fetchall() == [("preserve",)]


def test_bash_operation_storage_bounds_and_duplicate_identity(tmp_path: Path) -> None:
    with database(tmp_path / "guard.db") as connection:
        ensure_bash_operation_schema(connection, applied_at="2026-10-18T00:00:00Z")
        connection.execute("insert into guard_bash_operations values ('operation-00000001', '{}', '{}')")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("insert into guard_bash_operations values ('operation-00000001', '{}', '{}')")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("insert into guard_bash_operations values ('too-large', ?, '{}')", ("x" * 16385,))
