"""Storage migration only; native code authenticates all execution records."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Final

from .store_command_activity_schema import _validate_schema_object_sql

BASH_OPERATION_MIGRATION_VERSION: Final = 30


def bash_operation_schema_statement() -> str:
    return (Path(__file__).parent / "schemas" / "native_bash_operations_v1.sql").read_text(encoding="utf-8")


def ensure_bash_operation_schema(connection: sqlite3.Connection, *, applied_at: str) -> None:
    statement = bash_operation_schema_statement()
    connection.execute("savepoint bash_operation_schema_v1")
    try:
        connection.execute(statement)
        _validate_schema_object_sql(connection, (statement,), family_label="Bash operation ")
        connection.execute(
            "insert or ignore into schema_migrations (version, applied_at) values (?, ?)",
            (BASH_OPERATION_MIGRATION_VERSION, applied_at),
        )
    except BaseException:
        connection.execute("rollback to bash_operation_schema_v1")
        connection.execute("release bash_operation_schema_v1")
        raise
    connection.execute("release bash_operation_schema_v1")
