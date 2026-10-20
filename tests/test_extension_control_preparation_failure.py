"""A failed protection change must name its cause and leave a record."""

from __future__ import annotations

import logging
import socket
import ssl
import urllib.error

import pytest

from codex_plugin_scanner.guard.catalog_delivery.authority import ExpiredDistributionError
from codex_plugin_scanner.guard.catalog_delivery.preparation import UnavailablePackError
from codex_plugin_scanner.guard.catalog_delivery.revocations import RevokedPackError
from codex_plugin_scanner.guard.catalog_delivery.transport import MissingReleaseError
from codex_plugin_scanner.guard.daemon.extension_control_errors import ExtensionControlApiError
from codex_plugin_scanner.guard.extension_builder.native_source_compiler import (
    NativeSourceCompilerError,
)
from codex_plugin_scanner.guard.daemon.extension_control_preparation_failure import (
    classify,
    preparation_unavailable,
)


def _wrapped(error: BaseException) -> ValueError:
    """Rebuild the chain preparation raises: a ValueError over the real failure."""

    try:
        raise error
    except BaseException as exc:  # noqa: BLE001 - the chain is the point
        wrapper = ValueError(f"installed bundle metadata unavailable: {exc}")
        wrapper.__cause__ = exc
        return wrapper


@pytest.mark.parametrize(
    ("error", "cause"),
    [
        (urllib.error.URLError(OSError("unreachable")), "offline"),
        (socket.gaierror("name resolution failed"), "offline"),
        (ssl.SSLError("handshake failed"), "offline"),
        (ConnectionResetError("reset"), "offline"),
        (TimeoutError("timed out"), "offline"),
        (urllib.error.HTTPError("https://example.invalid", 404, "missing", None, None), "release_unavailable"),
        (MissingReleaseError("no such release"), "release_unavailable"),
        (ExpiredDistributionError("expired"), "release_unavailable"),
        (UnavailablePackError("pack_absent"), "release_unavailable"),
        (RevokedPackError("command.git", 7), "pack_revoked"),
        (
            _wrapped(NativeSourceCompilerError("source compiler manifest is unavailable")),
            "installed_runtime_incomplete",
        ),
        (ValueError("installed preparation authority is unavailable"), "authority_unavailable"),
        (ValueError("pack_lifecycle_pack_authority_unavailable"), "authority_unavailable"),
        (ValueError("committed subset requires an existing activation"), "authority_unavailable"),
        (ValueError("target catalog shape invalid"), "internal"),
        (OSError("cache read failed"), "local_storage"),
        (RuntimeError("not a preparation failure"), "internal"),
    ],
)
def test_every_preparation_failure_is_classified(error, cause):
    assert classify(error) == cause


def test_failure_keeps_the_public_code_and_adds_a_cause_and_recovery():
    error = preparation_unavailable(OSError("cache read failed"), stage="candidate-preparation")
    assert isinstance(error, ExtensionControlApiError)
    assert error.status == 503
    assert error.code == "pack_preparation_unavailable"
    assert error.to_payload() == {
        "error": "pack_preparation_unavailable",
        "cause": "local_storage",
        "recovery": {"action": "repair_local_cache"},
    }


def test_an_unclassified_failure_still_offers_a_next_step():
    error = preparation_unavailable(ValueError("target catalog shape invalid"), stage="target-metadata")
    assert error.to_payload() == {
        "error": "pack_preparation_unavailable",
        "cause": "internal",
        "recovery": {"action": "retry_pack_preparation"},
    }


def test_the_real_exception_is_recorded_once_with_its_traceback(caplog):
    try:
        raise ValueError("installed preparation authority is unavailable")
    except ValueError as exc:
        with caplog.at_level(logging.ERROR):
            preparation_unavailable(exc, stage="candidate-preparation")
    records = [record for record in caplog.records if record.levelno >= logging.ERROR]
    assert len(records) == 1
    assert "candidate-preparation" in records[0].getMessage()
    assert "cause=authority_unavailable" in records[0].getMessage()
    assert "ValueError" in records[0].getMessage()
    assert records[0].exc_info is not None


def test_the_cause_never_quotes_the_exception_message():
    error = preparation_unavailable(OSError("/Users/someone/.hol-guard/command-packs is unreadable"), stage="s")
    assert "/Users" not in repr(error.to_payload())
