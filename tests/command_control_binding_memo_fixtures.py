"""Keep the publisher's binding memo from serving one test's reads to another."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from codex_plugin_scanner.guard import native_command_control_binding_memo


@pytest.fixture(autouse=True)
def _command_control_binding_memo(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    # Tests swap binding inputs the memo does not key on (a patched authority
    # read, a replaced view), so reuse is off unless a test turns it back on.
    native_command_control_binding_memo.forget()
    monkeypatch.setattr(native_command_control_binding_memo, "FULL_READ_INTERVAL_SECONDS", 0.0)
    yield
    native_command_control_binding_memo.forget()
