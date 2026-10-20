"""The query the proxy sends for one inline approval answer, and what it accepts back.

The resident owns the classification and the block a refused answer produces;
this covers the transport around it, which must not read a verdict out of an
answer the resident did not give.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_mcp_proxy_decision
from codex_plugin_scanner.guard.native_mcp_proxy_decision import (
    MCP_PROXY_INLINE_APPROVAL_REPLY_FEATURE,
    NativeMcpProxyDecisionError,
    native_inline_approval_reply,
)

DENIED = {
    "decision_source": "inline-denied",
    "event_decision": "deny-inline",
    "reason": "HOL Guard blocked tool call delete_secret_file from workspace-files.",
}


def _ask(monkeypatch: pytest.MonkeyPatch, answer: object, sent: list[dict[str, Any]] | None = None) -> Any:
    def decide(query: Any, **kwargs: Any) -> Any:
        if sent is not None:
            sent.append({"query": dict(query), **kwargs})
        if isinstance(answer, BaseException):
            raise answer
        return answer

    monkeypatch.setattr(native_mcp_proxy_decision, "native_mcp_proxy_decide", decide)
    return native_inline_approval_reply(
        {"action": "accept", "content": {"decision": "deny"}},
        tool_name="delete_secret_file",
        server_name="workspace-files",
        guard_home=Path("/guard-home"),
    )


def test_the_query_carries_the_answer_the_client_gave(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[dict[str, Any]] = []

    _ = _ask(monkeypatch, {"inline_approval": "denied", "block": DENIED}, sent)

    assert sent[0]["query"] == {
        "check": "inline_approval_reply",
        "payload": {"action": "accept", "content": {"decision": "deny"}},
        "tool_name": "delete_secret_file",
        "server_name": "workspace-files",
    }
    assert sent[0]["required_feature"] == MCP_PROXY_INLINE_APPROVAL_REPLY_FEATURE
    assert sent[0]["guard_home"] == Path("/guard-home")


@pytest.mark.parametrize("block", [DENIED, None])
def test_the_resident_names_the_classification_and_the_block(monkeypatch: pytest.MonkeyPatch, block: object) -> None:
    assert _ask(monkeypatch, {"inline_approval": "denied", "block": block}) == {
        "inline_approval": "denied",
        "block": block,
    }


@pytest.mark.parametrize(
    "answer",
    [
        {},
        {"inline_approval": None, "block": None},
        {"inline_approval": "denied", "block": "inline-denied"},
        {"inline_approval": "denied", "block": {"decision_source": "inline-denied"}},
        {"inline_approval": "denied", "block": {**DENIED, "reason": None}},
        NativeMcpProxyDecisionError("native_mcp_proxy_decision_unavailable"),
    ],
)
def test_an_answer_the_resident_did_not_give_is_no_answer(monkeypatch: pytest.MonkeyPatch, answer: object) -> None:
    """The caller routes the error; it never reads a verdict out of a bad answer."""

    with pytest.raises(NativeMcpProxyDecisionError):
        _ = _ask(monkeypatch, answer)
