from __future__ import annotations

import copy
import re
import threading
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_extension_control
from codex_plugin_scanner.guard.daemon import client as daemon_client
from codex_plugin_scanner.guard.daemon.extension_control_api import ExtensionControlApiError, ExtensionControlApiService
from codex_plugin_scanner.guard.daemon.extension_control_semantic_preview import (
    SEMANTIC_PREVIEW_SCHEMA,
    _render,
)
from codex_plugin_scanner.guard.native_extension_control import (
    PREVIEW_LIMIT_CODES,
    NativeExtensionControlError,
)

_REPO_ROOT = Path(__file__).resolve().parents[1]


class _InvalidError(RuntimeError):
    pass


def _invalid() -> RuntimeError:
    return _InvalidError("invalid")


def _target() -> dict[str, object]:
    return {
        "target": {"kind": "permission", "target_id": "command.git.push"},
        "extension_id": "command.git",
        "label": "Push",
        "before_explicit": "inherited",
        "after_explicit": "disabled",
        "before_effective": "allowed",
        "after_effective": "blocked",
        "baseline_risk": "high",
        "baseline_floor": "ask",
        "affected_permission_ids": ["command.git.push"],
        "affected_rule_ids": ["git.push"],
        "affected_extension_ids": [],
        "dependency_permission_ids": [],
        "implied_permission_ids": [],
        "conflict_permission_ids": [],
        "provenance": ["local"],
        "warnings": [{"code": "indirect", "count": 2, "message": "Affects 2 permissions."}],
        "extension_name": "Git",
    }


def _preview() -> dict[str, object]:
    return {
        "schema_version": SEMANTIC_PREVIEW_SCHEMA,
        "global_lockdown": {"before": False, "after": False, "changed": False},
        "changed_target_count": 1,
        "affected_permission_count": 1,
        "affected_rule_count": 1,
        "changed_targets": [_target()],
        "approval_required": False,
        "summary": {"newly_blocked_permissions": 1, "newly_allowed_permissions": 0, "effective_change_count": 1},
    }


def _with_target(**changes: object) -> dict[str, object]:
    value = _preview()
    target = copy.deepcopy(_target())
    target.update(changes)
    value["changed_targets"] = [target]
    return value


def test_render_keeps_a_well_formed_preview_in_digest_order() -> None:
    value = _preview()
    shuffled = dict(reversed(list(value.items())))

    rendered = _render(shuffled, _invalid)

    assert rendered == value
    assert list(rendered) == list(value)


def test_render_accepts_a_target_without_its_optional_fields() -> None:
    target = _target()
    for name in ("baseline_risk", "baseline_floor", "extension_name"):
        del target[name]
    target["warnings"] = [{"code": "conflict", "message": "Conflicts.", "target_id": "command.git.force"}]
    value = _preview()
    value["changed_targets"] = [target]

    assert _render(value, _invalid) == value


@pytest.mark.parametrize(
    "mutate",
    [
        lambda v: v.update(changed_targets=["not-a-target"]),
        lambda v: v.update(changed_targets=[{}]),
        lambda v: v.update(global_lockdown={"before": False, "after": False}),
        lambda v: v.update(global_lockdown={"before": False, "after": False, "changed": "no"}),
        lambda v: v.update(global_lockdown={"before": 0, "after": False, "changed": False}),
        lambda v: v.update(summary={"newly_blocked_permissions": 1}),
        lambda v: v.update(
            summary={"newly_blocked_permissions": "1", "newly_allowed_permissions": 0, "effective_change_count": 1}
        ),
        lambda v: v.update(
            summary={"newly_blocked_permissions": True, "newly_allowed_permissions": 0, "effective_change_count": 1}
        ),
        lambda v: v.update(
            summary={"newly_blocked_permissions": -1, "newly_allowed_permissions": 0, "effective_change_count": 1}
        ),
        lambda v: v.update(affected_rule_count="1"),
        lambda v: v.update(affected_permission_count=-1),
        lambda v: v.update(changed_target_count=2),
        lambda v: v.update(approval_required=1),
        lambda v: v.update(schema_version="other"),
        lambda v: v.update(extra=1),
        lambda v: v.pop("summary"),
    ],
)
def test_render_refuses_a_malformed_top_level_or_nested_object(mutate) -> None:
    value = _preview()
    mutate(value)

    with pytest.raises(_InvalidError):
        _render(value, _invalid)


@pytest.mark.parametrize(
    "changes",
    [
        {"target": {"kind": "rule", "target_id": "command.git.push"}},
        {"target": {"kind": "permission"}},
        {"target": "command.git.push"},
        {"target": {"kind": ["permission"], "target_id": "command.git.push"}},
        {"extension_id": 7},
        {"label": None},
        {"before_explicit": "maybe"},
        {"after_explicit": None},
        {"before_effective": "inherited"},
        {"after_effective": "ask"},
        {"affected_permission_ids": "command.git.push"},
        {"affected_rule_ids": [1]},
        {"provenance": [["local"]]},
        {"warnings": {"code": "indirect"}},
        {"warnings": ["indirect"]},
        {"warnings": [{"code": "indirect"}]},
        {"warnings": [{"code": "indirect", "message": "m", "count": "2"}]},
        {"warnings": [{"code": "indirect", "message": "m", "target_id": 3}]},
        {"warnings": [{"code": "indirect", "message": "m", "unknown": 1}]},
        {"baseline_risk": 4},
        {"extension_name": ["Git"]},
        {"unknown": 1},
    ],
)
def test_render_refuses_a_malformed_changed_target(changes: dict[str, object]) -> None:
    with pytest.raises(_InvalidError):
        _render(_with_target(**changes), _invalid)


def test_render_refuses_a_target_missing_a_required_field() -> None:
    value = _preview()
    del value["changed_targets"][0]["affected_extension_ids"]  # type: ignore[index]

    with pytest.raises(_InvalidError):
        _render(value, _invalid)


def test_render_bounds_the_lists_it_forwards() -> None:
    too_many = [f"command.git.p{index}" for index in range(4097)]

    with pytest.raises(_InvalidError):
        _render(_with_target(affected_permission_ids=too_many), _invalid)
    with pytest.raises(_InvalidError):
        _render(_with_target(warnings=[{"code": "w", "message": "m"}] * 65), _invalid)


def test_preview_limit_refusals_report_a_limit_not_a_dead_runtime() -> None:
    assert {
        "native_extension_control_too_many_items",
        "native_extension_control_reply_too_large",
    } == PREVIEW_LIMIT_CODES
    service = ExtensionControlApiService.__new__(ExtensionControlApiService)
    service._preview_lock = threading.Lock()
    for code in sorted(PREVIEW_LIMIT_CODES):

        def refuse(_payload: dict[str, object], code: str = code) -> dict[str, object]:
            raise NativeExtensionControlError(code)

        service._preview_locked = refuse  # type: ignore[method-assign]
        with pytest.raises(ExtensionControlApiError) as limit:
            service.preview({})
        assert (limit.value.status, limit.value.code) == (400, "control_limit_exceeded")

    def unavailable(_payload: dict[str, object]) -> dict[str, object]:
        raise NativeExtensionControlError("native_extension_control_unavailable")

    service._preview_locked = unavailable  # type: ignore[method-assign]
    with pytest.raises(ExtensionControlApiError) as dead:
        service.preview({})
    assert (dead.value.status, dead.value.code) == (503, "native_runtime_unavailable")


def test_preview_deadlines_nest_from_the_resident_out_to_the_dashboard() -> None:
    granted = native_extension_control._PREVIEW_TIMEOUT_SECONDS
    ceiling = re.search(
        r"EXTENSION_CONTROL_TIMEOUT_CEILING_MS: u64 = ([0-9_]+);",
        (_REPO_ROOT / "rust/crates/guard-runtime/src/managed_resident_client_timeout.rs").read_text(),
    )

    assert ceiling is not None
    # The resident client clamps to its ceiling, so the ceiling must grant what Python asks for.
    assert int(ceiling.group(1).replace("_", "")) >= granted * 1000
    # The daemon answers only after the resident does; its client waits longer.
    assert granted < daemon_client._EXTENSION_MUTATION_REQUEST_TIMEOUT_S
