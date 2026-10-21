"""Deterministic semantic preview for extension-control authority mutations.

The preview describes effective consequences without executing commands and without
changing detector metadata. The resident computes it with the same resolver command
enforcement uses, so neither the daemon nor the dashboard carries policy truth.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Final

from ..native_extension_control import preview_control_mutation
from ..runtime.command_extensions import CommandSafetyExtensionRegistry
from ..runtime.extension_control_contract import ExtensionControlLayer

SEMANTIC_PREVIEW_SCHEMA: Final = "guard.daemon.extension-control-semantic-preview.v1"
_FIELDS: Final = (
    "schema_version",
    "global_lockdown",
    "changed_target_count",
    "affected_permission_count",
    "affected_rule_count",
    "changed_targets",
    "approval_required",
    "summary",
)


def _render(value: object, invalid: Callable[[], RuntimeError]) -> dict[str, object]:
    """The resident's preview, in the field order the dashboard renders and digests."""

    if not isinstance(value, dict) or set(value) != set(_FIELDS) or value["schema_version"] != SEMANTIC_PREVIEW_SCHEMA:
        raise invalid()
    if not isinstance(value["changed_targets"], list) or value["changed_target_count"] != len(value["changed_targets"]):
        raise invalid()
    if not all(isinstance(value[name], dict) for name in ("global_lockdown", "summary")):
        raise invalid()
    if type(value["approval_required"]) is not bool:
        raise invalid()
    return {name: value[name] for name in _FIELDS}


def build_extension_control_semantic_preview(
    registry: CommandSafetyExtensionRegistry,
    current_layers: tuple[ExtensionControlLayer, ...],
    proposed_layers: tuple[ExtensionControlLayer, ...],
    *,
    guard_home: Path | None = None,
) -> dict[str, object]:
    return preview_control_mutation(registry, current_layers, proposed_layers, _render, guard_home=guard_home)
