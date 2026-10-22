"""Runtime artifact policy facts for the native configured-policy action.

The resident owns the verdict. This module projects the guard config, ships
the artifact for the resident to read its own facts from, and records the
protection events the answer returns.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

from ..action_lattice import normalize_guard_action
from ..config import GuardConfig
from ..harness_posture import harness_posture_override
from ..models import GuardAction, GuardArtifact
from ..native_hook_artifact_compose import native_hook_compose
from ..native_hook_artifact_facts import (
    HookArtifactFactsUnavailableError,
    native_hook_artifact_facts_with_content_hashes,
)
from ..protection_events import record_protection_event
from .commands_support_runtime_resolution import _canonical_harness_name


def _runtime_artifact_command_action_floor(artifact: GuardArtifact) -> GuardAction | None:
    if "command_action_floor" not in artifact.metadata:
        return None
    return normalize_guard_action(artifact.metadata.get("command_action_floor"), unknown_action="block")


def artifact_fact_risk_classes(facts: Mapping[str, object]) -> list[str]:
    """The risk classes the resident read off one artifact."""

    classes = facts.get("risk_classes")
    if not isinstance(classes, list) or not all(isinstance(item, str) for item in classes):
        raise HookArtifactFactsUnavailableError
    return cast("list[str]", classes)


def artifact_fact_skip_native_floor(facts: Mapping[str, object]) -> bool:
    """Whether the resident says the native command floor is skipped.

    A missing or non-boolean answer is no answer: the hook fails closed rather
    than guessing whether the floor applies.
    """

    skipped = facts.get("skip_native_floor")
    if not isinstance(skipped, bool):
        raise HookArtifactFactsUnavailableError
    return skipped


def _typed_text(value: object) -> str | None:
    # A non-string setting normalizes to the unknown action natively, as it did here.
    return value if value is None or isinstance(value, str) else ""


def runtime_policy_config_facts(config: GuardConfig, harness: str) -> dict[str, object]:
    canonical_harness = _canonical_harness_name(harness)
    return {
        "default_action": config.default_action,
        "risk_actions": dict(config.risk_actions or {}),
        "harness_risk_actions": {name: dict(actions) for name, actions in (config.harness_risk_actions or {}).items()},
        "security_level": config.security_level,
        "protection_posture": config.protection_posture,
        "protection_posture_explicit": bool(config.protection_posture_explicit),
        "managed_locks_level": "security_level" in config.managed_locked_settings,
        "harness": canonical_harness,
        "harness_posture_override": harness_posture_override(config, canonical_harness),
    }


def runtime_policy_artifact_facts(
    config: GuardConfig,
    artifact: GuardArtifact,
    harness: str,
    *,
    guard_home: Path | None = None,
) -> dict[str, object]:
    """Return the resident's facts for ``artifact``."""

    return runtime_policy_artifact_facts_batch(config, ((artifact, harness),), guard_home=guard_home)[0]


def artifact_content_hash_fields(artifact: GuardArtifact) -> dict[str, object]:
    """The artifact's own fields, unredacted, for the resident to digest.

    The digest covers the artifact as ``GuardArtifact.to_dict`` renders it and
    then restores the raw metadata over the redacted copy, so what travels has
    to be the raw fields: a copy redacted on this side would hash differently
    and miss every approval the user has already saved.
    """

    return {
        "artifact_id": artifact.artifact_id,
        "name": artifact.name,
        "harness": artifact.harness,
        "artifact_type": artifact.artifact_type,
        "source_scope": artifact.source_scope,
        "config_path": artifact.config_path,
        "command": artifact.command,
        "args": list(artifact.args),
        "url": artifact.url,
        "transport": artifact.transport,
        "publisher": artifact.publisher,
        "metadata": dict(artifact.metadata),
    }


def runtime_policy_artifact_facts_batch(
    config: GuardConfig,
    artifacts: Sequence[tuple[GuardArtifact, str]],
    *,
    guard_home: Path | None = None,
) -> list[dict[str, object]]:
    """Return the resident's facts for each ``(artifact, harness)`` pair."""

    facts, _ = runtime_policy_artifact_facts_with_content_hashes(
        config,
        [(artifact, harness, None) for artifact, harness in artifacts],
        guard_home=guard_home,
    )
    return facts


def runtime_policy_artifact_facts_with_content_hashes(
    config: GuardConfig,
    artifacts: Sequence[tuple[GuardArtifact, str, Mapping[str, object] | None]],
    *,
    guard_home: Path | None = None,
) -> tuple[list[dict[str, object]], list[str | None]]:
    """Return the facts, and the content hash of each artifact that asks for one.

    Only the configured override is still read here: it is a settings lookup
    for this artifact, publisher and harness, not a reading of the artifact.
    Everything the verdict turns on comes from the resident, so an unavailable
    one raises instead of letting this side describe the artifact.

    One evaluation's artifacts are asked for together, so reading facts costs
    the hook a single resident round trip however many artifacts it holds. The
    third element of a triple is the fields to digest, from
    ``artifact_content_hash_fields``; a caller reads them before the run's
    posture is stamped onto the artifact the facts are read from.
    """

    return native_hook_artifact_facts_with_content_hashes(
        [_facts_entry(config, artifact, harness, to_hash) for artifact, harness, to_hash in artifacts],
        guard_home=guard_home if guard_home is not None else config.guard_home,
    )


def _facts_entry(
    config: GuardConfig,
    artifact: GuardArtifact,
    harness: str,
    to_hash: Mapping[str, object] | None,
) -> dict[str, object]:
    entry: dict[str, object] = {
        "artifact_type": artifact.artifact_type,
        "metadata": artifact.metadata,
        "configured_override": _typed_text(
            config.resolve_action_override(_canonical_harness_name(harness), artifact.artifact_id, artifact.publisher)
        ),
    }
    if to_hash is not None:
        entry["content_hash_artifact"] = to_hash
    return entry


def record_policy_auto_stops(config: GuardConfig, events: object) -> None:
    for event in cast("list[dict[str, object]]", events):
        record_protection_event(config.guard_home, "guard.protection.auto_stop", event)


def _runtime_artifact_policy_action(
    config: GuardConfig,
    artifact: GuardArtifact,
    harness: str,
    *,
    guard_home: Path | None = None,
) -> GuardAction:
    answer = native_hook_compose(
        "config_action",
        {
            "policy_config": runtime_policy_config_facts(config, harness),
            "artifact": runtime_policy_artifact_facts(config, artifact, harness, guard_home=guard_home),
        },
        guard_home=guard_home,
    )
    record_policy_auto_stops(config, answer["auto_stop_events"])
    return cast(GuardAction, answer["action"])
