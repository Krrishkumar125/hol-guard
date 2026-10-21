"""Test-only entry point for the resident's GitHub CLI capability classifier.

The Rust command model owns every GitHub CLI classification
(``rust/crates/guard-command/src/github_command_capabilities.rs``). Production
code calls the resident through
``codex_plugin_scanner.guard.native_github_cli``; nothing in ``src/`` turns that
classification into a :class:`GitHubCommandAssessment` any more.

These helpers exist so the capability suites can keep asserting the assessment
shape without a production module whose only callers are tests. When the
resident cannot answer, the capability is ``unknown`` (the review floor), never
a Python re-derivation.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import cast

from codex_plugin_scanner.guard.native_github_cli import (
    NativeGitHubCliClassification,
    github_cli_classify_native,
)
from codex_plugin_scanner.guard.runtime.github_capability_contract import (
    GitHubCommandAssessment,
    GitHubCommandCapability,
    github_assessment,
)

_ASSESSMENT_CACHE_LIMIT = 512
_ASSESSMENT_CACHE: dict[tuple[str, ...], NativeGitHubCliClassification] = {}


def reset_github_capability_cache() -> None:
    """Drop every memoized classification so a test can re-observe the resident."""

    _ASSESSMENT_CACHE.clear()


def _classification(args: Sequence[str]) -> NativeGitHubCliClassification | None:
    """Return the native classification, memoizing only successful answers.

    The classification is a pure function of the arguments, and several cases
    classify the same command in one suite. Failures are never cached, so an
    unavailable resident still fails closed on every call.
    """

    key = tuple(args)
    cached = _ASSESSMENT_CACHE.get(key)
    if cached is not None:
        return cached
    native = github_cli_classify_native(key)
    if native is not None:
        if len(_ASSESSMENT_CACHE) >= _ASSESSMENT_CACHE_LIMIT:
            _ASSESSMENT_CACHE.clear()
        _ASSESSMENT_CACHE[key] = native
    return native


def github_cli_assessment(args: Sequence[str]) -> GitHubCommandAssessment:
    """Return the native assessment for GitHub CLI arguments (without ``gh``)."""

    native = _classification(args)
    if native is None:
        return github_assessment(
            "unknown",
            "github.native.unavailable",
            "The native GitHub command classifier is unavailable, so the command is unverified.",
        )
    try:
        return GitHubCommandAssessment(
            # The contract's __post_init__ rejects any value outside the capability set.
            capability=cast(GitHubCommandCapability, native.capability),
            reason_code=native.reason_code,
            detail=native.detail,
            capabilities=tuple(cast(GitHubCommandCapability, item) for item in native.capabilities),
        )
    except ValueError:
        return github_assessment(
            "unknown",
            "github.native.malformed",
            "The native GitHub command classifier returned an unrecognized capability.",
        )


__all__ = ["github_cli_assessment", "reset_github_capability_cache"]
