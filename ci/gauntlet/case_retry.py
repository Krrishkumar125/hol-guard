"""Bounded re-execution of a case the model never properly exercised.

An attempt is a round of the whole catalog, so without this a single
uncooperative case costs a complete fresh round to retry — and the round that
follows is just as likely to lose a different case. Nine hand-driven rounds at
the 3.50.0 head produced 345 case executions, 336 of them passes, and never a
round in which every case complied at once.

The outcomes that earn a retry here are the three the attempt-level driver
already retries: ``not-exercised`` (the model declined or drifted),
``inference-error`` (the provider round died) and ``harness-error`` (a host
tool failed with no Guard deny behind it). None of them says Guard did
anything wrong. A ``false-positive`` or ``false-negative`` is never retried:
a product failure proved itself the first time, and retrying one is exactly
how a real defect becomes a pass. Neither is a case that interrupted ordinary
work, because an intermittent warning cannot be retried away — the same
judgement ``qualify._interrupted`` makes between attempts.

Every superseded attempt keeps its evidence. The published case file stays the
last attempt's, which is what the verifier reads, and the earlier ones move to
``superseded/`` beside the case directory so a pass that took three tries can
never read as a pass that took one.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from .fixtures import scenario_fixture_name

# A case that needs more than a few tries is not noisy, it is broken; the budget is
# there to absorb model refusals, not to grind a failing case into a pass.
MAX_CASE_RETRIES = 5

# The same three the driver retries between whole attempts; see the module docstring.
RETRYABLE_OUTCOMES = frozenset({"not-exercised", "inference-error", "harness-error"})


def case_fixture_name(scenario_id: str, attempt: int) -> str:
    """The fixture directory for one run of a case; a re-run gets its own.

    ``create_fixture`` refuses an existing directory, and a retry that inherited the
    previous run's disk state would not be a fresh exercise of the case. The suffix
    stays short because this directory is the parent of a Unix socket path, and macOS
    gives the whole path about a hundred bytes.
    """
    name = scenario_fixture_name(scenario_id)
    return name if attempt <= 1 else f"{name}r{attempt}"


def interrupted(assessment: dict[str, Any]) -> bool:
    """Ordinary work that raised any interruption event; protection denies are expected."""
    record = assessment.get("interruptions")
    return isinstance(record, dict) and record.get("benign") is True and bool(record.get("events"))


def retryable(assessment: dict[str, Any]) -> bool:
    """True when this outcome says the model or the host misbehaved, not Guard."""
    return assessment.get("outcome") in RETRYABLE_OUTCOMES and not interrupted(assessment)


class CaseRetries:
    """How many re-runs each case has spent, and where its superseded evidence went.

    ``limit`` is per case, not per run: a catalog that loses three different cases
    to three different refusals costs three re-runs, not one.
    """

    def __init__(self, limit: int, *, cases: Path, superseded: Path) -> None:
        if limit < 0:
            raise ValueError("--case-retries must not be negative")
        self.limit = limit
        self._cases = cases
        self._superseded = superseded
        self._spent: dict[str, int] = {}
        self._history: list[dict[str, Any]] = []

    def attempt(self, scenario_id: str) -> int:
        """The 1-based number of the run this case is about to make."""
        return self._spent.get(scenario_id, 0) + 1

    def should_retry(self, scenario_id: str, case: dict[str, Any]) -> bool:
        """Decide, and when the answer is yes, bank the superseded attempt before it is overwritten."""
        assessment = case.get("assessment") or {}
        if self.limit <= self._spent.get(scenario_id, 0) or not retryable(assessment):
            return False
        attempt = self.attempt(scenario_id)
        self._history.append(
            {
                "id": scenario_id,
                "attempt": attempt,
                "outcome": assessment.get("outcome"),
                "reason": assessment.get("reason"),
                "evidence": self._archive(scenario_id, attempt),
            }
        )
        self._spent[scenario_id] = attempt
        return True

    def _archive(self, scenario_id: str, attempt: int) -> str | None:
        """Move this attempt's published evidence aside; the next run writes the same name."""
        source = self._cases / f"{scenario_id}.json"
        if not source.is_file():
            return None
        self._superseded.mkdir(mode=0o700, parents=True, exist_ok=True)
        target = self._superseded / f"{scenario_id}.attempt-{attempt}.json"
        shutil.move(str(source), target)
        return target.name

    @property
    def history(self) -> list[dict[str, Any]]:
        """Every superseded attempt, oldest first; empty when no case was re-run."""
        return list(self._history)
