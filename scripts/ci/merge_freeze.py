#!/usr/bin/env python3
"""Merge freeze: one policy for the CI aggregate gate and the toggle workflow.

The freeze is a repository Actions variable (``MERGE_FREEZE``). A pull request
cannot merge while it is ``true`` because ``hol-guard / required`` fails. Two
paths keep that result honest:

* ``gate`` runs inside the ``hol-guard / required`` job, so every new or
  re-run CI result reflects the flag at the moment it is computed.
* ``reconcile`` runs from ``merge-freeze.yml`` after the flag is toggled and
  re-evaluates pull requests whose CI already finished. A finished check cannot
  be changed by flipping a variable, and a re-run reuses the workflow file the
  run started with, so reconcile posts a failing check run with the aggregate's
  own name while frozen. When the freeze lifts it re-runs the real aggregate,
  whose newer result replaces that check run. The failing check run is never
  turned green by hand, so a pull request only passes on a real CI result.

The gate runs the copy of this file from the pull request's base revision, so a
pull request cannot change the policy that decides whether it may merge.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

FREEZE_VARIABLE = "MERGE_FREEZE"
ALLOW_VARIABLE = "MERGE_FREEZE_ALLOW"
TOGGLE_WORKFLOW = "merge-freeze.yml"
# The name and app of the required check the rulesets enforce.
AGGREGATE_CHECK = "hol-guard / required"
ACTIONS_APP_ID = 15368
GATE_STEP_NAME = "Merge freeze gate"
OVERLAY_EXTERNAL_ID = "merge-freeze/v1"
PASSING_CONCLUSIONS = frozenset({"success", "neutral", "skipped"})
MAX_PAGES = 30


def clean(text: str, limit: int = 80) -> str:
    """Make operator-supplied text safe to echo into logs and annotations."""
    printable = "".join(ch if ch.isprintable() else "?" for ch in text)
    return printable if len(printable) <= limit else printable[: limit - 3] + "..."


@dataclass(frozen=True)
class Freeze:
    """The parsed ``MERGE_FREEZE`` flag. An invalid value is active and fails closed."""

    active: bool
    error: str | None = None


def parse_freeze(raw: str | None) -> Freeze:
    value = (raw or "").strip()
    if not value:
        return Freeze(False)
    lowered = value.lower()
    if lowered == "true":
        return Freeze(True)
    if lowered == "false":
        return Freeze(False)
    return Freeze(True, f"{FREEZE_VARIABLE} is {clean(value)!r}; it must be exactly true or false, or be unset")


def parse_allowlist(raw: str | None) -> tuple[frozenset[int], str | None]:
    """Parse ``MERGE_FREEZE_ALLOW``. One bad entry discards the list (fail closed)."""
    numbers: set[int] = set()
    for token in re.split(r"[,\s]+", (raw or "").strip()):
        if not token:
            continue
        match = re.fullmatch(r"#?([1-9][0-9]{0,8})", token)
        if match is None:
            return frozenset(), f"{ALLOW_VARIABLE} entry {clean(token, 24)!r} is not a pull request number; ignoring it"
        numbers.add(int(match.group(1)))
    return frozenset(numbers), None


@dataclass(frozen=True)
class Pull:
    number: int
    head_sha: str


@dataclass(frozen=True)
class Verdict:
    blocked: bool
    reason: str


def decide(freeze_raw: str | None, allow_raw: str | None, pull: Pull) -> Verdict:
    """Decide whether the freeze blocks one pull request.

    The only exemption is an admin-set ``MERGE_FREEZE_ALLOW`` entry. Anything a
    pull request author controls, such as a branch name, could be chosen to
    claim an exemption, so none of it is consulted.
    """
    freeze = parse_freeze(freeze_raw)
    if freeze.error is not None:
        return Verdict(True, freeze.error)
    if not freeze.active:
        return Verdict(False, "Merge freeze is not active.")
    allowed, allow_error = parse_allowlist(allow_raw)
    if pull.number in allowed:
        return Verdict(False, f"Pull request #{pull.number} is in {ALLOW_VARIABLE}; exempt from the merge freeze.")
    reason = "Merge freeze active."
    if allow_error is not None:
        reason += f" {allow_error}."
    return Verdict(True, reason)


def lift_command(repository: str) -> str:
    return (
        f"gh variable set {FREEZE_VARIABLE} --body false --repo {repository} "
        f"&& gh workflow run {TOGGLE_WORKFLOW} --repo {repository}"
    )


def freeze_summary(reason: str, repository: str) -> str:
    return (
        "## Merge freeze active\n\n"
        f"{reason}\n\n"
        "This pull request cannot merge until the freeze is lifted. A repository admin lifts it with:\n\n"
        f"    {lift_command(repository)}\n\n"
        f"Deleting the variable (`gh variable delete {FREEZE_VARIABLE} --repo {repository}`) also lifts it. "
        f"To let specific pull requests through, set {ALLOW_VARIABLE} to a comma-separated list of numbers.\n"
    )


def run_gate(env: Mapping[str, str], summary_path: str | None) -> int:
    """Fail the aggregate for a pull request while the freeze is active."""
    if env.get("EVENT_NAME") != "pull_request":
        print("Not a pull request run; the merge freeze does not apply.")
        return 0
    repository = env.get("REPOSITORY", "")
    number = env.get("PR_NUMBER", "")
    pull = Pull(number=int(number) if number.isdecimal() else 0, head_sha="")
    verdict = decide(env.get(FREEZE_VARIABLE), env.get(ALLOW_VARIABLE), pull)
    print(verdict.reason)
    if not verdict.blocked:
        return 0
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as handle:
            handle.write(freeze_summary(verdict.reason, repository))
    print(f"::error title=Merge freeze active::{verdict.reason} Lift it with: {lift_command(repository)}")
    return 1


class ApiError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"HTTP {status}: {message}")
        self.status = status


class Api:
    """Minimal GitHub REST client for one repository."""

    def __init__(self, repository: str, token: str, base: str = "https://api.github.com") -> None:
        self.root = f"{base}/repos/{repository}"
        self.token = token

    def call(self, method: str, path: str, body: Mapping[str, Any] | None = None) -> Any:
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(
            f"{self.root}/{path}",
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = response.read()
        except urllib.error.HTTPError as exc:
            raise ApiError(exc.code, exc.read().decode(errors="replace")[:200]) from exc
        return json.loads(payload) if payload else None

    def pages(self, path: str, key: str | None = None) -> list[dict[str, Any]]:
        joiner = "&" if "?" in path else "?"
        items: list[dict[str, Any]] = []
        for page in range(1, MAX_PAGES + 1):
            batch = self.call("GET", f"{path}{joiner}per_page=100&page={page}")
            batch = batch[key] if key else batch
            items.extend(batch)
            if len(batch) < 100:
                return items
        raise ApiError(0, f"more than {MAX_PAGES} pages for {path.split('?')[0]}")


@dataclass
class Outcome:
    number: int
    action: str
    detail: str = ""
    error: bool = False


@dataclass
class Plan:
    outcomes: list[Outcome] = field(default_factory=list)

    @property
    def failed(self) -> bool:
        return any(outcome.error for outcome in self.outcomes)


def _aggregate_path(sha: str, view: str) -> str:
    name = urllib.parse.quote(AGGREGATE_CHECK, safe="")
    return f"commits/{sha}/check-runs?check_name={name}&filter={view}&app_id={ACTIONS_APP_ID}"


def _is_overlay(run: Mapping[str, Any]) -> bool:
    return run.get("external_id") == OVERLAY_EXTERNAL_ID


def _passes(run: Mapping[str, Any]) -> bool:
    return run.get("status") == "completed" and run.get("conclusion") in PASSING_CONCLUSIONS


def _finished_failing(run: Mapping[str, Any]) -> bool:
    return run.get("status") == "completed" and run.get("conclusion") not in PASSING_CONCLUSIONS


def _newest(runs: list[dict[str, Any]]) -> dict[str, Any] | None:
    return max(runs, key=lambda run: (run.get("completed_at") or run.get("started_at") or "", run["id"]), default=None)


@dataclass(frozen=True)
class Aggregate:
    """The aggregate check runs on one head commit, split the way GitHub ranks them."""

    # The newest finished run, which is the result GitHub's required check reads.
    result: dict[str, Any] | None
    # The newest finished run from CI itself, never a freeze check run.
    real: dict[str, Any] | None
    # CI runs still going. Each one finishes later than any check run posted now,
    # so its result will replace whatever the required check shows today.
    in_flight: bool


def _aggregate(api: Api, sha: str) -> Aggregate:
    runs = api.pages(_aggregate_path(sha, "all"), key="check_runs")
    finished = [run for run in runs if run.get("status") == "completed"]
    return Aggregate(
        result=_newest(finished),
        real=_newest([run for run in finished if not _is_overlay(run)]),
        in_flight=any(run.get("status") != "completed" and not _is_overlay(run) for run in runs),
    )


def _gate_failed(api: Api, job_id: int) -> bool:
    job = api.call("GET", f"actions/jobs/{job_id}")
    return any(
        step.get("name") == GATE_STEP_NAME and step.get("conclusion") == "failure" for step in job.get("steps") or []
    )


IN_FLIGHT_WHILE_FROZEN = (
    "CI is still running and could finish green after the freeze took effect; re-run this workflow once it finishes"
)


def _hold(api: Api, pull: Pull, reason: str, repository: str, dry_run: bool) -> Outcome:
    aggregate = _aggregate(api, pull.head_sha)
    if aggregate.result is not None and _finished_failing(aggregate.result):
        if aggregate.in_flight:
            return Outcome(pull.number, "held", IN_FLIGHT_WHILE_FROZEN, error=True)
        return Outcome(pull.number, "held", "newest aggregate result already fails")
    if dry_run:
        return Outcome(pull.number, "would block", "post a failing aggregate check run")
    api.call(
        "POST",
        "check-runs",
        {
            "name": AGGREGATE_CHECK,
            "head_sha": pull.head_sha,
            "status": "completed",
            "conclusion": "failure",
            "external_id": OVERLAY_EXTERNAL_ID,
            "output": {"title": "Merge freeze active", "summary": freeze_summary(reason, repository)},
        },
    )
    latest = api.pages(_aggregate_path(pull.head_sha, "latest"), key="check_runs")
    if not latest or any(_passes(run) for run in latest):
        return Outcome(pull.number, "blocked", "the latest aggregate check run still passes", error=True)
    if aggregate.in_flight:
        return Outcome(pull.number, "blocked", IN_FLIGHT_WHILE_FROZEN, error=True)
    return Outcome(pull.number, "blocked", "posted a failing aggregate check run")


def _release(api: Api, pull: Pull, dry_run: bool) -> Outcome:
    aggregate = _aggregate(api, pull.head_sha)
    result, real = aggregate.result, aggregate.real
    if result is None:
        return Outcome(pull.number, "unchanged", "")
    if _is_overlay(result):
        if not _finished_failing(result):
            return Outcome(pull.number, "unchanged", "")
        if aggregate.in_flight:
            # The running aggregate reads the lifted flag and its result replaces
            # the freeze check run. If it had already passed its gate while
            # frozen it fails there, and the next dispatch re-runs it.
            return Outcome(pull.number, "waiting", "CI is still running; its result replaces the freeze check run")
        if real is None:
            # A fork awaiting approval or a pull request whose CI never started
            # stays blocked until CI reports; nothing here may stand in for it.
            return Outcome(pull.number, "waiting", "no CI result yet; the freeze check run stays until CI reports")
    elif aggregate.in_flight or not (_finished_failing(result) and _gate_failed(api, result["id"])):
        # A genuine CI failure, a pass, or a run still going needs nothing here.
        return Outcome(pull.number, "unchanged", "")
    if real is None:
        return Outcome(pull.number, "unchanged", "")
    if dry_run:
        return Outcome(pull.number, "would release", "re-run the aggregate")
    try:
        api.call("POST", f"actions/jobs/{real['id']}/rerun")
    except ApiError as exc:
        # Keep the block: a pull request must never go green on a stale result.
        return Outcome(pull.number, "release failed", f"could not re-run the aggregate ({exc})", error=True)
    return Outcome(pull.number, "released", "re-ran the aggregate; its result replaces the freeze check run")


def reconcile(
    api: Api,
    repository: str,
    freeze_raw: str | None,
    allow_raw: str | None,
    *,
    dry_run: bool = False,
    log: Callable[[str], None] = print,
) -> Plan:
    """Bring every open pull request's aggregate result in line with the flag.

    Check runs belong to a commit, not a pull request, so pull requests that
    share a head commit share one decision: the commit stays blocked while any
    of them is blocked.
    """
    plan = Plan()
    pulls = [Pull(item["number"], item["head"]["sha"]) for item in api.pages("pulls?state=open")]
    blocking: dict[str, Verdict] = {}
    for pull in pulls:
        verdict = decide(freeze_raw, allow_raw, pull)
        if verdict.blocked:
            blocking.setdefault(pull.head_sha, verdict)
    decided: dict[str, Outcome] = {}
    for pull in pulls:
        first = decided.get(pull.head_sha)
        if first is not None:
            outcome = Outcome(pull.number, first.action, f"shares its head commit with #{first.number}", first.error)
        else:
            verdict = blocking.get(pull.head_sha)
            try:
                outcome = (
                    _hold(api, pull, verdict.reason, repository, dry_run)
                    if verdict is not None
                    else _release(api, pull, dry_run)
                )
            except ApiError as exc:
                outcome = Outcome(pull.number, "error", str(exc), error=True)
            decided[pull.head_sha] = outcome
        plan.outcomes.append(outcome)
        if outcome.action != "unchanged":
            log(f"#{outcome.number}: {outcome.action} {outcome.detail}".rstrip())
    return plan


def render_report(plan: Plan, freeze_raw: str | None, repository: str, dry_run: bool) -> str:
    freeze = parse_freeze(freeze_raw)
    state = freeze.error or ("active" if freeze.active else "not active")
    lines = [f"## Merge freeze: {state}" + (" (dry run)" if dry_run else ""), ""]
    counts: dict[str, int] = {}
    for outcome in plan.outcomes:
        counts[outcome.action] = counts.get(outcome.action, 0) + 1
    lines.append(f"Open pull requests evaluated: {len(plan.outcomes)}")
    lines.extend(f"- {action}: {count}" for action, count in sorted(counts.items()))
    problems = [outcome for outcome in plan.outcomes if outcome.error]
    if problems:
        lines += ["", "Needs attention (re-run this workflow to retry):"]
        lines.extend(f"- #{outcome.number}: {outcome.action} - {outcome.detail}" for outcome in problems)
    if freeze.active:
        lines += ["", f"Lift the freeze with: `{lift_command(repository)}`"]
    return "\n".join(lines) + "\n"


def run_reconcile(env: Mapping[str, str], summary_path: str | None, *, dry_run: bool) -> int:
    repository = env["REPOSITORY"]
    api = Api(repository, env["GITHUB_TOKEN"])
    freeze_raw, allow_raw = env.get(FREEZE_VARIABLE), env.get(ALLOW_VARIABLE)
    plan = reconcile(api, repository, freeze_raw, allow_raw, dry_run=dry_run)
    report = render_report(plan, freeze_raw, repository, dry_run)
    print(report)
    if summary_path:
        with Path(summary_path).open("a", encoding="utf-8") as handle:
            handle.write(report)
    return 1 if plan.failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("gate", help="fail while the freeze applies to this pull request")
    reconcile_parser = commands.add_parser("reconcile", help="re-evaluate every open pull request")
    reconcile_parser.add_argument("--dry-run", action="store_true", help="report without writing")
    args = parser.parse_args(argv)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if args.command == "gate":
        return run_gate(os.environ, summary)
    return run_reconcile(os.environ, summary, dry_run=args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
