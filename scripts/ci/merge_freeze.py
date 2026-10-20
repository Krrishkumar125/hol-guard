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
  own name while frozen. When the freeze lifts it re-runs the real aggregate
  and resolves its own check run.
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
# Release Please branches are produced by the release automation; hotfix
# releases must still ship during a freeze.
RELEASE_BRANCH_PREFIX = "release-please--branches--"
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
    head_ref: str
    head_repo: str | None


@dataclass(frozen=True)
class Verdict:
    blocked: bool
    reason: str


def decide(freeze_raw: str | None, allow_raw: str | None, pull: Pull, repository: str) -> Verdict:
    """Decide whether the freeze blocks one pull request."""
    freeze = parse_freeze(freeze_raw)
    if freeze.error is not None:
        return Verdict(True, freeze.error)
    if not freeze.active:
        return Verdict(False, "Merge freeze is not active.")
    # A fork can pick any branch name, so the exemption needs a same-repository head.
    same_repository = pull.head_repo is not None and pull.head_repo.casefold() == repository.casefold()
    if same_repository and pull.head_ref.startswith(RELEASE_BRANCH_PREFIX):
        return Verdict(False, "Release Please pull request; exempt from the merge freeze.")
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
    pull = Pull(
        number=int(number) if number.isdecimal() else 0,
        head_sha="",
        head_ref=env.get("HEAD_REF", ""),
        head_repo=env.get("HEAD_REPO") or None,
    )
    verdict = decide(env.get(FREEZE_VARIABLE), env.get(ALLOW_VARIABLE), pull, repository)
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


def _gate_failed(api: Api, job_id: int) -> bool:
    job = api.call("GET", f"actions/jobs/{job_id}")
    return any(
        step.get("name") == GATE_STEP_NAME and step.get("conclusion") == "failure" for step in job.get("steps") or []
    )


def _hold(api: Api, pull: Pull, reason: str, repository: str, dry_run: bool) -> Outcome:
    runs = api.pages(_aggregate_path(pull.head_sha, "all"), key="check_runs")
    newest = _newest(runs)
    if newest is not None and _finished_failing(newest):
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
    return Outcome(pull.number, "blocked", "posted a failing aggregate check run")


def _release(api: Api, pull: Pull, dry_run: bool) -> Outcome:
    runs = api.pages(_aggregate_path(pull.head_sha, "all"), key="check_runs")
    overlays = [run for run in runs if _is_overlay(run) and run.get("conclusion") == "failure"]
    real = _newest([run for run in runs if not _is_overlay(run)])
    needs_rerun = False
    if real is not None and real.get("status") == "completed":
        # The aggregate failed only because of the freeze when its gate step did.
        needs_rerun = bool(overlays) or (_finished_failing(real) and _gate_failed(api, real["id"]))
    if not overlays and not needs_rerun:
        return Outcome(pull.number, "unchanged", "")
    if dry_run:
        return Outcome(pull.number, "would release", "re-run the aggregate" if needs_rerun else "resolve the overlay")
    if needs_rerun and real is not None:
        try:
            api.call("POST", f"actions/jobs/{real['id']}/rerun")
        except ApiError as exc:
            # Keep the block: a pull request must never go green on a stale result.
            return Outcome(pull.number, "release failed", f"could not re-run the aggregate ({exc})", error=True)
    for run in overlays:
        api.call(
            "PATCH",
            f"check-runs/{run['id']}",
            {
                "status": "completed",
                "conclusion": "success",
                "output": {"title": "Merge freeze lifted", "summary": "The merge freeze is no longer active."},
            },
        )
    return Outcome(pull.number, "released", "re-ran the aggregate" if needs_rerun else "resolved the overlay")


def reconcile(
    api: Api,
    repository: str,
    freeze_raw: str | None,
    allow_raw: str | None,
    *,
    dry_run: bool = False,
    log: Callable[[str], None] = print,
) -> Plan:
    """Bring every open pull request's aggregate result in line with the flag."""
    plan = Plan()
    for item in api.pages("pulls?state=open"):
        head = item["head"]
        pull = Pull(item["number"], head["sha"], head["ref"], (head.get("repo") or {}).get("full_name"))
        verdict = decide(freeze_raw, allow_raw, pull, repository)
        try:
            outcome = (
                _hold(api, pull, verdict.reason, repository, dry_run)
                if verdict.blocked
                else _release(api, pull, dry_run)
            )
        except ApiError as exc:
            outcome = Outcome(pull.number, "error", str(exc), error=True)
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
