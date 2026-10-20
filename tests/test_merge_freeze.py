"""The merge freeze blocks every pull request except the documented exemptions, and fails closed."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from scripts.check_privileged_workflows import validate_privileged_workflows
from scripts.ci import merge_freeze as freeze

ROOT = Path(__file__).resolve().parents[1]
REPO = "hashgraph-online/hol-guard"
RELEASE_BRANCH = "release-please--branches--main--components--hol-guard"


def pull(number: int = 7, ref: str = "feature", repo: str | None = REPO, sha: str = "a" * 40) -> freeze.Pull:
    return freeze.Pull(number=number, head_sha=sha, head_ref=ref, head_repo=repo)


@pytest.mark.parametrize("raw", [None, "", "  ", "false", "False", " FALSE "])
def test_unset_empty_or_false_never_blocks(raw: str | None) -> None:
    assert not freeze.decide(raw, None, pull(), REPO).blocked


@pytest.mark.parametrize("raw", ["true", "True", " true\n"])
def test_true_blocks_an_ordinary_pull_request(raw: str) -> None:
    verdict = freeze.decide(raw, None, pull(), REPO)
    assert verdict.blocked
    assert verdict.reason.startswith("Merge freeze active")


@pytest.mark.parametrize("raw", ["1", "yes", "on", "tru", "true false", "null", "enabled"])
def test_any_other_value_fails_closed_with_a_clear_message(raw: str) -> None:
    verdict = freeze.decide(raw, None, pull(), REPO)
    assert verdict.blocked
    assert "must be exactly true or false" in verdict.reason


def test_invalid_value_gets_no_exemptions() -> None:
    release = pull(ref=RELEASE_BRANCH)
    assert freeze.decide("maybe", "7", release, REPO).blocked
    assert freeze.decide("maybe", "7", pull(number=7), REPO).blocked


def test_release_please_branch_in_this_repository_is_exempt() -> None:
    assert not freeze.decide("true", None, pull(ref=RELEASE_BRANCH), REPO).blocked


@pytest.mark.parametrize(
    "candidate",
    [
        pull(ref=RELEASE_BRANCH, repo="someone/hol-guard"),
        pull(ref=RELEASE_BRANCH, repo=None),
        pull(ref="release-please-fake"),
        pull(ref="feature/release-please--branches--main"),
    ],
)
def test_release_exemption_needs_a_same_repository_release_please_branch(candidate: freeze.Pull) -> None:
    assert freeze.decide("true", None, candidate, REPO).blocked


@pytest.mark.parametrize("allow", ["7", "#7", "1, 7 ,9", "1,7\n9"])
def test_allowlist_exempts_listed_numbers_only(allow: str) -> None:
    assert not freeze.decide("true", allow, pull(number=7), REPO).blocked
    assert freeze.decide("true", allow, pull(number=8), REPO).blocked


@pytest.mark.parametrize("allow", ["7,x", "0", "-3", "7.5", "7;8", "seven"])
def test_malformed_allowlist_is_ignored_wholesale_and_reported(allow: str) -> None:
    verdict = freeze.decide("true", allow, pull(number=7), REPO)
    assert verdict.blocked
    assert freeze.ALLOW_VARIABLE in verdict.reason


def test_allowlist_is_not_consulted_when_not_frozen() -> None:
    assert not freeze.decide("false", "garbage", pull(), REPO).blocked


def test_operator_text_cannot_inject_workflow_commands() -> None:
    verdict = freeze.decide("x\n::error::boom", None, pull(), REPO)
    assert "\n" not in verdict.reason


def gate_env(**overrides: str) -> dict[str, str]:
    env = {
        "EVENT_NAME": "pull_request",
        "REPOSITORY": REPO,
        "PR_NUMBER": "7",
        "HEAD_REF": "feature",
        "HEAD_REPO": REPO,
        "MERGE_FREEZE": "true",
    }
    env.update(overrides)
    return env


def test_gate_fails_with_the_freeze_message_and_the_lift_command(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    summary = tmp_path / "summary.md"
    assert freeze.run_gate(gate_env(), str(summary)) == 1
    text = summary.read_text(encoding="utf-8")
    assert "Merge freeze active" in text
    expected = (
        "gh variable set MERGE_FREEZE --body false --repo hashgraph-online/hol-guard "
        "&& gh workflow run merge-freeze.yml --repo hashgraph-online/hol-guard"
    )
    assert expected in text
    assert "::error title=Merge freeze active::" in capsys.readouterr().out


def test_gate_passes_when_not_frozen_or_exempt(tmp_path: Path) -> None:
    summary = tmp_path / "summary.md"
    assert freeze.run_gate(gate_env(MERGE_FREEZE=""), str(summary)) == 0
    assert freeze.run_gate(gate_env(HEAD_REF=RELEASE_BRANCH), str(summary)) == 0
    assert freeze.run_gate(gate_env(MERGE_FREEZE_ALLOW="7"), str(summary)) == 0
    assert not summary.exists()


@pytest.mark.parametrize("event", ["push", "schedule", "workflow_dispatch", "merge_group"])
def test_gate_only_applies_to_pull_requests(event: str) -> None:
    assert freeze.run_gate(gate_env(EVENT_NAME=event), None) == 0


def test_gate_fork_with_release_please_branch_is_blocked() -> None:
    assert freeze.run_gate(gate_env(HEAD_REF=RELEASE_BRANCH, HEAD_REPO="fork/hol-guard"), None) == 1


def test_gate_tolerates_a_missing_pull_request_number() -> None:
    assert freeze.run_gate(gate_env(PR_NUMBER=""), None) == 1


def load(name: str) -> dict[Any, Any]:
    return yaml.safe_load((ROOT / ".github/workflows" / name).read_text(encoding="utf-8"))


def test_aggregate_runs_the_gate_after_the_existing_evaluation() -> None:
    required = load("ci.yml")["jobs"]["required"]
    steps = required["steps"]
    assert required["name"] == freeze.AGGREGATE_CHECK
    assert steps[0]["name"] == "Evaluate planned required results"
    gate = next(step for step in steps if step.get("name") == freeze.GATE_STEP_NAME)
    assert steps.index(gate) > 0
    assert gate["run"] == "python3 scripts/ci/merge_freeze.py gate"
    assert gate["if"] == "${{ !cancelled() }}"
    assert gate["env"]["MERGE_FREEZE"] == "${{ vars.MERGE_FREEZE }}"
    assert gate["env"]["MERGE_FREEZE_ALLOW"] == "${{ vars.MERGE_FREEZE_ALLOW }}"
    assert gate["env"]["HEAD_REPO"] == "${{ github.event.pull_request.head.repo.full_name }}"
    checkout = steps[steps.index(gate) - 1]
    assert checkout["uses"].startswith("actions/checkout@")
    assert checkout["with"]["sparse-checkout"] == "scripts/ci/merge_freeze.py"
    assert checkout["with"]["persist-credentials"] is False


def test_the_aggregate_is_the_check_the_ruleset_names() -> None:
    """The gate rides on `hol-guard / required`; rulesets must keep requiring that name."""
    assert load("ci.yml")["jobs"]["required"]["name"] == "hol-guard / required"
    assert freeze.ACTIONS_APP_ID == 15368


def test_toggle_workflow_is_dispatch_only_and_least_privilege() -> None:
    workflow = load("merge-freeze.yml")
    assert set(workflow[True]) == {"workflow_dispatch"}
    assert workflow["permissions"] == {}
    job = workflow["jobs"]["reconcile"]
    assert job["if"] == "github.ref == 'refs/heads/main'"
    assert job["permissions"] == {
        "actions": "write",
        "checks": "write",
        "contents": "read",
        "pull-requests": "read",
    }
    assert workflow["concurrency"]["cancel-in-progress"] is False


def test_toggle_workflow_never_interpolates_expressions_into_shell() -> None:
    for step in load("merge-freeze.yml")["jobs"]["reconcile"]["steps"]:
        assert "${{" not in step.get("run", "")


def test_toggle_workflow_passes_the_privileged_workflow_policy() -> None:
    violations = validate_privileged_workflows(ROOT)
    assert [v.render(root=ROOT) for v in violations if v.workflow.name == "merge-freeze.yml"] == []


def test_documented_commands_match_the_real_names() -> None:
    header = (ROOT / ".github/workflows/merge-freeze.yml").read_text(encoding="utf-8").split("\non:\n")[0]
    assert "gh variable set MERGE_FREEZE --body true" in header
    assert "gh variable set MERGE_FREEZE --body false" in header
    assert f"gh workflow run {freeze.TOGGLE_WORKFLOW}" in header
    assert (ROOT / ".github/workflows" / freeze.TOGGLE_WORKFLOW).is_file()
    assert re.search(r"MERGE_FREEZE_ALLOW --body", header)


class FakeApi:
    """GitHub REST stand-in. `latest` views mimic GitHub: the newest run for the name wins."""

    def __init__(self, pulls: list[dict[str, Any]]) -> None:
        self.pulls = pulls
        self.runs: dict[str, list[dict[str, Any]]] = {}
        self.jobs: dict[int, dict[str, Any]] = {}
        self.writes: list[tuple[str, str, Any]] = []
        self.tick = 0
        self.next_id = 900
        self.rerun_error: freeze.ApiError | None = None
        self.mask_latest = False

    def stamp(self) -> str:
        self.tick += 1
        return f"2026-10-20T10:00:{self.tick:02d}Z"

    def add_real(self, sha: str, conclusion: str | None, run_id: int = 100, gate_failed: bool = False) -> int:
        status = "completed" if conclusion else "in_progress"
        stamp = self.stamp()
        self.runs.setdefault(sha, []).append(
            {
                "id": run_id,
                "status": status,
                "conclusion": conclusion,
                "external_id": "",
                "started_at": stamp,
                "completed_at": stamp if conclusion else None,
            }
        )
        steps = [{"name": freeze.GATE_STEP_NAME, "conclusion": "failure" if gate_failed else "success"}]
        self.jobs[run_id] = {"steps": steps}
        return run_id

    def pages(self, path: str, key: str | None = None) -> list[dict[str, Any]]:
        if path.startswith("pulls"):
            return self.pulls
        sha = path.split("/")[1]
        runs = self.runs.get(sha, [])
        if "filter=latest" in path:
            pool = [r for r in runs if not r["external_id"]] if self.mask_latest else runs
            newest = freeze._newest(pool)
            return [newest] if newest else []
        return list(runs)

    def call(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        self.writes.append((method, path, body))
        if method == "GET":
            return self.jobs[int(path.rsplit("/", 1)[1])]
        if (method, path) == ("POST", "check-runs"):
            assert body is not None
            self.next_id += 1
            stamp = self.stamp()
            run = {
                "id": self.next_id,
                "status": body["status"],
                "conclusion": body["conclusion"],
                "external_id": body["external_id"],
                "started_at": stamp,
                "completed_at": stamp,
            }
            self.runs.setdefault(body["head_sha"], []).append(run)
            return run
        if method == "PATCH":
            run_id = int(path.rsplit("/", 1)[1])
            assert body is not None
            for runs in self.runs.values():
                for run in runs:
                    if run["id"] == run_id:
                        run.update(status=body["status"], conclusion=body["conclusion"])
            return None
        if method == "POST" and path.endswith("/rerun"):
            if self.rerun_error:
                raise self.rerun_error
            job_id = int(path.split("/")[2])
            for sha, runs in self.runs.items():
                if any(r["id"] == job_id for r in runs):
                    self.add_real(sha, "success", run_id=job_id + 1000)
            return None
        raise AssertionError((method, path))

    def mutations(self) -> list[tuple[str, str]]:
        return [(m, p) for m, p, _ in self.writes if m != "GET"]


def api_pull(number: int, sha: str, ref: str = "feature", repo: str | None = REPO) -> dict[str, Any]:
    head: dict[str, Any] = {"sha": sha, "ref": ref, "repo": None if repo is None else {"full_name": repo}}
    return {"number": number, "head": head}


SHA_A, SHA_B, SHA_C = "a" * 40, "b" * 40, "c" * 40


def run(api: FakeApi, freeze_raw: str | None, allow: str | None = None, *, dry_run: bool = False) -> freeze.Plan:
    return freeze.reconcile(api, REPO, freeze_raw, allow, dry_run=dry_run, log=lambda _line: None)  # type: ignore[arg-type]


def newest_state(api: FakeApi, sha: str) -> tuple[str | None, str | None]:
    newest = freeze._newest(api.runs[sha])
    assert newest is not None
    return newest["status"], newest["conclusion"]


def test_freezing_blocks_a_pull_request_whose_ci_already_finished_green() -> None:
    api = FakeApi([api_pull(1, SHA_A)])
    api.add_real(SHA_A, "success")
    plan = run(api, "true")
    assert [o.action for o in plan.outcomes] == ["blocked"]
    assert not plan.failed
    assert newest_state(api, SHA_A) == ("completed", "failure")
    _, _, body = next(w for w in api.writes if w[1] == "check-runs")
    assert body["name"] == "hol-guard / required"
    assert body["output"]["title"] == "Merge freeze active"
    assert "gh variable set MERGE_FREEZE --body false" in body["output"]["summary"]


def test_freezing_twice_is_idempotent() -> None:
    api = FakeApi([api_pull(1, SHA_A)])
    api.add_real(SHA_A, "success")
    run(api, "true")
    api.writes.clear()
    plan = run(api, "true")
    assert [o.action for o in plan.outcomes] == ["held"]
    assert api.mutations() == []


def test_a_rerun_that_went_green_during_the_freeze_is_blocked_again() -> None:
    api = FakeApi([api_pull(1, SHA_A)])
    api.add_real(SHA_A, "success")
    run(api, "true")
    api.add_real(SHA_A, "success", run_id=101)
    assert newest_state(api, SHA_A) == ("completed", "success")
    run(api, "true")
    assert newest_state(api, SHA_A) == ("completed", "failure")


def test_a_pull_request_with_no_ci_yet_is_held_too() -> None:
    api = FakeApi([api_pull(1, SHA_A)])
    assert [o.action for o in run(api, "true").outcomes] == ["blocked"]


def test_an_aggregate_that_already_fails_is_left_alone() -> None:
    api = FakeApi([api_pull(1, SHA_A)])
    api.add_real(SHA_A, "failure", gate_failed=True)
    assert [o.action for o in run(api, "true").outcomes] == ["held"]
    assert api.mutations() == []


def test_exempt_pull_requests_are_untouched_while_frozen() -> None:
    api = FakeApi(
        [
            api_pull(1, SHA_A, ref=RELEASE_BRANCH),
            api_pull(2, SHA_B, ref=RELEASE_BRANCH, repo="fork/hol-guard"),
            api_pull(3, SHA_C),
        ]
    )
    for sha in (SHA_A, SHA_B, SHA_C):
        api.add_real(sha, "success")
    plan = run(api, "true", "3")
    assert {o.number: o.action for o in plan.outcomes} == {1: "unchanged", 2: "blocked", 3: "unchanged"}


def test_unfreezing_reruns_the_real_aggregate_then_resolves_the_overlay() -> None:
    api = FakeApi([api_pull(1, SHA_A)])
    api.add_real(SHA_A, "success")
    run(api, "true")
    api.writes.clear()
    plan = run(api, "false")
    assert [o.action for o in plan.outcomes] == ["released"]
    methods = api.mutations()
    rerun = methods.index(("POST", "actions/jobs/100/rerun"))
    patch = next(i for i, (m, _) in enumerate(methods) if m == "PATCH")
    assert rerun < patch
    assert newest_state(api, SHA_A) == ("completed", "success")
    assert all(r["conclusion"] == "success" for r in api.runs[SHA_A])


def test_unfreezing_reruns_a_gate_failure_that_has_no_overlay() -> None:
    api = FakeApi([api_pull(1, SHA_A)])
    api.add_real(SHA_A, "failure", gate_failed=True)
    plan = run(api, "false")
    assert [o.action for o in plan.outcomes] == ["released"]
    assert ("POST", "actions/jobs/100/rerun") in api.mutations()
    assert newest_state(api, SHA_A) == ("completed", "success")


def test_unfreezing_leaves_a_genuine_ci_failure_alone() -> None:
    api = FakeApi([api_pull(1, SHA_A)])
    api.add_real(SHA_A, "failure", gate_failed=False)
    plan = run(api, "false")
    assert [o.action for o in plan.outcomes] == ["unchanged"]
    assert api.mutations() == []


def test_a_rerun_failure_keeps_the_block_and_fails_the_dispatch() -> None:
    api = FakeApi([api_pull(1, SHA_A)])
    api.add_real(SHA_A, "success")
    run(api, "true")
    api.rerun_error = freeze.ApiError(403, "run is still in progress")
    plan = run(api, "false")
    assert plan.failed
    assert plan.outcomes[0].action == "release failed"
    assert newest_state(api, SHA_A) == ("completed", "failure")
    assert not any(m == "PATCH" for m, _ in api.mutations())


def test_unfreezing_while_ci_is_in_flight_just_resolves_the_overlay() -> None:
    api = FakeApi([api_pull(1, SHA_A)])
    api.add_real(SHA_A, "success")
    run(api, "true")
    api.add_real(SHA_A, None, run_id=101)
    api.writes.clear()
    plan = run(api, "false")
    assert [o.action for o in plan.outcomes] == ["released"]
    assert not any(p.endswith("/rerun") for _, p in api.mutations())


def test_unfreezing_with_no_real_aggregate_resolves_the_overlay_only() -> None:
    api = FakeApi([api_pull(1, SHA_A)])
    run(api, "true")
    assert [o.action for o in run(api, "false").outcomes] == ["released"]
    assert newest_state(api, SHA_A) == ("completed", "success")


def test_an_invalid_value_blocks_everything_including_release_please() -> None:
    api = FakeApi([api_pull(1, SHA_A, ref=RELEASE_BRANCH), api_pull(2, SHA_B)])
    api.add_real(SHA_A, "success")
    api.add_real(SHA_B, "success")
    plan = run(api, "maybe")
    assert [o.action for o in plan.outcomes] == ["blocked", "blocked"]


def test_an_ineffective_overlay_fails_the_dispatch_loudly() -> None:
    api = FakeApi([api_pull(1, SHA_A)])
    api.add_real(SHA_A, "success")
    api.mask_latest = True
    plan = run(api, "true")
    assert plan.failed
    assert "still passes" in plan.outcomes[0].detail


def test_dry_run_writes_nothing() -> None:
    api = FakeApi([api_pull(1, SHA_A), api_pull(2, SHA_B)])
    api.add_real(SHA_A, "success")
    api.add_real(SHA_B, "failure", run_id=200, gate_failed=True)
    assert [o.action for o in run(api, "true", dry_run=True).outcomes] == ["would block", "held"]
    assert api.mutations() == []
    assert [o.action for o in run(api, "false", dry_run=True).outcomes] == ["unchanged", "would release"]
    assert api.mutations() == []


def test_api_errors_are_reported_per_pull_request_without_stopping() -> None:
    api = FakeApi([api_pull(1, SHA_A), api_pull(2, SHA_B)])
    api.add_real(SHA_A, "success")
    api.add_real(SHA_B, "success", run_id=200)
    original = api.call

    def flaky(method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        if method == "POST" and body and body.get("head_sha") == SHA_A:
            raise freeze.ApiError(500, "boom")
        return original(method, path, body)

    api.call = flaky  # type: ignore[method-assign]
    plan = run(api, "true")
    assert [o.action for o in plan.outcomes] == ["error", "blocked"]
    assert plan.failed


def test_report_names_the_state_and_the_lift_command() -> None:
    api = FakeApi([api_pull(1, SHA_A)])
    report = freeze.render_report(run(api, "true"), "true", REPO, dry_run=False)
    assert "Merge freeze: active" in report
    assert freeze.lift_command(REPO) in report
    assert "not active" in freeze.render_report(freeze.Plan(), None, REPO, dry_run=True)
