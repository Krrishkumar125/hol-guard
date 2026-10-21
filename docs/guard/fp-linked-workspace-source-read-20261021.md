# Reads in a workspace reached through a link are hard-blocked at PostToolUse

Status: pre-existing in v3.49.0, fixed here.

## What happens

An Oh My Pi `read` of an ordinary file is allowed at PreToolUse and then denied
at PostToolUse with reason code `no_output_to_review`. The model receives:

> HOL Guard blocked this tool output before Oh My Pi could use it. HOL Guard
> recorded this as no_output_to_review. Do not retry the same tool call
> automatically; wait for the user to approve or change the task.

The file in the observed case is an 87-byte README with no sensitive content.

## Cause

`classify_source_path` in `rust/crates/guard-secure-fs/src/source_path.rs`
refused a link before it compared the resolved target with the workspace:

```rust
if contains_symlink_component(&lexical) {
    return SourcePathDecision::deny("symlink_in_path");
}
let Ok(candidate) = fs::canonicalize(&lexical) else { ... };
let inside_workspace = candidate.starts_with(&workspace);
```

Every failure exit in `review_source` returns `inconclusive_source()`, which is
a deny carrying `no_output_to_review`, so the refusal reached the model as a
hard block on the output.

A linked ancestor is ordinary on a developer host. macOS resolves `/tmp` to
`/private/tmp`, so any absolute path spelled through `/tmp` carries a link
component. The same holds for a linked home directory, `/var`, `/Volumes`, and
any project directory a user reaches through a link. In such a workspace every
file read was blocked, however benign the file.

## Why it looked like a relative-path problem

An earlier write-up concluded that relative candidates were the trigger. They
are not. In the recorded Gauntlet run the model sometimes copied the absolute
`/private/tmp/...` spelling out of its prompt and sometimes shortened the path,
which made Oh My Pi join it onto its own `/tmp/...` working directory. Only the
second form carries a link component, so the outcome tracked the spelling, not
the relative/absolute distinction. Reproducing both forms against the native
runtime confirms it: a relative candidate with a matching working directory is
allowed, and an absolute `/tmp` candidate is denied regardless of the working
directory's spelling.

## The fix

Canonicalize first and refuse a traversed link only when the resolved target
leaves the canonicalized workspace. The containment comparison on the canonical
path is the authoritative escape check, and it is what the read then opens:
`read_bounded` is given `resolved_path`, the canonical leaf, so relaxing the
order introduces no time-of-check gap.

A link that stays inside the workspace keeps its screen. The in-workspace
branch already derives its parts from `candidate.strip_prefix(&workspace)`, so
a link planted in the tree that points at `.env`, `.git` or any other sensitive
family is refused on the resolved path.

`review_source` also reported an exhausted scan budget as `no_output_to_review`
while `review_inline` reported `scanner_budget_exhausted` for the same
condition. Both now name the real exit, so a load problem is no longer
indistinguishable from a classifier problem.

## Release-gate impact

In eight runs of the Gauntlet case `omp-native-read-feature-directory` the
outcome tracked the spelling the model chose: two false positives in eight,
roughly 25%. `ci.gauntlet qualify` retries a fresh full run only for
not-exercised, inference-error and harness-error results, so a false positive
reports `qualified: false` with no retry. A release gate run could go red on
this with nothing wrong in the release.

## Regression coverage

- `tests/fixtures/benign_false_positive_gate.json`:
  `omp-read-source-through-linked-workspace` replays an Oh My Pi PostToolUse
  read, with the source-file proof the extension attaches, in a workspace whose
  path crosses a link. The gate fixture grows a `linked_worktree` working
  directory for it; every other working directory it offers is resolved, which
  is why no existing case could express this.
- `rust/crates/guard-secure-fs/tests/decision_io.rs`:
  `a_workspace_spelled_through_a_linked_ancestor_still_classifies_its_own_sources`
  covers the classifier directly, including the planted link into `.env` and a
  link that leaves the workspace. Creating the links needs POSIX symlink
  permissions, so the test is `cfg(unix)`; the fix itself is platform-neutral.
