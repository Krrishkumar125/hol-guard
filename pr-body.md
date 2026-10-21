## What this does

HOL Guard's Review Inbox now links **every** command extension to its reviews end to end, not just Docker, Git, and GitHub.

Before this change, enabling a permission in Extensions only auto-settled uncertain reviews for Git and one Docker rule. Every other extension — Kubernetes, the `gh` CLI's unverified commands, file upload, destructive shell, cloud tooling, and the rest of the `command.*` catalog — kept sending the same commands back to the Inbox forever, and the Inbox never showed the "enable this permission" hint or the extension's icon for them. The plumbing is now generic at every layer:

- **Enforcement (Rust, `guard-command`)**: a new per-segment settle proof (`command_compatibility/settles.rs`) decides when an explicitly enabled permission may settle an uncertain rule observation, whichever extension owns the rule. Git and Docker keep their existing narrower proofs; kubectl/`oc`, the network tools, and `gh` get bounded proofs; everything else settles only with an inert environment and no interpreter in the segment.
- **Safety bounds stay put**: a segment never settles when its shape leaves what the text proves — a steering environment prefix, an interpreter or nested executor, an option that changes which authority answers (Docker remote context, `kubectl --context`/`--kubeconfig`/`--server`, credentials, ssh/rsync proxy programs), a program or file Guard never read (`curl -K`, `rsync -e`, `nc -e`, `find -exec`, `gh --input`, `gh -F name=@file`, jq reaching `env`, Git configured programs, unverified repository routes), or undeclared `$variables`. Fixed floors — Guard self-protection, secret access, exfiltration — remain unsettleable, and a command owned by two extensions still reviews until both permissions are enabled.
- **Verified hints**: the composite counterfactual, the resident hint-candidate gate, and the Python hint gates all use the same generic settle rule, so an "enable this permission in Extensions" hint is only stored when re-evaluating with that permission enabled really allows the command. Paused `require-reapproval` reviews (unverified `gh` commands) can carry the hint too, and enabling the "Unverified GitHub command capability" permission now suppresses the `critical.github-cli` floor like any other explicitly allowed capability.
- **Inbox presentation**: queue rows show the reviewing extension's brand mark for every command extension (reusing the Protection Center brand system), with category fallbacks for the Kubernetes, cloud/platform, remote-access, and data-protection families instead of only Docker/Git/GitHub icons.

## Regression coverage

- Rust `settles` unit proofs: every owner family has a settleable shape; unbounded shapes (authority changes, file/program inputs, steered environments, interpreters) never settle.
- Rust precedence tests: an explicit Allow settles an uncertain `curl` upload, `rm -rf` with both owning permissions, and an unverified `gh` command; it never settles `kubectl --context`, `kubectl exec`, `curl -K`, `rsync -e`, `nc -e`, configured-program Git fetches, or environment-steered deletes. The pre-existing GitHub read-permission regressions (GraphQL mutations with declared variables settle; `@file` fields, stdin bodies, jq `env` access, and undeclared variables do not) all pass.
- Python hint tests: Docker, unverified-`gh`, file-upload, and destructive-shell reviews recommend the right permission and verify end-to-end (the enabled evaluation allows); steered or authority-changing forms store no hint.
- Dashboard `queue-state` tests: Kubernetes/remote/data-protection categories and the extension-id routing for brand marks.

The benign false-positive gate fixture (`tests/fixtures/benign_false_positive_gate.json`) replays first-contact commands with no extension controls enabled, so it has no dimension that can express an enabled-permission case; the Rust and Python unit tests above are the named regression coverage for this enforcement change.

## Python-runtime note

The only Python change mirrors the resident's hint-candidate gate (admit any rule uncertainty and `require-reapproval` pauses so the verifying counterfactual can run). All decision logic stays in the Rust runtime (`guard-command`/`hol-guard-runtime`); no new Python runtime logic is introduced.

## Verification

- `cargo test -p guard-command --lib`: 2349 passed, 1 pre-existing failure (`pretool::apply_patch_writes` protected-target proof, fails identically on the base commit in this environment).
- `cargo test -p hol-guard-runtime`: full suite passes, including 172 hook-direct tests.
- `pytest tests/test_guard_extension_allow_hint.py tests/test_native_review_allow_hint.py tests/test_guard_approval_extension_recommendation.py tests/test_native_review_dashboard_contract.py`: 48 passed.
- Dashboard: `queue-state.test.ts`, `approval-extension-recommendation.test.ts`, `extension-brand.test.ts`, `native-review-contract.test.ts` pass; `vite build` refreshed the daemon's static assets.
