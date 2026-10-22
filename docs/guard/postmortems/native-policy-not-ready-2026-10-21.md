# Every prompt blocked with `native_policy_not_ready`

Status: fixed, pending release
First reported: 2026-10-21
Fix: `#5658`

## What people saw

Every prompt in an affected harness was refused before review:

```
Warning: HOL Guard could not prepare protection for this prompt.
Retry the prompt to reconnect (native_policy_not_ready).
```

Retrying never helped. Updating to the latest release did not help either,
because the first attempted fix did not address the cause.

## The failure

`prepare_native_hook_policy` is the last gate before a prompt is reviewed
(`src/codex_plugin_scanner/guard/daemon/hook_policy_admission.py`). When
`HookWorker.prepare_workspace_policy` returns `None`, it writes the
`native_policy_not_ready` fail-safe and the prompt never reaches Guard. So the
whole incident reduces to one question: why did the worker hold no policy?

Three things lined up.

**1. The guard home's command catalog drifted from the installed runtime.**
A guard home records the command program named by its activated catalog. The
runtime binary carries its own `PACKAGED_COMMAND_PROGRAM_ID`. On an affected
home, a committed activation named a program no installed runtime builds.
`_stamp_runtime_program_digest`
(`native_policy_snapshot_publisher_transport.py`) deliberately declines to
overwrite `program_digest` when the catalog and trust digests do not match the
runtime, so every push shipped the stale program.

**2. The resident refused the whole snapshot over the command binding.**
Command-extension admission failures are refusals of one optional part of the
snapshot, but the publisher treated them as refusals of the snapshot. The
publisher raised, held nothing, and the worker had no policy to give the hook.
Enforcement was lost for a reason that had nothing to do with enforcement.

**3. The real error code never reached the publisher.**
`safe_error_response` (`rust/crates/guard-runtime/src/resident_protocol.rs`)
rewrites any error code outside its declared allow-lists into the literal
`native_request_invalid_json`. None of the command-admission codes were
declared, so the publisher — and every log and diagnostic built on it — saw a
JSON parse failure for a payload that parsed fine. The one piece of evidence
that pointed at the cause was being erased in transit.

Together: a drifted catalog made every push unacceptable, an unacceptable
binding sank the whole policy, and the masked code sent diagnosis in the wrong
direction.

## The fix

`#5658` has two halves.

- **Rust.** Declare the command-admission codes in
  `NATIVE_COMMAND_CONTROL_ERROR_CODES` so `safe_error_response` stops rewriting
  them. A new resident test pins that these codes reach the publisher unchanged.
- **Python.** The publisher now retries once without the command binding when a
  push is refused for a reason listed in `COMMAND_BINDING_UNUSABLE_CODES`. The
  snapshot republishes in `enforce` mode, minus command extensions, and the hook
  barrier opens. Any other refusal still fails closed, unchanged.

The recovery list includes `native_request_invalid_json` on purpose: a resident
built before the Rust half shipped reports every admission failure under that
code, and those installs are exactly the ones that are stuck. The Python half is
what unblocks an already-wedged machine; the Rust half makes the next failure
legible.

Losing command extensions is a real reduction in coverage. It is strictly better
than losing all enforcement, which is what the old behavior did, and the
publisher records why the binding was dropped.

## Verification

`tests/test_native_hook_barrier_command_binding_wedge.py` drives the real
publisher and the real `HookWorker` against a resident that refuses every push
carrying a command binding — which is what a drifted catalog does — and asserts
the barrier opens on the republished snapshot. Against the pre-fix transport,
that file and the transport unit tests fail 21 of 24; against the fix, 24 pass.
The three that pass either way are the negative controls that must keep failing
closed.

## Why the first attempt shipped broken

The earlier release was cut on evidence that looked complete and was not. The
gaps, in the order they mattered:

- **The reported symptom was never reproduced.** Work started from a hypothesis
  about the publisher and stayed there. Nothing in that first cycle ever called
  `prepare_workspace_policy` and watched it return `None`, which is the only
  thing that produces the message people saw.
- **A component probe was accepted as a system proof.** "The publisher recovers"
  and "the prompt is admitted" are different claims. Only the first was
  established, and the second was reported.
- **Acceptance ran against a clean home.** A fresh install cannot exhibit a
  defect that only exists when a home's committed state has drifted from the
  installed runtime. A clean-home pass was read as evidence of a fix when it was
  evidence of nothing.
- **The masked error code was believed.** `native_request_invalid_json` sent the
  investigation at serialization and payload size, and a correct early
  hypothesis was dropped as disproven on the strength of that code. The
  rewriting in `safe_error_response` was found only after reading the emission
  site in the Rust source instead of trusting the wire.
- **"Released" was reported as "fixed."** A merged PR and a published version
  are facts about the repository. Neither is a fact about the machine that
  reported the problem.

## What changed so this does not repeat

The acceptance rules are now written down, in
`guard-gauntlet/references/installed-acceptance.md`, and referenced from the PR
review loop and the dev-testing skill. The claim that has to be met before a
runtime fix is called shipped:

> On the machine and configuration that reported the problem, a prompt that was
> failing now completes, and a prompt that should be stopped is still stopped.

With the supporting rules that this incident cost: reproduce through the
production wiring that emitted the message, run acceptance against the reporting
configuration rather than a clean one, never root-cause from a wire code without
reading its emission site, prove the new test fails without the fix, and state
which claim you actually hold.
