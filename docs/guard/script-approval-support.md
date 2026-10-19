# Content-bound Bash approvals

This describes the candidate native Bash execution route. It is not a release or installed-machine qualification statement.

| Platform and host | Execution route |
| --- | --- |
| macOS on Apple silicon, pinned OMP or Pi SDK | Native owner delivery, with immutable Bash code and enforced effects; covered by SDK integration tests. A real managed-host consent workflow is a separate acceptance gate. |
| macOS on Intel | Shares the macOS implementation; installed Intel qualification remains required. |
| Linux or Windows | The native immutable Bash owner is unavailable. Saving consent cannot create that execution capability. |
| Other host adapters | This Bash owner is not delivered by their admission hooks. They must not present an unsupported grant as permission to execute reviewed bytes. |

The bounded graph supports literal commands, exact arguments, literal loops, pipelines, sources and mode dispatch. A supported helper is captured Bash code, a specifically constrained system operation, or an eligible hardened compiled image delivered through the native broker. This is not permission to execute an arbitrary binary or arbitrary dynamically discovered code.

Compiled broker images must satisfy the existing strict signature, hardened-runtime and no-entitlement checks. An ordinary Mach-O file can be refused even when its pathname names a familiar utility. Refusal must remain effective; renaming a helper or saving an approval does not establish execution assurance.

The output profile supports one prepared report. Its initialization must be the first material effect, with only proven infallible setup before it; later writes must append to that same report. Multiple report destinations, delayed initialization and later truncation require a separate execution proof and are refused by this route. The report target is checked without following a symlink and remains bound during execution.

An eligible once grant permits one real invocation. A persistent exact-version grant binds the project, execution context, meaningful arguments, interpreter and executable inputs. Timestamp-only changes and unrelated data edits do not by themselves invalidate an unchanged reviewed version. Changes to script, helper or dependency bytes require reevaluation. A dry-mode grant does not authorize deletion mode.

Execution completion and host delivery are separate. The candidate result path checks the native authenticated invocation journal, scans the complete output and applies current output restrictions. It acknowledges a clean completion only after the reviewed result reaches stored host context with matching content and exit/error status. A withheld or altered result cannot advance the invocation. Compatible hosts must support this delivery protocol; older clients cannot advertise the route.

OMP print mode does not emit the host input event used to distinguish new user requests. The candidate adapter binds its initial durable user turn and retains that intent across programmatic continuations. A later new intent requires an observed human input event; a `user` label alone is insufficient. Multiple print-mode batch prompts without distinct trusted input events remain unqualified as separate user requests.

Every launch still evaluates current policy and extension restrictions. Saved consent cannot override a non-overridable denial, Guard self-approval protection, failed integrity checks or an unbound execution route. A code digest is identity evidence, not a safety verdict about remote targets or mutable services.

Local consent is independent of a Cloud subscription. Cloud dependency evidence uses the existing feature entitlement, freshness and revocation authority. Unknown or stale evidence is not a clean verdict, and purchasing a plan never executes an action.

The package evaluator treats stored evaluation JSON as a lookup hint. A cache hit rebuilds its verdict and package details from a currently verified, unexpired signed bundle for the paired workspace, with complete locally pinned target coverage. Reusing a permissive verdict also requires a current trusted session and authoritative feature entitlement. A current saved block may retain a cached Cloud error, but the response is rebuilt without cached entitlement, user copy or Cloud provenance. These checks reuse the existing native bundle verifier; they do not establish a new signing trust root or a monotonic intelligence-generation floor.

The candidate Bash owner currently checks local command and extension policy. It does not yet connect its code-input graph to the package Cloud evaluator. Composed script-dependency entitlement, freshness, revocation and disclosure checks remain delivery gates; existing package-only tests do not establish that integration.

Qualification must distinguish source tests, pinned SDK delivery, exact-wheel real-agent workflows, rendered dashboard behavior and the operator's installed runtime. The admission benchmark in `scripts/bench_native_bash_admission.py` includes policy binding, host observation, IPC, filesystem capture, hashing and the decision store. Its warm 20 ms and cold 100 ms targets remain explicit; a cache change alone does not establish that either target is met.

The real-agent consent test physically completed one reviewed invocation, but post-tool policy withheld its result. That workflow remains unqualified. The packaged SDK post-policy suite now exercises production native post review and final-context acknowledgement for once consent, persistent restarts and nonzero completion. It checks the complete dry-run report and protected deletion sentinels without a model or network. This SDK/native evidence does not replace the required fresh exact-wheel real-agent workflow.
