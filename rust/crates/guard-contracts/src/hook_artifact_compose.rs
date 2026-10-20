//! `HookArtifactCompose` — wire contract for the resident hook-artifact
//! decision composition op.
//!
//! Python gathers evidence (policy config, store rows, scanner results) and the
//! resident decides: it composes the action lattice over the gathered inputs,
//! settles local grants, evaluates saved/claimed approval reuse, decides the
//! trusted-request override, and selects the decision copy. Every query is
//! pure: no IO, no SQLite. Python must send every field explicitly (nulls
//! included) so the request digest it binds matches the resident's.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Schema discriminator for the request.
pub const HOOK_ARTIFACT_COMPOSE_REQUEST_SCHEMA: &str = "guard-hook-artifact-compose-request.v1";
/// Schema discriminator for the result.
pub const HOOK_ARTIFACT_COMPOSE_RESULT_SCHEMA: &str = "guard-hook-artifact-compose-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const HOOK_ARTIFACT_COMPOSE_FEATURE: &str = "hook-artifact-compose-v1";
/// Capability advertised when the `remembered_rule_reason` query is served.
/// A runtime that predates the query rejects it as an unknown kind, so the
/// caller requires this feature for that query alone.
pub const HOOK_ARTIFACT_COMPOSE_REMEMBERED_RULE_FEATURE: &str =
    "hook-artifact-compose-remembered-rule-v1";
/// Capability advertised when the `package_reuse_settle` query is served. A
/// runtime that predates the query rejects it as an unknown kind, so the
/// caller requires this feature for that query alone.
pub const HOOK_ARTIFACT_COMPOSE_PACKAGE_REUSE_FEATURE: &str =
    "hook-artifact-compose-package-reuse-v1";
/// Capability advertised when the resident decides a prompt request's hard
/// block from the prompt's own classes. A runtime that predates the field
/// rejects it as unknown, so the caller requires this feature for a prompt
/// artifact alone.
pub const HOOK_ARTIFACT_COMPOSE_PROMPT_FACTS_FEATURE: &str =
    "hook-artifact-compose-prompt-facts-v1";
/// Capability advertised when the resident derives the restricted-pytest and
/// shell local-script facts from the artifact's reason code. A runtime that
/// predates the field rejects it as unknown, so the caller requires this
/// feature for an artifact that names a reason code.
pub const HOOK_ARTIFACT_COMPOSE_REASON_FACTS_FEATURE: &str =
    "hook-artifact-compose-reason-facts-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HookArtifactComposeRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub query: HookArtifactComposeQueryV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HookArtifactComposeQueryV1 {
    /// Current action composition, local-grant eligibility, and risk copy.
    PolicyStack(Box<PolicyStackQueryV1>),
    /// Configured policy action of one artifact (no lattice composition).
    ConfigAction(Box<ConfigActionQueryV1>),
    /// A matched local tool grant settles the current review as an allow.
    ToolGrantApply,
    /// Settle a local CLI grant result and the native floor.
    GrantSettle(GrantSettleQueryV1),
    /// What observe mode records as the action that would have executed.
    ObserveExecutableAction(Box<ObserveExecutableActionQueryV1>),
    /// Non-package saved-approval reuse composition.
    SavedReuse(Box<SavedReuseQueryV1>),
    /// A saved block selected for a package request.
    SavedBlockReuse {
        current_action: Value,
        policy_action: Value,
        stored_artifact_hash: Value,
    },
    /// The trusted-request override decision.
    TrustedOverride(Box<TrustedOverrideQueryV1>),
    /// Reuse composition after an atomic saved-approval claim.
    ClaimedReuse(Box<ClaimedReuseQueryV1>),
    /// Decision copy overlay for the composed action.
    DecisionCopy(Box<DecisionCopyQueryV1>),
    /// Build the canonical decision and its copy in the same resident request.
    DecisionBuildCopy(Box<DecisionBuildCopyQueryV1>),
    /// Why a remembered local rule was refused while local trust is degraded.
    RememberedRuleReason(RememberedRuleReasonQueryV1),
    /// Settle a package request's saved-approval reuse from the reasons the
    /// evaluation carries, folding the saved-block reuse of the same request.
    PackageReuseSettle(Box<PackageReuseSettleQueryV1>),
}

/// The package-request facts the reuse settlement reads. `reasons` is the
/// evaluation's reason list as it stands after the stored-policy override.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageReuseSettleQueryV1 {
    pub reasons: Vec<Value>,
    /// The caller claims a saved approval on this pass.
    pub claim_saved_approval: bool,
    /// The composed action before any reuse is applied.
    pub current_action: Value,
    /// The evaluation's own action after the stored-policy override.
    pub evaluation_policy_action: Value,
    /// The saved decision's action, `null` when nothing is saved.
    pub stored_policy_action: Value,
    /// The saved decision's artifact hash, `null` when nothing is saved.
    pub stored_artifact_hash: Value,
    /// The source already named for this request's reuse evidence, if any.
    pub approval_reuse_source: Value,
}

/// Guard configuration facts the native policy-config action reads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfigFactsV1 {
    pub default_action: String,
    pub risk_actions: BTreeMap<String, String>,
    pub harness_risk_actions: BTreeMap<String, BTreeMap<String, String>>,
    pub security_level: String,
    pub protection_posture: String,
    pub protection_posture_explicit: bool,
    /// Managed policy locks `security_level`.
    pub managed_locks_level: bool,
    /// Canonical harness every action is resolved for.
    pub harness: String,
    /// Per-harness posture override for `harness`, `null` when none.
    pub harness_posture_override: Option<String>,
}

/// Facts of one artifact the native policy-config action reads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyArtifactFactsV1 {
    /// The prompt asks to bypass Guard. A caller that sends
    /// `prompt_request_classes` leaves this `false` and lets the resident
    /// decide; a caller that still derives it keeps the answer it had.
    pub hard_block: bool,
    /// The prompt request's own classes, for a `prompt_request` artifact
    /// whose caller lets the resident decide the hard block. Absent for
    /// every other artifact, so an older runtime still answers for them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_request_classes: Option<Vec<String>>,
    /// Artifact, publisher, or harness action override.
    pub configured_override: Option<String>,
    /// Normalized command-action floor.
    pub command_action_floor: Option<String>,
    /// A verified explicit catalog-permission allow.
    pub explicit_permission_allow: bool,
    pub risk_classes: Vec<String>,
    /// A restricted pytest sandbox profile is already in force. A caller that
    /// sends `reason_code` leaves this `false` and lets the resident decide;
    /// a caller that still derives it keeps the answer it had.
    pub pytest_restricted_sandbox: bool,
    /// The shell local-script execution review detector fired. Decided the
    /// same way as `pytest_restricted_sandbox`.
    pub shell_local_script_review: bool,
    /// `reason_code` metadata, for the facts the resident reads off it.
    /// Absent when the artifact names none, where both facts above are false
    /// for every caller, so an older runtime still answers for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    /// `restricted_profile_version` metadata, when the artifact names one as
    /// text. Sent beside a reason code, since only that pair decides the
    /// restricted pytest fact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restricted_profile_version: Option<String>,
    /// `guard_default_action` metadata; non-strings arrive as `""`.
    pub guard_default_action: Option<String>,
    /// `str(confidence or "")` of the artifact risk confidence. Whether that
    /// confidence is strong enough to stop a posture is read off this text
    /// here, so no caller decides it.
    pub confidence_text: String,
    /// A caller that already knows the artifact installs a boot or login
    /// item says so here; the resident reads `action_class` for the rest.
    pub writes_launch_agent: bool,
    /// `action_class` metadata; absent or non-string arrives as `null`.
    #[serde(default)]
    pub action_class: Option<String>,
    pub skill_is_known_bad: bool,
}

impl PolicyArtifactFactsV1 {
    /// The action class of a repository-code pytest run.
    const PYTEST_ACTION_CLASS: &'static str = "pytest repository-code execution";
    /// The reason code a restricted pytest profile is required under.
    const PYTEST_REASON_CODE: &'static str = "pytest_restricted_profile_required";
    /// The reason code the shell local-script detector reports.
    const SHELL_SCRIPT_REASON_CODE: &'static str = "shell_local_script_execution_review";

    /// A restricted pytest sandbox profile is already in force.
    ///
    /// A caller that sends the reason code stops deciding this. One that still
    /// sends the fact keeps the answer it had, so this reads the same value
    /// from the same metadata either way.
    #[must_use]
    pub fn pytest_restricted_sandbox(&self) -> bool {
        self.pytest_restricted_sandbox
            || (self.action_class.as_deref() == Some(Self::PYTEST_ACTION_CLASS)
                && self.reason_code.as_deref() == Some(Self::PYTEST_REASON_CODE)
                && self.restricted_profile_version.is_some())
    }

    /// The shell local-script execution review detector fired.
    #[must_use]
    pub fn shell_local_script_review(&self) -> bool {
        self.shell_local_script_review
            || self.reason_code.as_deref() == Some(Self::SHELL_SCRIPT_REASON_CODE)
    }

    /// The artifact risk confidence is one a protection posture stops on.
    #[must_use]
    pub fn confidence_strong(&self) -> bool {
        self.confidence_text
            .trim_matches(is_python_space)
            .eq_ignore_ascii_case("strong")
    }
}

/// What `str.strip()` removes. Rust's own `trim` leaves the C1 and the
/// information separators in place, so confidence text padded with them would
/// read as a weaker confidence than the one the artifact reported.
fn is_python_space(ch: char) -> bool {
    matches!(
        ch,
        '\u{09}'..='\u{0d}'
            | ' '
            | '\u{1c}'..='\u{1f}'
            | '\u{85}'
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'..='\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConfigActionQueryV1 {
    pub policy_config: PolicyConfigFactsV1,
    pub artifact: PolicyArtifactFactsV1,
}

/// The native edge result fields the policy stack floors on.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NativeEdgeFactsV1 {
    pub event_name: Option<String>,
    pub policy_action: Value,
    pub minimum_action: Value,
    pub decision: Value,
    pub reason_code: Value,
    /// The runtime artifact is a `package_request`.
    pub package_request: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyStackQueryV1 {
    pub policy_config: PolicyConfigFactsV1,
    pub runtime: PolicyArtifactFactsV1,
    pub approval_context: PolicyArtifactFactsV1,
    /// A data-flow signal carries strong confidence.
    pub data_flow_strong: bool,
    /// Trusted CLI action; `null` means none was supplied.
    pub cli_action: Value,
    pub payload_action_present: bool,
    pub payload_action: Value,
    pub native_floor: Value,
    /// The native edge verdict for this hook; the op derives its floor.
    pub native_edge: Option<NativeEdgeFactsV1>,
    pub current_action_override_present: bool,
    pub has_package: bool,
    pub package_policy_action: Value,
    pub has_data_flow: bool,
    pub has_scanner: bool,
    pub scanner_action: Value,
    pub has_compound_findings: bool,
    pub artifact_risk_signals: Vec<String>,
    pub data_flow_reasons: Vec<String>,
    pub artifact_risk_summary: String,
    pub data_flow_summary: Option<String>,
    pub package_risk_signals: Vec<String>,
    pub package_risk_summary: Option<String>,
    pub scanner_risk_signals: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GrantSettleQueryV1 {
    pub current_action: Value,
    pub policy_action: Value,
    pub approval_context_action: Value,
    pub granted_action: Value,
    pub native_floor: Value,
}

/// The composed sources observe mode re-reads to name the action that would
/// have run.
///
/// Each field carries one source's action, or null when that source said
/// nothing. They arrive as raw values rather than as `GuardAction` because an
/// unrecognized source name must be ignored here, not normalized into a
/// verdict: observe mode reports what the harness would have done, so a source
/// this build cannot read contributes nothing instead of a guess.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ObserveExecutableActionQueryV1 {
    pub current_config_action: Value,
    pub current_action_override: Value,
    pub trusted_cli_override: Value,
    pub untrusted_hook_payload_hint: Value,
    pub package_action: Value,
    pub data_flow_action: Value,
    pub scanner_action: Value,
    /// The package evaluation's own action, which the composition trace does
    /// not always carry.
    pub package_evaluation_action: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SavedReuseQueryV1 {
    pub current_action: Value,
    pub stored_present: bool,
    pub stored_action: Value,
    pub stored_artifact_hash: Value,
    pub integrity_failure: bool,
    pub stored_validation_reason: Option<String>,
    pub cursor_native_present: bool,
    pub cursor_validation_reason: Option<String>,
    pub diagnostic_reason: Option<String>,
    pub diagnostic_stored_hash: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TrustedOverrideQueryV1 {
    pub token_validation_reason: Option<String>,
    pub policy_action: Value,
    pub remembered_rule_rejected: bool,
    pub prior_reuse_reason_code: Option<String>,
    pub stored_present: bool,
    pub stored_action: Value,
    pub stored_source: Value,
    pub stored_validation_reason: Option<String>,
    /// `null` before the caller has attempted the claim.
    pub claim_succeeded: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PriorReuseV1 {
    pub action: Value,
    pub saved_action: Value,
    pub reason_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClaimedReuseQueryV1 {
    pub claimed_hash: Value,
    pub token_validation_reason: Option<String>,
    pub post_claim_refresh_failed: bool,
    pub remembered_rule_rejected: bool,
    pub prior_reuse: Option<PriorReuseV1>,
    pub package_reuse_saved_action: Value,
    pub workflow_capability_required: bool,
    pub workflow_authorization_claimed: bool,
    pub policy_action: Value,
    pub current_policy_action: Value,
    pub claimed_trusted_request_override: bool,
    pub claimed_package_approval_consumed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DecisionCopyPackageV1 {
    pub reason_codes: Vec<String>,
    pub user_title: String,
    pub user_summary: String,
    pub user_harness_message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DecisionCopyQueryV1 {
    pub policy_action: Value,
    pub package: Option<DecisionCopyPackageV1>,
    pub package_policy_action: Value,
    pub has_compound_findings: bool,
    pub compound_finding_count: Option<u64>,
    pub risk_summary: String,
    pub scanner_raised_to_block: bool,
    pub has_scanner_evidence: bool,
    pub scanner_primary_signal: Option<String>,
    pub base_user_body: Value,
    pub base_harness_message: Value,
    pub base_dashboard_primary_detail: Value,
    pub remembered_rule_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RememberedRuleReasonQueryV1 {
    /// Reported state of remembered local rules, `unknown` when absent.
    pub remembered_rules: String,
    /// Integrity detail to append to the reason, when one was reported.
    pub integrity_message: Option<String>,
    /// How the request is named in the reason.
    pub artifact_summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DecisionBuildCopyQueryV1 {
    pub copy: DecisionCopyQueryV1,
    pub reason: String,
    pub signals: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HookArtifactComposeResultV1 {
    pub schema: String,
    pub request_id: String,
    /// `sha256:` digest of the canonical request, binding the reply to it.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or a `native_hook_artifact_compose_*` failure code.
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

#[cfg(test)]
mod confidence_tests {
    use super::PolicyArtifactFactsV1;
    use serde_json::json;

    fn facts(confidence_text: &str) -> PolicyArtifactFactsV1 {
        serde_json::from_value(json!({
            "hard_block": false,
            "configured_override": null,
            "command_action_floor": null,
            "explicit_permission_allow": false,
            "risk_classes": [],
            "pytest_restricted_sandbox": false,
            "shell_local_script_review": false,
            "guard_default_action": null,
            "confidence_text": confidence_text,
            "writes_launch_agent": false,
            "skill_is_known_bad": false,
        }))
        .expect("artifact facts decode")
    }

    #[test]
    fn a_strong_confidence_is_read_off_the_confidence_text() {
        assert!(facts("strong").confidence_strong());
        assert!(facts("  Strong  ").confidence_strong());
    }

    #[test]
    fn any_other_confidence_text_is_not_strong() {
        for text in ["", "weak", "moderate", "strongly"] {
            assert!(!facts(text).confidence_strong(), "{text:?} read as strong");
        }
    }

    #[test]
    fn padding_a_strong_confidence_does_not_weaken_it() {
        // The reporting side strips with `str.strip()`, which also removes the
        // information separators and the C1 space that Rust's `trim` keeps.
        for text in [
            "\u{1c}strong\u{1f}",
            "\u{1d}\u{1e}Strong",
            "\u{85}strong\u{a0}",
            "\u{2028}strong\u{3000}",
        ] {
            assert!(facts(text).confidence_strong(), "{text:?} read as weaker");
        }
    }

    fn reason_facts(value: serde_json::Value) -> PolicyArtifactFactsV1 {
        let mut base = json!({
            "hard_block": false,
            "configured_override": null,
            "command_action_floor": null,
            "explicit_permission_allow": false,
            "risk_classes": [],
            "pytest_restricted_sandbox": false,
            "shell_local_script_review": false,
            "guard_default_action": null,
            "confidence_text": "",
            "writes_launch_agent": false,
            "skill_is_known_bad": false,
        });
        for (key, item) in value.as_object().expect("an object of overrides") {
            base[key] = item.clone();
        }
        serde_json::from_value(base).expect("artifact facts decode")
    }

    #[test]
    fn a_restricted_pytest_sandbox_needs_the_whole_reason() {
        let whole = json!({
            "action_class": "pytest repository-code execution",
            "reason_code": "pytest_restricted_profile_required",
            "restricted_profile_version": "2",
        });
        assert!(reason_facts(whole.clone()).pytest_restricted_sandbox());
        for missing in ["action_class", "reason_code", "restricted_profile_version"] {
            let mut partial = whole.clone();
            partial[missing] = json!(null);
            assert!(
                !reason_facts(partial).pytest_restricted_sandbox(),
                "{missing} was not required"
            );
        }
        let mut wrong = whole.clone();
        wrong["reason_code"] = json!("shell_local_script_execution_review");
        assert!(!reason_facts(wrong).pytest_restricted_sandbox());
    }

    #[test]
    fn a_shell_local_script_review_is_read_off_the_reason_code() {
        assert!(
            reason_facts(json!({"reason_code": "shell_local_script_execution_review"}))
                .shell_local_script_review()
        );
        for code in [
            json!(null),
            json!(""),
            json!("pytest_restricted_profile_required"),
        ] {
            assert!(
                !reason_facts(json!({"reason_code": code})).shell_local_script_review(),
                "a wrong reason code read as a local-script review"
            );
        }
    }

    #[test]
    fn a_caller_that_still_decides_keeps_its_own_answer() {
        let decided = reason_facts(json!({
            "pytest_restricted_sandbox": true,
            "shell_local_script_review": true,
        }));
        assert!(decided.pytest_restricted_sandbox());
        assert!(decided.shell_local_script_review());
    }

    #[test]
    fn a_reason_code_is_absent_from_the_wire_until_a_caller_sends_one() {
        let value = serde_json::to_value(reason_facts(json!({}))).expect("encode");
        let object = value.as_object().expect("an object");
        assert!(!object.contains_key("reason_code"));
        assert!(!object.contains_key("restricted_profile_version"));
    }

    #[test]
    fn the_caller_may_not_send_its_own_strength() {
        let mut value = serde_json::to_value(facts("strong")).expect("encode");
        value["confidence_strong"] = json!(false);
        serde_json::from_value::<PolicyArtifactFactsV1>(value)
            .expect_err("a caller-sent strength must be rejected");
    }
}
