//! `ApprovalScopeSelect` - resident op that resolves one approval decision
//! against the request's own scope contract.
//!
//! Faithful port of `approval_scope_support.resolve_request_scope_selection`.
//! The Python function decided three different things about a user's answer:
//! whether the scope they chose is one this request offers for that action,
//! whether a client resolving against an older contract may still be heard,
//! and whether a legacy client with no contract at all gets its choice
//! narrowed to the artifact instead of refused. All three decide what an
//! approval ends up covering, so they belong here with the contract they read.
//!
//! The caller never supplies the contract. It ships the request, and the op
//! derives the contract with the same code `ApprovalScope` publishes, so a
//! caller cannot widen a scope by claiming a contract the request does not
//! have. The derived contract rides back on the reply because every refusal
//! the Python callers raise carries it.
//!
//! The conditions run in the Python order, and each reason code is the
//! message that function raised, so a caller reports the same refusal it
//! always did.
//!
//! The op also owns what `approvals.apply_approval_resolution` decided after
//! the selection: whether a remembered decision survives, and whether an
//! allow can be executed at all. Those two read the same contract this op
//! already derived - `exact_action_persistence_eligible`, and the
//! `can_run_once` / `can_persist_exact_version` projections - so deciding
//! them here keeps one reader of the contract instead of two. A caller that
//! cannot reach the resident now has no way to honour a remembered allow the
//! request never offered.

use guard_contracts::{
    ApprovalScopeSelectRequestV1, ApprovalScopeSelectResultV1, APPROVAL_SCOPE_SELECT_MAX_BYTES,
    APPROVAL_SCOPE_SELECT_RESULT_SCHEMA,
};
use serde_json::{json, Value};

use crate::approval_scope_contract::{contract, ScopeContract, View};
use crate::approval_scope_material::APPROVAL_SCOPE_CONTRACT_VERSION;
use crate::approval_scope_op::contract_value;
use crate::package_authority_op::request_digest_with_limit;

/// `models.DECISION_SCOPE_VALUES`.
const DECISION_SCOPE_VALUES: &[&str] = &["global", "harness", "workspace", "artifact", "publisher"];

pub(crate) fn evaluate_approval_scope_select_request(
    request: &ApprovalScopeSelectRequestV1,
    owner: Option<&crate::policy_store::PolicySnapshotStore>,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, APPROVAL_SCOPE_SELECT_MAX_BYTES)
        .map_err(|_| "native_approval_scope_select_too_large".to_owned())?;
    let payload = evaluate_with_owner(request, owner);
    crate::encode_response(&ApprovalScopeSelectResultV1 {
        schema: APPROVAL_SCOPE_SELECT_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "ok".to_owned(),
        code: "ok".to_owned(),
        payload: Some(payload),
    })
}

#[cfg(test)]
pub(crate) fn evaluate(request: &ApprovalScopeSelectRequestV1) -> Value {
    evaluate_with_owner(request, None)
}

fn evaluate_with_owner(
    request: &ApprovalScopeSelectRequestV1,
    owner: Option<&crate::policy_store::PolicySnapshotStore>,
) -> Value {
    // The action and the scope name are read before the contract is derived,
    // exactly as the Python function did: an answer that names no action Guard
    // records, or no scope Guard has, is not about this request at all.
    let resolution_action = match request.action.as_str() {
        "allow" => "allow",
        "block" => "block",
        _ => return refused("unsupported_resolution_action", None),
    };
    if !DECISION_SCOPE_VALUES.contains(&request.requested_scope.as_str()) {
        return refused("unsupported_approval_scope", None);
    }

    // Derived exactly as `ApprovalScope` publishes it, owner check included:
    // a native Bash request the owner verified offers different scopes, and a
    // client echoing the published digest must be checked against that one.
    let mut view = View::new(&request.item);
    view.native_bash_owner_verified = owner.is_some_and(|store| {
        crate::native_bash_review_scope::owner_verified(&request.item, store, None)
    });
    let derived = contract(&view);
    let echoed = (
        request.contract_version.as_deref(),
        request.contract_digest.as_deref(),
    );
    match echoed {
        (Some(version), Some(digest)) => {
            if version != APPROVAL_SCOPE_CONTRACT_VERSION || digest != derived.digest {
                return refused("stale_scope_contract", Some(&derived));
            }
        }
        (None, None) => {}
        // One without the other is not a contract: a client either resolves
        // against a version it read with its digest, or against none.
        _ => return refused("incomplete_scope_contract", Some(&derived)),
    }

    let eligible = if resolution_action == "allow" {
        &derived.allow_scopes
    } else {
        &derived.block_scopes
    };
    if eligible.contains(&request.requested_scope.as_str()) {
        return resolve_persistence(
            request,
            resolution_action,
            &request.requested_scope,
            None,
            &derived,
        );
    }
    // A client that read the contract chose a scope the contract does not
    // offer, so it is refused rather than reinterpreted. A block is refused
    // the same way whatever the client read: narrowing a recorded block would
    // silently record less than the user asked for.
    if request.contract_version.is_some() || resolution_action == "block" {
        return refused("ineligible_request_scope", Some(&derived));
    }
    if !eligible.contains(&"artifact") {
        return refused("request_action_not_overridable", Some(&derived));
    }
    // A legacy client never saw the contract, so its wider choice is narrowed
    // to the one scope this request does offer, and the warning says so.
    resolve_persistence(
        request,
        resolution_action,
        "artifact",
        Some("legacy_scope_narrowed_to_artifact"),
        &derived,
    )
}

/// Decide what the client's `persist_policy` resolves to, and whether the
/// approval can be executed at all, against the scope that was applied.
///
/// Faithful port of the block `approvals.apply_approval_resolution` ran after
/// the selection. The order matters: a narrowed selection drops the
/// remembered decision before eligibility is read, because the user never saw
/// the scope their decision would have been saved at.
fn resolve_persistence(
    request: &ApprovalScopeSelectRequestV1,
    resolution_action: &str,
    applied_scope: &str,
    warning: Option<&str>,
    derived: &ScopeContract,
) -> Value {
    // A caller that did not ask for this leg gets exactly the selection it
    // got before, with no remembered decision and no execution check.
    let Some(persistence) = request.persistence.as_ref() else {
        return selected(
            &request.requested_scope,
            applied_scope,
            warning,
            None,
            derived,
        );
    };
    let mut persist_policy = persistence.persist_policy;
    if warning.is_some() {
        persist_policy = None;
    } else if applied_scope == "artifact" && persistence.persist_policy == Some(true) {
        if request.contract_version.is_some() {
            if !derived.exact_action_persistence_eligible {
                return refused_at(
                    if resolution_action == "allow" {
                        "saved_allow_scope_ineligible"
                    } else {
                        "saved_block_scope_ineligible"
                    },
                    applied_scope,
                    derived,
                );
            }
        } else {
            // A client with no contract never read that this request can be
            // remembered, so its request to remember is not honoured.
            persist_policy = None;
        }
    }
    // An allow that cannot be run once and is not being saved as the exact
    // version has no way to reach the action the user approved.
    if resolution_action == "allow"
        && !derived.can_run_once()
        && !(applied_scope == "artifact"
            && persist_policy == Some(true)
            && derived.can_persist_exact_version())
    {
        return refused_at("execution_binding_unavailable", applied_scope, derived);
    }
    selected(
        &request.requested_scope,
        applied_scope,
        warning,
        persist_policy,
        derived,
    )
}

fn selected(
    requested_scope: &str,
    applied_scope: &str,
    warning: Option<&str>,
    persist_policy: Option<bool>,
    derived: &ScopeContract,
) -> Value {
    json!({
        "outcome": "selected",
        "requested_scope": requested_scope,
        "applied_scope": applied_scope,
        "warning": warning,
        "persist_policy": persist_policy,
        "contract": contract_value(derived),
    })
}

fn refused(reason: &str, derived: Option<&ScopeContract>) -> Value {
    json!({
        "outcome": "refused",
        "reason": reason,
        "applied_scope": Value::Null,
        "contract": derived.map(contract_value),
    })
}

/// A refusal reached after a scope was already applied. The caller reports
/// the scope the refusal is about, which is not always the one it asked for.
fn refused_at(reason: &str, applied_scope: &str, derived: &ScopeContract) -> Value {
    json!({
        "outcome": "refused",
        "reason": reason,
        "applied_scope": applied_scope,
        "contract": contract_value(derived),
    })
}

#[cfg(test)]
#[path = "approval_scope_select_op_tests.rs"]
mod tests;
