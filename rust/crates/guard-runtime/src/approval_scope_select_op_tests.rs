//! The conditions `resolve_request_scope_selection` used to decide in Python,
//! each exercised against a contract this op derives itself.

use guard_contracts::{
    ApprovalScopeItemV1, ApprovalScopePersistenceV1, ApprovalScopeSelectRequestV1,
    APPROVAL_SCOPE_SELECT_REQUEST_SCHEMA,
};
use serde_json::{json, Value};

use super::evaluate;
use crate::approval_scope_material::APPROVAL_SCOPE_CONTRACT_VERSION;

/// A native review with a retry binding: it offers an allow at the artifact.
fn bound_review() -> ApprovalScopeItemV1 {
    ApprovalScopeItemV1 {
        artifact_id: Some(json!("omp:native-pretool:bash")),
        artifact_type: Some(json!("tool_call")),
        artifact_hash: Some(json!(format!(
            "native-review-v4:{}:deny:review:review:test",
            "a".repeat(64)
        ))),
        policy_action: Some(json!("review")),
        ..Default::default()
    }
}

/// The same review with no binding: a block may be recorded, an allow may not.
fn unbound_review() -> ApprovalScopeItemV1 {
    ApprovalScopeItemV1 {
        artifact_hash: Some(json!("unbound-request")),
        ..bound_review()
    }
}

/// A context token of the shape `build_approval_context_token` produces, so
/// the derived contract treats the exact action as something Guard can store.
fn exact_context_token() -> String {
    crate::context_digest::build_context_token_fields(
        &json!({"command": "cat notes.txt"}),
        &json!({}),
        &json!({}),
        &json!({}),
        "",
        |out| {
            out.extend_from_slice(b"{}");
            Ok(())
        },
    )
    .expect("context token")
}

/// A review whose retry binding is gone but whose exact action can still be
/// stored: it may be saved as the exact version, it may not be run once.
fn persistable_unbound_review() -> ApprovalScopeItemV1 {
    ApprovalScopeItemV1 {
        artifact_hash: Some(json!("unbound-request")),
        raw_command_text: Some(json!("cat notes.txt")),
        action_envelope_json: Some(json!({"exact_context_token": exact_context_token()})),
        ..bound_review()
    }
}

fn select(
    item: ApprovalScopeItemV1,
    action: &str,
    requested_scope: &str,
    echoed: Option<(&str, &str)>,
) -> Value {
    let (contract_version, contract_digest) = match echoed {
        Some((version, digest)) => (Some(version.to_owned()), Some(digest.to_owned())),
        None => (None, None),
    };
    evaluate(&ApprovalScopeSelectRequestV1 {
        schema: APPROVAL_SCOPE_SELECT_REQUEST_SCHEMA.to_owned(),
        request_id: "select".to_owned(),
        item,
        action: action.to_owned(),
        requested_scope: requested_scope.to_owned(),
        contract_version,
        contract_digest,
        persistence: None,
    })
}

/// The same selection, with the leg that decides whether the decision may be
/// remembered and whether the allow can be executed at all.
fn select_persisting(
    item: ApprovalScopeItemV1,
    action: &str,
    requested_scope: &str,
    echoed: Option<(&str, &str)>,
    persist_policy: Option<bool>,
) -> Value {
    let (contract_version, contract_digest) = match echoed {
        Some((version, digest)) => (Some(version.to_owned()), Some(digest.to_owned())),
        None => (None, None),
    };
    evaluate(&ApprovalScopeSelectRequestV1 {
        schema: APPROVAL_SCOPE_SELECT_REQUEST_SCHEMA.to_owned(),
        request_id: "select".to_owned(),
        item,
        action: action.to_owned(),
        requested_scope: requested_scope.to_owned(),
        contract_version,
        contract_digest,
        persistence: Some(ApprovalScopePersistenceV1 { persist_policy }),
    })
}

fn digest_of(item: ApprovalScopeItemV1) -> String {
    let answer = select(item, "block", "artifact", None);
    answer["contract"]["scope_contract_digest"]
        .as_str()
        .expect("digest")
        .to_owned()
}

#[test]
fn an_offered_scope_is_honoured_as_chosen() {
    let digest = digest_of(bound_review());
    let answer = select(
        bound_review(),
        "allow",
        "artifact",
        Some((APPROVAL_SCOPE_CONTRACT_VERSION, &digest)),
    );
    assert_eq!(answer["outcome"], json!("selected"));
    assert_eq!(answer["requested_scope"], json!("artifact"));
    assert_eq!(answer["applied_scope"], json!("artifact"));
    assert_eq!(answer["warning"], Value::Null);
    assert_eq!(answer["contract"]["scope_contract_digest"], json!(digest));
}

#[test]
fn a_legacy_client_has_its_wider_choice_narrowed_to_the_artifact() {
    let answer = select(bound_review(), "allow", "workspace", None);
    assert_eq!(answer["outcome"], json!("selected"));
    assert_eq!(answer["requested_scope"], json!("workspace"));
    assert_eq!(answer["applied_scope"], json!("artifact"));
    assert_eq!(
        answer["warning"],
        json!("legacy_scope_narrowed_to_artifact")
    );
}

#[test]
fn a_client_that_read_the_contract_is_refused_rather_than_narrowed() {
    let digest = digest_of(bound_review());
    let answer = select(
        bound_review(),
        "allow",
        "workspace",
        Some((APPROVAL_SCOPE_CONTRACT_VERSION, &digest)),
    );
    assert_eq!(answer["outcome"], json!("refused"));
    assert_eq!(answer["reason"], json!("ineligible_request_scope"));
    assert_eq!(answer["contract"]["scope_contract_digest"], json!(digest));
}

#[test]
fn a_block_is_never_narrowed_for_a_legacy_client() {
    let answer = select(bound_review(), "block", "workspace", None);
    assert_eq!(answer["outcome"], json!("refused"));
    assert_eq!(answer["reason"], json!("ineligible_request_scope"));
}

#[test]
fn an_allow_the_request_cannot_offer_at_all_is_not_overridable() {
    let answer = select(unbound_review(), "allow", "workspace", None);
    assert_eq!(answer["outcome"], json!("refused"));
    assert_eq!(answer["reason"], json!("request_action_not_overridable"));
    assert_eq!(
        answer["contract"]["allowed_scopes_by_action"]["allow"],
        json!([])
    );
}

#[test]
fn a_superseded_contract_is_refused_with_the_current_one() {
    for echoed in [
        (APPROVAL_SCOPE_CONTRACT_VERSION, "0".repeat(64)),
        ("guard.approval-scopes.v1", digest_of(bound_review())),
    ] {
        let answer = select(
            bound_review(),
            "allow",
            "artifact",
            Some((echoed.0, &echoed.1)),
        );
        assert_eq!(answer["outcome"], json!("refused"));
        assert_eq!(answer["reason"], json!("stale_scope_contract"));
        assert_eq!(
            answer["contract"]["scope_contract_version"],
            json!(APPROVAL_SCOPE_CONTRACT_VERSION)
        );
    }
}

#[test]
fn half_a_contract_is_not_a_contract() {
    let request = ApprovalScopeSelectRequestV1 {
        schema: APPROVAL_SCOPE_SELECT_REQUEST_SCHEMA.to_owned(),
        request_id: "select".to_owned(),
        item: bound_review(),
        action: "allow".to_owned(),
        requested_scope: "artifact".to_owned(),
        contract_version: Some(APPROVAL_SCOPE_CONTRACT_VERSION.to_owned()),
        contract_digest: None,
        persistence: None,
    };
    let answer = evaluate(&request);
    assert_eq!(answer["outcome"], json!("refused"));
    assert_eq!(answer["reason"], json!("incomplete_scope_contract"));
}

#[test]
fn an_action_or_scope_guard_does_not_record_is_refused_before_the_contract() {
    let unsupported_action = select(bound_review(), "defer", "artifact", None);
    assert_eq!(
        unsupported_action["reason"],
        json!("unsupported_resolution_action")
    );
    assert_eq!(unsupported_action["contract"], Value::Null);
    let unsupported_scope = select(bound_review(), "allow", "repository", None);
    assert_eq!(
        unsupported_scope["reason"],
        json!("unsupported_approval_scope")
    );
    assert_eq!(unsupported_scope["contract"], Value::Null);
}

#[test]
fn a_caller_that_does_not_ask_keeps_the_selection_it_always_got() {
    // An unbound review offers no allow to run once, but a caller resolving
    // only the scope must not start seeing that refusal.
    let answer = select(unbound_review(), "block", "artifact", None);
    assert_eq!(answer["outcome"], json!("selected"));
    assert_eq!(answer["persist_policy"], Value::Null);
}

#[test]
fn an_allow_with_no_way_to_run_is_refused_at_the_scope_it_applied() {
    // The allow is offered at the artifact, but the retry it would have been
    // reused by is gone, and the client asked for this turn only.
    let answer = select_persisting(
        persistable_unbound_review(),
        "allow",
        "artifact",
        None,
        None,
    );
    assert_eq!(answer["outcome"], json!("refused"));
    assert_eq!(answer["reason"], json!("execution_binding_unavailable"));
    assert_eq!(answer["applied_scope"], json!("artifact"));
    // The refusal still reports what the request does offer.
    assert_eq!(
        answer["contract"]["scope_contract_version"],
        json!(APPROVAL_SCOPE_CONTRACT_VERSION)
    );
}

#[test]
fn an_allow_that_cannot_run_once_may_still_be_saved_as_the_exact_version() {
    let item = persistable_unbound_review();
    let digest = digest_of(item.clone());
    let answer = select_persisting(
        item,
        "allow",
        "artifact",
        Some((APPROVAL_SCOPE_CONTRACT_VERSION, &digest)),
        Some(true),
    );
    assert_eq!(answer["outcome"], json!("selected"));
    assert_eq!(answer["applied_scope"], json!("artifact"));
    assert_eq!(answer["persist_policy"], json!(true));
}

#[test]
fn a_bound_review_may_be_run_once_and_keeps_the_clients_preference() {
    let answer = select_persisting(bound_review(), "allow", "artifact", None, Some(false));
    assert_eq!(answer["outcome"], json!("selected"));
    assert_eq!(answer["applied_scope"], json!("artifact"));
    assert_eq!(answer["persist_policy"], json!(false));
}

#[test]
fn a_client_with_no_contract_cannot_have_its_decision_remembered() {
    // It never read that this request can be remembered, so the preference is
    // dropped rather than honoured - but the allow still runs once.
    let answer = select_persisting(bound_review(), "allow", "artifact", None, Some(true));
    assert_eq!(answer["outcome"], json!("selected"));
    assert_eq!(answer["persist_policy"], Value::Null);
}

#[test]
fn a_narrowed_selection_drops_the_remembered_decision() {
    let answer = select_persisting(bound_review(), "allow", "workspace", None, Some(true));
    assert_eq!(answer["outcome"], json!("selected"));
    assert_eq!(answer["applied_scope"], json!("artifact"));
    assert_eq!(
        answer["warning"],
        json!("legacy_scope_narrowed_to_artifact")
    );
    assert_eq!(answer["persist_policy"], Value::Null);
}

#[test]
fn a_client_that_read_the_contract_is_told_when_it_cannot_be_remembered() {
    let item = unbound_review();
    let digest = digest_of(item.clone());
    let answer = select_persisting(
        item,
        "block",
        "artifact",
        Some((APPROVAL_SCOPE_CONTRACT_VERSION, &digest)),
        Some(true),
    );
    assert_eq!(answer["outcome"], json!("refused"));
    assert_eq!(answer["reason"], json!("saved_block_scope_ineligible"));
    assert_eq!(answer["applied_scope"], json!("artifact"));
}
