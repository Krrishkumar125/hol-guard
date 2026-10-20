//! The composition `resolve_policy_decision_lookup_with_memory_pattern` used
//! to run in Python over the probes it had just resolved.

use guard_contracts::{
    PolicyLookupCandidateV1, PolicyLookupComposeRequestV1, POLICY_LOOKUP_COMPOSE_REQUEST_SCHEMA,
};
use serde_json::{json, Value};

use super::{evaluate, evaluate_policy_lookup_compose_request};

fn trust(state: &str) -> Value {
    json!({"remembered_rules": state})
}

fn probe(action: Option<&str>, revision: i64) -> PolicyLookupCandidateV1 {
    PolicyLookupCandidateV1 {
        decision: action.map(|action| json!({"action": action, "scope": "artifact"})),
        ignored_local_integrity: None,
        trust_status: trust("enabled"),
        authority_revision: revision,
    }
}

fn compose(candidates: Vec<PolicyLookupCandidateV1>) -> Option<Value> {
    evaluate(&PolicyLookupComposeRequestV1 {
        schema: POLICY_LOOKUP_COMPOSE_REQUEST_SCHEMA.to_owned(),
        request_id: "compose".to_owned(),
        candidates,
    })
}

#[test]
fn a_single_probe_is_its_own_answer() {
    let composed = compose(vec![probe(Some("allow"), 7)]).expect("composed");
    assert_eq!(composed["decision"]["action"], json!("allow"));
    assert_eq!(
        composed["decision"]["_approval_authority_revision"],
        json!(7)
    );
    assert_eq!(composed["authority_revision"], json!(7));
    assert_eq!(composed["trust_status"], trust("enabled"));
    assert_eq!(composed["ignored_local_integrity"], Value::Null);
}

#[test]
fn no_probe_at_all_is_refused_rather_than_read_as_no_match() {
    assert!(compose(vec![]).is_none());
}

#[test]
fn the_more_restrictive_later_probe_wins() {
    let composed =
        compose(vec![probe(Some("allow"), 3), probe(Some("block"), 3)]).expect("composed");
    assert_eq!(composed["decision"]["action"], json!("block"));
}

#[test]
fn a_less_restrictive_later_probe_does_not_displace_the_direct_answer() {
    let composed =
        compose(vec![probe(Some("block"), 3), probe(Some("allow"), 3)]).expect("composed");
    assert_eq!(composed["decision"]["action"], json!("block"));
}

#[test]
fn an_equally_restrictive_later_probe_does_not_displace_the_earlier_one() {
    // Python replaces only on a strictly greater severity, so the direct
    // artifact match keeps its own trust status.
    let mut later = probe(Some("review"), 3);
    later.trust_status = trust("later");
    let composed = compose(vec![probe(Some("review"), 3), later]).expect("composed");
    assert_eq!(composed["trust_status"], trust("enabled"));
}

#[test]
fn a_probe_that_found_nothing_is_skipped() {
    let composed =
        compose(vec![probe(None, 4), probe(Some("warn"), 4), probe(None, 4)]).expect("composed");
    assert_eq!(composed["decision"]["action"], json!("warn"));
}

#[test]
fn every_probe_empty_composes_to_no_decision() {
    let composed = compose(vec![probe(None, 4), probe(None, 4)]).expect("composed");
    assert_eq!(composed["decision"], Value::Null);
    assert_eq!(composed["authority_revision"], json!(4));
}

#[test]
fn an_unreadable_saved_action_is_read_as_block() {
    // An action the lattice does not know could be anything, so it is treated
    // as the most restrictive thing it could be and wins over an allow.
    for unknown in [json!("teleport"), json!(null), json!(7)] {
        let candidate = PolicyLookupCandidateV1 {
            decision: Some(json!({"action": unknown})),
            ..probe(None, 5)
        };
        let composed = compose(vec![probe(Some("allow"), 5), candidate]).expect("composed");
        assert_eq!(composed["decision"]["action"], unknown);
    }
}

#[test]
fn a_saved_decision_with_no_action_at_all_still_reads_as_block() {
    let candidate = PolicyLookupCandidateV1 {
        decision: Some(json!({"scope": "artifact"})),
        ..probe(None, 5)
    };
    let composed = compose(vec![probe(Some("allow"), 5), candidate]).expect("composed");
    assert_eq!(composed["decision"]["scope"], json!("artifact"));
}

#[test]
fn ask_is_the_review_rank_it_aliases_to() {
    let composed =
        compose(vec![probe(Some("ask"), 2), probe(Some("review"), 2)]).expect("composed");
    // Equal severity, so the first probe is kept and still reads as `ask`.
    assert_eq!(composed["decision"]["action"], json!("ask"));
    let upgraded = compose(vec![probe(Some("ask"), 2), probe(Some("block"), 2)]).expect("composed");
    assert_eq!(upgraded["decision"]["action"], json!("block"));
}

#[test]
fn ignored_integrity_comes_from_the_first_probe_that_reports_any() {
    let mut second = probe(None, 1);
    second.ignored_local_integrity = Some(json!({"reason": "second"}));
    let mut third = probe(Some("block"), 1);
    third.ignored_local_integrity = Some(json!({"reason": "third"}));
    let composed = compose(vec![probe(Some("allow"), 1), second, third]).expect("composed");
    // The winning probe is the third, but the integrity is the second's: a
    // probe that found no decision still reports what it had to ignore.
    assert_eq!(composed["decision"]["action"], json!("block"));
    assert_eq!(
        composed["ignored_local_integrity"],
        json!({"reason": "second"})
    );
}

#[test]
fn the_direct_probes_integrity_is_never_overwritten() {
    let mut first = probe(Some("allow"), 1);
    first.ignored_local_integrity = Some(json!({"reason": "direct"}));
    let mut later = probe(Some("block"), 1);
    later.ignored_local_integrity = Some(json!({"reason": "later"}));
    let composed = compose(vec![first, later]).expect("composed");
    assert_eq!(
        composed["ignored_local_integrity"],
        json!({"reason": "direct"})
    );
}

#[test]
fn probes_that_disagree_on_the_authority_have_none() {
    let composed =
        compose(vec![probe(Some("allow"), 3), probe(Some("block"), 4)]).expect("composed");
    assert_eq!(composed["authority_revision"], json!(-1));
    assert_eq!(
        composed["decision"]["_approval_authority_revision"],
        json!(-1)
    );
}

#[test]
fn the_winning_probes_trust_status_is_the_answers() {
    let mut later = probe(Some("block"), 9);
    later.trust_status = trust("disabled_degraded");
    let composed = compose(vec![probe(Some("allow"), 9), later]).expect("composed");
    assert_eq!(composed["trust_status"], trust("disabled_degraded"));
}

#[test]
fn the_result_binds_its_request_and_refuses_an_empty_composition() {
    let request = PolicyLookupComposeRequestV1 {
        schema: POLICY_LOOKUP_COMPOSE_REQUEST_SCHEMA.to_owned(),
        request_id: "bound".to_owned(),
        candidates: vec![probe(Some("allow"), 1)],
    };
    let encoded = evaluate_policy_lookup_compose_request(&request).expect("encoded");
    let answer: Value = serde_json::from_slice(&encoded).expect("json");
    assert_eq!(answer["request_id"], json!("bound"));
    assert_eq!(answer["status"], json!("ok"));
    assert_eq!(answer["code"], json!("ok"));
    let digest = answer["request_sha256"].as_str().expect("digest");
    assert!(digest.starts_with("sha256:"));
    assert_eq!(digest.len(), "sha256:".len() + 64);

    let empty = PolicyLookupComposeRequestV1 {
        candidates: vec![],
        ..request
    };
    let encoded = evaluate_policy_lookup_compose_request(&empty).expect("encoded");
    let answer: Value = serde_json::from_slice(&encoded).expect("json");
    assert_eq!(answer["status"], json!("error"));
    assert_eq!(answer["code"], json!("native_policy_lookup_compose_empty"));
    assert_eq!(answer.get("payload"), None);
}

#[test]
fn an_unknown_request_field_is_rejected() {
    let mut wire = serde_json::to_value(PolicyLookupComposeRequestV1 {
        schema: POLICY_LOOKUP_COMPOSE_REQUEST_SCHEMA.to_owned(),
        request_id: "unknown".to_owned(),
        candidates: vec![probe(Some("allow"), 1)],
    })
    .expect("wire");
    wire.as_object_mut()
        .expect("object")
        .insert("consume_one_shot".to_owned(), json!(true));
    assert!(serde_json::from_value::<PolicyLookupComposeRequestV1>(wire).is_err());
}
