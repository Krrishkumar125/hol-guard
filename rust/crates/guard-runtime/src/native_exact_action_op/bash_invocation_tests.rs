//! Exercise allocation, durable completion and SDK acknowledgement via dispatch.
use super::*;
use guard_contracts::NativeBashAckResultV1;

fn invocation(
    request: &NativeBashCaptureV1,
    envelope: &GuardHookEnvelopeV2,
) -> NativeBashExecuteRequestV1 {
    let mut execution = quiet(request, envelope);
    execution.operation_id = format!("bash-operation:{}", "a".repeat(64));
    execution.tool_call_id = Some("sdk-call-0".into());
    execution
}

fn ack(
    execution: &NativeBashExecuteRequestV1,
    store: &PolicySnapshotStore,
    code: i32,
) -> NativeBashAckResultV1 {
    serde_json::from_slice(
        &dispatch(
            "native_bash_ack",
            json!({
                "schema":"guard-native-bash-ack-request.v1", "request_id":"ack-delivery-test",
                "guard_home":execution.capture.guard_home,
                "store_path":execution.authorization.store_path(), "base_id":execution.operation_id,
                "harness":execution.capture.harness, "project":execution.capture.workspace,
                "tool_call_id":execution.tool_call_id, "exit_code":code,
            }),
            Some(store),
        )
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn bash_sdk_same_intent_distinct_acknowledged_calls_execute_across_restarts_and_old_calls_replay() {
    let (_root, request) = tests::fixture();
    let (mut store, envelope) = policy_store(&request);
    let mut execution = invocation(&request, &envelope);
    let report = Path::new(&request.home_dir).join("maintenance-report.tsv");
    let mut ids = std::collections::BTreeSet::new();
    for iteration in 0..10 {
        execution.tool_call_id = Some(format!("sdk-call-{iteration}"));
        std::fs::write(&report, "must be refreshed").unwrap();
        let result = execute(&execution, &store);
        assert_eq!(result.status, "ok", "{}", result.code);
        assert!(ids.insert(result.operation.unwrap().operation_id));
        assert!(std::fs::read_to_string(&report)
            .unwrap()
            .contains("local metadata"));
        assert!(ack(&execution, &store, 0).acknowledged);
        drop(store);
        store = PolicySnapshotStore::new(Path::new(&request.guard_home), &"a".repeat(64)).unwrap();
    }
    std::fs::write(&report, "old call must not execute").unwrap();
    execution.tool_call_id = Some("sdk-call-0".into());
    let old = execute(&execution, &store);
    assert!(old.replayed);
    assert_eq!(old.status, "recorded");
    assert!(
        !ack(&execution, &store, 0).acknowledged,
        "late ACK cannot advance the current call"
    );
    assert_eq!(
        std::fs::read_to_string(report).unwrap(),
        "old call must not execute"
    );
}

#[test]
fn bash_sdk_unacknowledged_completion_and_forged_exit_cannot_advance() {
    let (_root, request) = tests::fixture();
    let (store, envelope) = policy_store(&request);
    let mut execution = invocation(&request, &envelope);
    assert_eq!(ack(&execution, &store, 0).status, "error");
    let first = execute(&execution, &store);
    assert_eq!(first.status, "ok");
    assert_eq!(ack(&execution, &store, 7).status, "error");
    let report = Path::new(&request.home_dir).join("maintenance-report.tsv");
    std::fs::write(&report, "preserve unacknowledged result").unwrap();
    execution.tool_call_id = Some("sdk-distinct-before-ack".into());
    let pending = execute(&execution, &store);
    assert!(pending.replayed);
    assert_eq!(pending.operation, first.operation);
    assert_eq!(
        std::fs::read_to_string(&report).unwrap(),
        "preserve unacknowledged result"
    );
    // Receipt of native completion on recovery can be acknowledged, but that
    // call remains pinned. Only a later distinct call gets a new invocation.
    assert!(ack(&execution, &store, 0).acknowledged);
    assert!(execute(&execution, &store).replayed);
    execution.tool_call_id = Some("sdk-distinct-after-ack".into());
    assert_eq!(execute(&execution, &store).status, "ok");
}

#[test]
fn bash_sdk_deleted_journal_cannot_repeat_a_completed_invocation_or_advance() {
    let (_root, request) = tests::fixture();
    let (store, envelope) = policy_store(&request);
    let mut execution = invocation(&request, &envelope);
    let first = execute(&execution, &store);
    assert_eq!(first.status, "ok");
    assert!(ack(&execution, &store, 0).acknowledged);
    let report = Path::new(&request.home_dir).join("maintenance-report.tsv");
    std::fs::write(&report, "preserve after journal deletion").unwrap();
    Connection::open(execution.authorization.store_path())
        .unwrap()
        .execute(
            "DELETE FROM guard_bash_operations WHERE operation_id=?1",
            [first.operation.unwrap().operation_id],
        )
        .unwrap();
    assert_eq!(execute(&execution, &store).status, "error");
    execution.tool_call_id = Some("new-call-after-deletion".into());
    assert_eq!(execute(&execution, &store).status, "error");
    assert_eq!(
        std::fs::read_to_string(report).unwrap(),
        "preserve after journal deletion"
    );
}

#[test]
fn bash_sdk_unsigned_lifetime_edit_cannot_enable_a_new_invocation() {
    let (_root, request) = tests::fixture();
    let (store, envelope) = policy_store(&request);
    let mut execution = invocation(&request, &envelope);
    assert_eq!(execute(&execution, &store).status, "ok");
    Connection::open(execution.authorization.store_path()).unwrap().execute(
        "UPDATE guard_bash_invocations SET payload=json_set(payload,'$.acknowledged',json('true'))",
        [],
    ).unwrap();
    let report = Path::new(&request.home_dir).join("maintenance-report.tsv");
    std::fs::write(&report, "preserve after forged acknowledgement").unwrap();
    assert_eq!(ack(&execution, &store, 0).status, "error");
    execution.tool_call_id = Some("new-call-after-forgery".into());
    assert_eq!(execute(&execution, &store).status, "error");
    assert_eq!(
        std::fs::read_to_string(report).unwrap(),
        "preserve after forged acknowledgement"
    );
}
