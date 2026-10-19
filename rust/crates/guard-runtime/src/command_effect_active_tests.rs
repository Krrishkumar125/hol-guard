use super::*;
use guard_command::{parse_command, CommandModelRequestV1};
use serde_json::{json, Value};

fn request(controls: &CompiledNativeCommandControls) -> CommandEffectRequestV1 {
    let command = "vttforge init example";
    let model = parse_command(&CommandModelRequestV1 {
        command: command.into(),
        dialect: "posix".into(),
        transport: "shell_string".into(),
        extraction_provenance: "guard-shell".into(),
    })
    .unwrap();
    let result = guard_command::pretool::evaluate_pre_tool_envelope_with_execution_context(
        "claude-code",
        "PreToolUse",
        &json!({"tool_name":"Bash","tool_input":{"command":command}}),
        Some(controls),
        None,
        Default::default(),
        None,
    );
    let mut evidence = serde_json::to_value(result).unwrap();
    evidence["command_model"] = serde_json::to_value(&model).unwrap();
    serde_json::from_value(json!({
        "schema":COMMAND_EFFECT_REQUEST_SCHEMA,"request_id":"active-command",
        "command_text":command,"canonical_command":model,
        "native_extension_evidence":evidence,"control_snapshot":controls.control_binding(),
    }))
    .unwrap()
}

#[test]
fn optional_command_effect_uses_admitted_catalog_and_rejects_tampering() {
    let home = std::env::temp_dir().join(format!(
        "guard-command-effect-active-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&home).unwrap();
    let home = home.canonicalize().unwrap();
    let controls = crate::contributed_mcp_catalog_test_support::controls_for(
        &home,
        false,
        &["command.vttforge"],
        &["command.vttforge"],
    );
    let active = request(&controls);
    let result = evaluate(&active, Some(&controls)).unwrap();
    assert_eq!(result["controlling_rule_id"], "command.vttforge.init");
    assert_eq!(result["minimum_action"], "review");
    // Request layers cannot authorize optional metadata without a capture.
    assert!(evaluate(&active, None).is_err());
    let batch: CommandEffectBatchRequestV1 = serde_json::from_value(json!({
        "schema":COMMAND_EFFECT_BATCH_REQUEST_SCHEMA,"request_id":"active-batch","items":[active],
    }))
    .unwrap();
    let result: Value =
        serde_json::from_slice(&batch_in(&batch, Some(&controls)).unwrap()).unwrap();
    assert_eq!(result["items"][0]["status"], "ok");
    let mut tampered = batch.items[0].clone();
    tampered.control_snapshot["program_digest"] = json!("0".repeat(64));
    assert!(evaluate(&tampered, Some(&controls)).is_err());
    let inactive = crate::contributed_mcp_catalog_test_support::controls_for(
        &home,
        false,
        &["command.vttforge"],
        &[],
    );
    let result = evaluate(&request(&inactive), Some(&inactive)).unwrap();
    assert!(result["extension_observations"]
        .as_array()
        .unwrap()
        .iter()
        .all(|observation| observation["extension_id"] != "command.vttforge"));
    std::fs::remove_dir_all(home).unwrap();
}
