//! A captured benign helper cannot launder a disabled command permission.

use super::*;
use crate::policy_enforcement::{
    tests::{policy, snapshot},
    AdmittedPolicySnapshot,
};
use guard_contracts::NativeCommandControlBindingV1;
use serde_json::json;

#[test]
fn bash_nested_extension_deny_survives_allowed_parent_and_sibling() {
    let (_root, request) = tests::fixture();
    let cwd = Path::new(&request.cwd);
    let helper = cwd.join("aws");
    // This is a local fake helper. No network client or command is executed.
    std::fs::write(&helper, "#!/bin/bash\nprintf 'local fixture only\\n'\n").unwrap();
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(
        cwd.join("maintenance.sh"),
        "aws s3 ls\nprintf 'allowed sibling\\n'\n",
    )
    .unwrap();
    let captured = capture_for_launch(&request, &tests::admitted("allow")).unwrap();
    let identity = captured.subject.identity_sha256().unwrap();

    let program = guard_command::native_command_program::packaged_command_program().unwrap();
    let mut binding: NativeCommandControlBindingV1 = serde_json::from_value(json!({
        "schema":"guard.native-command-control-binding.v1",
        "program_digest":program.program_digest,
        "catalog_digest":program.catalog_digest,
        "trust_digest":program.trust_digest,
        "health":"protected", "revision":1, "managed_revision":0, "effective_digest":"",
        "layers":[{
            "schema_version":"1.0.0", "kind":"local-admin", "catalog_digest":program.catalog_digest,
            "global_lockdown":false,
            "controls":[{"target_kind":"permission","target_id":"command.storage.aws-s3.permission.ls","state":"disabled"}]
        }]
    })).unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    let mut changed = snapshot(policy("allow"));
    changed.command_extensions = Some(binding);
    let changed = AdmittedPolicySnapshot::new(changed).unwrap();
    let assessment = super::super::super::bash_policy::assess(
        &captured.graph,
        &request,
        &changed,
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap();
    assert_ne!(assessment.decisions[0].minimum_action, "block");
    assert!(assessment
        .decisions
        .iter()
        .skip(1)
        .any(|decision| decision.minimum_action == "block"
            && decision.reason_code == "native_command_permission_disabled"));
    assert!(assessment.has_hard_deny());
    assert_eq!(
        inspect(&request).unwrap().identity_sha256().unwrap(),
        identity
    );
    assert!(
        matches!(capture_for_launch(&request, &changed), Err(reason) if reason == "bash_current_policy_denied")
    );
}
