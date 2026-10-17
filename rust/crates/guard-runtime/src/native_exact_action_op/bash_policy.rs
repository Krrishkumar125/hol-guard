//! Current policy is separate from captured code identity and saved consent.

use std::time::Instant;

use guard_command::bash_approval::graph::Graph;
use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use guard_contracts::{NativeBashCaptureV1, PreToolResultV1};
use serde_json::json;

use crate::policy_enforcement::{apply_pre_tool_policy, AdmittedPolicySnapshot};

/// This is a risk assessment, never an execution or grant receipt. The launch
/// owner must repeat it with the currently admitted generation at commit.
pub(crate) struct Assessment {
    pub(crate) decisions: Vec<PreToolResultV1>,
}

impl Assessment {
    pub(crate) fn has_hard_deny(&self) -> bool {
        self.decisions
            .iter()
            .any(|result| matches!(result.minimum_action.as_str(), "block" | "sandbox-required"))
    }
}

pub(crate) fn assess(
    graph: &Graph,
    request: &NativeBashCaptureV1,
    snapshot: &AdmittedPolicySnapshot,
    deadline: Instant,
) -> Result<Assessment, String> {
    let mut decisions = Vec::with_capacity(1 + graph.invocations.len() + graph.writes.len());
    let mut judge = |command: &str| -> Result<(), String> {
        if Instant::now() >= deadline {
            return Err("bash_policy_deadline_exceeded".into());
        }
        let payload = json!({"tool_name":"bash","tool_input":{"command":command}});
        let intrinsic = evaluate_pre_tool_envelope_with_execution_context(
            &request.harness,
            "PreToolUse",
            &payload,
            snapshot.command_extensions.as_ref(),
            Some(deadline),
            PathContext {
                home_dir: Some(&request.home_dir),
                cwd: Some(&request.cwd),
                shell_home_matches: true,
                ..PathContext::default()
            },
            Some(&request.execution_environment),
        );
        decisions.push(apply_pre_tool_policy(snapshot, &payload, intrinsic)?);
        Ok(())
    };
    judge(&request.command)?;
    for invocation in &graph.invocations {
        let command = invocation
            .operation
            .argv
            .iter()
            .map(|value| quote(value))
            .collect::<Vec<_>>()
            .join(" ");
        judge(&command)?;
    }
    for effect in &graph.writes {
        let redirect = if effect.redirect.append { ">>" } else { ">" };
        judge(&format!(": {redirect} {}", quote(&effect.redirect.path)))?;
    }
    if Instant::now() >= deadline {
        return Err("bash_policy_deadline_exceeded".into());
    }
    Ok(Assessment { decisions })
}

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}
