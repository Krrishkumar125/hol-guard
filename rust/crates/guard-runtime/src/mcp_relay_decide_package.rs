//! The package check the proxy runs before the tool policy.
//!
//! The proxy asks `extract_package_intent_request` whether a call installs or
//! runs a package (`runtime_mcp.py` `_package_request_artifact`) and sends a
//! call that does through the package policy; a call the parser finds no
//! intent in goes on with `package_present: false`. The resident asks the same
//! parser with the inputs the proxy hands it: the tool name and the arguments
//! as the host sent them, their `_command_argument`, the proxy's workspace, no
//! home directory and the proxy's own `PATH` (`_resident_environment`). An
//! input the two could read differently defers.
//!
//! The intent itself is the answer, because the package lane decides the call
//! from it (`mcp_relay_decide_package_leg.rs`). It is not wire-serializable --
//! `to_dict` sanitizes the raw spec and drops the source url -- so the relay
//! and the resident each parse it in process from the same inputs rather than
//! shipping one to the other.
//!
//! The parser's answer does not depend on key order: it finds an intent when
//! any candidate command has one, and the candidates are the same set in any
//! order.

use std::collections::BTreeMap;
use std::path::Path;

use guard_command::mcp_tool_signals::risk_arguments;
use guard_command::package_intent_common::PackageIntent;
use guard_command::package_intent_parser::extract_package_intent_request;
use serde_json::{Map, Value};

use super::McpRelayDecideRequestV1;
use crate::context_digest::python_strip;

/// A claimed call the gate now finds a package intent in. The claim is held
/// only for a call with none, so the claim rolls back rather than answering a
/// package request the lane never routed it for.
pub(super) const PACKAGE_CLAIMED: &str = "mcp_relay_package_claimed";
/// The proxy strips a name or a command the parser would read unstripped.
pub(super) const PACKAGE_AMBIGUOUS: &str = "mcp_relay_package_ambiguous";
/// The workspace is not in the form `str(Path(...).resolve())` prints, so the
/// proxy could hand the parser another path.
pub(super) const WORKSPACE_UNNORMALIZED: &str = "mcp_relay_workspace_unnormalized";

/// `_command_argument`: the argument keys the proxy reads as the command.
const COMMAND_KEYS: [&str; 4] = ["command", "cmd", "shell_command", "shellCommand"];

/// The package request the proxy's check finds in the call, or `None` for the
/// call it takes straight to the tool policy.
pub(super) fn package_gate(
    request: &McpRelayDecideRequestV1,
) -> Result<Option<PackageIntent>, &'static str> {
    let normalized;
    let workspace = match request.workspace.as_deref() {
        Some(workspace) => match resolved_path_text(workspace) {
            Some(resolved) => {
                normalized = resolved;
                Some(Path::new(normalized.as_str()))
            }
            None => return Err(WORKSPACE_UNNORMALIZED),
        },
        None => None,
    };
    let tool = request.build.tool_name.as_str();
    let arguments = risk_arguments(&request.arguments);
    // The proxy strips with `str.strip` and the parser with `str::trim`; they
    // differ only on the separators U+001C to U+001F.
    if python_strip(tool) != tool.trim() || !strips_agree(&arguments) {
        return Err(PACKAGE_AMBIGUOUS);
    }
    let environment = request
        .path
        .as_ref()
        .filter(|path| !path.is_empty())
        .map(|path| BTreeMap::from([("PATH".to_owned(), path.clone())]));
    Ok(extract_package_intent_request(
        tool,
        &arguments,
        command_argument(arguments.as_object()),
        workspace,
        None,
        environment.as_ref(),
    ))
}

/// `_command_argument`: the first command key holding a non-blank string,
/// stripped.
fn command_argument(arguments: Option<&Map<String, Value>>) -> Option<&str> {
    let arguments = arguments?;
    COMMAND_KEYS.iter().find_map(|key| {
        let command = python_strip(arguments.get(*key)?.as_str()?);
        (!command.is_empty()).then_some(command)
    })
}

/// Whether both strips agree on every string in `value`.
fn strips_agree(value: &Value) -> bool {
    match value {
        Value::String(text) => python_strip(text) == text.trim(),
        Value::Array(items) => items.iter().all(strips_agree),
        Value::Object(map) => map.values().all(strips_agree),
        Value::Null | Value::Bool(_) | Value::Number(_) => true,
    }
}

/// The absolute path `str(Path(path))` prints, or `None` for a path the proxy
/// could hand the parser as another path.
///
/// An empty component (`//`, a trailing `/`) and a `.` component name the
/// directory the component before them already named, so dropping them is
/// what `Path` itself prints and cannot send the parser to another directory.
/// A `..` component is read against whatever the component before it resolves
/// to, which only the filesystem knows, so a path carrying one is still left
/// to the proxy, as is a relative path or one holding a NUL.
fn resolved_path_text(path: &str) -> Option<String> {
    let rest = path.strip_prefix('/')?;
    if path.contains('\0') {
        return None;
    }
    let mut parts: Vec<&str> = Vec::new();
    for part in rest.split('/') {
        if part == ".." {
            return None;
        }
        if !part.is_empty() && part != "." {
            parts.push(part);
        }
    }
    Some(format!("/{}", parts.join("/")))
}

#[cfg(test)]
#[path = "mcp_relay_decide_package_tests.rs"]
mod tests;
