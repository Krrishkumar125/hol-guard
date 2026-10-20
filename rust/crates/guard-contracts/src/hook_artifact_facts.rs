//! `HookArtifactFacts` - wire contract for the resident op that derives the
//! per-artifact facts the native configured-policy action reads.
//!
//! The facts themselves are `PolicyArtifactFactsV1`, the struct the compose
//! op already takes. This op exists so the caller stops deriving them: it
//! ships the artifact as it stands and the resident reads the metadata.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const HOOK_ARTIFACT_FACTS_REQUEST_SCHEMA: &str = "guard-hook-artifact-facts-request.v1";
/// Schema discriminator for the result.
pub const HOOK_ARTIFACT_FACTS_RESULT_SCHEMA: &str = "guard-hook-artifact-facts-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const HOOK_ARTIFACT_FACTS_FEATURE: &str = "hook-artifact-facts-v1";
/// Largest canonical request serialization the op will accept.
pub const HOOK_ARTIFACT_FACTS_MAX_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HookArtifactFactsRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    /// `GuardArtifact.artifact_type`.
    pub artifact_type: String,
    /// `GuardArtifact.metadata`, unchanged.
    #[serde(default)]
    pub metadata: Value,
    /// The artifact, publisher or harness override the config resolved, which
    /// is a settings lookup rather than a reading of the artifact.
    #[serde(default)]
    pub configured_override: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HookArtifactFactsResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_hook_artifact_facts_*` codes.
    pub code: String,
    /// The derived `PolicyArtifactFactsV1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
