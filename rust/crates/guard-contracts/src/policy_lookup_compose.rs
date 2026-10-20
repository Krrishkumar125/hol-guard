//! `PolicyLookupCompose` - wire contract for the resident op that picks which
//! saved decision a multi-probe policy lookup actually returns.
//!
//! A remembered-decision lookup probes the artifact itself, then any exact
//! command the memory pattern names, then the pattern's own artifact. Each
//! probe may come back with its own saved decision, and the answer the hook
//! acts on is the most restrictive of them. Choosing between saved decisions
//! is a verdict, so the resident owns it: the caller ships the probes it ran
//! and reads back the one that won, together with the authority revision the
//! probes agreed on.
//!
//! The op is pure. It reads no store and consumes no one-shot row; every
//! probe has already been resolved by the time the caller composes them.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const POLICY_LOOKUP_COMPOSE_REQUEST_SCHEMA: &str = "guard-policy-lookup-compose-request.v1";
/// Schema discriminator for the result.
pub const POLICY_LOOKUP_COMPOSE_RESULT_SCHEMA: &str = "guard-policy-lookup-compose-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const POLICY_LOOKUP_COMPOSE_FEATURE: &str = "policy-lookup-compose-v1";
/// Largest canonical request serialization the op will accept.
pub const POLICY_LOOKUP_COMPOSE_MAX_BYTES: usize = 4 * 1024 * 1024;

/// One resolved probe, exactly as `PolicyDecisionLookupResult` carries it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct PolicyLookupCandidateV1 {
    /// The saved decision this probe found, or `null` for a probe that found
    /// none. A probe with no decision can still carry ignored integrity.
    #[serde(default)]
    pub decision: Option<Value>,
    /// Local integrity the probe had to ignore to answer at all.
    #[serde(default)]
    pub ignored_local_integrity: Option<Value>,
    /// The trust status the probe answered under.
    pub trust_status: Value,
    /// The approval-authority revision the probe read.
    pub authority_revision: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyLookupComposeRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    /// The probes to compose, in the order they were run. The first is the
    /// direct artifact lookup, which is what an empty composition falls back
    /// to. Required: an empty list is refused rather than read as "no match".
    pub candidates: Vec<PolicyLookupCandidateV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyLookupComposeResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_policy_lookup_compose_*` failure codes.
    pub code: String,
    /// The composed `PolicyDecisionLookupResult`, or absent on an error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
