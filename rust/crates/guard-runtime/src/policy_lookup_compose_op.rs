//! `PolicyLookupCompose` - resident op that picks the saved decision a
//! multi-probe policy lookup returns.
//!
//! Faithful port of `store_policy._most_restrictive_policy_lookup`. A
//! remembered-decision lookup runs up to three probes - the artifact itself,
//! each exact command the memory pattern names, then the pattern's own
//! artifact - and each probe may come back with a saved decision of its own.
//! Deciding which of those the hook acts on is a verdict about the user's own
//! remembered rules, so it belongs with the action lattice that orders them
//! rather than in the store that ran the queries.
//!
//! The composition keeps the Python shape exactly:
//!
//!   * the first probe is the standing answer, and a later probe replaces it
//!     only on a strictly higher action severity, so an equally severe later
//!     match never displaces an earlier one;
//!   * an unreadable or absent action is read as `block`, so an unrecognized
//!     saved action is treated as the most restrictive thing it could be;
//!   * ignored local integrity is taken from the first probe that reports any,
//!     in probe order, including probes that found no decision at all, and is
//!     not re-read from whichever probe ends up winning;
//!   * the authority revision is the one every probe agreed on, and `-1` when
//!     they disagree, which is the value a caller treats as no single
//!     authority; the winning decision carries it as
//!     `_approval_authority_revision`;
//!   * the trust status is the winning probe's own.
//!
//! The op is pure: it reads no store, so composing cannot consume a one-shot
//! row that the probes already resolved.

use guard_contracts::{
    PolicyLookupCandidateV1, PolicyLookupComposeRequestV1, PolicyLookupComposeResultV1,
    POLICY_LOOKUP_COMPOSE_MAX_BYTES, POLICY_LOOKUP_COMPOSE_RESULT_SCHEMA,
};
use serde_json::Value;

use crate::mcp_tool_policy_lookup::most_restrictive;
use crate::package_authority_op::request_digest_with_limit;

/// `store_policy._most_restrictive_policy_lookup` refuses an empty list.
const EMPTY: &str = "native_policy_lookup_compose_empty";

pub(crate) fn evaluate_policy_lookup_compose_request(
    request: &PolicyLookupComposeRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, POLICY_LOOKUP_COMPOSE_MAX_BYTES)
        .map_err(|_| "native_policy_lookup_compose_too_large".to_owned())?;
    let (status, code, payload) = match evaluate(request) {
        Some(payload) => ("ok", "ok", Some(payload)),
        None => ("error", EMPTY, None),
    };
    crate::encode_response(&PolicyLookupComposeResultV1 {
        schema: POLICY_LOOKUP_COMPOSE_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        payload,
    })
}

/// The composed lookup, or `None` when no probe was supplied.
///
/// The ordering itself is `mcp_tool_policy_lookup::most_restrictive`, the
/// composition the MCP tool-call lane already runs against the same Python
/// recording. Keeping one composer means the hook lane and the tool-call lane
/// cannot drift into disagreeing about which saved rule a user is under.
pub(crate) fn evaluate(request: &PolicyLookupComposeRequestV1) -> Option<Value> {
    let lookups = wire_probes(&request.candidates)?;
    most_restrictive(&lookups)
}

/// The probes as the composer reads them. Each field is named exactly as the
/// composer looks it up, and an absent decision or integrity note is the null
/// the composer treats as "this probe found none".
fn wire_probes(candidates: &[PolicyLookupCandidateV1]) -> Option<Vec<Value>> {
    candidates
        .iter()
        .map(|candidate| serde_json::to_value(candidate).ok())
        .collect()
}

#[cfg(test)]
#[path = "policy_lookup_compose_op_tests.rs"]
mod tests;
