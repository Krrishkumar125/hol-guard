//! Resident preparation and execution of an exact captured Bash invocation.
//! These operations do not by themselves advertise a host delivery capability.

use serde::{Deserialize, Serialize};

use crate::{
    ClaimApprovalReuseDecisionsRequestV1, GuardHookEnvelopeV2, NativeBashCaptureV1,
    NativeBashSubjectV1, PreToolResultV1,
};

pub const NATIVE_BASH_PREPARE_REQUEST_SCHEMA: &str = "guard-native-bash-prepare-request.v1";
pub const NATIVE_BASH_PREPARE_RESULT_SCHEMA: &str = "guard-native-bash-prepare-result.v1";
pub const NATIVE_BASH_EXECUTE_REQUEST_SCHEMA: &str = "guard-native-bash-execute-request.v1";
pub const NATIVE_BASH_EXECUTE_RESULT_SCHEMA: &str = "guard-native-bash-execute-result.v1";
pub const NATIVE_BASH_HOST_REQUEST_SCHEMA: &str = "guard-native-bash-host-request.v1";
pub const NATIVE_BASH_HOST_RESULT_SCHEMA: &str = "guard-native-bash-host-result.v1";
pub const NATIVE_BASH_LAUNCH_MAX_REQUEST_BYTES: usize = 512 * 1024;
pub const NATIVE_BASH_PREPARE_MAX_BUDGET_MS: u64 = 5000;
pub const NATIVE_BASH_EXECUTE_MAX_TIMEOUT_MS: u64 = 120_000;

/// Local sink input. The earlier hook's capture fields are intentions only;
/// actual cwd, HOME, environment and mask are replaced in the sink process.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBashHostRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub capture: NativeBashCaptureV1,
    pub budget_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBashHostResultV1 {
    pub schema: String,
    pub request_id: String,
    pub request_sha256: String,
    pub status: String,
    pub code: String,
    pub payload: Option<NativeBashCaptureV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBashPrepareRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub capture: NativeBashCaptureV1,
    pub envelope: GuardHookEnvelopeV2,
    pub budget_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBashPreparedV1 {
    pub subject: NativeBashSubjectV1,
    pub artifact_id: String,
    pub artifact_hash: String,
    pub assessment: Vec<PreToolResultV1>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBashPrepareResultV1 {
    pub schema: String,
    pub request_id: String,
    pub request_sha256: String,
    pub status: String,
    pub code: String,
    pub payload: Option<NativeBashPreparedV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBashExecuteRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub capture: NativeBashCaptureV1,
    pub envelope: GuardHookEnvelopeV2,
    pub claim: ClaimApprovalReuseDecisionsRequestV1,
    pub timeout_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBashCompletedV1 {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub output_limited: bool,
    pub timed_out: bool,
    pub cancelled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBashExecuteResultV1 {
    pub schema: String,
    pub request_id: String,
    pub request_sha256: String,
    /// Transport/owner result; a nonzero payload exit is still an execution failure.
    pub status: String,
    pub code: String,
    /// Consent was spent or matched. This never implies dispatch or success.
    pub grant_claimed: bool,
    /// The native source protocol received S; absence means start is unproven.
    pub dispatch_acknowledged: bool,
    pub payload: Option<NativeBashCompletedV1>,
}
