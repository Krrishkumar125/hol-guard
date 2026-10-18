//! Authoritative execution deduplication in guard.db, not an allowlist.
//! A reservation and its authenticated consent claim share one transaction.

use guard_contained_process::CapturedOutput;
use guard_contracts::{
    ClaimApprovalReuseDecisionsRequestV1, NativeBashAuthorizationKindV1 as Authorization,
    NativeBashCompletionSummaryV1, NativeBashOperationStateV1 as State, NativeBashOperationV1,
};
use guard_policy_snapshot::local_authority_integrity::{
    sign_local_authority_payload, verify_local_authority_payload,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};

use super::policy_store_authority;
use super::PolicySnapshotStore;

const PURPOSE: &str = "guard-native-bash-operation-v1";
const MAX_RECORD_BYTES: usize = 16 * 1024;
const SCHEMA: &str = include_str!(
    "../../../../src/codex_plugin_scanner/guard/schemas/native_bash_operations_v1.sql"
);

pub(crate) struct BashOperationJournal<'store> {
    connection: Connection,
    store: &'store PolicySnapshotStore,
    operation_id: &'store str,
    artifact_hash: &'store str,
}

impl<'store> BashOperationJournal<'store> {
    pub(crate) fn open(
        store: &'store PolicySnapshotStore,
        store_path: &str,
        operation_id: &'store str,
        artifact_hash: &'store str,
    ) -> Result<Self, String> {
        if !guard_contracts::native_bash_operation_id_is_valid(operation_id) {
            return Err("native_bash_operation_id_invalid".into());
        }
        store.require_store_path(store_path)?;
        let connection =
            Connection::open_with_flags(store_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)
                .map_err(|_| "native_bash_operation_store_unavailable")?;
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| "native_bash_operation_store_unavailable")?;
        // A committed reservation must reach durable storage before effects.
        connection
            .execute_batch("PRAGMA synchronous=FULL;")
            .map_err(|_| "native_bash_operation_store_unavailable")?;
        connection
            .execute_batch(SCHEMA)
            .map_err(|_| "native_bash_operation_store_unavailable")?;
        let journal = Self {
            connection,
            store,
            operation_id,
            artifact_hash,
        };
        journal
            .require_authority()
            .map_err(|_| "native_bash_operation_authority_changed")?;
        Ok(journal)
    }

    fn require_authority(&self) -> rusqlite::Result<()> {
        if self
            .store
            .authority_changed
            .load(std::sync::atomic::Ordering::SeqCst)
            || !policy_store_authority::authority_unchanged_fenced(self.store)
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        Ok(())
    }

    pub(crate) fn read(&self) -> rusqlite::Result<Option<NativeBashOperationV1>> {
        self.require_authority()?;
        // Bound allocations even when the database has been modified externally.
        let row: Option<(Option<String>, Option<String>)> = self
            .connection
            .query_row(
                "SELECT CASE WHEN length(payload)<=16384 THEN payload END,
                    CASE WHEN length(integrity)<=4096 THEN integrity END
               FROM guard_bash_operations WHERE operation_id=?1",
                [self.operation_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((Some(payload), Some(integrity))) = row else {
            return if row.is_none() {
                Ok(None)
            } else {
                Err(rusqlite::Error::InvalidQuery)
            };
        };
        let payload: Value =
            serde_json::from_str(&payload).map_err(|_| rusqlite::Error::InvalidQuery)?;
        let integrity: Value =
            serde_json::from_str(&integrity).map_err(|_| rusqlite::Error::InvalidQuery)?;
        let key_id = guard_policy_snapshot::verifier_key_id(&self.store.verifier_key);
        if verify_local_authority_payload(
            &payload,
            &integrity,
            Some(&self.store.verifier_key),
            Some(&key_id),
            PURPOSE,
        )
        .status
            != "valid"
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let record: NativeBashOperationV1 =
            serde_json::from_value(payload).map_err(|_| rusqlite::Error::InvalidQuery)?;
        if record.operation_id != self.operation_id
            || record.artifact_hash != self.artifact_hash
            || (record.state == State::Completed) != record.completion.is_some()
            || (matches!(record.state, State::Dispatched | State::Completed)
                && !record.dispatch_acknowledged)
            || (record.state == State::Claimed && record.dispatch_acknowledged)
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        Ok(Some(record))
    }

    fn encode(&self, record: &NativeBashOperationV1) -> rusqlite::Result<(String, String)> {
        self.require_authority()?;
        let payload = serde_json::to_value(record).map_err(|_| rusqlite::Error::InvalidQuery)?;
        let timestamp: String = self.connection.query_row(
            "SELECT strftime('%Y-%m-%dT%H:%M:%f+00:00','now')",
            [],
            |row| row.get(0),
        )?;
        let signed = sign_local_authority_payload(
            &payload,
            &self.store.verifier_key,
            &guard_policy_snapshot::verifier_key_id(&self.store.verifier_key),
            PURPOSE,
            &timestamp,
        )
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let integrity = json!({
            "integrity_version":signed.integrity_version, "payload_hash":signed.payload_hash,
            "payload_mac":signed.payload_mac, "integrity_key_id":signed.integrity_key_id,
            "signed_at":signed.signed_at,
        });
        let payload = serde_json::to_string(&payload).map_err(|_| rusqlite::Error::InvalidQuery)?;
        if payload.len() > MAX_RECORD_BYTES {
            return Err(rusqlite::Error::InvalidQuery);
        }
        Ok((payload, integrity.to_string()))
    }

    pub(crate) fn reserve(
        &self,
        claim: &ClaimApprovalReuseDecisionsRequestV1,
    ) -> Result<bool, String> {
        crate::claim_approval_reuse_op::claim_now_then(claim, &self.connection, &mut |_| {
            self.insert(Authorization::SavedGrant)
        })
        .map(|record| record.is_some())
    }

    /// The fenced launch owner has established that every current decision
    /// permits this action. No approval row is created, matched or consumed.
    pub(crate) fn reserve_allowed(&self) -> rusqlite::Result<bool> {
        self.connection.execute_batch("BEGIN IMMEDIATE")?;
        match self.insert(Authorization::CurrentPolicy) {
            Ok(Some(())) => {
                self.connection.execute_batch("COMMIT")?;
                Ok(true)
            }
            Ok(None) => {
                self.connection.execute_batch("ROLLBACK")?;
                Ok(false)
            }
            Err(error) => {
                let _ = self.connection.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }

    fn insert(&self, authorization: Authorization) -> rusqlite::Result<Option<()>> {
        // Always inside BEGIN IMMEDIATE, including the saved-grant claim.
        if self.read()?.is_some() {
            return Ok(None);
        }
        let record = NativeBashOperationV1 {
            operation_id: self.operation_id.into(),
            artifact_hash: self.artifact_hash.into(),
            authorization,
            state: State::Claimed,
            dispatch_acknowledged: false,
            completion: None,
        };
        let (payload, integrity) = self.encode(&record)?;
        self.connection.execute(
            "INSERT INTO guard_bash_operations(operation_id,payload,integrity) VALUES(?1,?2,?3)",
            params![self.operation_id, payload, integrity],
        )?;
        Ok(Some(()))
    }

    pub(crate) fn dispatched(&self) -> rusqlite::Result<NativeBashOperationV1> {
        self.transition(State::Dispatched, true, None)
    }

    pub(crate) fn uncertain(&self, dispatched: bool) -> rusqlite::Result<NativeBashOperationV1> {
        self.transition(State::Uncertain, dispatched, None)
    }

    pub(crate) fn completed(
        &self,
        output: &CapturedOutput,
    ) -> rusqlite::Result<NativeBashOperationV1> {
        self.transition(
            State::Completed,
            true,
            Some(NativeBashCompletionSummaryV1 {
                exit_code: output.exit_code,
                output_limited: output.output_limited,
                timed_out: output.timed_out,
                cancelled: output.cancelled,
                stdout_sha256: guard_policy_snapshot::digest_bytes(&output.stdout),
                stderr_sha256: guard_policy_snapshot::digest_bytes(&output.stderr),
            }),
        )
    }

    fn transition(
        &self,
        state: State,
        dispatched: bool,
        completion: Option<NativeBashCompletionSummaryV1>,
    ) -> rusqlite::Result<NativeBashOperationV1> {
        self.connection.execute_batch("BEGIN IMMEDIATE")?;
        let result =
            (|| {
                let mut record = self.read()?.ok_or(rusqlite::Error::InvalidQuery)?;
                let valid = match state {
                    State::Dispatched => record.state == State::Claimed,
                    State::Completed => record.state == State::Dispatched,
                    State::Uncertain => matches!(record.state, State::Claimed | State::Dispatched),
                    State::Claimed => false,
                };
                if !valid || (record.dispatch_acknowledged && !dispatched) {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                record.state = state;
                record.dispatch_acknowledged = dispatched;
                record.completion = completion;
                let (payload, integrity) = self.encode(&record)?;
                if self.connection.execute(
                "UPDATE guard_bash_operations SET payload=?1,integrity=?2 WHERE operation_id=?3",
                params![payload, integrity, self.operation_id],
            )? != 1 { return Err(rusqlite::Error::InvalidQuery); }
                Ok(record)
            })();
        match result {
            Ok(record) => {
                self.connection.execute_batch("COMMIT")?;
                Ok(record)
            }
            Err(error) => {
                let _ = self.connection.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }
}
