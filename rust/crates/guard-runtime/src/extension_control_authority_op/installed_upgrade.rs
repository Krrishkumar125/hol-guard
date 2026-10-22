//! An installed release may replace policy compiled by an older engine, but
//! cannot use that migration to change the user's controls or pack selection.
use super::layers::{layers_from_json, layers_from_values, layers_to_values};
use super::records::{
    canonical, field, query_row, row_text, tampered, verify_record, Res, Row, SNAPSHOT_PURPOSE,
};
use super::Ctx;
use guard_command::native_command_program::{NativeCommandProgram, PackAdmissionBudget};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

const REFUSED: &str = "installed command pack upgrade is not authorized";
const UNOPENED: &str = "installed command pack upgrade record did not open";
const SNAPSHOT_ROW: &str = "installed command pack upgrade snapshot does not match its row";
const NO_ACTIVATION: &str = "installed command pack upgrade has no active command pack";
const ACTIVATION_CHANGED: &str = "installed command pack upgrade activation record changed";
const BINDING: &str = "installed command pack upgrade snapshot binding mismatch";
const NO_KEY: &str = "installed command pack upgrade cannot read the policy verifier key";
const RELEASE: &str = "installed command pack upgrade release evidence is not usable";
const FLOOR: &str = "installed command pack upgrade floor transition is not usable";
const SAME_ENGINE: &str = "installed command pack upgrade is already on the installed engine";
const IDENTITY: &str = "installed command pack upgrade identity mismatch";
const PROGRAM: &str = "installed command pack upgrade program is not in the pack cache";
const UNREADABLE: &str = "installed command pack upgrade release artifacts are not readable";
const PROGRAM_BINDING: &str = "installed command pack upgrade program binding mismatch";
const CANDIDATE: &str = "installed command pack upgrade candidate is incomplete";

/// Whether the head snapshot's retained pack binding names `activation`.
///
/// A catalog migration commits no pack record of its own, and only since the
/// release that introduced this upgrade does it carry the binding the head
/// already had. An install whose catalog last moved under an older runtime
/// therefore has an unbound head above an activation row that is still
/// bound. That row is already pinned by record, digest and mac, and this
/// upgrade seals the binding the head is missing, so an unbound head is
/// rebound here rather than refused forever: refusing it leaves the
/// authority stale and every hook on the install closed.
pub(super) fn binding_names(payload: &Map<String, Value>, activation: &Value) -> bool {
    let binding = field(payload, "command_pack_record_digest");
    binding.is_null() || binding == activation
}

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn open(value: &Value, key: &[u8], directory: &Path) -> Res<Value> {
    let result = crate::pack_lifecycle::evaluate(&json!({
        "kind":"record", "operation":"open", "purpose":"activation",
        "key":hex::encode(key), "directory":directory,
        "record":value["record"], "digest":value["digest"], "mac":value["mac"],
    }))
    .map_err(|_| tampered(UNOPENED))?;
    if !result["fault"].is_null() || !result["selected"].is_array() {
        return Err(tampered(UNOPENED));
    }
    Ok(result)
}

impl Ctx<'_> {
    pub(super) fn installed_upgrade_digest(&self, source: &Row) -> Res<Option<String>> {
        let migration = self
            .request
            .catalog_migration
            .as_ref()
            .ok_or_else(|| tampered(REFUSED))?;
        let Some(evidence) = &migration.installed_upgrade else {
            return Ok(None);
        };
        let key = self.require_key()?;
        let payload = verify_record(
            &row_text(source, "snapshot_json")?,
            &row_text(source, "snapshot_digest")?,
            &row_text(source, "snapshot_mac")?,
            key,
            SNAPSHOT_PURPOSE,
        )?;
        let stored_layers = row_text(source, "layers_json")?;
        let stored_catalog = row_text(source, "catalog_digest")?;
        if field(&payload, "layers_json").as_str() != Some(stored_layers.as_str())
            || field(&payload, "catalog_digest").as_str() != Some(stored_catalog.as_str())
        {
            return Err(tampered(SNAPSHOT_ROW));
        }
        let mut retained = layers_from_json(&stored_layers)?;
        let target = self.catalog_digest()?;
        for layer in &mut retained {
            layer.catalog_digest = target.to_owned();
        }
        let requested_layers = layers_from_values(&migration.layers)?;
        if layers_to_values(&retained) != layers_to_values(&requested_layers) {
            return Err(tampered("installed command pack upgrade changed controls"));
        }
        let current = query_row(self.connection,
            "select record_json, record_digest, record_mac from extension_command_pack_activation where singleton=1", [],
        )?.ok_or_else(|| tampered(NO_ACTIVATION))?;
        for (wire, column) in [
            ("record", "record_json"),
            ("digest", "record_digest"),
            ("mac", "record_mac"),
        ] {
            if evidence["previous"][wire] != row_text(&current, column)? {
                return Err(tampered(ACTIVATION_CHANGED));
            }
        }
        if !binding_names(&payload, &evidence["previous"]["digest"]) {
            return Err(tampered(BINDING));
        }
        let policy_key = crate::policy_store::read_verifier_key(
            &Path::new(&self.request.guard_home).join("native-runtime"),
        )
        .map_err(|_| tampered(NO_KEY))?;
        let directory = Path::new(&self.request.guard_home).join("native-runtime/command-packs");
        let previous_open = open(&evidence["previous"], &policy_key, &directory)?;
        let candidate_open = open(&evidence["candidate"], &policy_key, &directory)?;
        if previous_open["selected"] != candidate_open["selected"] {
            return Err(tampered("installed command pack upgrade changed selection"));
        }
        let previous = &previous_open["value"];
        let candidate = &candidate_open["value"];
        let installed = crate::pack_lifecycle::evaluate(&json!({"kind":"installed",
            "runtime_manifest":evidence["release"]["runtime_manifest"],
            "compiler_manifest":evidence["release"]["compiler_manifest"],
            "release_data":evidence["release"]["release_data"]}))
        .map_err(|_| tampered(RELEASE))?;
        let floor = crate::pack_lifecycle::evaluate(
            &json!({"kind":"transition","key":hex::encode(policy_key),
            "floor":evidence["floor"],"candidate":installed,"ancestry":null}),
        )
        .map_err(|_| tampered(FLOOR))?;
        if previous["engine"] == installed["engine"] {
            return Err(tampered(SAME_ENGINE));
        }
        if floor["record"] != evidence["next_floor"]
            || candidate["authority_profile"] != "installed"
            || candidate["engine"] != installed["engine"]
            || candidate["source_sha"] != installed["source"]
            || candidate["root_digest"] != installed["root"]
            || candidate["catalog_digest"] != target
            || candidate["previous_digest"] != evidence["previous"]["digest"]
            || candidate["revision"].as_u64()
                != previous["revision"].as_u64().and_then(|v| v.checked_add(1))
        {
            return Err(tampered(IDENTITY));
        }
        let digest = candidate["program_digest"]
            .as_str()
            .ok_or_else(|| tampered(CANDIDATE))?;
        let program = NativeCommandProgram::from_pack_cache(
            &directory,
            digest,
            PackAdmissionBudget::resident(),
        )
        .map_err(|_| tampered(PROGRAM))?;
        let release: Value = serde_json::from_str(
            evidence["release"]["release_data"]
                .as_str()
                .ok_or_else(|| tampered(RELEASE))?,
        )
        .map_err(|_| tampered(RELEASE))?;
        let set_bytes = guard_secure_fs::read_bounded(
            &directory.join("sets").join(format!("{digest}.json")),
            65536,
        )
        .map_err(|_| tampered(UNREADABLE))?
        .bytes;
        let set: Value = serde_json::from_slice(&set_bytes).map_err(|_| tampered(UNREADABLE))?;
        if set["release"]["sha256"] != hash(canonical(&release["policy"]["root"])?.as_bytes())
            || program.catalog_digest != candidate["catalog_digest"]
            || program.trust_digest != candidate["trust_digest"]
            || candidate["distribution"]["sha256"] != installed["root"]
        {
            return Err(tampered(PROGRAM_BINDING));
        }
        Ok(Some(
            evidence["candidate"]["digest"]
                .as_str()
                .ok_or_else(|| tampered(CANDIDATE))?
                .to_owned(),
        ))
    }
}
