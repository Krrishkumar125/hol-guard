//! Trust-root assembly for policy bundles: legacy anchor migration, the
//! verification context (trusted vs. pinned anchors), and the keyring that is
//! persisted after a bundle is accepted.

use serde_json::Value;

use crate::policy_bundle_keys::{
    load_keys, merge_keys, resolve_key, safe_load_keys, Key, KEY_PURPOSE,
};
use crate::policy_bundle_py::py_strip;
use crate::policy_bundle_time::replaced_timestamp;

pub(crate) const V2_CONTRACT: &str = "guard-policy-bundle.v2";

/// Guard Cloud's production policy-bundle signing key, pinned in the release.
/// Without it an unmanaged device has no anchor at all, because sync-advertised
/// keys are never authority on their own, and every Cloud policy bundle is
/// rejected with `untrusted_signing_key`. Rotating this key requires a release.
const BUILTIN_KEY_ID: &str = "guard-bundle-key-prod-2026-06";
const BUILTIN_KEY_FINGERPRINT: &str =
    "4c8f2d81f564e4a5b108896b87599001bdaf30be8ae961769fe958590b3ebb52";
const BUILTIN_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAre602aUcqrQTE/V0TKnO\nm4WW9dZ6cJUoUKPyBvrb90y8YKPmlzQJb4Ua8cZpUfNUstnpRNyLV/qaBxcHMcbM\n0xU7hwOi7nMjOgVDb9qKfFeZF/1HH21fzfnkLbDYynkoGPoiOL/toc7RGNeLGMLz\naP+X+CsTRG5kaFLAkNFzVCOGvui1JwsYl5gkdSJIuF1GANOKBh9J/2sEo4pw5JiV\n6OKSfXNE8uXsejMJZT2/WhiqCaf1NbBb4lKETcMD2ul6uobflTpLRafg7L8TMHRp\nTkJCkPeFpNeWG4FzDkGUU+chwgXmZxrB4hAWaSLkeevgJiPglTj0PyEyVkvMShcX\nXQIDAQAB\n-----END PUBLIC KEY-----";

#[cfg(test)]
thread_local! {
    /// The recorded Python parity vectors predate the pinned anchor; replaying
    /// them turns it off so they keep checking everything else verbatim.
    pub(crate) static BUILTIN_ANCHOR_DISABLED: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

/// Pinned anchors scoped to the paired workspace. The bundle signature covers
/// `workspaceId` and the workspace is checked before any rule applies, so one
/// Cloud key serves every workspace without allowing cross-workspace replay.
pub(crate) fn builtin_keys(expected_workspace: Option<&str>) -> Vec<Key> {
    #[cfg(test)]
    if BUILTIN_ANCHOR_DISABLED.with(std::cell::Cell::get) {
        return Vec::new();
    }
    let Some(workspace) = expected_workspace.filter(|value| !py_strip(value).is_empty()) else {
        return Vec::new();
    };
    vec![Key {
        key_id: BUILTIN_KEY_ID.to_owned(),
        public_key_pem: BUILTIN_PUBLIC_KEY_PEM.to_owned(),
        fingerprint: BUILTIN_KEY_FINGERPRINT.to_owned(),
        state: "active".to_owned(),
        purpose: KEY_PURPOSE.to_owned(),
        workspace_id: Some(workspace.to_owned()),
        valid_from: None,
        valid_until: None,
    }]
}

pub(crate) struct Context {
    pub trusted: Vec<Key>,
    pub anchored: Vec<Key>,
    pub managed_configured: bool,
}

fn restrictive_state(left: &str, right: &str) -> &'static str {
    if left == "revoked" || right == "revoked" {
        "revoked"
    } else if left == "grace" || right == "grace" {
        "grace"
    } else {
        "active"
    }
}

fn latest(candidates: &[&String], later_wins: bool) -> Option<String> {
    let mut best: Option<(&String, f64)> = None;
    for candidate in candidates {
        let stamp = replaced_timestamp(candidate).unwrap_or(0.0);
        let replace = match best {
            None => true,
            Some((_, current)) => {
                if later_wins {
                    stamp > current
                } else {
                    stamp < current
                }
            }
        };
        if replace {
            best = Some((candidate, stamp));
        }
    }
    best.map(|(value, _)| value.clone())
}

/// `migrate_legacy_policy_bundle_anchors`.
pub(crate) fn migrate_legacy(
    stored_keyring: &Value,
    sync_keys: &[Key],
    expected_workspace: Option<&str>,
) -> Vec<Key> {
    let Value::Object(stored) = stored_keyring else {
        return Vec::new();
    };
    if stored.len() != 2 || !stored.contains_key("keys") || !stored.contains_key("workspace_id") {
        return Vec::new();
    }
    let Some(expected) = expected_workspace.filter(|value| !value.is_empty()) else {
        return Vec::new();
    };
    if stored.get("workspace_id").and_then(Value::as_str) != Some(expected) {
        return Vec::new();
    }
    if !matches!(stored.get("keys"), Some(Value::Array(_))) {
        return Vec::new();
    }
    let legacy_keys = safe_load_keys(stored_keyring);
    if legacy_keys.is_empty()
        || legacy_keys
            .iter()
            .any(|key| key.purpose != "unscoped" || key.workspace_id.is_some())
    {
        return Vec::new();
    }
    let mut migrated = Vec::new();
    for legacy in &legacy_keys {
        let advertised = sync_keys.iter().find(|key| {
            key.key_id == legacy.key_id
                && key.fingerprint == legacy.fingerprint
                && key.purpose == KEY_PURPOSE
                && key.workspace_id.as_deref() == Some(expected)
        });
        let Some(advertised) = advertised else {
            continue;
        };
        let froms: Vec<&String> = [&legacy.valid_from, &advertised.valid_from]
            .into_iter()
            .flatten()
            .collect();
        let untils: Vec<&String> = [&legacy.valid_until, &advertised.valid_until]
            .into_iter()
            .flatten()
            .collect();
        migrated.push(Key {
            key_id: legacy.key_id.clone(),
            public_key_pem: legacy.public_key_pem.clone(),
            fingerprint: legacy.fingerprint.clone(),
            state: restrictive_state(&legacy.state, &advertised.state).to_owned(),
            purpose: KEY_PURPOSE.to_owned(),
            workspace_id: Some(expected.to_owned()),
            valid_from: latest(&froms, true),
            valid_until: latest(&untils, false),
        });
    }
    migrated
}

/// `_policy_bundle_verification_context_with_source` over already-loaded inputs.
pub(crate) fn verification_context(
    stored_keyring: &Value,
    sync_keys: &[Key],
    managed_configured: bool,
    managed_keys: &[Key],
    provenance_present: bool,
    expected_workspace: Option<&str>,
) -> Context {
    if managed_configured {
        return Context {
            trusted: merge_keys(&[managed_keys, sync_keys]),
            anchored: managed_keys.to_vec(),
            managed_configured: true,
        };
    }
    let builtin = builtin_keys(expected_workspace);
    if provenance_present {
        return Context {
            trusted: merge_keys(&[&builtin, sync_keys]),
            anchored: builtin,
            managed_configured: false,
        };
    }
    let stored = safe_load_keys(stored_keyring);
    let migrated = migrate_legacy(stored_keyring, sync_keys, expected_workspace);
    Context {
        trusted: merge_keys(&[&builtin, &stored, &migrated, sync_keys]),
        anchored: merge_keys(&[&builtin, &stored, &migrated]),
        managed_configured: false,
    }
}

/// Keys advertised by a sync payload (`safe_load` of the optional field).
pub(crate) fn sync_keys(raw: &Value) -> Vec<Key> {
    if raw.is_null() {
        return Vec::new();
    }
    load_keys(raw, false).unwrap_or_default()
}

/// The pinned key ships with every release, so writing it into the stored
/// keyring would only keep a rotated-out key anchored after an upgrade. A stored
/// entry for the same id in any other state (a revocation) is still persisted.
fn is_pinned_builtin(key: &Key) -> bool {
    key.key_id == BUILTIN_KEY_ID
        && key.fingerprint == BUILTIN_KEY_FINGERPRINT
        && key.state == "active"
        && key.valid_from.is_none()
        && key.valid_until.is_none()
}

/// `persistable_policy_bundle_keyring`.
pub(crate) fn persistable(anchored: &[Key], bundle: &Value) -> Vec<Key> {
    let workspace = match bundle.get("workspaceId") {
        Some(Value::String(id)) if !py_strip(id).is_empty() => id.as_str(),
        _ => return Vec::new(),
    };
    let v2 = bundle.get("contractVersion").and_then(Value::as_str) == Some(V2_CONTRACT);
    let anchors: Vec<Key> = anchored
        .iter()
        .filter(|key| {
            !is_pinned_builtin(key)
                && key.purpose == KEY_PURPOSE
                && match key.workspace_id.as_deref() {
                    None => v2,
                    Some(id) => id == workspace,
                }
        })
        .cloned()
        .collect();
    let Some(Value::Object(verifier)) = bundle.get("verifier") else {
        return anchors;
    };
    if verifier.get("algorithm").and_then(Value::as_str) != Some("rsa-pss-sha256") {
        return anchors;
    }
    let key_id = match verifier.get("keyId") {
        Some(Value::String(id)) if !py_strip(id).is_empty() => py_strip(id),
        _ => return anchors,
    };
    match resolve_key(key_id, &anchors) {
        Some(signing) => merge_keys(&[&anchors, std::slice::from_ref(signing)]),
        None => anchors,
    }
}

#[cfg(test)]
mod builtin_anchor_tests {
    use super::*;
    use serde_json::json;

    fn managed_key() -> Key {
        Key {
            key_id: "managed-key".to_owned(),
            public_key_pem: "pem".to_owned(),
            fingerprint: "fp".to_owned(),
            state: "active".to_owned(),
            purpose: KEY_PURPOSE.to_owned(),
            workspace_id: Some("ws-1".to_owned()),
            valid_from: None,
            valid_until: None,
        }
    }

    #[test]
    fn unmanaged_device_anchors_the_pinned_cloud_key_for_its_workspace() {
        let built = verification_context(&Value::Null, &[], false, &[], false, Some("ws-1"));
        assert_eq!(built.anchored.len(), 1);
        let anchor = &built.anchored[0];
        assert_eq!(anchor.key_id, BUILTIN_KEY_ID);
        assert_eq!(anchor.purpose, KEY_PURPOSE);
        assert_eq!(anchor.workspace_id.as_deref(), Some("ws-1"));
        assert!(built.trusted.iter().any(|key| key.key_id == BUILTIN_KEY_ID));
    }

    #[test]
    fn pinned_key_is_never_written_to_the_stored_keyring() {
        let built = verification_context(&Value::Null, &[], false, &[], false, Some("ws-1"));
        let bundle = json!({
            "workspaceId": "ws-1",
            "verifier": { "algorithm": "rsa-pss-sha256", "keyId": BUILTIN_KEY_ID },
        });
        assert!(persistable(&built.anchored, &bundle).is_empty());

        let mut revoked = builtin_keys(Some("ws-1")).remove(0);
        revoked.state = "revoked".to_owned();
        let kept = persistable(&[revoked], &bundle);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].state, "revoked");
    }

    #[test]
    fn pinned_key_fingerprint_matches_its_public_key() {
        assert_eq!(
            crate::policy_bundle_keys::key_fingerprint(BUILTIN_PUBLIC_KEY_PEM),
            BUILTIN_KEY_FINGERPRINT
        );
        let wire = builtin_keys(Some("ws-1"))[0].to_value();
        let loaded = load_keys(&json!([wire]), false).expect("pinned key must load");
        assert_eq!(loaded[0].fingerprint, BUILTIN_KEY_FINGERPRINT);
    }

    #[test]
    fn no_workspace_means_no_pinned_anchor() {
        let built = verification_context(&Value::Null, &[], false, &[], false, None);
        assert!(built.anchored.is_empty());
        let blank = verification_context(&Value::Null, &[], false, &[], false, Some("  "));
        assert!(blank.anchored.is_empty());
    }

    #[test]
    fn managed_trust_root_stays_exclusive() {
        let managed = [managed_key()];
        let built = verification_context(&Value::Null, &[], true, &managed, false, Some("ws-1"));
        assert_eq!(built.anchored.len(), 1);
        assert_eq!(built.anchored[0].key_id, "managed-key");
    }

    #[test]
    fn stored_revocation_overrides_the_pinned_key() {
        let stored = json!({
            "workspace_id": "ws-1",
            "keys": [{
                "keyId": BUILTIN_KEY_ID,
                "publicKeyPem": BUILTIN_PUBLIC_KEY_PEM,
                "fingerprintSha256": BUILTIN_KEY_FINGERPRINT,
                "state": "revoked",
                "purpose": KEY_PURPOSE,
                "workspaceId": "ws-1",
            }],
        });
        let built = verification_context(&stored, &[], false, &[], false, Some("ws-1"));
        let anchor = built
            .anchored
            .iter()
            .find(|key| key.key_id == BUILTIN_KEY_ID)
            .unwrap();
        assert_eq!(anchor.state, "revoked");
    }
}
