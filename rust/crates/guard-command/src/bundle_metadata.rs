//! Installed metadata integrity only; this never enables contributed policy.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
#[path = "bundle_metadata_compatibility.rs"]
mod compatibility_reader;
#[path = "bundle_metadata_json.rs"]
mod strict_json;
pub(crate) use compatibility_reader::stream as compatibility_stream;
type Result<T> = std::result::Result<T, &'static str>;
const INVALID: &str = "installed bundle metadata invalid";

fn fields(value: &Value, names: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|v| v.len() == names.len() && names.iter().all(|k| v.contains_key(*k)))
}
fn hex(value: &Value, length: usize) -> bool {
    value.as_str().is_some_and(|s| {
        s.len() == length
            && s.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    })
}
fn positive(value: &Value) -> bool {
    value.as_u64().is_some_and(|n| n > 0)
}
fn matches(pattern: &str, value: &str) -> bool {
    regex::Regex::new(pattern)
        .expect("fixed metadata expression")
        .is_match(value)
}

fn target(value: &Value, source: Option<&str>) -> Result<Value> {
    if !fields(value, &["tag", "asset"]) && !fields(value, &["tag", "asset", "member"]) {
        return Err(INVALID);
    }
    let name = value
        .get("member")
        .unwrap_or(&value["asset"])
        .as_str()
        .ok_or(INVALID)?;
    let (kind, digest) = if let Some(digest) = name
        .strip_prefix("object-")
        .and_then(|s| s.strip_suffix(".json"))
    {
        ("object", digest)
    } else if let Some(digest) = name
        .strip_prefix("pack-")
        .and_then(|s| s.strip_suffix(".zip"))
    {
        ("pack", digest)
    } else {
        return Err(INVALID);
    };
    let tag = value["tag"].as_str().ok_or(INVALID)?;
    if !hex(&json!(digest), 64)
        || !matches(
            r"^extension-data-[0-9a-f]{40}-[0-9]{1,20}\.[0-9]{1,10}-[0-9]{6}$",
            tag,
        )
        || source.is_some_and(|source| !tag.starts_with(&format!("extension-data-{source}-0.0-")))
    {
        return Err(INVALID);
    }
    if value.get("member").is_some() {
        let asset = value["asset"].as_str().ok_or(INVALID)?;
        let pattern = if kind == "object" {
            r"^objects-[0-9]{6}\.zip$"
        } else {
            r"^packs-[0-9]{6}\.zip$"
        };
        if !matches(pattern, asset) {
            return Err(INVALID);
        }
    }
    Ok(json!({"name":name,"digest":digest,"kind":kind}))
}

fn reference(value: &Value, located: bool, source: Option<&str>) -> Result<()> {
    let mut expected = vec!["sha256", "length", "expanded_length", "kind"];
    if located {
        expected.push("location");
    }
    if !fields(value, &expected)
        || !hex(&value["sha256"], 64)
        || !value["length"]
            .as_u64()
            .is_some_and(|n| n > 0 && n <= 65536)
        || value["expanded_length"].as_u64() != value["length"].as_u64()
        || value["kind"] != "data"
    {
        return Err(INVALID);
    }
    if located {
        let selected = target(&value["location"], source)?;
        if selected["kind"] != "object" || selected["digest"] != value["sha256"] {
            return Err(INVALID);
        }
    }
    Ok(())
}

fn compatibility(value: &Value, extensions: u64, source: Option<&str>) -> Result<()> {
    if !fields(value, &["commands", "mcp"]) {
        return Err(INVALID);
    }
    let mut total = 0u64;
    for family in ["commands", "mcp"] {
        let row = &value[family];
        let count = row["count"].as_u64().ok_or(INVALID)?;
        if !fields(row, &["count", "index"]) || count > extensions {
            return Err(INVALID);
        }
        total = total.checked_add(count).ok_or(INVALID)?;
        if count == 0 {
            if !row["index"].is_null() {
                return Err(INVALID);
            }
        } else {
            reference(&row["index"], true, source)?;
        }
    }
    if total != extensions {
        return Err(INVALID);
    }
    Ok(())
}

fn root(data: &str, source: &str, engine: &str) -> Result<Value> {
    if data.is_empty() || data.len() > 65536 || !hex(&json!(source), 40) || !hex(&json!(engine), 64)
    {
        return Err(INVALID);
    }
    let root = strict_json::decode(data.as_bytes())?;
    let mut names = vec![
        "schema",
        "source_sha",
        "engine",
        "authority_epoch",
        "publication_id",
        "policy",
    ];
    if root.get("compatibility").is_some() {
        names.push("compatibility");
    }
    if !fields(&root, &names)
        || root["schema"] != "guard.command-pack-bundle.v1"
        || root["source_sha"] != source
        || root["engine"] != engine
        || root["publication_id"] != "0.0"
        || !positive(&root["authority_epoch"])
    {
        return Err(INVALID);
    }
    let policy = &root["policy"];
    if !fields(policy, &["root", "transport", "defaults", "revocations"]) {
        return Err(INVALID);
    }
    let native = &policy["root"];
    if !fields(
        native,
        &[
            "schema",
            "kind",
            "authority",
            "engine",
            "extensions",
            "index",
            "index_fanout",
            "objects",
            "object_bytes",
            "object_bytes_limit",
        ],
    ) || native["schema"] != "guard.command-pack-release.v1"
        || native["engine"] != engine
        || native["kind"] != "root"
        || native["authority"] != "requires-authenticated-release-binding"
        || native["index_fanout"].as_u64() != Some(64)
        || native["object_bytes_limit"].as_u64() != Some(65536)
        || !["extensions", "objects", "object_bytes"]
            .iter()
            .all(|k| positive(&native[k]))
    {
        return Err(INVALID);
    }
    reference(&native["index"], false, None)?;
    reference(&policy["transport"], true, Some(source))?;
    let extensions = native["extensions"].as_u64().ok_or(INVALID)?;
    if let Some(value) = root.get("compatibility") {
        compatibility(value, extensions, Some(source))?;
    }
    for name in ["defaults", "revocations"] {
        let row = &policy[name];
        let expected = if name == "defaults" {
            vec!["count", "index"]
        } else {
            vec!["count", "index", "epoch"]
        };
        let count = row["count"].as_u64().ok_or(INVALID)?;
        if !fields(row, &expected)
            || (name == "defaults" && count > extensions)
            || (name == "revocations" && row["epoch"].as_u64().is_none())
        {
            return Err(INVALID);
        }
        if count > 0 {
            reference(&row["index"], true, Some(source))?;
        } else if !row["index"].is_null() {
            return Err(INVALID);
        }
    }
    Ok(root)
}

pub(crate) fn evaluate(bytes: &[u8]) -> Result<Value> {
    let input = strict_json::decode(bytes)?;
    match input["operation"].as_str() {
        Some("installed-plan") => installed_plan(&input),
        Some("installed") => installed(&input),
        Some("root" | "descriptor") => {
            let data = input["data"].as_str().ok_or(INVALID)?;
            let source = input["source_sha"].as_str().ok_or(INVALID)?;
            let engine = input["engine"].as_str().ok_or(INVALID)?;
            let value = root(data, source, engine)?;
            if input["operation"] == "root" {
                Ok(value)
            } else {
                Ok(json!({"schema":"guard.command-pack-bundle.v1",
                    "path":"codex_plugin_scanner/guard/contracts/data/extensions/command-pack-bundle/command-pack-bundle.v1.json",
                    "sha256":hex::encode(Sha256::digest(data.as_bytes())),
                    "length":data.len(),"source_sha":source,"engine":engine}))
            }
        }
        Some("compatibility") => {
            compatibility(
                &input["value"],
                input["extensions"].as_u64().ok_or(INVALID)?,
                None,
            )?;
            Ok(json!({}))
        }
        _ => Err(INVALID),
    }
}

fn installed_plan(input: &Value) -> Result<Value> {
    let runtime = &input["runtime_manifest"];
    let compiler = &input["compiler_manifest"];
    if !runtime.is_object()
        || !compiler.is_object()
        || runtime["schema"] != "hol-guard-native-runtime.v1"
        || compiler["schema"] != "hol-guard-native-source-compiler.v2"
        || runtime["protocol_version"].as_u64() != Some(1)
        || compiler["protocol_version"].as_u64() != Some(1)
    {
        return Err("installed bundle native manifests differ");
    }
    for field in ["source_sha", "package_version", "target", "platform_tag"] {
        if !runtime[field].is_string() || runtime[field] != compiler[field] {
            return Err("installed bundle native manifests differ");
        }
    }
    if !matches!(
        compiler["executable"].as_str(),
        Some("hol-guard-runtime" | "hol-guard-runtime.exe")
    ) {
        return Err("installed bundle executable invalid");
    }
    let size = compiler["compiler_size"]
        .as_u64()
        .ok_or("installed bundle executable size differs")?;
    if size == 0 || size > 128 * 1024 * 1024 || runtime["runtime_size"].as_u64() != Some(size) {
        return Err("installed bundle executable size differs");
    }
    Ok(json!({"executable":compiler["executable"],"size":size}))
}

fn installed(input: &Value) -> Result<Value> {
    let plan = installed_plan(input)?;
    let runtime = &input["runtime_manifest"];
    let compiler = &input["compiler_manifest"];
    if input["binary_length"].as_u64() != plan["size"].as_u64()
        || !hex(&input["binary_digest"], 64)
        || input["binary_digest"] != runtime["runtime_sha256"]
        || input["binary_digest"] != compiler["compiler_sha256"]
    {
        return Err("installed bundle executable digest differs");
    }
    let data = input["data"].as_str().ok_or(INVALID)?;
    let source = runtime["source_sha"].as_str().ok_or(INVALID)?;
    let engine = compiler["implementation_digest"]
        .as_str()
        .ok_or("installed bundle engine identity missing")?;
    root(data, source, engine)?;
    let digest = hex::encode(Sha256::digest(data.as_bytes()));
    let descriptor = json!({"schema":"guard.command-pack-bundle.v1",
        "path":"codex_plugin_scanner/guard/contracts/data/extensions/command-pack-bundle/command-pack-bundle.v1.json",
        "sha256":digest,"length":data.len(),"source_sha":source,"engine":engine});
    if runtime["command_pack_bundle"] != descriptor || compiler["command_pack_bundle"] != descriptor
    {
        return Err("installed bundle native Root binding differs");
    }
    Ok(json!({"source_sha":source,"digest":digest,"engine":engine}))
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn fixture() -> Value {
        let reference =
            json!({"sha256":"c".repeat(64),"length":2,"expanded_length":2,"kind":"data"});
        let mut located = reference.clone();
        located["location"] = json!({"tag":format!("extension-data-{}-0.0-000000", "a".repeat(40)),"asset":format!("object-{}.json", "c".repeat(64))});
        json!({"schema":"guard.command-pack-bundle.v1","source_sha":"a".repeat(40),"engine":"b".repeat(64),
            "authority_epoch":1,"publication_id":"0.0","policy":{
                "root":{"schema":"guard.command-pack-release.v1","kind":"root","authority":"requires-authenticated-release-binding",
                    "engine":"b".repeat(64),"extensions":1,"index":reference,"index_fanout":64,"objects":1,"object_bytes":2,"object_bytes_limit":65536},
                "transport":located,"defaults":{"count":0,"index":null},"revocations":{"count":0,"index":null,"epoch":0}}})
    }

    fn validate(value: &Value) -> Result<Value> {
        root(
            &serde_json::to_string(value).unwrap(),
            &"a".repeat(40),
            &"b".repeat(64),
        )
    }

    fn installed_fixture() -> Value {
        let data = serde_json::to_string(&fixture()).unwrap();
        let digest = hex::encode(Sha256::digest(data.as_bytes()));
        let descriptor = json!({"schema":"guard.command-pack-bundle.v1",
            "path":"codex_plugin_scanner/guard/contracts/data/extensions/command-pack-bundle/command-pack-bundle.v1.json",
            "sha256":digest,"length":data.len(),"source_sha":"a".repeat(40),"engine":"b".repeat(64)});
        let common = json!({"protocol_version":1,"source_sha":"a".repeat(40),"package_version":"1.0",
            "target":"test","platform_tag":"test","command_pack_bundle":descriptor});
        let mut runtime = common.clone();
        runtime["schema"] = json!("hol-guard-native-runtime.v1");
        runtime["runtime_size"] = json!(18);
        runtime["runtime_sha256"] = json!("e".repeat(64));
        let mut compiler = common;
        compiler["schema"] = json!("hol-guard-native-source-compiler.v2");
        compiler["compiler_size"] = json!(18);
        compiler["compiler_sha256"] = json!("e".repeat(64));
        compiler["executable"] = json!("hol-guard-runtime");
        compiler["implementation_digest"] = json!("b".repeat(64));
        json!({"runtime_manifest":runtime,"compiler_manifest":compiler,"data":data,
            "binary_length":18,"binary_digest":"e".repeat(64)})
    }

    #[test]
    fn authenticates_both_release_manifests_executable_and_exact_root_descriptor() {
        let evidence = installed_fixture();
        let identity = installed(&evidence).unwrap();
        assert_eq!(identity["source_sha"], "a".repeat(40));
        assert_eq!(identity["engine"], "b".repeat(64));
        for (pointer, bad) in [
            ("/runtime_manifest/protocol_version", json!(true)),
            ("/compiler_manifest/protocol_version", json!(1.0)),
            ("/compiler_manifest/source_sha", json!("d".repeat(40))),
            ("/compiler_manifest/package_version", json!("2.0")),
            ("/compiler_manifest/target", json!(null)),
            ("/compiler_manifest/platform_tag", json!("other")),
            (
                "/compiler_manifest/executable",
                json!("../hol-guard-runtime"),
            ),
            ("/compiler_manifest/compiler_size", json!(134217729)),
            ("/runtime_manifest/runtime_size", json!(17)),
            ("/binary_length", json!(17)),
            ("/binary_digest", json!("f".repeat(64))),
            ("/runtime_manifest/runtime_sha256", json!("f".repeat(64))),
            ("/compiler_manifest/compiler_sha256", json!("f".repeat(64))),
            (
                "/compiler_manifest/implementation_digest",
                json!("f".repeat(64)),
            ),
            (
                "/compiler_manifest/command_pack_bundle/sha256",
                json!("f".repeat(64)),
            ),
            (
                "/runtime_manifest/command_pack_bundle/path",
                json!("elsewhere.json"),
            ),
        ] {
            let mut invalid = evidence.clone();
            *invalid.pointer_mut(pointer).unwrap() = bad;
            assert!(installed(&invalid).is_err(), "{pointer}");
        }
    }

    #[test]
    fn accepts_full_unsigned_epoch_range_and_long_root_transport_strings() {
        let mut value = fixture();
        value["authority_epoch"] = json!(u64::MAX);
        value["policy"]["revocations"]["epoch"] = json!(u64::MAX);
        assert!(validate(&value).is_ok());
        let mut evidence = installed_fixture();
        let data = format!("{}{}", " ".repeat(5000), evidence["data"].as_str().unwrap());
        let digest = hex::encode(Sha256::digest(data.as_bytes()));
        for manifest in ["runtime_manifest", "compiler_manifest"] {
            evidence[manifest]["command_pack_bundle"]["sha256"] = json!(digest);
            evidence[manifest]["command_pack_bundle"]["length"] = json!(data.len());
        }
        evidence["data"] = json!(data);
        evidence["operation"] = json!("installed");
        assert!(evaluate(&serde_json::to_vec(&evidence).unwrap()).is_ok());
    }

    #[test]
    fn complete_root_and_compatibility_preserve_default_off_inventory() {
        let mut value = fixture();
        assert_eq!(validate(&value).unwrap(), value);
        let data = serde_json::to_string(&value).unwrap();
        let mut request = json!({"operation":"root","data":data,
            "source_sha":"a".repeat(40),"engine":"b".repeat(64)});
        assert_eq!(
            evaluate(&serde_json::to_vec(&request).unwrap()).unwrap(),
            value
        );
        request["operation"] = json!("descriptor");
        assert_eq!(
            evaluate(&serde_json::to_vec(&request).unwrap()).unwrap(),
            installed_fixture()["runtime_manifest"]["command_pack_bundle"]
        );
        value["compatibility"] = json!({"commands":{"count":1,"index":value["policy"]["transport"]},"mcp":{"count":0,"index":null}});
        assert_eq!(validate(&value).unwrap(), value);
        assert_eq!(value["policy"]["defaults"]["count"], 0);
        for pointer in [
            "/compatibility/commands/count",
            "/policy/root/extensions",
            "/authority_epoch",
            "/policy/revocations/epoch",
        ] {
            for bad in [
                json!(true),
                json!(-1),
                json!(1.0),
                json!("1"),
                json!(null),
                json!({"$serde_json::private::Number":"1"}),
            ] {
                let mut invalid = value.clone();
                *invalid.pointer_mut(pointer).unwrap() = bad;
                assert!(validate(&invalid).is_err(), "{pointer}");
            }
        }
    }

    #[test]
    fn rejects_unknown_fields_identity_substitution_and_index_mismatch() {
        for (pointer, bad) in [
            ("/policy/root/index/length", json!(65537)),
            ("/policy/root/index/expanded_length", json!(3)),
            (
                "/policy/transport/location/tag",
                json!(format!("extension-data-{}-0.0-000000", "d".repeat(40))),
            ),
            ("/policy/defaults/count", json!(2)),
            ("/policy/revocations/index", json!({})),
            ("/engine", json!("d".repeat(64))),
        ] {
            let mut value = fixture();
            *value.pointer_mut(pointer).unwrap() = bad;
            assert!(validate(&value).is_err(), "{pointer}");
        }
        let mut value = fixture();
        value["expires_at"] = json!(9999999999u64);
        assert!(validate(&value).is_err());
        let data = serde_json::to_string(&fixture()).unwrap();
        let duplicate = format!("{},\"policy\":{{}}}}", &data[..data.len() - 1]);
        assert!(root(&duplicate, &"a".repeat(40), &"b".repeat(64)).is_err());
        assert!(root(&" ".repeat(65537), &"a".repeat(40), &"b".repeat(64)).is_err());
    }

    #[test]
    fn compatibility_requires_complete_counted_inventory() {
        let located = fixture()["policy"]["transport"].clone();
        let good = json!({"commands":{"count":1,"index":located},"mcp":{"count":0,"index":null}});
        assert!(compatibility(&good, 1, None).is_ok());
        assert!(evaluate(
            &serde_json::to_vec(&json!({"operation":"compatibility",
            "value":good,"extensions":1}))
            .unwrap()
        )
        .is_ok());
        assert!(compatibility(&good, 2, None).is_err());
        let mut invalid = good.clone();
        invalid["mcp"]["index"] = located.clone();
        assert!(compatibility(&invalid, 1, None).is_err());
        invalid = good;
        invalid["commands"]["remote"] = json!("https://example.com/unsigned");
        assert!(compatibility(&invalid, 1, None).is_err());
    }

    #[test]
    fn targets_require_exact_source_and_bounded_flat_container_names() {
        let source = "a".repeat(40);
        let mut location = fixture()["policy"]["transport"]["location"].clone();
        assert!(target(&location, Some(&source)).is_ok());
        location["member"] = location["asset"].clone();
        location["asset"] = json!("objects-000000.zip");
        assert!(target(&location, Some(&source)).is_ok());
        for asset in [
            "packs-000000.zip",
            "../objects-000000.zip",
            "objects-000000.zip\n",
        ] {
            location["asset"] = json!(asset);
            assert!(target(&location, Some(&source)).is_err());
        }
    }
}
