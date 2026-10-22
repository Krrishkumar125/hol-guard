use super::*;
use crate::delivery_object::stored_zip::tests::build;
use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};

fn source() -> String {
    "c".repeat(40)
}

fn tag() -> String {
    format!("extension-data-{}-0.0-000007", source())
}

fn digest(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

struct Bundle {
    dir: tempfile::TempDir,
    name: String,
    data: &'static [u8],
}

fn bundle() -> Bundle {
    let data: &'static [u8] = br#"{"n":1}"#;
    let name = format!("object-{}.json", digest(data));
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(tag())).unwrap();
    std::fs::write(
        dir.path().join(tag()).join("objects-000001.zip"),
        build(&[(&name, data)]),
    )
    .unwrap();
    Bundle { dir, name, data }
}

fn ask(bundle: &Bundle, target: Value, length: u64) -> Outcome {
    fetch(&json!({
        "root": bundle.dir.path().to_str().unwrap(),
        "target": target,
        "source": source(),
        "length": length,
    }))
}

fn member(bundle: &Bundle) -> Value {
    json!({"tag": tag(), "asset": "objects-000001.zip", "member": bundle.name})
}

#[test]
fn a_member_is_read_from_the_installed_container() {
    let bundle = bundle();
    let reply = ask(&bundle, member(&bundle), bundle.data.len() as u64).unwrap();
    assert_eq!(reply["data"], STANDARD.encode(bundle.data));
}

#[test]
fn a_whole_asset_is_resolved_and_left_to_the_caller() {
    let bundle = bundle();
    let target = json!({"tag": tag(), "asset": bundle.name});
    let reply = ask(&bundle, target, 7).unwrap();
    assert_eq!(reply["kind"], "object");
    assert_eq!(reply["asset"], bundle.name);
    assert!(reply.get("data").is_none());
}

#[test]
fn the_requested_length_is_bounded_by_the_kind() {
    let bundle = bundle();
    let refused = "installed bundle fetch bounds invalid";
    for length in [0, OBJECT_BYTES + 1] {
        assert_eq!(ask(&bundle, member(&bundle), length).unwrap_err(), refused);
    }
    let pack = json!({
        "tag": tag(),
        "asset": "packs-000001.zip",
        "member": format!("pack-{}.zip", "ab".repeat(32)),
    });
    assert_eq!(ask(&bundle, pack, PACK_BYTES + 1).unwrap_err(), refused);
    let outcome = fetch(&json!({
        "root": bundle.dir.path().to_str().unwrap(),
        "target": member(&bundle),
        "source": source(),
        "length": "7",
    }));
    assert_eq!(outcome.unwrap_err(), refused);
}

#[test]
fn a_location_from_another_source_is_refused() {
    let bundle = bundle();
    let other = json!({
        "tag": format!("extension-data-{}-0.0-000007", "d".repeat(40)),
        "asset": "objects-000001.zip",
        "member": bundle.name,
    });
    assert_eq!(
        ask(&bundle, other, 7).unwrap_err(),
        "installed bundle asset source differs"
    );
}

#[test]
fn a_member_of_the_wrong_length_or_a_missing_container_is_refused() {
    let bundle = bundle();
    assert_eq!(
        ask(&bundle, member(&bundle), 8).unwrap_err(),
        "delivery container member length differs"
    );
    let absent = json!({"tag": tag(), "asset": "objects-000002.zip", "member": bundle.name});
    assert_eq!(
        ask(&bundle, absent, 7).unwrap_err(),
        "delivery container unreadable"
    );
}

#[cfg(unix)]
#[test]
fn a_symlinked_tag_directory_is_not_followed() {
    let bundle = bundle();
    let real = bundle.dir.path().join(tag());
    let moved = bundle.dir.path().join("moved");
    std::fs::rename(&real, &moved).unwrap();
    std::os::unix::fs::symlink(&moved, &real).unwrap();
    assert_eq!(
        ask(&bundle, member(&bundle), 7).unwrap_err(),
        "delivery container unreadable"
    );
}

#[test]
fn a_member_request_needs_a_root() {
    let bundle = bundle();
    let outcome = fetch(&json!({
        "target": member(&bundle),
        "source": source(),
        "length": 7,
    }));
    assert_eq!(outcome.unwrap_err(), "delivery object request invalid");
}

fn batch_ask(bundle: &Bundle, items: Vec<Value>) -> Outcome {
    batch(&json!({"root": bundle.dir.path(), "source": source(), "items": items}))
}

#[test]
fn a_bounded_batch_checks_every_member_and_preserves_order() {
    let bundle = bundle();
    let second = br#"{"n":2}"#;
    let name = format!("object-{}.json", digest(second));
    std::fs::write(
        bundle.dir.path().join(tag()).join("objects-000001.zip"),
        build(&[(&bundle.name, bundle.data), (&name, second)]),
    )
    .unwrap();
    let item = json!({"target": member(&bundle), "length": bundle.data.len()});
    let other = json!({"target": {"tag": tag(), "asset": "objects-000001.zip", "member": name}, "length": second.len()});
    let requests = (0..BATCH_ITEMS)
        .map(|i| {
            if i % 2 == 0 {
                item.clone()
            } else {
                other.clone()
            }
        })
        .collect();
    let reply = batch_ask(&bundle, requests).unwrap();
    let items = reply["items"].as_array().unwrap();
    assert_eq!(items.len(), BATCH_ITEMS);
    for (index, item) in items.iter().enumerate() {
        assert_eq!(
            item["data"],
            STANDARD.encode(if index % 2 == 0 { bundle.data } else { second })
        );
    }
    let wrapped = crate::delivery_object::evaluate(&json!({
        "operation": "installed-batch", "root": bundle.dir.path(), "source": source(),
        "items": [{"target": member(&bundle), "length": bundle.data.len()}],
    }))
    .unwrap();
    assert_eq!(wrapped["items"][0], items[0]);
}

#[test]
fn even_maximum_object_batches_have_a_bounded_serialized_reply() {
    let bundle = bundle();
    let bytes = vec![b'a'; OBJECT_BYTES as usize];
    let name = format!("object-{}.json", digest(&bytes));
    std::fs::write(
        bundle.dir.path().join(tag()).join("objects-000001.zip"),
        build(&[(&name, &bytes)]),
    )
    .unwrap();
    let item = json!({"target": {"tag": tag(), "asset": "objects-000001.zip", "member": name}, "length": bytes.len()});
    let reply = batch_ask(&bundle, vec![item; BATCH_ITEMS]).unwrap();
    assert_eq!(reply["items"].as_array().unwrap().len(), BATCH_ITEMS);
    assert!(serde_json::to_vec(&reply).unwrap().len() < 6 * 1024 * 1024);
}

#[test]
fn batches_refuse_empty_oversized_and_non_object_requests() {
    let bundle = bundle();
    let item = json!({"target": member(&bundle), "length": bundle.data.len()});
    for items in [vec![], vec![item; BATCH_ITEMS + 1]] {
        assert_eq!(
            batch_ask(&bundle, items).unwrap_err(),
            "installed bundle batch bounds invalid"
        );
    }
    let pack = json!({"tag": tag(), "asset": format!("pack-{}.zip", "ab".repeat(32))});
    assert_eq!(
        batch_ask(&bundle, vec![json!({"target": pack, "length": 7})]).unwrap_err(),
        "installed bundle batch requires objects"
    );
}

#[test]
fn every_batch_bound_is_checked_before_any_container_is_opened() {
    let bundle = bundle();
    std::fs::remove_file(bundle.dir.path().join(tag()).join("objects-000001.zip")).unwrap();
    let first = json!({"target": member(&bundle), "length": 7});
    for length in [json!(0), json!(OBJECT_BYTES + 1), json!("7")] {
        assert_eq!(
            batch_ask(
                &bundle,
                vec![
                    first.clone(),
                    json!({"target": member(&bundle), "length": length})
                ]
            )
            .unwrap_err(),
            "installed bundle batch bounds invalid"
        );
    }
    let mut other = member(&bundle);
    other["tag"] = json!(format!("extension-data-{}-0.0-000007", "d".repeat(40)));
    assert_eq!(
        batch_ask(&bundle, vec![first, json!({"target": other, "length": 7})]).unwrap_err(),
        "installed bundle asset source differs"
    );
}

#[test]
fn a_batch_rechecks_changed_members_and_rejects_a_late_corruption() {
    let bundle = bundle();
    let item = json!({"target": member(&bundle), "length": bundle.data.len()});
    assert!(batch_ask(&bundle, vec![item.clone()]).is_ok());
    let different = json!({
        "target": {"tag": tag(), "asset": "objects-000001.zip", "member": format!("object-{}.json", "ab".repeat(32))},
        "length": 7,
    });
    assert!(batch_ask(&bundle, vec![item.clone(), different]).is_err());
    std::fs::write(
        bundle.dir.path().join(tag()).join("objects-000001.zip"),
        b"corrupt",
    )
    .unwrap();
    assert!(batch_ask(&bundle, vec![item]).is_err());
}
