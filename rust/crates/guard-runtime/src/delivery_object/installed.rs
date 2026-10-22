//! Fetches from the installed release bundle.
//!
//! The bundle ships its delivery data under one fixed directory, one
//! subdirectory per release tag. A location names the asset to read; this
//! resolves it against the bundle's source and reads a member out of its
//! container in one step. A bulk traversal can share a process while retaining
//! those same checks for each object.
use super::{container, location, request, Outcome};
use serde_json::{json, Value};
use std::{fs, path::Path};

const OBJECT_BYTES: u64 = 65536;
const PACK_BYTES: u64 = 32 * 1024 * 1024;
const BATCH_ITEMS: usize = 64;
const BATCH_BYTES: u64 = BATCH_ITEMS as u64 * OBJECT_BYTES;

/// Read a bounded batch of small installed objects with the same checks as a
/// single fetch. Validate the whole request before opening any container.
pub(super) fn batch(input: &Value) -> Outcome {
    let items = input["items"]
        .as_array()
        .filter(|items| !items.is_empty() && items.len() <= BATCH_ITEMS)
        .ok_or("installed bundle batch bounds invalid")?;
    let mut total = 0u64;
    for item in items {
        let plan = location::asset(&json!({
            "profile": "installed", "target": item["target"], "source": input["source"],
        }))?;
        let length = item["length"]
            .as_u64()
            .filter(|length| (1..=OBJECT_BYTES).contains(length))
            .ok_or("installed bundle batch bounds invalid")?;
        if plan["kind"] != "object" {
            return Err("installed bundle batch requires objects".into());
        }
        total = total
            .checked_add(length)
            .filter(|total| *total <= BATCH_BYTES)
            .ok_or("installed bundle batch bounds invalid")?;
    }
    let replies = items
        .iter()
        .map(|item| {
            fetch(&json!({
                "root": input["root"], "source": input["source"],
                "target": item["target"], "length": item["length"],
            }))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(json!({"items": replies}))
}

/// Validate a location of the installed bundle and, for a container member,
/// return its verified bytes. A whole asset is only resolved: the caller holds
/// the file handle and whoever consumes the bytes checks their digest.
///
/// `root` is the bundle's asset directory, chosen by the installation and
/// already checked by the caller up to that directory. This refuses a tag
/// directory that is a symlink; the container itself is read without
/// following one.
pub(super) fn fetch(input: &Value) -> Outcome {
    let plan = location::asset(&json!({
        "profile": "installed",
        "target": input["target"],
        "source": input["source"],
    }))?;
    let limit = if plan["kind"] == "object" {
        OBJECT_BYTES
    } else {
        PACK_BYTES
    };
    let length = input["length"]
        .as_u64()
        .filter(|length| (1..=limit).contains(length))
        .ok_or("installed bundle fetch bounds invalid")?;
    if plan["bound"].is_null() {
        return Ok(plan);
    }
    let root = input["root"].as_str().ok_or_else(request)?;
    let text = |key: &str| plan[key].as_str().unwrap_or_default();
    let directory = Path::new(root).join(text("tag"));
    if fs::symlink_metadata(&directory).is_ok_and(|found| found.file_type().is_symlink()) {
        return Err("delivery container unreadable".into());
    }
    let path = directory.join(text("asset"));
    container::member(&json!({
        "path": path.to_string_lossy(),
        "asset": text("asset"),
        "name": text("name"),
        "length": length,
    }))
}

#[cfg(test)]
#[path = "installed_tests.rs"]
mod tests;
