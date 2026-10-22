//! Asset names and locations of the catalog delivery channel.
//!
//! A located object is either a whole release asset or one member of a bounded
//! transfer container. The name carries the content digest, so every consumer
//! can check the bytes it receives against the name alone.
use super::{request, Outcome};
use serde_json::{json, Value};

const OBJECTS_BOUND: usize = 8 * 1024 * 1024;
pub(super) const PACKS_BOUND: usize = 32 * 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Family {
    Objects,
    Packs,
}

impl Family {
    pub(super) fn bound(self) -> usize {
        match self {
            Family::Objects => OBJECTS_BOUND,
            Family::Packs => PACKS_BOUND,
        }
    }
}

pub(super) fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn digits(value: &str, least: usize, most: usize) -> bool {
    (least..=most).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_digit())
}

/// `extension-data-<source>-<publication>.<epoch>-<sequence>`
fn tag(value: &str) -> bool {
    let rest = value.strip_prefix("extension-data-");
    let Some((source, rest)) = rest.and_then(|rest| rest.split_once('-')) else {
        return false;
    };
    let Some((publication, rest)) = rest.split_once('.') else {
        return false;
    };
    let Some((epoch, sequence)) = rest.split_once('-') else {
        return false;
    };
    lower_hex(source, 40)
        && digits(publication, 1, 20)
        && digits(epoch, 1, 10)
        && digits(sequence, 6, 6)
}

/// `objects-NNNNNN.zip` or `packs-NNNNNN.zip`.
pub(super) fn family(name: &str) -> Option<Family> {
    let (found, rest) = match (name.strip_prefix("objects-"), name.strip_prefix("packs-")) {
        (Some(rest), _) => (Family::Objects, rest),
        (_, Some(rest)) => (Family::Packs, rest),
        _ => return None,
    };
    digits(rest.strip_suffix(".zip")?, 6, 6).then_some(found)
}

/// `object-<digest>.json` or `pack-<digest>.zip`: the kind and the digest.
fn data_name(name: &str) -> Option<(&'static str, &str)> {
    let (kind, suffix, rest) = match (name.strip_prefix("object-"), name.strip_prefix("pack-")) {
        (Some(rest), _) => ("object", ".json", rest),
        (_, Some(rest)) => ("pack", ".zip", rest),
        _ => return None,
    };
    let (digest, tail) = rest.split_at_checked(64)?;
    (lower_hex(digest, 64) && tail == suffix).then_some((kind, digest))
}

/// The location of the object `kind` with `digest`: a whole asset named for it,
/// or a member of a container of the matching family.
pub(super) fn check(value: &Value, digest: &str, kind: &str) -> Result<(), String> {
    let invalid = || "delivery asset location invalid".to_owned();
    let map = value.as_object().ok_or_else(invalid)?;
    let tagged = map.get("tag").and_then(Value::as_str).is_some_and(tag);
    let shaped = map.contains_key("asset")
        && (map.len() == 2 || (map.len() == 3 && map.contains_key("member")));
    if !matches!(kind, "object" | "pack") || !lower_hex(digest, 64) || !tagged || !shaped {
        return Err(invalid());
    }
    let name = format!(
        "{kind}-{digest}.{}",
        if kind == "object" { "json" } else { "zip" }
    );
    let asset = map.get("asset").and_then(Value::as_str);
    match map.get("member") {
        None if asset != Some(name.as_str()) => Err("delivery asset identity invalid".into()),
        None => Ok(()),
        Some(member) => {
            let wanted = if kind == "object" {
                Family::Objects
            } else {
                Family::Packs
            };
            if member.as_str() == Some(name.as_str()) && asset.and_then(family) == Some(wanted) {
                Ok(())
            } else {
                Err("delivery container location invalid".into())
            }
        }
    }
}

/// Resolve the asset a fetch names. `release` is the public release transport;
/// `installed` is the packaged bundle, which also binds the tag to its source.
pub(super) fn asset(input: &Value) -> Outcome {
    let installed = match input["profile"].as_str() {
        Some("release") => false,
        Some("installed") => true,
        _ => return Err(request()),
    };
    let (shape, naming) = if installed {
        (
            "installed bundle location invalid",
            "installed bundle asset invalid",
        )
    } else {
        (
            "release object location invalid",
            "release object location invalid",
        )
    };
    let target = &input["target"];
    let map = target.as_object().ok_or(shape)?;
    let name = match map.get("member").or_else(|| map.get("asset")) {
        None => "",
        Some(Value::String(name)) => name,
        Some(_) => return Err(naming.into()),
    };
    let (kind, digest) = data_name(name).ok_or(naming)?;
    check(target, digest, kind)?;
    let tag = map["tag"].as_str().unwrap_or_default();
    if installed {
        let source = input["source"].as_str().filter(|s| lower_hex(s, 40));
        let bound = format!("extension-data-{}-0.0-", source.ok_or_else(request)?);
        if !tag.starts_with(&bound) {
            return Err("installed bundle asset source differs".into());
        }
    }
    let asset = map["asset"].as_str().unwrap_or_default();
    let bound = map
        .contains_key("member")
        .then(|| family(asset).map(Family::bound));
    Ok(json!({
        "name": name,
        "digest": digest,
        "kind": kind,
        "tag": tag,
        "asset": asset,
        "bound": bound.flatten(),
    }))
}

#[cfg(test)]
#[path = "location_tests.rs"]
mod tests;
