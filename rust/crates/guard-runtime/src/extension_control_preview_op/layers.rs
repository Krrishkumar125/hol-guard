//! Layer reading for the preview: explicit local state, reverting one target,
//! provenance, and what one set of layers blocks as the resolver answers it.
//!
//! Explicit state, reverts and provenance read the layers exactly as the
//! caller sent them; only resolution reads their typed, validated form.

use std::collections::HashMap;

use guard_command::extension_control::{
    compose_control_layers, resolve_extension_controls, ControlSurface, MAX_CONTROL_LAYERS,
};
use guard_contracts::{NativeExtensionControlLayerV1, NativeExtensionControlV1};

use crate::extension_control_op::typed_layers;

use super::catalog::PreviewCatalog;

pub(super) const LOCAL_ADMIN: &str = "local-admin";
const INHERITED: &str = "inherited";

/// A control target: its kind (`extension` or `permission`) and id.
pub(super) type TargetKey = (String, String);

fn matches(control: &NativeExtensionControlV1, kind: &str, target_id: &str) -> bool {
    control.target_kind == kind && control.target_id == target_id
}

/// The first local-admin layer and its position.
pub(super) fn local_layer(
    layers: &[NativeExtensionControlLayerV1],
) -> Option<(usize, &NativeExtensionControlLayerV1)> {
    layers
        .iter()
        .enumerate()
        .find(|(_, layer)| layer.kind == LOCAL_ADMIN)
}

/// Each local control's state by target; a later duplicate wins.
pub(super) fn local_controls(
    layers: &[NativeExtensionControlLayerV1],
) -> HashMap<TargetKey, String> {
    local_layer(layers)
        .map(|(_, layer)| {
            layer
                .controls
                .iter()
                .map(|control| {
                    (
                        (control.target_kind.clone(), control.target_id.clone()),
                        control.state.clone(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The local layer's state for a target, or `inherited` when it has none.
pub(super) fn explicit_state(
    layers: &[NativeExtensionControlLayerV1],
    kind: &str,
    target_id: &str,
) -> String {
    local_layer(layers)
        .and_then(|(_, layer)| {
            layer
                .controls
                .iter()
                .find(|control| matches(control, kind, target_id))
        })
        .map_or_else(|| INHERITED.to_owned(), |control| control.state.clone())
}

/// The proposed layers with one target's local control put back to what the
/// current local layer holds for it (or removed when it holds none). Local
/// controls are re-sorted by kind then id; other layers are untouched.
pub(super) fn layers_with_target_reverted(
    current_layers: &[NativeExtensionControlLayerV1],
    proposed_layers: &[NativeExtensionControlLayerV1],
    (kind, target_id): (&str, &str),
) -> Vec<NativeExtensionControlLayerV1> {
    let current_control = local_layer(current_layers).and_then(|(_, layer)| {
        layer
            .controls
            .iter()
            .find(|control| matches(control, kind, target_id))
    });
    let mut reverted = proposed_layers.to_vec();
    let Some((index, _)) = local_layer(proposed_layers) else {
        return reverted;
    };
    let local = &mut reverted[index];
    local
        .controls
        .retain(|control| !matches(control, kind, target_id));
    if let Some(control) = current_control {
        local.controls.push(control.clone());
    }
    local.controls.sort_by(|left, right| {
        (left.target_kind.as_str(), left.target_id.as_str())
            .cmp(&(right.target_kind.as_str(), right.target_id.as_str()))
    });
    reverted
}

/// Which sources hold a control for the target: a global lockdown, then each
/// layer naming it in order, or the built-in default when none does.
pub(super) fn provenance(
    layers: &[NativeExtensionControlLayerV1],
    kind: &str,
    target_id: &str,
    global_lockdown: bool,
) -> Vec<String> {
    let mut sources = Vec::new();
    if global_lockdown {
        sources.push("global-lockdown".to_owned());
    }
    for layer in layers {
        if layer
            .controls
            .iter()
            .any(|control| matches(control, kind, target_id))
        {
            sources.push(layer.kind.clone());
        }
    }
    if sources.is_empty() {
        sources.push("built-in-default".to_owned());
    }
    sources
}

/// What one set of layers blocks.
pub(super) struct Effective {
    pub(super) global_lockdown: bool,
    /// Every catalog permission, by id: whether it is allowed.
    pub(super) permission_allowed: HashMap<String, bool>,
    /// The asked extensions, by canonical id: whether they are blocked.
    pub(super) extension_blocked: HashMap<String, bool>,
}

impl Effective {
    pub(super) fn allowed(&self, permission_id: &str) -> bool {
        self.permission_allowed
            .get(permission_id)
            .copied()
            .unwrap_or(false)
    }

    pub(super) fn blocked_extension(&self, extension_id: &str) -> bool {
        self.extension_blocked
            .get(extension_id)
            .copied()
            .unwrap_or(true)
    }
}

/// Resolve every catalog permission, one at a time, and each named extension
/// against `layers` on the command-evaluation surface, as command evaluation
/// resolves them. Only the first `MAX_CONTROL_LAYERS + 1` layers are read,
/// the slice the resolver itself bounds to.
pub(super) fn resolve_effective(
    catalog: &PreviewCatalog<'_>,
    layers: &[NativeExtensionControlLayerV1],
    extension_ids: &[String],
) -> Result<Effective, String> {
    let bounded = &layers[..layers.len().min(MAX_CONTROL_LAYERS + 1)];
    let typed = typed_layers(bounded)?;
    let resolver = catalog.resolver();
    let blocked = |extensions: &[String], permissions: &[String]| {
        resolve_extension_controls(
            &typed,
            Some(resolver),
            extensions,
            permissions,
            ControlSurface::CommandEvaluation,
            &[],
            None,
        )
        .blocked
    };
    let permission_allowed = catalog
        .registry
        .permissions
        .iter()
        .map(|permission| {
            let ids = [permission.permission_id.clone()];
            (permission.permission_id.clone(), !blocked(&[], &ids))
        })
        .collect();
    let extension_blocked = extension_ids
        .iter()
        .map(|extension_id| {
            (
                extension_id.clone(),
                blocked(std::slice::from_ref(extension_id), &[]),
            )
        })
        .collect();
    Ok(Effective {
        global_lockdown: compose_control_layers(&typed).global_lockdown,
        permission_allowed,
        extension_blocked,
    })
}
