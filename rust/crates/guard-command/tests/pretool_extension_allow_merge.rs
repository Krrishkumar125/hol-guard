#![cfg(unix)]
//! A user who sets an extension's merge permission to Allow has decided that
//! merge commands of that shape run without review. Guard honours that Allow
//! for the merges the extension identifies, in every harness.

use crate::git_helper_fixture as fixture;
use fixture::FixtureCleanup;
use serde_json::json;
use std::path::{Path, PathBuf};

fn git(root: &Path, directory: &Path, arguments: &[&str]) {
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap())
        .env("HOME", root)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .unwrap();
    assert!(status.success(), "git {arguments:?}");
}

/// `root/project` on `main` with a GitHub origin and a `feature` branch one
/// commit ahead.
fn checkout(label: &str) -> (PathBuf, FixtureCleanup) {
    let root = std::env::temp_dir().join(format!(
        "guard-extension-allow-merge-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let project = root.join("project");
    std::fs::create_dir_all(&project).unwrap();
    git(&root, &project, &["init", "--quiet", "-b", "main"]);
    git(&root, &project, &["config", "user.name", "Guard Fixture"]);
    git(
        &root,
        &project,
        &["config", "user.email", "guard-fixture@example.invalid"],
    );
    git(
        &root,
        &project,
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/example-org/app-portal.git",
        ],
    );
    std::fs::write(project.join("tracked.txt"), "fixture\n").unwrap();
    git(&root, &project, &["add", "tracked.txt"]);
    git(&root, &project, &["commit", "--quiet", "-m", "fixture"]);
    git(&root, &project, &["checkout", "--quiet", "-b", "feature"]);
    std::fs::write(project.join("feature.txt"), "feature\n").unwrap();
    git(&root, &project, &["add", "feature.txt"]);
    git(&root, &project, &["commit", "--quiet", "-m", "feature"]);
    git(&root, &project, &["checkout", "--quiet", "main"]);
    let root = root.canonicalize().unwrap();
    (root.clone(), FixtureCleanup(root))
}

/// Every permission in the packaged catalog set to `state`, as the Extensions
/// page writes it when the user allows each pattern.
fn every_permission(
    state: &str,
) -> guard_command::native_command_controls::CompiledNativeCommandControls {
    let program = guard_command::native_command_program::packaged_command_program().unwrap();
    let controls: Vec<_> = program
        .extensions
        .iter()
        .flat_map(|extension| extension.permissions.iter())
        .map(|permission| {
            json!({"target_kind":"permission", "target_id":permission.permission_id, "state":state})
        })
        .collect();
    let value = json!({
        "schema":"guard.native-command-control-binding.v1",
        "program_digest":program.program_digest, "catalog_digest":program.catalog_digest,
        "trust_digest":program.trust_digest, "health":"protected", "revision":1,
        "managed_revision":0, "effective_digest":"", "layers":[{
            "schema_version":"1.0.0", "kind":"local-admin", "catalog_digest":program.catalog_digest,
            "global_lockdown":false, "controls":controls
        }]
    });
    let mut binding: guard_contracts::NativeCommandControlBindingV1 =
        serde_json::from_value(value).unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    guard_command::native_command_controls::CompiledNativeCommandControls::new(&binding).unwrap()
}

fn decide(
    root: &Path,
    harness: &str,
    command: &str,
    controls: &guard_command::native_command_controls::CompiledNativeCommandControls,
) -> guard_contracts::PreToolResultV1 {
    fixture::evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(controls),
        None,
        root.to_str(),
        root.join("project").to_str(),
    )
}

fn observed(result: &guard_contracts::PreToolResultV1) -> String {
    let Some(extensions) = result.command_extensions.as_ref() else {
        return "no command extensions".to_owned();
    };
    let rules: Vec<_> = extensions
        .observations
        .iter()
        .map(|observation| {
            format!(
                "{}{:?}",
                observation.rule_id, observation.uncertainty_reasons
            )
        })
        .collect();
    let permissions: Vec<_> = extensions
        .permission_observations
        .iter()
        .map(|observation| {
            format!(
                "{}{:?}",
                observation.permission_id, observation.uncertainty_reasons
            )
        })
        .collect();
    format!(
        "rules {rules:?} permissions {permissions:?} error {:?}",
        extensions.evaluation_error
    )
}

const MERGES: &[&str] = &[
    "gh pr merge 12 --squash",
    "gh pr merge 5410 --repo example-org/app-portal --squash --delete-branch=false",
    "gh pr merge 12 --squash --delete-branch",
    "gh pr merge 12 --merge",
    "git merge --ff-only feature",
    "git merge feature",
];

#[test]
fn an_allowed_merge_permission_runs_the_merge_without_review() {
    let (root, _cleanup) = checkout("allow");
    let controls = every_permission("enabled");
    for harness in ["omp", "zcode", "codex", "claude-code"] {
        for command in MERGES {
            let result = decide(&root, harness, command, &controls);
            assert_eq!(
                result.decision,
                "allow",
                "{harness}: {command}: {} ({})",
                result.reason_code,
                observed(&result)
            );
        }
    }
}

#[test]
fn a_merge_without_an_allow_still_waits_for_review() {
    let (root, _cleanup) = checkout("default");
    let controls = fixture::github_controls("default");
    for harness in ["omp", "zcode"] {
        for command in MERGES {
            let result = decide(&root, harness, command, &controls);
            assert_ne!(result.decision, "allow", "{harness}: {command}");
        }
    }
}
