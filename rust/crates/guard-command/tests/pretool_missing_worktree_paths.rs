#![cfg(unix)]

use crate::git_helper_fixture as fixture;
use fixture::{evaluate_pre_tool_envelope_with_context, FixtureCleanup};
use serde_json::json;
use std::path::{Path, PathBuf};

fn git(home: &Path, repository: &Path, arguments: &[&str]) {
    assert!(std::process::Command::new("git")
        .arg("-C")
        .arg(repository)
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_COMMON_DIR")
        .args(arguments)
        .status()
        .unwrap()
        .success());
}

struct Workspace {
    home: PathBuf,
    checkout: PathBuf,
    _cleanup: FixtureCleanup,
}

/// A main checkout below the private home with one linked worktree beside it,
/// the shape an agent is given when the change belongs in the worktree.
fn workspace(name: &str) -> Workspace {
    let unique = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-missing-worktree")
        .join(format!("{name}-{unique}"));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let cleanup = FixtureCleanup(root.clone());
    let home = root.join("home");
    let checkout = home.join("app");
    std::fs::create_dir_all(checkout.join("src")).unwrap();
    git(&home, &checkout, &["init", "--quiet"]);
    git(&home, &checkout, &["config", "user.name", "Guard Fixture"]);
    git(
        &home,
        &checkout,
        &["config", "user.email", "guard-fixture@example.invalid"],
    );
    std::fs::write(checkout.join("src/settings.ts"), "retryLimit = 3\n").unwrap();
    git(&home, &checkout, &["add", "src/settings.ts"]);
    git(&home, &checkout, &["commit", "--quiet", "-m", "fixture"]);
    git(
        &home,
        &checkout,
        &[
            "worktree",
            "add",
            "--quiet",
            "-b",
            "review",
            home.join("review-worktree").to_str().unwrap(),
        ],
    );
    std::fs::create_dir_all(home.join("notes")).unwrap();
    Workspace {
        home,
        checkout,
        _cleanup: cleanup,
    }
}

fn call(workspace: &Workspace, tool: &str, path: &str) -> guard_contracts::PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name": tool, "tool_input": {"path": path}}),
        None,
        None,
        workspace.home.to_str(),
        workspace.checkout.to_str(),
    )
}

#[test]
fn a_missing_path_in_a_registered_worktree_is_read_and_listed_quietly() {
    let w = workspace("missing-worktree-path");
    // The agent was told to make the change in the linked worktree, so it
    // names the note it is about to write there before writing it. Nothing is
    // behind that name, so the call reads nothing; every existing file in the
    // same worktree is already routed, and stopping the call would only spend
    // the agent's turn on the message the tool returns by itself.
    let note = w.home.join("review-worktree/docs/change.md");
    let note = note.to_str().unwrap().to_owned();
    for path in [note.as_str(), "~/review-worktree/docs/change.md"] {
        let result = call(&w, "read", path);
        assert_eq!(
            result.minimum_action, "allow",
            "read {path}: {}",
            result.reason_code
        );
        assert_ne!(result.reason_code, "native_missing_path", "read {path}");
    }
    // A listing of the folder that note goes in gets the same answer, so the
    // agent is not told two different things about one missing name.
    for tool in ["glob", "find", "ls"] {
        let result = call(&w, tool, "~/review-worktree/docs");
        assert_eq!(
            result.minimum_action, "allow",
            "{tool}: {}",
            result.reason_code
        );
        assert_ne!(result.reason_code, "native_missing_path", "{tool}");
    }
}

#[test]
fn a_missing_path_outside_the_registered_worktree_still_says_it_is_missing() {
    let w = workspace("missing-outside-worktree");
    // Home at large is not the agent's worktree. A name with nothing behind
    // it there keeps the explanation that lets the agent correct the path,
    // and a sensitive name keeps its own handling instead.
    for tool in ["read", "glob", "find", "ls"] {
        for path in ["~/notes/absent.md", "~/absent-worktree/docs/change.md"] {
            let result = call(&w, tool, path);
            assert_eq!(
                result.reason_code, "native_missing_path",
                "{tool} {path}: {}",
                result.minimum_action
            );
            assert_eq!(result.minimum_action, "block", "{tool} {path}");
        }
        for path in ["~/.ssh/id_absent", "~/review-worktree/.env"] {
            let result = call(&w, tool, path);
            assert_ne!(result.reason_code, "native_missing_path", "{tool} {path}");
        }
    }
}
