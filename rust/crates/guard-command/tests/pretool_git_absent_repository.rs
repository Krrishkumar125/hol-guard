//! `git -C <directory>` where Git's own discovery walk finds no repository.
//! The command can only print `fatal: not a git repository` — or, when the
//! directory is not there, the path it could not enter — so it reads nothing
//! and must not ask. Agents reach this shape while probing for a checkout
//! that a scratch or sibling directory may or may not hold.
//!
//! The fixture roots live below the shared temporary directory because
//! `CARGO_TARGET_TMPDIR` sits inside this repository, where the discovery
//! walk would find the repository's own `.git` and answer a different
//! question.
#![cfg(unix)]

use std::path::{Path, PathBuf};

use crate::git_helper_fixture as fixture;
use crate::pretool_home_layout_reads::{assert_decision, repository};

struct Scratch {
    _cleanup: fixture::FixtureCleanup,
    root: PathBuf,
}

fn scratch(name: &str) -> Scratch {
    let root = std::fs::canonicalize("/tmp").unwrap().join(format!(
        "guard-absent-repository-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    Scratch {
        _cleanup: fixture::FixtureCleanup(root.clone()),
        root: fixture::canonical_spelling(root),
    }
}

fn directory(root: &Path, name: &str) -> PathBuf {
    let path = root.join(name);
    std::fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn git_read_routed_to_a_directory_without_a_repository_is_allowed() {
    let scratch = scratch("plain");
    let home = directory(&scratch.root, "home");
    let workspace = directory(&scratch.root, "home/Code/app-portal");
    repository(&workspace);
    let plain = directory(&scratch.root, "home/Code/scratch-notes");
    for command in [
        format!("git -C {} status --short", fixture::shell_word(&plain)),
        format!("git -C {} status", fixture::shell_word(&plain)),
        "git -C ../scratch-notes log --oneline -3".to_owned(),
        "git -C ~/Code/scratch-notes diff --stat".to_owned(),
    ] {
        assert_decision(&workspace, &home, &command, true);
    }
}

#[test]
fn git_read_routed_to_a_missing_directory_is_allowed() {
    let scratch = scratch("missing");
    let home = directory(&scratch.root, "home");
    let workspace = directory(&scratch.root, "home/Code/app-portal");
    repository(&workspace);
    let missing = scratch.root.join("home/Code/not-cloned-yet");
    for command in [
        format!("git -C {} log --oneline -3", fixture::shell_word(&missing)),
        "git -C ../not-cloned-yet status --short".to_owned(),
    ] {
        assert_decision(&workspace, &home, &command, true);
    }
}

/// Discovery finds the repository above a plain subdirectory, so the route
/// keeps that repository's answer: a checkout below a home dot-directory is
/// still reviewed, and so is every directory inside it.
#[test]
fn git_read_routed_below_a_reviewed_repository_is_still_reviewed() {
    let scratch = scratch("below");
    let home = directory(&scratch.root, "home");
    let workspace = directory(&scratch.root, "home/Code/app-portal");
    repository(&workspace);
    let hidden = directory(&scratch.root, "home/.config-repo");
    repository(&hidden);
    let below = directory(&scratch.root, "home/.config-repo/notes");
    for command in [
        format!("git -C {} status --short", fixture::shell_word(&hidden)),
        format!("git -C {} log --oneline -1", fixture::shell_word(&below)),
    ] {
        assert_decision(&workspace, &home, &command, false);
    }
}
