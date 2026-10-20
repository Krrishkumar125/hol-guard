#![cfg(windows)]
//! A Windows session started in a plain folder beside the repository it edits
//! writes that repository through Git Bash the way a file-edit tool does:
//! `cat C:/.../x.ts > C:/.../other-project/src/summary.ts`, an append or a
//! quoted heredoc. The POSIX proof (`pretool_sibling_repository_writes`) never
//! compiled here, and the sibling-repository lookup it relies on returned
//! nothing off Unix, so every such write was reviewed. Instruction files, Git
//! control files, links, programs and folders that are not repositories keep
//! their review.

#[allow(dead_code)]
#[path = "support/git_helper_fixture.rs"]
mod git_helper_fixture;

use git_helper_fixture::FixtureCleanup;
use serde_json::json;
use std::path::{Path, PathBuf};

fn git(repository: &Path, arguments: &[&str]) {
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .unwrap();
    assert!(status.success(), "{arguments:?}");
}

/// The drive path an agent spells, with forward slashes.
fn spelled(path: &Path) -> String {
    path.to_str()
        .unwrap()
        .trim_start_matches(r"\\?\")
        .replace('\\', "/")
}

struct Layout {
    _cleanup: FixtureCleanup,
    home: PathBuf,
    /// The session folder: a plain directory, not a repository.
    session: PathBuf,
    sibling: PathBuf,
    notes: PathBuf,
    stage: PathBuf,
}

fn layout(name: &str) -> Layout {
    let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
    std::fs::create_dir_all(&parent).unwrap();
    let root = parent
        .canonicalize()
        .unwrap()
        .join(format!("guard-win-sibling-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let cleanup = FixtureCleanup(root.clone());
    let home = root.join("home");
    let session = home.join("work");
    let sibling = home.join("other-project");
    let notes = home.join("plain-notes");
    let stage = root.join("stage");
    for directory in [&session, &notes, &stage, &sibling.join("src")] {
        std::fs::create_dir_all(directory).unwrap();
    }
    git(&sibling, &["init", "--quiet"]);
    git(&sibling, &["config", "user.name", "Guard Fixture"]);
    git(
        &sibling,
        &["config", "user.email", "guard-fixture@example.invalid"],
    );
    std::fs::write(sibling.join("src/summary.ts"), "export const a = 1;\n").unwrap();
    std::fs::write(sibling.join("AGENTS.md"), "rules\n").unwrap();
    git(&sibling, &["add", "."]);
    git(&sibling, &["commit", "--quiet", "-m", "fixture"]);
    std::fs::write(sibling.join("src/run.cmd"), "@echo off\n").unwrap();
    std::fs::write(sibling.join(".env"), "SESSION_KEY=synthetic\n").unwrap();
    std::fs::write(notes.join("a.md"), "notes\n").unwrap();
    std::fs::write(stage.join("x.ts"), "export const x = 1;\n").unwrap();
    Layout {
        _cleanup: cleanup,
        home,
        session,
        sibling,
        notes,
        stage,
    }
}

/// The decision for `command` run from the session folder, with the home
/// handed over in the given spelling.
fn action(layout: &Layout, home: &str, command: &str) -> String {
    let cwd = spelled(&layout.session);
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: ["GIT_CONFIG_NOSYSTEM", "HOME", "PATH"]
            .iter()
            .map(|name| (*name).to_owned())
            .collect(),
        environment_digest: "0".repeat(64),
        home: Some(home.to_owned()),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: true,
        library_search_paths: Default::default(),
    };
    let controls = git_helper_fixture::github_controls("enabled");
    let result = guard_command::pretool::evaluate_pre_tool_envelope_with_execution_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(&controls),
        None,
        guard_command::pretool::PathContext {
            home_dir: Some(home),
            cwd: Some(&cwd),
            cdpath_unset: false,
            rustup_override_absent: false,
            npm_config_inert: false,
            pip_config_inert: false,
            shell_home_matches: false,
            ripgrep_config_absent: false,
            psql_environment: Default::default(),
        },
        Some(&environment),
    );
    format!("{} {}", result.minimum_action, result.reason_code)
}

/// The home as the harness may hand it over: drive spelling with forward
/// slashes, or the native backslash spelling.
fn homes(layout: &Layout) -> [String; 2] {
    let native = layout
        .home
        .to_str()
        .unwrap()
        .trim_start_matches(r"\\?\")
        .to_owned();
    [spelled(&layout.home), native]
}

#[test]
fn redirects_into_a_sibling_repository_are_the_edits_a_file_tool_makes() {
    let layout = layout("allowed");
    let (sibling, stage) = (spelled(&layout.sibling), spelled(&layout.stage));
    for home in homes(&layout) {
        for command in [
            format!("cat {stage}/x.ts > {sibling}/src/summary.ts"),
            format!("cat {stage}/x.ts > {sibling}/src/new.ts"),
            format!("cat {stage}/x.ts >> {sibling}/src/summary.ts"),
            format!("cat > {sibling}/notes.md <<'EOF'\n# Pending\n- a\nEOF"),
            format!("cat >> {sibling}/notes.md <<'EOF'\n- b\nEOF"),
        ] {
            let decision = action(&layout, &home, &command);
            assert!(
                decision.starts_with("allow "),
                "{home}: {command}: {decision}"
            );
        }
    }
}

#[test]
fn protected_targets_links_and_other_folders_keep_their_review() {
    let layout = layout("reviewed");
    let (sibling, stage) = (spelled(&layout.sibling), spelled(&layout.stage));
    let (home_folder, notes) = (spelled(&layout.home), spelled(&layout.notes));
    // A junction is the link an unprivileged Windows user can make.
    let junction = layout.sibling.join("linked");
    let made = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&junction)
        .arg(&layout.notes)
        .output()
        .unwrap();
    assert!(made.status.success(), "{made:?}");
    // A folder holding an empty `.git` marker is not a repository.
    let empty = layout.home.join("empty-marker");
    std::fs::create_dir_all(empty.join(".git")).unwrap();
    let empty = spelled(&empty);
    let mut wrongly_allowed = Vec::new();
    for home in homes(&layout) {
        for command in [
            // Instruction files a newly started agent loads.
            format!("cat {stage}/x.ts > {sibling}/AGENTS.md"),
            format!("cat {stage}/x.ts >> {sibling}/AGENTS.md"),
            format!("cat > {sibling}/AGENTS.md <<'EOF'\nmore rules\nEOF"),
            // Git control files, hooks and dotenv.
            format!("cat {stage}/x.ts > {sibling}/.git/config"),
            format!("cat {stage}/x.ts >> {sibling}/.git/hooks/pre-commit"),
            format!("cat {stage}/x.ts >> {sibling}/.env"),
            // Existing programs, streams and links.
            format!("cat {stage}/x.ts > {sibling}/src/run.cmd"),
            format!("cat {stage}/x.ts > {sibling}/src/summary.ts:stream"),
            format!("cat {stage}/x.ts > {sibling}/linked/a.md"),
            // Folders that are not repositories, and the home itself.
            format!("cat {stage}/x.ts > {notes}/a.md"),
            format!("cat {stage}/x.ts > {empty}/report.ts"),
            format!("cat {stage}/x.ts > {home_folder}/notes.md"),
            format!("cat > {notes}/b.md <<'EOF'\nx\nEOF"),
        ] {
            let decision = action(&layout, &home, &command);
            if decision.starts_with("allow ") {
                wrongly_allowed.push(format!("{home}: {command}: {decision}"));
            }
        }
    }
    assert!(wrongly_allowed.is_empty(), "{wrongly_allowed:#?}");
}
