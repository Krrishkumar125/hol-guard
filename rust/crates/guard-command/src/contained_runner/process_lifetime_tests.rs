//! Proofs for the process lifetime a contained launch is held to: it runs with
//! a cleared environment in its own process group, its output is captured, and
//! a timeout takes the whole group down rather than leaving work running after
//! the runner has reported.

use std::collections::BTreeMap;
use std::fs;
use std::time::{Duration, Instant};

use nix::sys::signal::kill;
use nix::unistd::Pid;

use super::contract::Backend;
use super::process::run_process;
use super::vector_support::Workspace;

fn shell(script: &str) -> Vec<String> {
    vec!["/bin/sh".to_owned(), "-c".to_owned(), script.to_owned()]
}

fn run(
    workspace: &Workspace,
    script: &str,
    timeout_seconds: f64,
) -> super::process::ProcessOutcome {
    let root = workspace.path.join("run");
    fs::create_dir_all(&root).expect("run root");
    run_process(
        &shell(script),
        &workspace.path.to_string_lossy(),
        &BTreeMap::new(),
        timeout_seconds,
        &root,
        Backend::MacosSandbox,
    )
    .expect("run")
}

/// Whether the process is still addressable. A killed-and-reaped descendant of
/// the runner is gone, not a zombie, because the runner reaps its own group.
fn still_running(pid: i32) -> bool {
    kill(Pid::from_raw(pid), None).is_ok()
}

#[test]
fn an_exit_code_and_both_streams_are_reported() {
    let workspace = Workspace::new();

    let outcome = run(
        &workspace,
        "printf standard; printf diagnostic >&2; exit 7",
        10.0,
    );

    assert_eq!(outcome.exit_code, Some(7));
    assert_eq!(outcome.stdout, "standard");
    assert_eq!(outcome.stderr, "diagnostic");
    assert!(!outcome.timed_out);
    // Without bubblewrap there is no private status channel to consult, so the
    // completed launch is the evidence.
    assert!(outcome.execution_completed);
}

#[test]
fn a_signalled_child_reports_the_signal_rather_than_success() {
    let workspace = Workspace::new();

    let outcome = run(&workspace, "kill -9 $$", 10.0);

    assert_eq!(outcome.exit_code, Some(-9));
    assert!(!outcome.timed_out);
}

#[test]
fn the_environment_the_caller_did_not_grant_is_not_inherited() {
    let workspace = Workspace::new();
    let root = workspace.path.join("env-run");
    fs::create_dir_all(&root).expect("run root");
    let mut environment = BTreeMap::new();
    environment.insert("GUARD_GRANTED".to_owned(), "yes".to_owned());

    let outcome = run_process(
        &shell("printf '%s %s' \"${GUARD_GRANTED:-missing}\" \"${PATH:-cleared}\""),
        &workspace.path.to_string_lossy(),
        &environment,
        10.0,
        &root,
        Backend::MacosSandbox,
    )
    .expect("run");

    assert_eq!(outcome.stdout, "yes cleared");
}

#[test]
fn a_timeout_takes_the_whole_process_group_with_it() {
    let workspace = Workspace::new();
    let pid_file = workspace.path.join("descendant.pid");
    // The shell backgrounds a long sleep and then blocks itself. Killing only
    // the direct child would leave that sleep running after the runner reported
    // a timeout, which is exactly the escape this proves closed.
    let script = format!(
        "sleep 120 & printf '%s' \"$!\" > {}; sleep 120",
        pid_file.display()
    );

    let outcome = run(&workspace, &script, 0.5);

    assert!(outcome.timed_out);
    assert_eq!(outcome.exit_code, None);
    let descendant: i32 = fs::read_to_string(&pid_file)
        .expect("descendant pid")
        .trim()
        .parse()
        .expect("pid");
    let deadline = Instant::now() + Duration::from_secs(5);
    while still_running(descendant) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        !still_running(descendant),
        "the backgrounded descendant must not survive the timeout"
    );
}
