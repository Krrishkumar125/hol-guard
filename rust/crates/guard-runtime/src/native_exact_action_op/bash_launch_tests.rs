//! Real frozen execution under Seatbelt, with synthetic test authorization.
//! These checks do not establish an authenticated grant or host integration.

use super::*;
use guard_contained_process::SourceLaunchGate;
use std::io;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::AtomicBool;

struct Gate {
    allow: bool,
    prepared: usize,
    committed: usize,
    released: usize,
}

impl SourceLaunchGate for Gate {
    fn prepare_effects(&mut self) -> io::Result<()> {
        self.prepared += 1;
        if self.allow {
            Ok(())
        } else {
            Err(io::ErrorKind::PermissionDenied.into())
        }
    }
    fn commit(&mut self) -> io::Result<()> {
        self.committed += 1;
        if self.allow {
            Ok(())
        } else {
            Err(io::ErrorKind::PermissionDenied.into())
        }
    }
    fn released(&mut self) -> io::Result<()> {
        self.released += 1;
        Ok(())
    }
}

fn hardened_helper(root: &Path, return_code: u8) -> PathBuf {
    let source = root.join("compiled-helper.c");
    let image = root.join("compiled-helper");
    std::fs::write(
        &source,
        format!(
            r#"#include <stdio.h>
int main(int argc, char **argv) {{
  printf("argv0=%s arg=%s\n", argv[0], argc > 1 ? argv[1] : "");
  fputs("broker-stderr\n", stderr);
  return {return_code};
}}
"#
        ),
    )
    .unwrap();
    let mut compile = Command::new("/usr/bin/clang");
    compile
        .args(["-O0", "-Wl,-no_uuid"])
        .arg(&source)
        .arg("-o")
        .arg(&image);
    let mut signing = Command::new("/usr/bin/codesign");
    signing
        .args([
            "--force",
            "--sign",
            "-",
            "--options",
            "runtime",
            "--identifier",
            "guard.bash-broker-test",
        ])
        .arg(&image);
    for command in [&mut compile, &mut signing] {
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "fixture command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    image
}

#[test]
fn bash_broker_runs_the_captured_hardened_image_after_source_mutation() {
    let (_root, request) = tests::fixture();
    let root = Path::new(&request.cwd);
    let helper = hardened_helper(root, 7);
    std::fs::write(root.join("maintenance.sh"), "compiled-helper value\n").unwrap();
    let captured = capture_for_launch(&request, &tests::admitted("allow")).unwrap();
    assert_eq!(
        captured.subject.execution_assurance,
        guard_contracts::NativeBashAssuranceV1::MacosHardenedBrokerV1
    );
    assert_eq!(captured.graph.brokered_images.len(), 1);
    assert_eq!(captured.brokered_commands.len(), 1);
    std::fs::write(&helper, "#!/bin/bash\nprintf attacked\n").unwrap();
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut gate = Gate {
        allow: true,
        prepared: 0,
        committed: 0,
        released: 0,
    };
    let output = super::super::super::bash_launch::execute(
        captured,
        Instant::now() + Duration::from_secs(10),
        &AtomicBool::new(false),
        &mut gate,
    )
    .unwrap();
    assert_eq!(output.exit_code, Some(7));
    assert_eq!(output.stdout, b"argv0=compiled-helper arg=value\n");
    assert_eq!(output.stderr, b"broker-stderr\n");
    assert_eq!((gate.prepared, gate.committed, gate.released), (0, 1, 1));
}

#[test]
fn bash_broker_cache_returns_the_final_pinned_image_identity() {
    let (_root, request) = tests::fixture();
    let cwd = Path::new(&request.cwd);
    let home = Path::new(&request.home_dir);
    let environment = environment(&request).unwrap();
    hardened_helper(cwd, 7);
    let resolver = Resolver {
        cwd,
        home,
        environment: &environment,
        names: &request.execution_environment.environment_names,
        deadline: Instant::now() + Duration::from_secs(10),
        captured: RefCell::new(BTreeMap::new()),
        brokered_commands: RefCell::new(Vec::new()),
        source_snapshots: RefCell::new(BTreeMap::new()),
        source_contents: RefCell::new(BTreeMap::new()),
        network_destinations: RefCell::new(BTreeSet::new()),
    };
    let argv = vec!["compiled-helper".into(), "value".into()];
    let first = graph::Resolver::resolve(&resolver, &argv).unwrap();
    hardened_helper(cwd, 8);
    let second = graph::Resolver::resolve(&resolver, &argv).unwrap();
    let digest = |executable: graph::Executable| match executable {
        graph::Executable::Native {
            content_sha256,
            delivery: graph::NativeDelivery::HardenedBroker,
            ..
        } => content_sha256,
        _ => panic!("expected hardened broker image"),
    };
    let first = digest(first);
    let second = digest(second);
    assert_ne!(first, second);
    let commands = resolver.brokered_commands.into_inner();
    assert_eq!(commands.len(), 2);
    assert_eq!(commands[0].executable_digest, first);
    assert_eq!(commands[1].executable_digest, second);
}

#[test]
fn bash_owned_launch_runs_captured_fixture_and_preserves_mutation_sentinels() {
    let (_root, request) = tests::fixture();
    let entry = Path::new(&request.cwd).join("maintenance.sh");
    let helper = Path::new(&request.cwd).join("fixture-registry");
    let settings = Path::new(&request.home_dir).join("settings.sh");
    let protected = Path::new(&request.home_dir).join("protected");
    let report = Path::new(&request.home_dir).join("maintenance-report.tsv");
    std::fs::write(&settings, "fixture_home=$HOME\n").unwrap();
    let script = std::fs::read_to_string(&entry).unwrap();
    std::fs::write(
        &entry,
        format!(
            ". \"$HOME/settings.sh\"\n{}",
            script.replace("$HOME", "$fixture_home")
        ),
    )
    .unwrap();
    std::fs::write(&protected, b"protected sentinel").unwrap();
    let captured = capture_for_launch(&request, &tests::admitted("allow")).unwrap();
    assert!(!report.exists());
    for path in [&entry, &helper, &settings] {
        std::fs::write(path, "printf attacked > \"$HOME/protected\"\n").unwrap();
    }
    let mut gate = Gate {
        allow: true,
        prepared: 0,
        committed: 0,
        released: 0,
    };
    let result = super::super::super::bash_launch::execute(
        captured,
        Instant::now() + Duration::from_secs(5),
        &AtomicBool::new(false),
        &mut gate,
    )
    .unwrap();
    assert_eq!(
        result.exit_code,
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!((gate.prepared, gate.committed, gate.released), (1, 1, 1));
    assert!(
        result.stderr.is_empty(),
        "benign captured launch wrote stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(std::fs::read(&protected).unwrap(), b"protected sentinel");
    assert_eq!(std::fs::read_to_string(&report).unwrap(), "alpha/current\nalpha/obsolete\nalpha\tlocal metadata\nbeta/current\nbeta/obsolete\nbeta\tlocal metadata\n");
    assert_eq!(
        std::fs::metadata(&report).unwrap().permissions().mode() & 0o777,
        0o644
    );
}

#[test]
fn bash_owned_launch_denial_creates_no_report() {
    let (_root, request) = tests::fixture();
    let captured = capture_for_launch(&request, &tests::admitted("allow")).unwrap();
    let mut gate = Gate {
        allow: false,
        prepared: 0,
        committed: 0,
        released: 0,
    };
    assert!(super::super::super::bash_launch::execute(
        captured,
        Instant::now() + Duration::from_secs(5),
        &AtomicBool::new(false),
        &mut gate,
    )
    .is_err());
    assert_eq!((gate.prepared, gate.committed, gate.released), (1, 0, 0));
    assert!(!Path::new(&request.home_dir)
        .join("maintenance-report.tsv")
        .exists());
}

#[test]
fn bash_profile_resolves_physical_cwd_but_denies_unreviewed_child_file_data() {
    use guard_contained_process::Isolation;
    use std::ffi::OsStr;

    let (_root, request) = tests::fixture();
    let protected = Path::new(&request.cwd).join("unreviewed-input.txt");
    std::fs::write(&protected, "protected fixture data\n").unwrap();
    let captured = capture_for_launch(&request, &tests::admitted("allow")).unwrap();
    let profile = super::super::super::bash_launch::profile(&captured).unwrap();
    // A kernel-profile probe, deliberately independent of graph eligibility
    // and consent. This does not advertise pwd/read as supported script edges.
    let protected_literal = format!("'{}'", protected.to_str().unwrap().replace('\'', "'\\''"));
    let probe = format!(
        "pwd -P; if IFS= read -r value < {protected_literal}; then printf exposed; exit 99; fi; printf kept",
    );
    let command = captured
        .interpreter
        .with_invocation(
            &[
                OsStr::new("--noprofile"),
                OsStr::new("--norc"),
                OsStr::new("-c"),
                OsStr::new(&probe),
            ],
            &[],
        )
        .unwrap();
    let output = command
        .capture(
            b"",
            16384,
            Instant::now() + Duration::from_secs(5),
            &AtomicBool::new(false),
            Isolation {
                seatbelt: Some(profile),
                ..Isolation::default()
            },
        )
        .unwrap();
    assert_eq!(
        output.exit_code,
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("{}\nkept", request.cwd)
    );
    let errors = String::from_utf8(output.stderr).unwrap();
    assert!(!errors.contains("getcwd"), "{errors}");
    assert!(
        errors.contains("Operation not permitted"),
        "the real child-file read must be denied: {errors}"
    );
}

#[test]
fn bash_owned_launch_preserves_locale_and_checks_no_output_authority() {
    let (_root, mut request) = tests::fixture();
    std::fs::write(
        Path::new(&request.cwd).join("maintenance.sh"),
        "printf '%s\\n' 'ä' z | sort\n",
    )
    .unwrap();
    request
        .execution_environment
        .environment_names
        .push("LC_ALL".into());
    request
        .environment
        .insert("LC_ALL".into(), "en_US.UTF-8".into());
    let captured = capture_for_launch(&request, &tests::admitted("allow")).unwrap();
    assert!(captured.report.is_none());
    let mut reference = std::process::Command::new("/usr/bin/sort")
        .env_clear()
        .env("LC_ALL", "en_US.UTF-8")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    std::io::Write::write_all(&mut reference.stdin.take().unwrap(), "ä\nz\n".as_bytes()).unwrap();
    let reference = reference.wait_with_output().unwrap();
    assert!(reference.status.success());
    let mut allowed = Gate {
        allow: true,
        prepared: 0,
        committed: 0,
        released: 0,
    };
    let result = super::super::super::bash_launch::execute(
        captured,
        Instant::now() + Duration::from_secs(5),
        &AtomicBool::new(false),
        &mut allowed,
    )
    .unwrap();
    assert_eq!(
        result.exit_code,
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(result.stdout, reference.stdout);
    assert_eq!(
        (allowed.prepared, allowed.committed, allowed.released),
        (0, 1, 1)
    );
    let captured = capture_for_launch(&request, &tests::admitted("allow")).unwrap();
    let mut denied = Gate {
        allow: false,
        prepared: 0,
        committed: 0,
        released: 0,
    };
    assert!(super::super::super::bash_launch::execute(
        captured,
        Instant::now() + Duration::from_secs(5),
        &AtomicBool::new(false),
        &mut denied,
    )
    .is_err());
    assert_eq!(
        (denied.prepared, denied.committed, denied.released),
        (0, 1, 0)
    );
}
