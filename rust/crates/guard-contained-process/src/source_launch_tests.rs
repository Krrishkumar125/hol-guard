use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::time::Duration;

use super::*;

#[derive(Default)]
struct Gate {
    allow: bool,
    fail_release: bool,
    commits: usize,
    releases: usize,
}

impl SourceLaunchGate for Gate {
    fn commit(&mut self) -> io::Result<()> {
        self.commits += 1;
        if self.allow {
            Ok(())
        } else {
            Err(io::ErrorKind::PermissionDenied.into())
        }
    }
    fn released(&mut self) -> io::Result<()> {
        self.releases += 1;
        if self.fail_release {
            Err(io::ErrorKind::BrokenPipe.into())
        } else {
            Ok(())
        }
    }
}

fn command(root: &Path) -> PinnedCommand {
    let root = std::fs::canonicalize(root).unwrap();
    PinnedCommand::new(
        Path::new("/bin/bash"),
        &[
            OsStr::new("--noprofile"),
            OsStr::new("--norc"),
            OsStr::new("-c"),
            OsStr::new("IFS= read -r -d '' frozen || exit 125; eval \"$frozen\""),
            OsStr::new("frozen-fixture"),
            OsStr::new("result"),
        ],
        &root,
        &[(OsString::from("LC_ALL"), OsString::from("C"))],
    )
    .unwrap()
}

#[test]
fn acknowledged_frame_is_ready_before_claim_and_denial_cannot_run() {
    use std::io::Read;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;

    struct ReadyGate {
        stream: UnixStream,
        allow: bool,
        ready: bool,
        started: bool,
    }
    impl SourceLaunchGate for ReadyGate {
        fn commit(&mut self) -> io::Result<()> {
            let mut byte = [0];
            self.stream.read_exact(&mut byte)?;
            assert_eq!(byte, *b"R");
            self.ready = true;
            if self.allow {
                Ok(())
            } else {
                Err(io::ErrorKind::PermissionDenied.into())
            }
        }
        fn released(&mut self) -> io::Result<()> {
            let mut byte = [0];
            self.stream.read_exact(&mut byte)?;
            assert_eq!(byte, *b"S");
            self.started = true;
            Ok(())
        }
    }
    for allow in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let source = format!("#{}\nprintf executed > result", "x".repeat(300_000));
        let bootstrap = format!(
            "IFS= read -r -d '' code || exit 125; [ \"${{#code}}\" -eq {} ] || exit 125; \
             printf R >&6 || exit 125; IFS= read -r -d '' auth || exit 125; \
             [ -z \"$auth\" ] || exit 125; printf S >&6 || exit 125; exec 6>&-; eval \"$code\"",
            source.len()
        );
        let command = PinnedCommand::new(
            Path::new("/bin/bash"),
            &[
                OsStr::new("--noprofile"),
                OsStr::new("--norc"),
                OsStr::new("-c"),
                OsStr::new(&bootstrap),
            ],
            &std::fs::canonicalize(root.path()).unwrap(),
            &[("LC_ALL".into(), "C".into())],
        )
        .unwrap();
        let (reader, writer) = UnixStream::pair().unwrap();
        reader
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut gate = ReadyGate {
            stream: reader,
            allow,
            ready: false,
            started: false,
        };
        let result = command.capture_acknowledged_source(
            source.as_bytes(),
            1024,
            Instant::now() + Duration::from_secs(5),
            &AtomicBool::new(false),
            Isolation {
                inherited_files: vec![std::fs::File::from(OwnedFd::from(writer))],
                ..Isolation::default()
            },
            &mut gate,
        );
        assert!(gate.ready);
        assert_eq!(gate.started, allow);
        assert_eq!(root.path().join("result").exists(), allow);
        if allow {
            assert_eq!(result.unwrap().exit_code, Some(0));
        } else {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        }
    }
}

#[test]
fn rejected_commit_releases_no_marker_and_has_no_effect() {
    let root = tempfile::tempdir().unwrap();
    let mut gate = Gate::default();
    let result = command(root.path()).capture_frozen_source(
        b"printf executed > \"$1\"",
        1024,
        Instant::now() + Duration::from_secs(5),
        &AtomicBool::new(false),
        Isolation::default(),
        &mut gate,
    );
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    assert_eq!((gate.commits, gate.releases), (1, 0));
    assert!(!root.path().join("result").exists());
}

#[test]
fn successful_commit_runs_once_and_acknowledges_one_dispatch() {
    let root = tempfile::tempdir().unwrap();
    let mut gate = Gate {
        allow: true,
        ..Gate::default()
    };
    let source = format!("#{}\nprintf executed > \"$1\"", "x".repeat(300_000));
    let result = command(root.path())
        .capture_frozen_source(
            source.as_bytes(),
            1024,
            Instant::now() + Duration::from_secs(5),
            &AtomicBool::new(false),
            Isolation::default(),
            &mut gate,
        )
        .unwrap();
    assert_eq!(result.exit_code, Some(0));
    assert_eq!((gate.commits, gate.releases), (1, 1));
    assert_eq!(
        std::fs::read(root.path().join("result")).unwrap(),
        b"executed"
    );
}

#[test]
fn a_lost_acknowledgement_retains_the_released_state() {
    let root = tempfile::tempdir().unwrap();
    let mut gate = Gate {
        allow: true,
        fail_release: true,
        ..Gate::default()
    };
    let result = command(root.path()).capture_frozen_source(
        b"printf executed > \"$1\"",
        1024,
        Instant::now() + Duration::from_secs(5),
        &AtomicBool::new(false),
        Isolation::default(),
        &mut gate,
    );
    assert!(result.is_err());
    // The caller must regard this as uncertain execution, not an unused grant.
    assert_eq!((gate.commits, gate.releases), (1, 1));
}

#[test]
fn an_expired_window_cannot_claim_a_grant() {
    let root = tempfile::tempdir().unwrap();
    let mut gate = Gate {
        allow: true,
        ..Gate::default()
    };
    let result = command(root.path()).capture_frozen_source(
        b"printf executed > \"$1\"",
        1024,
        Instant::now(),
        &AtomicBool::new(false),
        Isolation::default(),
        &mut gate,
    );
    assert!(result.is_err());
    assert_eq!((gate.commits, gate.releases), (0, 0));
    assert!(!root.path().join("result").exists());
}

#[test]
fn cancellation_during_commit_cannot_release_the_frame() {
    struct Cancels<'a>(&'a AtomicBool, usize);
    impl SourceLaunchGate for Cancels<'_> {
        fn commit(&mut self) -> io::Result<()> {
            self.0.store(true, std::sync::atomic::Ordering::Release);
            Ok(())
        }
        fn released(&mut self) -> io::Result<()> {
            self.1 += 1;
            Ok(())
        }
    }
    let root = tempfile::tempdir().unwrap();
    let cancelled = AtomicBool::new(false);
    let mut gate = Cancels(&cancelled, 0);
    let result = command(root.path()).capture_frozen_source(
        b"printf executed > \"$1\"",
        1024,
        Instant::now() + Duration::from_secs(5),
        &cancelled,
        Isolation::default(),
        &mut gate,
    );
    assert!(result.is_err());
    assert_eq!(gate.1, 0);
    assert!(!root.path().join("result").exists());
}

#[cfg(target_os = "macos")]
#[test]
fn system_root_proof_does_not_trust_private_readonly_images() {
    let root = tempfile::tempdir().unwrap();
    assert!(command(root.path()).has_readonly_system_image().unwrap());
    let private = PinnedCommand::new(
        &std::env::current_exe().unwrap(),
        &[],
        &root.path().canonicalize().unwrap(),
        &[],
    )
    .unwrap();
    assert!(!private.has_readonly_system_image().unwrap());
}
