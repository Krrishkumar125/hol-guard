use super::*;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn generation_parser_rejects_zero_and_non_numeric() {
    assert!(parse_generation("0").is_err());
    assert!(parse_generation("not-a-number").is_err());
    assert_eq!(parse_generation("7").unwrap(), 7);
}

#[cfg(unix)]
#[test]
fn startup_wait_honors_remaining_caller_budget() {
    use std::time::{SystemTime, UNIX_EPOCH};

    let root = std::env::temp_dir().join(format!(
        "hol-guard-startup-budget-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let lock = crate::resident_state::acquire_startup_lock(&root)
        .unwrap()
        .unwrap();
    let caller_budget = Duration::from_secs(2);
    let scheduling_allowance = Duration::from_millis(500);
    let started = Instant::now();
    let result = client_request(&root, b"{}", caller_budget);
    let elapsed = started.elapsed();
    drop(lock);
    fs::remove_dir_all(&root).unwrap();

    assert!(matches!(
        result.unwrap_err().as_str(),
        "native_resident_start_in_progress" | "native_client_deadline_exceeded"
    ));
    assert!(
        elapsed >= Duration::from_millis(1_500),
        "premature startup failure: {elapsed:?}"
    );
    assert!(
        elapsed < caller_budget + scheduling_allowance,
        "startup exceeded the caller deadline: {elapsed:?}"
    );
}

#[test]
fn zero_client_timeout_rejects_before_state_mutation() {
    let root = std::env::temp_dir().join(format!(
        "hol-guard-managed-zero-timeout-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after the Unix epoch")
            .as_nanos()
    ));

    assert_eq!(
        client_request(&root, br"{}", Duration::ZERO),
        Err("native_client_deadline_exceeded".to_owned())
    );
    assert!(!root.exists());
}

#[test]
fn expired_client_deadline_rejects_before_request_setup() {
    let root = std::env::temp_dir().join(format!(
        "hol-guard-managed-expired-deadline-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after the Unix epoch")
            .as_nanos()
    ));
    fs::create_dir(&root).expect("test state directory should be created");
    let client_lease = lease::acquire(&root).expect("test lease should be acquired");

    let result = client_request_with_deadline(
        &root,
        br"{}",
        Instant::now() - Duration::from_millis(1),
        &client_lease,
    );
    assert_eq!(result, Err("native_client_deadline_exceeded".to_owned()));

    drop(client_lease);
    fs::remove_dir_all(root).expect("test state directory should be removable");
}

#[cfg(unix)]
#[test]
fn client_request_cannot_spawn_while_update_barrier_is_held() {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let root = std::env::temp_dir().join(format!(
        "hol-guard-managed-update-barrier-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).expect("test state directory should be created");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let lock_path = root.join(crate::resident_update_lock::RESIDENT_UPDATE_LOCK_FILE_NAME);
    let digest = runtime_digest().unwrap();
    let mut update_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .unwrap();
    update_file
        .write_all(format!("{digest}\n").as_bytes())
        .unwrap();
    update_file.sync_all().unwrap();
    fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).unwrap();
    fs2::FileExt::try_lock_exclusive(&update_file).unwrap();
    let client_lease = lease::acquire(&root).expect("test lease should be acquired");

    let result = client_request_with_deadline(
        &root,
        br"{}",
        Instant::now() + Duration::from_secs(1),
        &client_lease,
    );
    assert_eq!(result, Err("native_resident_update_in_progress".to_owned()));
    let spawned_scope = fs::read_dir(&root)
        .unwrap()
        .filter_map(Result::ok)
        .any(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("resident-v3-")
        });
    assert!(
        !spawned_scope,
        "blocked request must not create resident state"
    );

    drop(client_lease);
    fs2::FileExt::unlock(&update_file).unwrap();
    drop(update_file);
    fs::remove_dir_all(root).expect("test state directory should be removable");
}

#[test]
fn client_stream_eof_is_clean_and_partial_headers_fail_closed() {
    use std::io::Cursor;

    assert_eq!(
        read_client_stream_frame(&mut Cursor::new(Vec::<u8>::new())).unwrap(),
        None
    );
    let error = read_client_stream_frame(&mut Cursor::new(vec![0, 0])).unwrap_err();
    assert_eq!(error, "native_client_stream_frame_truncated");
}

#[test]
fn client_stream_frames_are_bounded_and_big_endian() {
    use std::io::Cursor;

    let mut encoded = Vec::new();
    write_client_stream_frame(&mut encoded, b"{}").unwrap();
    assert_eq!(&encoded[..4], &[0, 0, 0, 2]);
    assert_eq!(
        read_client_stream_frame(&mut Cursor::new(encoded)).unwrap(),
        Some(b"{}".to_vec())
    );
    let oversized = vec![0xff; crate::MAX_NATIVE_RESPONSE_BYTES + 1];
    assert_eq!(
        write_client_stream_frame(&mut Vec::new(), &oversized).unwrap_err(),
        "native_client_stream_response_too_large"
    );
}

#[test]
fn client_leases_keep_shared_resident_alive_until_last_client_closes() {
    let root = std::env::temp_dir().join(format!(
        "hol-guard-managed-client-lease-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let digest = runtime_digest().unwrap();
    let first = lease::acquire(&root).unwrap();
    let second = lease::acquire(&root).unwrap();
    assert!(lease::any_live(&root, &digest));
    let foreign = root
        .join("resident-client-leases.v1")
        .join("client-foreign.lease");
    fs::write(
        &foreign,
        format!(
            "{}\n{}\n{}\n",
            std::process::id(),
            process_start_marker(std::process::id()).unwrap(),
            "f".repeat(64)
        ),
    )
    .unwrap();
    #[cfg(windows)]
    crate::resident_state::protect_windows_private_path(&foreign, false, &root).unwrap();
    assert!(lease::any_live_for_home(&root));
    drop(first);
    assert!(lease::any_live(&root, &digest));
    drop(second);
    assert!(!lease::any_live(&root, &digest));
    fs::remove_file(foreign).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn retire_clients_for_update_terminates_exact_process() {
    use std::path::PathBuf;
    use std::process::{Command, Stdio};

    if let Some(root) = std::env::var_os("HOL_GUARD_LEASE_RETIRE_CHILD") {
        let root = PathBuf::from(root);
        let _lease = lease::acquire(&root).expect("child lease should be acquired");
        fs::write(root.join("child-ready"), []).expect("child readiness marker should be written");
        // Outlive the parent's retirement budget; a normal fixture exit is not proof of retirement.
        std::thread::sleep(Duration::from_secs(120));
        return;
    }
    let root = std::env::temp_dir().join(format!(
        "hol-guard-managed-lease-retire-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let test_name = "managed_resident::tests::retire_clients_for_update_terminates_exact_process";
    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg(test_name)
        .arg("--nocapture")
        .env("HOL_GUARD_LEASE_RETIRE_CHILD", &root)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    for _ in 0..6_000 {
        if root.join("child-ready").is_file() || child.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if !root.join("child-ready").is_file() {
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_dir_all(&root);
        panic!("child did not acquire a lease");
    }
    let digest = runtime_digest().unwrap();
    // This correctness test authenticates the entire test executable. LLVM
    // coverage makes that unoptimized binary much larger than the shipped
    // runtime, so fingerprinting must not consume the fixture's stop budget.
    // Production stop deadlines remain unchanged in stop_managed.
    let retirement =
        lease::retire_clients_for_update(&root, &digest, Instant::now() + Duration::from_secs(60));
    if let Err(error) = retirement {
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_dir_all(&root);
        panic!("authenticated client retirement should succeed: {error}");
    }
    let status = child.wait().unwrap();
    assert!(!status.success(), "retired client should not exit normally");
    let remaining_leases = fs::read_dir(root.join("resident-client-leases.v1"))
        .unwrap()
        .filter_map(Result::ok)
        .any(|entry| entry.file_name().to_string_lossy().ends_with(".lease"));
    assert!(
        !remaining_leases,
        "retired lease should be removed by identity"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn stale_lease_cleanup_requires_a_dead_process_identity() {
    let root = std::env::temp_dir().join(format!(
        "hol-guard-managed-stale-lease-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let directory = root.join("resident-client-leases.v1");
    fs::create_dir(&directory).unwrap();
    let current_process_lease = directory.join("client-current.lease");
    fs::write(
        &current_process_lease,
        format!(
            "{}\n{}\n{}\n",
            std::process::id(),
            process_start_marker(std::process::id()).unwrap(),
            "f".repeat(64)
        ),
    )
    .unwrap();
    let dead_process_lease = directory.join("client-dead.lease");
    fs::write(
        &dead_process_lease,
        "4294967295\nstale\n".to_owned() + &"e".repeat(64) + "\n",
    )
    .unwrap();
    #[cfg(windows)]
    {
        crate::resident_state::protect_windows_private_path(&directory, true, &root).unwrap();
        crate::resident_state::protect_windows_private_path(&current_process_lease, false, &root)
            .unwrap();
        crate::resident_state::protect_windows_private_path(&dead_process_lease, false, &root)
            .unwrap();
    }
    std::thread::sleep(lease::LEASE_EXPIRY + Duration::from_millis(100));
    assert!(!lease::any_live_for_home(&root));
    // Expired leases are drained even when the owning process is still running.
    assert!(!current_process_lease.exists());
    assert!(!dead_process_lease.exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn lease_directory_overflow_fails_closed_without_unbounded_collection() {
    let root = std::env::temp_dir().join(format!(
        "hol-guard-managed-lease-overflow-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(root.join("resident-client-leases.v1")).unwrap();
    #[cfg(unix)]
    {
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(
            root.join("resident-client-leases.v1"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }
    #[cfg(windows)]
    {
        crate::resident_state::protect_windows_private_path(&root, true, &root).unwrap();
        crate::resident_state::protect_windows_private_path(
            &root.join("resident-client-leases.v1"),
            true,
            &root,
        )
        .unwrap();
    }
    for index in 0..=64 {
        let path = root
            .join("resident-client-leases.v1")
            .join(format!("client-{index:03}.lease"));
        fs::write(&path, format!("4294967295\nstale\n{}\n", "e".repeat(64))).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        #[cfg(windows)]
        crate::resident_state::protect_windows_private_path(&path, false, &root).unwrap();
    }
    assert!(lease::any_live_for_home(&root));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn owner_liveness_expires_after_launcher_and_all_clients_disappear() {
    use std::fs;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    let root = std::env::temp_dir().join(format!(
        "hol-guard-managed-owner-liveness-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let lease = lease::acquire(&root).unwrap();
    let digest = runtime_digest().unwrap();
    let alive = managed_owner_liveness(&root, 1, "never-matches".to_owned(), &digest);
    std::thread::sleep(Duration::from_millis(150));
    assert!(alive.load(Ordering::Acquire));
    drop(lease);
    for _ in 0..40 {
        if !alive.load(Ordering::Acquire) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(!alive.load(Ordering::Acquire));
    fs::remove_dir_all(root).unwrap();
}

/// Build a state base a resident scope can live under, owned by this test.
fn supervised_exit_fixture(label: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!(
        "hol-guard-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    root
}

/// Read the restart budget a supervisor left behind, or `None` before the
/// first spawn has charged one.
fn supervised_exit_budget(scope: &Path) -> Option<serde_json::Value> {
    let encoded = fs::read(scope.join("restart-budget.json")).ok()?;
    serde_json::from_slice(&encoded).ok()
}

/// Drive one managed run the way the two processes really do: the supervisor
/// claims the scope and charges the spawn, the serving child leaves a note
/// named after itself if it was asked to stop, and the supervisor closes the
/// run out against the child it reaped.
fn drive_supervised_run(
    state_base: &Path,
    digest: &str,
    scope: &Path,
    serving_child: u32,
    stop_requested: bool,
) {
    let supervised = exit_record::supervised_scope(state_base, digest).unwrap();
    restart_budget::consume(scope).unwrap();
    // Measure the run from the charge the supervisor gives back, so the
    // release lands in the window that charge opened rather than in one
    // before it.
    let serving = Instant::now();
    if stop_requested {
        requested_stop::record(scope, serving_child).unwrap();
    }
    // The serve loops return as soon as the `shutdown` operation lands, so a
    // stop reaches the supervisor as a clean run far shorter than the second
    // an unexplained success has to clear, and as nothing else.
    exit_record::record_supervised_exit(
        supervised,
        None,
        true,
        Some(0),
        serving.elapsed(),
        serving_child,
    );
}

/// Two builds installed against one guard home stop each other's resident to
/// take the home-wide owner lock. Every one of those stops is requested, and
/// none of them is a crash, so no number of them may open the restart
/// circuit: once it opens, no resident starts, no policy is published, and
/// every prompt is refused with `native_policy_not_ready`.
#[test]
fn requested_stops_driven_through_the_supervisor_never_open_the_circuit() {
    let root = supervised_exit_fixture("supervised-requested-stop");
    let digest = "a".repeat(64);
    let scope = crate::resident_state::state_scope(&root, &digest).unwrap();

    // Twice the free restarts a window allows, so a charged stop could not
    // survive the loop. Each run is a fresh child, as it is in a real loop of
    // two runtimes stopping each other.
    for serving_child in 1..=6 {
        drive_supervised_run(&root, &digest, &scope, serving_child, true);
    }
    let budget = supervised_exit_budget(&scope).unwrap();
    let spawn_after_the_stops = restart_budget::consume(&scope);

    fs::remove_dir_all(&root).unwrap();

    assert_eq!(budget["attempts"], 0, "requested stops kept a charge");
    assert_eq!(
        budget["circuit_until_ms"], 0,
        "requested stops paced a spawn"
    );
    assert_eq!(budget["backoff_steps"], 0);
    assert!(
        spawn_after_the_stops.is_ok(),
        "a resident could not start after repeated requested stops: {spawn_after_the_stops:?}"
    );
}

/// The same loop without the note is a crash loop, and it must still stop
/// one. Without this the test above would pass against a budget that never
/// charges anything.
#[test]
fn immediate_exits_nobody_asked_for_still_open_the_circuit() {
    let root = supervised_exit_fixture("supervised-premature-exit");
    let digest = "b".repeat(64);
    let scope = crate::resident_state::state_scope(&root, &digest).unwrap();

    let mut opened_after = None;
    for attempt in 1..=6 {
        if restart_budget::consume(&scope).is_err() {
            opened_after = Some(attempt);
            break;
        }
        let supervised = exit_record::supervised_scope(&root, &digest).unwrap();
        let serving = Instant::now();
        exit_record::record_supervised_exit(
            supervised,
            None,
            true,
            Some(0),
            serving.elapsed(),
            attempt,
        );
    }

    fs::remove_dir_all(&root).unwrap();

    assert_eq!(
        opened_after,
        Some(4),
        "an unrequested immediate exit stopped keeping its restart charge"
    );
}

#[path = "managed_resident_owner_lock_tests.rs"]
mod owner_lock_tests; // includes managed_owner_lock_rejects_second_process contention proof

#[path = "managed_resident_retry_tests.rs"]
mod retry_tests;
