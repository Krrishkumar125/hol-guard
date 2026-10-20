//! Unit tests for the Windows read-only pytest planner.
//!
//! The module these cover is `#[cfg(windows)]`, so the file compiles only
//! where the behaviour it describes exists. `ci/platform_arms.json` records
//! that arm and the Unix behaviour it mirrors.
use super::*;
use serde_json::json;

#[test]
fn reads_an_environment_interpreter_back_from_a_plan() {
    let (environment, interpreter) =
        staged_interpreter(Path::new(".venv/Scripts/python.exe")).expect("a staged interpreter");
    assert_eq!(environment, Path::new(".venv"));
    assert_eq!(interpreter, Path::new(".venv/Scripts/python.exe"));
}

#[test]
fn reads_a_backslash_spelling_and_a_nested_environment() {
    let (environment, interpreter) =
        staged_interpreter(Path::new(r"services\api\.venv\bin\python3.12.exe"))
            .expect("a staged interpreter");
    assert_eq!(environment, Path::new("services/api/.venv"));
    assert_eq!(
        interpreter,
        Path::new("services/api/.venv/bin/python3.12.exe")
    );
}

#[test]
fn refuses_an_interpreter_outside_the_snapshot() {
    for spelling in [
        r"C:\Python312\python.exe",
        "../.venv/Scripts/python.exe",
        ".venv/Scripts/pytest.exe",
        ".venv/lib/python.exe",
        "Scripts/python.exe",
        ".venv/Scripts/../python.exe",
    ] {
        assert!(
            staged_interpreter(Path::new(spelling)).is_none(),
            "{spelling} should not name a staged interpreter"
        );
    }
}

#[test]
fn names_the_environment_binaries_from_the_run_directory() {
    assert_eq!(
        relative_from(Path::new(""), Path::new(".venv/Scripts")),
        Path::new(".venv/Scripts")
    );
    assert_eq!(
        relative_from(Path::new("services/api"), Path::new(".venv/Scripts")),
        Path::new("../../.venv/Scripts")
    );
}

#[test]
fn reads_only_a_module_run_of_pytest() {
    let arguments = |items: &[&str]| {
        items
            .iter()
            .map(|item| (*item).to_owned())
            .collect::<Vec<_>>()
    };
    assert!(arguments_target_pytest(&arguments(&["-m", "pytest", "-q"])));
    assert!(arguments_target_pytest(&arguments(&[
        "-X", "utf8", "-mpytest"
    ])));
    assert!(!arguments_target_pytest(&arguments(&["-c", "import os"])));
    assert!(!arguments_target_pytest(&arguments(&[
        "-m", "pip", "install", "x"
    ])));
    assert!(!arguments_target_pytest(&arguments(&[
        "--", "-m", "pytest"
    ])));
    assert!(!arguments_target_pytest(&arguments(&["-q"])));
}

#[test]
fn refuses_shell_operators_in_argv() {
    let arguments = vec!["-q".to_owned(), "&&".to_owned(), "curl".to_owned()];
    assert_eq!(
        screened(&arguments).expect_err("a refusal").reason_code,
        INVALID
    );
}

#[test]
fn reads_the_interpreter_names_an_environment_creates() {
    for name in ["python.exe", "python3.exe", "pythonw.exe", "python3.12.exe"] {
        assert!(interpreter_named(name), "{name} should be an interpreter");
    }
    for name in ["pytest.exe", "node.exe", "python3x.exe", "python3..exe"] {
        assert!(!interpreter_named(name), "{name} should not be one");
    }
}

#[test]
fn refuses_a_directory_that_is_not_an_environment() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let root = directory.path().to_path_buf();
    let failure = base_interpreter(&root).expect_err("no pyvenv.cfg");
    assert_eq!(failure.reason_code, UNAVAILABLE);
    std::fs::write(
        root.join("pyvenv.cfg"),
        "include-system-site-packages = false\n",
    )
    .expect("a configuration without a home");
    assert_eq!(
        base_interpreter(&root).expect_err("no home").reason_code,
        UNAVAILABLE
    );
}

#[test]
fn refuses_an_environment_with_no_interpreter_of_its_own() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let root = directory.path().to_path_buf();
    std::fs::create_dir_all(root.join("bin")).expect("a binaries directory");
    std::fs::write(root.join("bin/pytest"), "#!/bin/sh\n").expect("a POSIX launcher");
    let failure = environment_interpreter(&root).expect_err("no interpreter");
    assert_eq!(failure.reason_code, UNAVAILABLE);
    std::fs::write(root.join("bin/python.exe"), b"MZ").expect("an interpreter");
    assert_eq!(
        environment_interpreter(&root).expect("an interpreter"),
        Path::new("bin/python.exe")
    );
}

#[test]
fn reads_the_environment_a_launcher_belongs_to() {
    assert_eq!(
        environment_root(Path::new(r"C:\repo\.venv\Scripts\pytest.exe")),
        Some(PathBuf::from(r"C:\repo\.venv"))
    );
    assert_eq!(
        environment_root(Path::new(r"C:\repo\tools\pytest.exe")),
        None
    );
}

#[test]
fn refuses_a_writable_run() {
    let result = plan(&json!({"command": ["pytest"], "workspace": ".", "cwd": "."}))
        .expect_err("a read-only profile only");
    assert_eq!(result.reason_code, UNAVAILABLE);
}

#[test]
fn reports_a_refusal_as_a_resident_reason_code() {
    let value = prepare(&json!({"command": ["pytest"], "workspace": ".", "cwd": "."}));
    assert_eq!(value["reason_code"], json!(UNAVAILABLE));
    assert!(value.get("value").is_none());
}
