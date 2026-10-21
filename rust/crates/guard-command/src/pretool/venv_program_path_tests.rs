use super::environment_program;
use crate::pretool::PathContext;
use std::path::{Path, PathBuf};

fn root(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("venv-program-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("project/.venv/bin")).unwrap();
    root
}

fn program(root: &Path, marked: bool, name: &str) {
    let venv = root.join("project/.venv");
    if marked {
        std::fs::write(
            venv.join("pyvenv.cfg"),
            "home = /usr/bin\nversion = 3.12.0\n",
        )
        .unwrap();
    }
    std::fs::write(venv.join("bin").join(name), "#!/bin/sh\nexit 0\n").unwrap();
}

fn proven(root: &Path, executable: &str) -> bool {
    let home = root.to_str().unwrap().to_owned();
    let cwd = root.join("project").to_str().unwrap().to_owned();
    environment_program(
        executable,
        PathContext {
            home_dir: Some(&home),
            cwd: Some(&cwd),
            ..Default::default()
        },
    )
}

#[test]
fn a_marked_environments_own_interpreter_is_proven() {
    let root = root("marked");
    program(&root, true, "python");
    assert!(proven(&root, ".venv/bin/python"));
}

#[test]
fn a_directory_dressed_as_an_environment_is_not() {
    let root = root("unmarked");
    program(&root, false, "python");
    assert!(!proven(&root, ".venv/bin/python"));
}

#[test]
fn a_file_beside_the_environment_is_not_one_of_its_programs() {
    let root = root("beside");
    program(&root, true, "python");
    std::fs::write(root.join("project/.venv/python"), "#!/bin/sh\nexit 0\n").unwrap();
    assert!(!proven(&root, ".venv/python"));
}

#[test]
fn a_name_the_environment_does_not_hold_is_not_proven() {
    let root = root("absent");
    program(&root, true, "python");
    assert!(!proven(&root, ".venv/bin/ruff"));
}

#[cfg(unix)]
#[test]
fn the_interpreter_link_an_environment_writes_stays_inside_it() {
    // A virtualenv links its interpreter to the base one it was built from.
    // Following that link leads out of the environment the marker proves, so
    // the directory is what gets canonicalized, not the program.
    let root = root("linked");
    program(&root, true, "python3.12");
    let base = root.join("base-python");
    std::fs::write(&base, "#!/bin/sh\nexit 0\n").unwrap();
    std::os::unix::fs::symlink(&base, root.join("project/.venv/bin/python")).unwrap();
    assert!(proven(&root, ".venv/bin/python"));
}
