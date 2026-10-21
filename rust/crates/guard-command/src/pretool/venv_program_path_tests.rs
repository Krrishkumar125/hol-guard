use super::environment_program;
use crate::pretool::PathContext;
use std::path::{Path, PathBuf};

fn root(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("venv-program-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("project/.venv/bin")).unwrap();
    std::fs::create_dir_all(root.join("base")).unwrap();
    root
}

fn mark(root: &Path) {
    std::fs::write(
        root.join("project/.venv/pyvenv.cfg"),
        format!("home = {}\nversion = 3.12.0\n", root.join("base").display()),
    )
    .unwrap();
}

/// A file written straight into the environment's `bin`, the way a session
/// that plants one does.
fn program(root: &Path, marked: bool, name: &str) {
    if marked {
        mark(root);
    }
    std::fs::write(
        root.join("project/.venv/bin").join(name),
        "#!/bin/sh\nexit 0\n",
    )
    .unwrap();
}

/// The environment's own entry: a link to the base interpreter it was built
/// from, which is what `venv`, `virtualenv` and `uv` write.
#[cfg(unix)]
fn linked(root: &Path, marked: bool, name: &str, base: &Path) {
    if marked {
        mark(root);
    }
    if let Some(parent) = base.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(base, "#!/bin/sh\nexit 0\n").unwrap();
    std::os::unix::fs::symlink(base, root.join("project/.venv/bin").join(name)).unwrap();
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

#[cfg(unix)]
#[test]
fn a_marked_environments_own_interpreter_is_proven() {
    let root = root("marked");
    let base = root.join("base/python3.12");
    linked(&root, true, "python", &base);
    assert!(proven(&root, ".venv/bin/python"));
}

#[cfg(unix)]
#[test]
fn a_directory_dressed_as_an_environment_is_not() {
    let root = root("unmarked");
    let base = root.join("base/python3.12");
    linked(&root, false, "python", &base);
    assert!(!proven(&root, ".venv/bin/python"));
}

/// The marker says the directory is an environment. It says nothing about
/// which program a file in its `bin` runs, and the floor judges the command
/// by that file's name, so a name that is not the interpreter's would inherit
/// the verdict of a program on `PATH` it is not.
#[cfg(unix)]
#[test]
fn a_program_that_is_not_the_interpreter_keeps_its_review() {
    let root = root("basename");
    let base = root.join("base/busybox");
    linked(&root, true, "ls", &base);
    assert!(!proven(&root, ".venv/bin/ls"));
}

/// An environment's interpreter is a link to the base one it was built from.
/// A file written at that name resolves to itself, inside the environment the
/// session writes, and proves nothing about what runs.
#[test]
fn a_script_written_into_the_environment_is_not_its_interpreter() {
    let root = root("planted");
    program(&root, true, "python");
    assert!(!proven(&root, ".venv/bin/python"));
}

/// The working directory is where the session writes without review, so an
/// interpreter the link reaches there is the same planted file one step out.
#[cfg(unix)]
#[test]
fn an_interpreter_inside_the_working_directory_is_not_proven() {
    let root = root("worktree");
    let base = root.join("project/tools/python3.12");
    linked(&root, true, "python", &base);
    assert!(!proven(&root, ".venv/bin/python"));
}

#[cfg(unix)]
#[test]
fn a_file_beside_the_environment_is_not_one_of_its_programs() {
    let root = root("beside");
    let base = root.join("base/python3.12");
    linked(&root, true, "python", &base);
    std::os::unix::fs::symlink(&base, root.join("project/.venv/python")).unwrap();
    assert!(!proven(&root, ".venv/python"));
}

#[cfg(unix)]
#[test]
fn a_name_the_environment_does_not_hold_is_not_proven() {
    let root = root("absent");
    let base = root.join("base/python3.12");
    linked(&root, true, "python", &base);
    assert!(!proven(&root, ".venv/bin/python3"));
}

#[cfg(unix)]
#[test]
fn a_parent_component_is_not_a_spelling_this_rule_proves() {
    // Nothing downstream reads the word again, so the rule refuses a spelling
    // whose meaning depends on where the shell starts rather than resolving it.
    let root = root("parent");
    let base = root.join("base/python3.12");
    linked(&root, true, "python", &base);
    assert!(!proven(&root, ".venv/bin/../bin/python"));
}

#[cfg(unix)]
#[test]
fn a_glob_is_not_a_spelling_this_rule_proves() {
    let root = root("glob");
    let base = root.join("base/python3.12");
    linked(&root, true, "python", &base);
    assert!(!proven(&root, ".venv/bin/pyth*n"));
}

/// A virtualenv links its interpreter to the base one it was built from, and
/// the environment's own name for it is the link, not the target.
#[cfg(unix)]
#[test]
fn the_interpreter_link_an_environment_writes_leads_to_its_base() {
    let root = root("linked");
    let base = root.join("base/python3.12");
    linked(&root, true, "python3.12", &base);
    std::os::unix::fs::symlink(&base, root.join("project/.venv/bin/python")).unwrap();
    assert!(proven(&root, ".venv/bin/python"));
    assert!(proven(&root, ".venv/bin/python3.12"));
}
