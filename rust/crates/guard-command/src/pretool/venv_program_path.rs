//! A marked virtual environment's own program, spelled by path.
//!
//! The exact-safe floor refuses a path-spelled executable. A name looked up
//! on `PATH` reaches a program the trusted-location screen has vetted, while
//! a path reaches whatever file it names, so the basename the command would
//! otherwise be judged by proves nothing about what runs.
//!
//! `.venv/bin/python --version` is the shape that pays for that rule without
//! being what it guards against. It is the same program the activation
//! projection already hands on: `source .venv/bin/activate && python -V`
//! is rewritten to exactly this spelling before the floor reads it, so a
//! marked environment's own `bin` is a place Guard already resolves programs
//! out of. A command that names that file directly, the way an agent does
//! when it would rather not activate, runs the same program.
//!
//! PEP 405 puts `pyvenv.cfg` directly above `bin`, and only `venv`,
//! `virtualenv` and `uv` write it, so the marker is what admits the spelling:
//! a directory called `.venv` with no marker beside it stays refused, and a
//! marked environment under any other name is admitted. The directory is
//! canonical before the marker is read, so no link can dress another place as
//! an environment. The program file itself is not canonicalized: an
//! environment links its interpreter to the base one it was built from, and
//! following that link would lead out of the environment the marker proves.
//!
//! This proves only which file the word names. The basename still decides
//! what the command may do with it.

use std::path::Path;

pub(super) fn environment_program(executable: &str, context: super::PathContext<'_>) -> bool {
    if !super::read_paths::bounded_file_read_target(executable, context.home_dir, context.cwd) {
        return false;
    }
    let Ok(candidate) = guard_secure_fs::resolve_candidate(
        executable,
        context.cwd.map(Path::new),
        Path::new(context.home_dir.unwrap_or_default()),
    ) else {
        return false;
    };
    let (Some(parent), Some(program)) = (candidate.parent(), candidate.file_name()) else {
        return false;
    };
    let Ok(binaries) = std::fs::canonicalize(parent) else {
        return false;
    };
    if !binaries.join(program).is_file() {
        return false;
    }
    // POSIX environments keep their programs in `bin`, Windows ones in
    // `Scripts`; the marker sits directly above either.
    if !binaries
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
        .is_some_and(|name| name == "bin" || name == "scripts")
    {
        return false;
    }
    binaries
        .parent()
        .is_some_and(|root| root.join("pyvenv.cfg").is_file())
}

#[cfg(test)]
#[path = "venv_program_path_tests.rs"]
mod tests;
