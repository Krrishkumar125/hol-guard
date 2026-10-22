//! Python package managers running a read-only query.
//!
//! [`super::package`] keeps every Python manager out of the contained route
//! because each one installs what it runs, and an install the sandbox has no
//! network for would fail where it works today. A query is the other half of
//! that surface: `pip list`, `pip freeze` and `pip show` report what an
//! environment already holds, write nothing and reach no registry, so the
//! sandbox bounds them the way it bounds `npm ls` or `cargo tree`. Without
//! this the same listing is the one shape of ordinary work that stops for an
//! approval in an ecosystem whose neighbours stay quiet.
//!
//! The reading surface is pip's own, so [`super::super::pip_reads`] decides it
//! here as well: one allowlist of subcommands, options and operands serves the
//! path-spelled `pip` a project runs and the `uv pip` that drives the same
//! environment.
//!
//! A contained run is given the workspace as its `HOME`, so only the reads
//! that resolve from the environment's own prefix are routed here. What pip
//! finds through the home directory — its cache, the user site — and every
//! `pipx` query, which reports the layout under pipx's own home, would answer
//! for the sandbox rather than the developer. Those keep the review they have
//! today until the runner can show the contained command the real directory.

use std::path::Path;

/// Whether a Python manager segment runs a query against an environment that
/// already exists. `uvx` fetches the tool it names, `pipenv` installs what it
/// runs, and `pipx` reports a home the sandbox replaces, so none of them
/// reaches this. Poetry reaches it for the verbs that read only the project
/// in front of them.
///
/// The pip has to be a virtual environment's own. Outside one, pip reports the
/// user site under the home directory as well, which the sandbox replaces, so
/// a bare `pip list` would describe the sandbox and `pip show` would miss the
/// packages the developer installed for themselves. That is the same wrong
/// environment the `--user` and cache spellings are kept out for.
pub(super) fn local_python_work(
    name: &str,
    executable: &str,
    arguments: &[String],
    directory: &Path,
) -> bool {
    match name {
        "pip" | "pip3" => {
            let words: Vec<&str> = arguments.iter().map(String::as_str).collect();
            virtual_environment_executable(executable, directory)
                && super::super::pip_reads::environment_read_words(&words)
        }
        "poetry" => local_poetry_work(arguments, directory),
        _ => false,
    }
}

/// The poetry verbs that read only the project in front of them. Everything
/// else poetry does - `add`, `install`, `update`, `lock`, `publish` - reaches
/// a registry, so it keeps the admission it has today. The list is an
/// allowlist because poetry's installing verbs are many and grow: a verb this
/// module does not know stays out.
const POETRY_LOCAL_VERBS: &[&str] = &["check", "run", "version"];

/// Options poetry reads before the verb that change only how it reports.
/// `-C`, `--directory` and `--project` are deliberately absent: each moves the
/// project this module checks `.venv` against, so a command carrying one keeps
/// the admission it has today rather than being judged against the wrong
/// directory.
const POETRY_INERT_FLAGS: &[&str] = &["--no-ansi", "--no-interaction", "-n", "--quiet", "-q"];

/// Whether `poetry` runs a verb against the project it stands in.
///
/// `poetry run` is the way a poetry project runs its own tools, the way
/// `uv run` is for uv, and the command it names is decided on its own merits
/// exactly as it is behind any other runner. It needs the environment to
/// exist already: poetry puts that environment under its own home unless
/// `virtualenvs.in-project` writes it beside the project, and a contained run
/// is given the workspace as its `HOME`, so only the in-project environment is
/// one the sandbox can still find. Without `.venv` the run keeps the
/// admission it has today, the same way `uv run` does.
///
/// `poetry check` validates the manifest and the lock beside it, and a bare
/// `poetry version` reports the manifest's version. Both read the project and
/// nothing else. A `poetry version 2.0.0` writes that version back into the
/// manifest, so an operand keeps the verb out.
fn local_poetry_work(arguments: &[String], directory: &Path) -> bool {
    let mut words = arguments
        .iter()
        .map(String::as_str)
        .take_while(|word| *word != "--")
        .skip_while(|word| POETRY_INERT_FLAGS.contains(word));
    let Some(verb) = words.next() else {
        return false;
    };
    if !POETRY_LOCAL_VERBS.contains(&verb) {
        return false;
    }
    if verb == "run" {
        return directory.join(".venv").is_dir();
    }
    words.all(|word| word.starts_with('-'))
}

/// Whether the spelled executable lives in a virtual environment's `bin`. The
/// prefix beside that directory holds `pyvenv.cfg`, which is what makes the
/// environment one pip reads without the user site. A bare name carries no
/// prefix to check, so it is never one.
fn virtual_environment_executable(executable: &str, directory: &Path) -> bool {
    let spelled = Path::new(executable);
    if spelled
        .parent()
        .is_none_or(|parent| parent.as_os_str().is_empty())
    {
        return false;
    }
    let resolved = if spelled.is_absolute() {
        spelled.to_owned()
    } else {
        directory.join(spelled)
    };
    resolved
        .parent()
        .and_then(Path::parent)
        .is_some_and(isolated_virtual_environment)
}

/// Whether the prefix holds a virtual environment pip reads without the user
/// site.
///
/// `pyvenv.cfg` is what makes a prefix one, and the file's
/// `include-system-site-packages` key is what decides whether the user site
/// stays enabled inside it: `python -m venv --system-site-packages` writes it
/// true, and CPython then leaves `ENABLE_USER_SITE` on, so `pip list` in that
/// environment still reports what the developer installed under their own
/// home. The sandbox replaces that home, so such an environment answers for
/// the sandbox and keeps the review it has today — the same wrong environment
/// the bare `pip` and the `--user` spellings are kept out for.
///
/// A missing, unreadable or directory-shaped `pyvenv.cfg` reads as no
/// environment, which is the answer a prefix that is not one should give.
fn isolated_virtual_environment(prefix: &Path) -> bool {
    let Ok(config) = std::fs::read_to_string(prefix.join("pyvenv.cfg")) else {
        return false;
    };
    !config.lines().any(|line| {
        line.split_once('=').is_some_and(|(key, value)| {
            key.trim()
                .eq_ignore_ascii_case("include-system-site-packages")
                && value.trim().eq_ignore_ascii_case("true")
        })
    })
}

/// Whether `uv pip <rest>` is one of pip's own queries against the project's
/// environment. uv puts pip's surface in front of that environment, so the
/// words after `pip` are read by the same allowlist, and an install or a sync
/// falls out of it there too. Without a materialized `.venv` beside the
/// project uv searches for an environment of its own, which the listing would
/// then describe, so the environment has to be one the same way the spelled
/// pip's is: a directory holding `pyvenv.cfg` is not enough on its own, and an
/// empty `.venv` is not an environment at all.
pub(super) fn local_uv_pip_work(words: &[&str], project: &Path) -> bool {
    super::super::pip_reads::environment_read_words(words)
        && isolated_virtual_environment(&project.join(".venv"))
}

#[cfg(test)]
#[path = "workspace_contained_python_tests.rs"]
mod python_tests;
