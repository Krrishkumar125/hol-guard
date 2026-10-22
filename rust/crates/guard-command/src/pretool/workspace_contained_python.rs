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
/// already exists. `uvx` fetches the tool it names, `poetry` and `pipenv`
/// install what they run, and `pipx` reports a home the sandbox replaces, so
/// none of them reaches this.
pub(super) fn local_python_work(name: &str, arguments: &[String]) -> bool {
    match name {
        "pip" | "pip3" => {
            let words: Vec<&str> = arguments.iter().map(String::as_str).collect();
            super::super::pip_reads::environment_read_words(&words)
        }
        _ => false,
    }
}

/// Whether `uv pip <rest>` is one of pip's own queries against the project's
/// environment. uv puts pip's surface in front of that environment, so the
/// words after `pip` are read by the same allowlist, and an install or a sync
/// falls out of it there too. Without a `.venv` beside the project uv resolves
/// an environment of its own, which the listing would then describe.
pub(super) fn local_uv_pip_work(words: &[&str], project: &Path) -> bool {
    super::super::pip_reads::environment_read_words(words) && project.join(".venv").is_dir()
}

#[cfg(test)]
#[path = "workspace_contained_python_tests.rs"]
mod python_tests;
