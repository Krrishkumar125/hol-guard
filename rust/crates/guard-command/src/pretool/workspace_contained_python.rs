//! Python package managers running a read-only query.
//!
//! [`super::package`] keeps every Python manager out of the contained route
//! because each one installs what it runs, and an install the sandbox has no
//! network for would fail where it works today. A query is the other half of
//! that surface: `pip list`, `pip freeze`, `pip show` and `pipx list` report
//! what an environment already holds, write nothing and reach no registry, so
//! the sandbox bounds them the way it bounds `npm ls` or `cargo tree`. Without
//! this the same listing is the one shape of ordinary work that stops for an
//! approval in an ecosystem whose neighbours stay quiet.
//!
//! The reading surface is pip's own, so [`super::super::pip_reads`] decides it
//! here as well: one allowlist of subcommands, options and operands serves the
//! path-spelled `pip` a project runs and the `uv pip` that drives the same
//! environment. `pipx` has a surface of its own, and only the two verbs that
//! report a layout are read here.

// pipx verbs that report what is installed. `run`, `install` and the rest
// fetch, so they keep the admission they have today.
const PIPX_LIST_FLAGS: &[&str] = &["--short", "--json", "--include-injected", "--global"];
// pipx options that change nothing a query reads, wherever they stand.
const PIPX_QUIET_FLAGS: &[&str] = &["-q", "--quiet", "-v", "--verbose"];

/// Whether a Python manager segment runs a query against an environment that
/// already exists. `uvx` fetches the tool it names and `poetry` and `pipenv`
/// install what they run, so neither reaches this.
pub(super) fn local_python_work(name: &str, arguments: &[String]) -> bool {
    match name {
        "pip" | "pip3" => super::super::pip_reads::safe_pip_arguments(arguments),
        "pipx" => {
            let words: Vec<&str> = arguments.iter().map(String::as_str).collect();
            local_pipx_work(&words)
        }
        _ => false,
    }
}

/// Whether `uv pip <rest>` is one of pip's own queries. uv puts pip's surface
/// in front of the project environment, so the words after `pip` are read by
/// the same allowlist, and an install or a sync falls out of it there too.
pub(super) fn local_uv_pip_work(words: &[&str]) -> bool {
    super::super::pip_reads::safe_pip_words(words)
}

/// `pipx list` and `pipx environment` print the layout pipx already wrote.
/// Both take no distribution name, so an operand means another verb's shape
/// and keeps the command out.
fn local_pipx_work(words: &[&str]) -> bool {
    let mut index = 0;
    while words
        .get(index)
        .is_some_and(|word| PIPX_QUIET_FLAGS.contains(word))
    {
        index += 1;
    }
    let (verb, rest) = match words.get(index) {
        Some(verb) => (*verb, &words[index + 1..]),
        None => return false,
    };
    match verb {
        "list" => rest
            .iter()
            .all(|word| PIPX_LIST_FLAGS.contains(word) || PIPX_QUIET_FLAGS.contains(word)),
        "environment" => pipx_environment(rest),
        _ => false,
    }
}

/// `pipx environment` prints every path it uses, or the one `--value` names.
fn pipx_environment(words: &[&str]) -> bool {
    let mut index = 0;
    while let Some(word) = words.get(index) {
        if PIPX_QUIET_FLAGS.contains(word) {
            index += 1;
            continue;
        }
        let named = match word.split_once('=') {
            Some(("--value", value)) => !value.is_empty(),
            Some(_) => false,
            None => {
                *word == "--value"
                    && words
                        .get(index + 1)
                        .is_some_and(|name| !name.starts_with('-'))
            }
        };
        if !named {
            return false;
        }
        index += if word.contains('=') { 1 } else { 2 };
    }
    true
}

#[cfg(test)]
#[path = "workspace_contained_python_tests.rs"]
mod python_tests;
