//! Composer and Bundler verbs that read a dependency tree the project owns.
//!
//! [`super::package`] keeps every package manager out of the contained route
//! because each one installs what it runs, and an install the sandbox has no
//! network for would fail where it works today. Composer and Bundler have a
//! second surface: both install into a directory beside the manifest —
//! `vendor` and `vendor/bundle` — so a verb that reads that tree reads the
//! workspace and nothing else. Running the project's own test suite through
//! `composer run-script test` or `bundle exec rspec` is the shape a PHP or
//! Ruby developer repeats all day, and today it is the one ecosystem whose
//! ordinary work stops for an approval while its neighbours stay quiet.
//!
//! A contained run is given a private scratch `HOME`, so only a project whose
//! dependencies are materialized beside the manifest is routed here. A project
//! that resolves its gems through the caller's own gem home, or its packages
//! through Composer's home cache, would answer for the sandbox rather than the
//! developer, so it keeps the admission it has today — the same gate `uv run`
//! applies to a project whose `.venv` is not materialized yet.
//!
//! Every verb that reaches a registry stays out: `install`, `update`,
//! `require`, `remove`, `lock`, `outdated`, `diagnose` and the rest are not in
//! the lists below, and an option this module does not know keeps the command
//! out as well, because Composer's `show --latest` and `--available` turn a
//! local listing into a registry query.

use std::path::Path;

/// The managers that install into a directory the project owns.
pub(super) const VENDORED_MANAGERS: &[&str] = &["composer", "bundle", "bundler"];

/// Composer verbs that read the project rather than a registry. `validate`
/// reads the manifest and lockfile alone; the rest report or run what is
/// already installed under `vendor`.
const COMPOSER_LOCAL_VERBS: &[&str] = &[
    "validate",
    "show",
    "info",
    "exec",
    "run",
    "run-script",
    "dump-autoload",
    "dumpautoload",
    "check-platform-reqs",
    "licenses",
    "status",
];
/// The verbs above that need the installed tree beside the manifest.
const COMPOSER_VENDOR_VERBS: &[&str] = &[
    "show",
    "info",
    "exec",
    "run",
    "run-script",
    "dump-autoload",
    "dumpautoload",
    "check-platform-reqs",
    "licenses",
    "status",
];
/// Composer options a local verb may carry. The list is an allowlist because
/// the options that reach a registry are many and grow: `--latest`, `--all`
/// and `--available` each turn `show` into a registry query, so an option this
/// module does not know keeps the command out.
const COMPOSER_INERT_FLAGS: &[&str] = &[
    "-q",
    "--quiet",
    "-n",
    "--no-interaction",
    "--no-ansi",
    "--ansi",
    "--no-plugins",
    "--no-scripts",
    "--no-cache",
    "--strict",
    "--format=json",
    "--format=text",
];
/// Composer verbs that hand the rest of the line to a project tool. What that
/// tool reads is the workspace the sandbox already bounds.
const COMPOSER_PROGRAM_VERBS: &[&str] = &["exec", "run", "run-script"];

/// Bundler verbs that read the bundle the project owns. `exec` starts a
/// project tool; the rest report what the bundle already holds.
const BUNDLE_LOCAL_VERBS: &[&str] = &["exec", "list", "show", "check"];

/// Whether a Composer or Bundler segment runs a verb against a dependency
/// tree the workspace holds. `directory` is where the chain stands by the time
/// the segment runs, so a `cd` ahead of it decides which project is read.
pub(super) fn local_vendored_work(name: &str, arguments: &[String], directory: &Path) -> bool {
    let words: Vec<&str> = arguments
        .iter()
        .map(String::as_str)
        .take_while(|word| *word != "--")
        .collect();
    if name == "composer" {
        local_composer_work(&words, directory)
    } else {
        local_bundle_work(&words, directory)
    }
}

fn local_composer_work(words: &[&str], directory: &Path) -> bool {
    let mut rest = words
        .iter()
        .copied()
        .skip_while(|word| COMPOSER_INERT_FLAGS.contains(word));
    let Some(verb) = rest.next() else {
        return false;
    };
    if !COMPOSER_LOCAL_VERBS.contains(&verb) {
        return false;
    }
    if COMPOSER_VENDOR_VERBS.contains(&verb) && !directory.join("vendor").is_dir() {
        return false;
    }
    if COMPOSER_PROGRAM_VERBS.contains(&verb) {
        // The script or binary comes first; what follows is its own line,
        // which the sandbox bounds like any other workspace command.
        return rest.next().is_some_and(|word| !word.starts_with('-'));
    }
    rest.all(|word| !word.starts_with('-') || COMPOSER_INERT_FLAGS.contains(&word))
}

fn local_bundle_work(words: &[&str], directory: &Path) -> bool {
    let mut rest = words.iter().copied();
    let Some(verb) = rest.next() else {
        return false;
    };
    if !BUNDLE_LOCAL_VERBS.contains(&verb) {
        return false;
    }
    // Without a bundle beside the manifest the gems resolve through the
    // caller's own home, which the sandbox replaces.
    if !directory.join("vendor").join("bundle").is_dir() {
        return false;
    }
    if verb != "exec" {
        return rest.all(|word| !word.starts_with('-'));
    }
    rest.next().is_some_and(|word| !word.starts_with('-'))
}

#[cfg(test)]
#[path = "workspace_contained_vendored_tests.rs"]
mod vendored_tests;
