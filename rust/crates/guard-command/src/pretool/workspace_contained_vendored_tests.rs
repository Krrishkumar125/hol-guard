//! Composer and Bundler read a dependency tree the project owns, so the verbs
//! that read it run inside the workspace sandbox the way `npm run` does.
//! Everything that reaches a registry keeps the admission it has today, as
//! does a project whose dependencies live outside the workspace. A host
//! without the sandbox, such as Windows, keeps the admission for every one.
use crate::pretool::workspace_contained_tests::{controls, host, workspace, CONTAINED};

fn outcome(harness: &str, command: &str, cwd: &std::path::Path) -> (String, String) {
    let controls = controls();
    let result = crate::pretool::evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &serde_json::json!({"tool_name": "bash", "tool_input": {"command": command}}),
        Some(&controls),
        None,
        Some("/Users/nobody"),
        cwd.to_str(),
    );
    (result.reason_code, result.minimum_action)
}

/// A PHP project whose packages are installed beside the manifest.
fn php_project(name: &str) -> std::path::PathBuf {
    let ws = workspace(name, true);
    std::fs::write(
        ws.join("composer.json"),
        "{\"name\": \"app/portal\", \"require\": {}}\n",
    )
    .unwrap();
    std::fs::write(ws.join("composer.lock"), "{\"packages\": []}\n").unwrap();
    std::fs::create_dir_all(ws.join("vendor/bin")).unwrap();
    std::fs::write(ws.join("vendor/autoload.php"), "<?php\n").unwrap();
    ws
}

/// A Ruby project whose gems are installed beside the manifest.
fn ruby_project(name: &str) -> std::path::PathBuf {
    let ws = workspace(name, true);
    std::fs::write(ws.join("Gemfile"), "source \"https://rubygems.invalid\"\n").unwrap();
    std::fs::write(
        ws.join("Gemfile.lock"),
        "DEPENDENCIES\n\nBUNDLED WITH\n   2.5.9\n",
    )
    .unwrap();
    std::fs::create_dir_all(ws.join("vendor/bundle/ruby/3.3.0/bin")).unwrap();
    std::fs::create_dir_all(ws.join(".bundle")).unwrap();
    std::fs::write(
        ws.join(".bundle/config"),
        "BUNDLE_PATH: \"vendor/bundle\"\n",
    )
    .unwrap();
    ws
}

#[test]
fn a_composer_verb_reads_the_vendor_tree_inside_the_sandbox() {
    let ws = php_project("php-reads");
    for command in [
        "composer validate",
        "composer validate --strict",
        "composer show",
        "composer show monolog/monolog",
        "composer info",
        "composer status",
        "composer licenses",
        "composer check-platform-reqs",
        "composer dump-autoload",
        "composer run-script test",
        "composer run test",
        "composer exec phpunit",
        "composer --no-interaction run-script lint",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, _) = outcome(harness, command, &ws);
            assert_eq!(reason == CONTAINED, host(), "{reason} {harness}: {command}");
        }
    }
}

#[test]
fn a_bundler_verb_reads_the_bundle_inside_the_sandbox() {
    let ws = ruby_project("ruby-reads");
    for command in [
        "bundle exec rspec",
        "bundle exec rspec spec/models",
        "bundle exec rubocop",
        "bundler exec rake",
        "bundle list",
        "bundle show",
        "bundle check",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, _) = outcome(harness, command, &ws);
            assert_eq!(reason == CONTAINED, host(), "{reason} {harness}: {command}");
        }
    }
}

#[test]
fn everything_that_reaches_a_registry_keeps_its_review() {
    let php = php_project("php-installs");
    for command in [
        "composer install",
        "composer update",
        "composer require monolog/monolog",
        "composer remove monolog/monolog",
        "composer create-project laravel/laravel app",
        "composer global require friendsofphp/php-cs-fixer",
        "composer diagnose",
        "composer self-update",
        // `show` reports the registry once one of these is attached.
        "composer show --latest",
        "composer show --all",
        "composer show --available",
        "composer show -o",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &php);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_eq!(minimum, "review", "{harness}: {command} ({reason})");
        }
    }
    let ruby = ruby_project("ruby-installs");
    for command in [
        "bundle install",
        "bundle update",
        "bundle add rails",
        "bundle outdated",
        "bundle lock",
        "bundle config set path vendor/bundle",
        "gem install rails",
        "gem update",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ruby);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_eq!(minimum, "review", "{harness}: {command} ({reason})");
        }
    }
}

#[test]
fn a_project_without_its_tree_beside_the_manifest_keeps_its_review() {
    // Without `vendor` the packages resolve through Composer's own home, and
    // without `vendor/bundle` the gems resolve through the caller's gem home;
    // the sandbox replaces both.
    let php = workspace("php-bare", true);
    std::fs::write(php.join("composer.json"), "{\"name\": \"app/portal\"}\n").unwrap();
    let ruby = workspace("ruby-bare", true);
    std::fs::write(
        ruby.join("Gemfile"),
        "source \"https://rubygems.invalid\"\n",
    )
    .unwrap();
    for (ws, command) in [
        (&php, "composer show"),
        (&php, "composer run-script test"),
        (&ruby, "bundle exec rspec"),
        (&ruby, "bundle list"),
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_eq!(minimum, "review", "{harness}: {command} ({reason})");
        }
    }
    // A manifest alone is not the tree: `composer validate` reads only the
    // manifest, so it stays local even here.
    for harness in ["codex", "claude-code", "omp"] {
        let (reason, _) = outcome(harness, "composer validate", &php);
        assert_eq!(reason == CONTAINED, host(), "{reason} {harness}");
    }
}

#[test]
fn a_verb_the_lists_do_not_hold_keeps_its_review() {
    let php = php_project("php-unknown");
    for command in [
        "composer",
        "composer --version",
        "composer archive",
        "composer exec --list",
        "composer run-script",
        "composer bump",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &php);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_eq!(minimum, "review", "{harness}: {command} ({reason})");
        }
    }
    let ruby = ruby_project("ruby-unknown");
    for command in [
        "bundle",
        "bundle exec",
        "bundle exec --help",
        "bundle doctor",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ruby);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_eq!(minimum, "review", "{harness}: {command} ({reason})");
        }
    }
}
