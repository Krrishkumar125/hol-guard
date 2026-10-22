//! A Python package query reports what an environment already holds, so it
//! runs inside the workspace sandbox the way `npm ls` and `cargo tree` do.
//! Everything that installs keeps the admission it has today, as does every
//! read that resolves through the home directory the sandbox replaces. A host
//! without the sandbox, such as Windows, keeps the admission for the queries
//! too.
use crate::pretool::workspace_contained_tests::{controls, host, workspace, CONTAINED};

const PROJECT: &str = "[project]\nname = \"app-portal\"\nversion = \"0.1.0\"\n";

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

/// A project whose environment is already materialized, with the console
/// scripts a `pip install -e .` leaves behind.
fn project(name: &str) -> std::path::PathBuf {
    let ws = workspace(name, true);
    std::fs::write(ws.join("pyproject.toml"), PROJECT).unwrap();
    std::fs::write(ws.join("uv.lock"), "version = 1\n").unwrap();
    std::fs::create_dir_all(ws.join(".venv/bin")).unwrap();
    // What makes the prefix a virtual environment pip reads without the user site.
    std::fs::write(
        ws.join(".venv/pyvenv.cfg"),
        "home = /usr/bin\nversion = 3.12.3\n",
    )
    .unwrap();
    for name in ["pip", "pip3", "python"] {
        std::fs::write(ws.join(".venv/bin").join(name), "#!/bin/sh\n").unwrap();
    }
    ws
}

#[test]
fn a_package_query_reads_the_environment_inside_the_sandbox() {
    let ws = project("python-reads");
    for command in [
        ".venv/bin/pip list",
        "./.venv/bin/pip list --format=freeze",
        ".venv/bin/pip3 freeze",
        ".venv/bin/pip show requests",
        ".venv/bin/pip check",
        "uv pip list",
        "uv pip freeze",
        "uv pip show requests",
        "uv pip check",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, _) = outcome(harness, command, &ws);
            assert_eq!(reason == CONTAINED, host(), "{reason} {harness}: {command}");
        }
    }
}

#[test]
fn everything_that_installs_keeps_its_review() {
    let ws = project("python-installs");
    for command in [
        ".venv/bin/pip install requests",
        ".venv/bin/pip install -r requirements.txt",
        ".venv/bin/pip uninstall -y requests",
        ".venv/bin/pip download requests",
        ".venv/bin/pip wheel .",
        ".venv/bin/pip config set global.index-url https://example.invalid/simple",
        "uv pip install requests",
        "uv pip uninstall requests",
        "uv pip sync requirements.txt",
        "uv pip compile pyproject.toml",
        "pipx install ruff",
        "pipx run ruff check .",
        "pipx inject app-portal httpx",
        "pipx upgrade-all",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_eq!(minimum, "review", "{harness}: {command} ({reason})");
        }
    }
}

#[test]
fn an_option_or_operand_outside_the_query_keeps_its_review() {
    let ws = project("python-unknown");
    for command in [
        // `--target` and `--index-url` belong to the installing surface, and
        // `pip list` takes no distribution name, so each is another command's
        // shape rather than the listing this module reads.
        ".venv/bin/pip list --index-url https://example.invalid/simple",
        ".venv/bin/pip list requests",
        ".venv/bin/pip show",
        "uv pip list --target build",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_eq!(minimum, "review", "{harness}: {command} ({reason})");
        }
    }
}

#[test]
fn a_uv_query_without_a_materialized_environment_keeps_its_review() {
    // Without `.venv` uv would have to install before it could report, and
    // the sandbox has no network for that.
    let bare = workspace("python-bare", true);
    std::fs::write(bare.join("pyproject.toml"), PROJECT).unwrap();
    for harness in ["codex", "claude-code", "omp"] {
        let (reason, _) = outcome(harness, "uv pip list", &bare);
        assert_ne!(reason, CONTAINED, "{harness}");
    }
}

#[test]
fn a_read_the_sandbox_would_answer_for_itself_keeps_its_review() {
    // A contained run is given the workspace as its `HOME`, so pip's cache,
    // the user site and every `pipx` layout resolve inside the sandbox. Each
    // of these would report that directory instead of the developer's, which
    // is a worse answer than the review it would replace.
    let ws = project("python-home-reads");
    for command in [
        ".venv/bin/pip cache dir",
        ".venv/bin/pip cache info",
        ".venv/bin/pip cache list",
        ".venv/bin/pip list --user",
        ".venv/bin/pip freeze --user",
        "uv pip list --user",
        "pipx list",
        "pipx list --short",
        "pipx environment",
        "pipx environment --value PIPX_HOME",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_eq!(minimum, "review", "{harness}: {command} ({reason})");
        }
    }
}

#[test]
fn a_query_beside_an_install_keeps_the_whole_command_out() {
    let ws = project("python-mixed");
    for command in [
        ".venv/bin/pip list && .venv/bin/pip install requests",
        "uv pip freeze > frozen.txt && uv pip install -r frozen.txt",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, _) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
        }
    }
}

#[test]
fn a_pip_outside_a_virtual_environment_keeps_its_review() {
    // Outside a virtual environment pip reports the user site under the home
    // directory the sandbox replaces, so the listing would describe the
    // sandbox and `pip show` would miss what the developer installed.
    let ws = project("python-bare-pip");
    std::fs::create_dir_all(ws.join("tools/bin")).unwrap();
    std::fs::write(ws.join("tools/bin/pip"), "#!/bin/sh\n").unwrap();
    for command in [
        "pip list",
        "pip3 freeze",
        "pip show requests",
        "tools/bin/pip list",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_eq!(minimum, "review", "{harness}: {command} ({reason})");
        }
    }
}

#[test]
fn a_virtual_environment_that_exposes_the_user_site_keeps_its_review() {
    // `python -m venv --system-site-packages` writes
    // `include-system-site-packages = true`, which leaves the user site
    // enabled inside the environment. pip there still reports what the
    // developer installed under their own home, so a contained run would
    // describe the sandbox's home instead.
    let ws = project("python-system-site");
    std::fs::write(
        ws.join(".venv/pyvenv.cfg"),
        "home = /usr/bin\ninclude-system-site-packages = true\nversion = 3.12.3\n",
    )
    .unwrap();
    for command in [
        ".venv/bin/pip list",
        ".venv/bin/pip show requests",
        "uv pip list",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_eq!(minimum, "review", "{harness}: {command} ({reason})");
        }
    }
}

#[test]
fn an_empty_venv_directory_is_not_an_environment() {
    // `.venv` can exist without holding an environment, and uv then searches
    // for one elsewhere; the listing would report whatever it found.
    let bare = workspace("python-empty-venv", true);
    std::fs::write(bare.join("pyproject.toml"), PROJECT).unwrap();
    std::fs::create_dir_all(bare.join(".venv/bin")).unwrap();
    for harness in ["codex", "claude-code", "omp"] {
        let (reason, _) = outcome(harness, "uv pip list", &bare);
        assert_ne!(reason, CONTAINED, "{harness}");
    }
}

/// A poetry project whose environment lives beside it, which is what
/// `virtualenvs.in-project` writes and the only layout a contained run can
/// still find once the sandbox has replaced the home directory.
fn poetry_project(name: &str) -> std::path::PathBuf {
    let ws = project(name);
    std::fs::write(ws.join("poetry.lock"), "# generated\n").unwrap();
    ws
}

#[test]
fn a_poetry_verb_that_reads_the_project_runs_inside_the_sandbox() {
    let ws = poetry_project("poetry-reads");
    for command in [
        "poetry check",
        "poetry check --lock",
        "poetry version",
        "poetry version --short",
        "poetry --no-interaction check",
        "poetry -q version",
        "poetry run python -V",
        "poetry run pytest -q",
        "poetry run -- pytest -q",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, _) = outcome(harness, command, &ws);
            assert_eq!(reason == CONTAINED, host(), "{reason} {harness}: {command}");
        }
    }
}

#[test]
fn every_poetry_verb_that_reaches_a_registry_keeps_its_review() {
    let ws = poetry_project("poetry-installs");
    for command in [
        "poetry add requests",
        "poetry install",
        "poetry install --no-root",
        "poetry update",
        "poetry lock",
        "poetry remove requests",
        "poetry export -f requirements.txt",
        "poetry publish --build",
        "poetry self update",
        "poetry source add internal https://example.invalid/simple",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_eq!(minimum, "review", "{harness}: {command} ({reason})");
        }
    }
}

#[test]
fn a_poetry_verb_that_writes_or_moves_the_project_keeps_its_review() {
    // `poetry version 2.0.0` writes the version back into the manifest, the
    // directory options name a project these checks never looked at, and
    // `env info` and `show` answer for the environment poetry resolves
    // through its own home, which the sandbox replaces.
    let ws = poetry_project("poetry-elsewhere");
    for command in [
        "poetry version 2.0.0",
        "poetry version patch",
        "poetry -C ../dashboard run pytest",
        "poetry --directory ../dashboard check",
        "poetry --project ../dashboard version",
        "poetry env info",
        "poetry show",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_eq!(minimum, "review", "{harness}: {command} ({reason})");
        }
    }
}

#[test]
fn a_poetry_run_without_a_materialized_environment_keeps_its_review() {
    // Poetry puts the environment under its own home unless the project holds
    // `.venv`, and a contained run is handed the workspace as that home, so
    // the run would have to create the environment the sandbox has no network
    // to fill.
    let bare = workspace("poetry-bare", true);
    std::fs::write(bare.join("pyproject.toml"), PROJECT).unwrap();
    std::fs::write(bare.join("poetry.lock"), "# generated\n").unwrap();
    for harness in ["codex", "claude-code", "omp"] {
        let (reason, _) = outcome(harness, "poetry run pytest -q", &bare);
        assert_ne!(reason, CONTAINED, "{harness}");
    }
    // The verbs that read the manifest need no environment at all.
    for harness in ["codex", "claude-code", "omp"] {
        let (reason, _) = outcome(harness, "poetry check", &bare);
        assert_eq!(reason == CONTAINED, host(), "{reason} {harness}");
    }
}

#[test]
fn a_poetry_read_beside_an_install_keeps_the_whole_command_out() {
    let ws = poetry_project("poetry-mixed");
    for command in [
        "poetry check && poetry install",
        "poetry version; poetry add requests",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, _) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
        }
    }
}
