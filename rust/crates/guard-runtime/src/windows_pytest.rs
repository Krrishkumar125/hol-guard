//! Windows planner for the read-only pytest profile (`pytest-readonly-v2`).
//!
//! macOS and Linux run pytest inside the seatbelt and bubblewrap restricted
//! profiles. Windows had no pytest backend at all, so a project that runs its
//! own `pytest` had no quiet route and every run became a review prompt. This
//! plans the same profile onto the LPAC snapshot runner the inline evaluation
//! and local Node tool profiles already use: the workspace is copied into a
//! credential-filtered read-only snapshot, the virtual environment the run
//! needs is copied with it, and the environment's own interpreter runs
//! `-m pytest` inside the container with no network, no user profile, a
//! private HOME and TEMP, and a kill-on-close job.
//!
//! The interpreter that runs is the copy inside the snapshot, so the run keeps
//! the prefix, the `site-packages` and the `.pth` processing of the
//! environment it was launched from — an editable install resolves exactly as
//! it does outside containment. Those bytes are the repository's own, but so
//! is every `conftest.py` pytest imports: the container, not the provenance of
//! the interpreter, is what bounds this profile. The environment still has to
//! record an all-users Python install as its base, which keeps a run that
//! cannot name a real interpreter out of the profile altogether.
use guard_command::restricted_command::{normalized_command, RestrictedPytestError};
use serde_json::{json, Value};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

pub(crate) const PROFILE: &str = "pytest-readonly-v2";
const INVALID: &str = "pytest_restricted_invalid_command";
const UNAVAILABLE: &str = "pytest_restricted_sandbox_unavailable";
/// A `pyvenv.cfg` holds a handful of `key = value` lines; a larger file is
/// not one, and reading it whole stays bounded.
const PYVENV_CFG_MAX_BYTES: u64 = 64 * 1024;
/// Where an environment keeps its executables: `Scripts` is what `venv`,
/// `virtualenv` and `uv` create on Windows; `bin` is what a POSIX-shaped
/// environment left by an MSYS or Cygwin Python uses.
const BINARY_DIRECTORIES: [&str; 2] = ["Scripts", "bin"];
/// The launcher names a pytest run is started through.
const PYTEST_NAMES: [&str; 8] = [
    "pytest",
    "pytest.exe",
    "pytest.cmd",
    "pytest.bat",
    "py.test",
    "py.test.exe",
    "py.test.cmd",
    "py.test.bat",
];

fn error(reason_code: &str, message: &str) -> RestrictedPytestError {
    RestrictedPytestError {
        reason_code: reason_code.to_owned(),
        message: message.to_owned(),
    }
}

fn invalid() -> RestrictedPytestError {
    error(
        INVALID,
        "Contained pytest receives argv directly and accepts only a pytest launcher or a Python `-m pytest` invocation.",
    )
}

fn unavailable(message: &str) -> RestrictedPytestError {
    error(UNAVAILABLE, message)
}

/// The name an interpreter inside an environment is created with.
fn interpreter_named(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    let stem = name.strip_suffix(".exe").unwrap_or(&name);
    matches!(stem, "python" | "pythonw" | "python3")
        || stem.strip_prefix("python3.").is_some_and(|minor| {
            !minor.is_empty() && minor.bytes().all(|byte| byte.is_ascii_digit())
        })
}

/// `python -m pytest`, with no `-c` and no `--` ahead of the module.
fn arguments_target_pytest(arguments: &[String]) -> bool {
    let mut index = 0usize;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--" || argument == "-c" || argument.starts_with("-c") {
            return false;
        }
        if argument == "-m" {
            return arguments
                .get(index + 1)
                .is_some_and(|module| module.split('.').next() == Some("pytest"));
        }
        if let Some(module) = argument.strip_prefix("-m").filter(|rest| !rest.is_empty()) {
            return module.split('.').next() == Some("pytest");
        }
        index += 1;
    }
    false
}

/// Argv reaches the container directly, so a shell operator in it is a sign
/// the caller did not split the command the way this profile assumes.
fn screened(arguments: &[String]) -> Result<(), RestrictedPytestError> {
    if arguments
        .iter()
        .any(|argument| matches!(argument.as_str(), ";" | "&&" | "||" | "|" | "|&" | "&"))
    {
        return Err(invalid());
    }
    Ok(())
}

/// A workspace-relative path whose components are all ordinary names.
fn relative_within(path: &Path, workspace: &Path) -> Option<PathBuf> {
    let relative = path.strip_prefix(workspace).ok()?;
    relative
        .components()
        .all(|component| matches!(component, Component::Normal(_)))
        .then(|| relative.to_path_buf())
}

/// The environment a launcher belongs to: `<environment>/<Scripts|bin>/<name>`.
fn environment_root(launcher: &Path) -> Option<PathBuf> {
    let binaries = launcher.parent()?;
    let named = binaries.file_name()?.to_str()?;
    if !BINARY_DIRECTORIES
        .iter()
        .any(|directory| named.eq_ignore_ascii_case(directory))
    {
        return None;
    }
    binaries.parent().map(Path::to_path_buf)
}

/// The all-users install a `pyvenv.cfg` records as the environment's base.
///
/// The interpreter the container runs is the environment's own copy, so this
/// does not decide which bytes execute. It decides whether the directory is a
/// virtual environment of a Python the machine installed for every user at
/// all: an environment that cannot name one is not a shape this profile
/// contains, and it keeps its review.
fn base_interpreter(environment: &Path) -> Result<PathBuf, RestrictedPytestError> {
    let configuration = environment.join("pyvenv.cfg");
    let unreadable = || {
        unavailable("Contained pytest on Windows runs from a virtual environment; this directory has no readable `pyvenv.cfg`.")
    };
    let mut file = std::fs::File::open(&configuration).map_err(|_| unreadable())?;
    if file.metadata().map(|data| data.len()).unwrap_or(u64::MAX) > PYVENV_CFG_MAX_BYTES {
        return Err(unreadable());
    }
    let mut text = String::new();
    file.read_to_string(&mut text).map_err(|_| unreadable())?;
    let home = text
        .lines()
        .filter_map(|line| line.split_once('='))
        .find(|(key, _)| key.trim().eq_ignore_ascii_case("home"))
        .map(|(_, value)| PathBuf::from(value.trim()))
        .ok_or_else(unreadable)?;
    // `home` names the directory the base interpreter lives in; an all-users
    // install ships `python.exe` there under a trusted install root.
    crate::windows_readonly::trusted_executable(&home.join("python.exe"))
}

/// The environment's own interpreter, as a path relative to the environment.
fn environment_interpreter(environment: &Path) -> Result<PathBuf, RestrictedPytestError> {
    let missing = || {
        unavailable(
            "The virtual environment holds no interpreter of its own; execution was not started.",
        )
    };
    for directory in BINARY_DIRECTORIES {
        for name in ["python.exe", "python3.exe", "pythonw.exe"] {
            let relative = Path::new(directory).join(name);
            if environment.join(&relative).is_file() {
                return Ok(relative);
            }
        }
    }
    Err(missing())
}

/// The snapshot-relative interpreter and its environment, read back from a
/// launch plan's own argv.
pub(crate) fn staged_interpreter(executable: &Path) -> Option<(PathBuf, PathBuf)> {
    let text = executable.to_str()?.replace('\\', "/");
    let path = PathBuf::from(&text);
    if path.is_absolute()
        || !path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        || !interpreter_named(path.file_name()?.to_str()?)
    {
        return None;
    }
    let environment = environment_root(&path)?;
    (!environment.as_os_str().is_empty()).then_some((environment, path))
}

/// A path to `target` from `base`, both relative to the same root.
///
/// The snapshot root exists only once the run starts, so the container's own
/// `PATH` names the environment's executables this way instead.
pub(crate) fn relative_from(base: &Path, target: &Path) -> PathBuf {
    let mut path = PathBuf::new();
    for _ in base.components() {
        path.push("..");
    }
    path.push(target);
    path
}

fn plan(input: &Value) -> Result<Value, RestrictedPytestError> {
    if input.get("read_only_workspace") != Some(&Value::Bool(true)) {
        return Err(unavailable(
            "Windows contains pytest read-only; a writable restricted run has no Windows backend.",
        ));
    }
    let command: Vec<String> = input
        .get("command")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?
        .iter()
        .map(|item| item.as_str().map(str::to_owned))
        .collect::<Option<_>>()
        .ok_or_else(invalid)?;
    let command = normalized_command(&command)?;
    let path = |key: &str| input.get(key).and_then(Value::as_str).map(PathBuf::from);
    let (workspace, cwd) = crate::windows_readonly::workspace_and_cwd(
        &path("workspace").ok_or_else(invalid)?,
        &path("cwd").ok_or_else(invalid)?,
    )?;
    let launcher = crate::windows_readonly::canonical(&cwd.join(&command[0]))
        .filter(|path| path.is_file())
        .ok_or_else(|| unavailable("The pytest launcher could not be resolved."))?;
    let named = launcher
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_ascii_lowercase)
        .ok_or_else(invalid)?;
    screened(&command[1..])?;
    let arguments: Vec<String> = if PYTEST_NAMES.contains(&named.as_str()) {
        ["-m", "pytest"]
            .into_iter()
            .map(str::to_owned)
            .chain(command[1..].iter().cloned())
            .collect()
    } else if interpreter_named(&named) && arguments_target_pytest(&command[1..]) {
        command[1..].to_vec()
    } else {
        return Err(invalid());
    };
    let environment = environment_root(&launcher).ok_or_else(|| {
        unavailable(
            "Contained pytest on Windows runs a virtual environment's own launcher; this command names none.",
        )
    })?;
    let relative = relative_within(&environment, &workspace).ok_or_else(|| {
        unavailable(
            "Contained pytest on Windows runs a virtual environment inside the workspace; this one is outside it.",
        )
    })?;
    base_interpreter(&environment)?;
    let interpreter = environment_interpreter(&environment)?;
    let backend = std::env::current_exe()
        .ok()
        .and_then(|path| crate::windows_readonly::canonical(&path))
        .ok_or_else(|| unavailable("The Guard runtime path is unavailable."))?;
    // The snapshot root is created at launch, so the plan names the
    // interpreter by its place inside the workspace copy.
    let staged = relative.join(&interpreter);
    let live = environment.join(&interpreter);
    let mut launch = vec![staged.to_string_lossy().replace('\\', "/")];
    launch.extend(arguments);
    Ok(json!({
        "profile_version": PROFILE,
        "backend": crate::windows_readonly::BACKEND,
        "backend_executable": backend,
        "workspace": workspace,
        "cwd": cwd,
        "executable": live,
        "command": launch,
        "allowed_executables": [live],
        "denied_capabilities": [
            "host-home-read",
            "host-secret-environment",
            "network",
            "docker-socket",
            "write-outside-workspace-and-private-temp",
            "unapproved-process-exec",
            "privileged-operation",
            "workspace-write",
            "workspace-credential-read",
        ],
    }))
}

/// Resident `prepare` on Windows: the read-only pytest profile's planner.
pub(crate) fn prepare(input: &Value) -> Value {
    match plan(input) {
        Ok(plan) => json!({ "value": plan }),
        Err(error) => json!({ "reason_code": error.reason_code, "message": error.message }),
    }
}

#[cfg(test)]
#[path = "windows_pytest_tests.rs"]
mod tests;
