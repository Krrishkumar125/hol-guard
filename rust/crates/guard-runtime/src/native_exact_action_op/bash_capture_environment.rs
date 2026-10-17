//! Closed startup environment for native-owned Bash capture.

use super::{BTreeMap, NativeBashCaptureV1, Result};

const SELECTED: &[&str] = &[
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LC_COLLATE",
    "LC_MESSAGES",
    "LC_NUMERIC",
    "LC_TIME",
    "LC_MONETARY",
    "TMPDIR",
];

pub(super) fn capture(request: &NativeBashCaptureV1) -> Result<BTreeMap<String, String>> {
    let stamp = &request.execution_environment;
    if !stamp.has_valid_shape() || stamp.home.as_deref() != Some(request.home_dir.as_str()) {
        return Err("bash_host_environment_unavailable");
    }
    for name in &stamp.environment_names {
        if matches!(
            name.as_str(),
            "BASH_ENV" | "ENV" | "SHELLOPTS" | "BASHOPTS" | "POSIXLY_CORRECT" | "GLOBIGNORE"
        ) || name.starts_with("LD_")
            || name.starts_with("DYLD_")
            || name.starts_with("BASH_FUNC_")
            || name.starts_with("__BASH_FUNC")
        {
            return Err("bash_startup_environment_unproven");
        }
        if SELECTED.contains(&name.as_str()) && !request.environment.contains_key(name) {
            return Err("bash_host_environment_value_withheld");
        }
    }
    if request.environment.iter().any(|(name, value)| {
        !SELECTED.contains(&name.as_str())
            || value.len() > 32 * 1024
            || value.contains('\0')
            || !stamp.environment_names.contains(name)
    }) {
        return Err("bash_host_environment_invalid");
    }
    let mut environment = request.environment.clone();
    environment.insert("HOME".into(), request.home_dir.clone());
    environment.insert("PATH".into(), stamp.path.clone());
    if environment
        .values()
        .any(|value| value.trim_start().starts_with("()"))
    {
        return Err("bash_startup_environment_unproven");
    }
    Ok(environment)
}
