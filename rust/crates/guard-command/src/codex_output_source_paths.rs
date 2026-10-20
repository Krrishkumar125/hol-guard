//! Source-path classification (`runtime/source_paths.py`) for the Codex
//! tool-output review. Decisions and reason codes match the retired Python.

use std::path::{Path, PathBuf};

use crate::codex_output_env::Ctx;
use crate::codex_output_fs as pyfs;
use crate::codex_output_py::{py_strip, strip_quotes, PyPath};
use crate::false_positive_rules::{
    target_is_known_skill_doc_path, KNOWN_SKILL_DOC_ROOT_SUFFIXES,
    SOURCE_INSPECTION_BENIGN_DOTFILES, SOURCE_INSPECTION_EXTENSIONS, SOURCE_INSPECTION_PARTS,
    SOURCE_INSPECTION_SENSITIVE_PARTS,
};
use crate::shell_secret_read_support::{classify_request_secret_path, classify_secret_path};

const EXTRA_EXTERNAL_SENSITIVE: &[&str] = &[
    "auth",
    "authorization",
    "credential",
    "credentials",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "passwd",
    "password",
    "private-key",
    "private_key",
    "secret",
    "secrets",
    "token",
    "tokens",
];

pub(crate) fn is_benign_source_dotfile(name: &str) -> bool {
    name == ".worktrees" || SOURCE_INSPECTION_BENIGN_DOTFILES.contains(&name)
}

pub(crate) fn is_sensitive_search_basename(name: &str) -> bool {
    name == "id_rsa" || SOURCE_INSPECTION_SENSITIVE_PARTS.contains(&name)
}

fn is_external_sensitive(name: &str) -> bool {
    is_sensitive_search_basename(name) || EXTRA_EXTERNAL_SENSITIVE.contains(&name)
}

fn is_source_part(name: &str) -> bool {
    SOURCE_INSPECTION_PARTS.contains(&name)
}

fn is_source_extension(suffix: &str) -> bool {
    SOURCE_INSPECTION_EXTENSIONS.contains(&suffix)
}

fn has_source_prefix(normalized: &str) -> bool {
    SOURCE_INSPECTION_PARTS
        .iter()
        .any(|part| normalized.starts_with(&format!("{part}/")))
}

/// `_hidden_parts_are_allowed_source` over already-lowered parts.
pub(crate) fn hidden_parts_are_allowed_source(parts: &[String]) -> bool {
    let hidden: Vec<&str> = parts
        .iter()
        .map(String::as_str)
        .filter(|part| part.starts_with('.'))
        .collect();
    if hidden.is_empty() || hidden.iter().all(|part| is_benign_source_dotfile(part)) {
        return true;
    }
    let workflow = parts
        .windows(2)
        .any(|pair| pair[0] == ".github" && pair[1] == "workflows");
    workflow && hidden == [".github"]
}

/// `SourcePathDecision`; `resolved_path` is set on every allow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SourceDecision {
    pub allowed: bool,
    pub reason_code: &'static str,
    pub resolved_path: Option<PyPath>,
}

fn deny(reason_code: &'static str) -> SourceDecision {
    SourceDecision {
        allowed: false,
        reason_code,
        resolved_path: None,
    }
}

fn allow(reason_code: &'static str, resolved_path: Option<PyPath>) -> SourceDecision {
    SourceDecision {
        allowed: true,
        reason_code,
        resolved_path,
    }
}

/// `path_contains_symlink`: `true` also when `path` escapes `base_dir`.
pub(crate) fn path_contains_symlink(path: &PyPath, base_dir: &PyPath) -> bool {
    let Some(relative) = path.relative_to(base_dir) else {
        return true;
    };
    let mut candidate = base_dir.clone();
    for part in relative {
        candidate = candidate.join(&part);
        if pyfs::is_symlink(&candidate).unwrap_or(true) {
            return true;
        }
    }
    false
}

fn path_contains_symlink_component(path: &PyPath) -> bool {
    let mut candidate = PyPath::new(path.root());
    for part in path.components() {
        if part == ".." {
            candidate = candidate.parent();
            continue;
        }
        candidate = candidate.join(part);
        if pyfs::is_symlink(&candidate).unwrap_or(true) {
            return true;
        }
    }
    false
}

fn is_immediate_sibling_git_checkout(path: &PyPath, workspace: &PyPath) -> bool {
    let parent = workspace.parent();
    let Some(relative) = path.relative_to(&parent) else {
        return false;
    };
    let Some(first) = relative.first() else {
        return false;
    };
    let checkout = parent.join(first);
    if checkout == *workspace {
        return false;
    }
    let marker = checkout.join(".git");
    let Ok(linked) = pyfs::is_symlink(&marker) else {
        return false;
    };
    if linked {
        return false;
    }
    match (pyfs::is_file(&marker), pyfs::is_dir(&marker)) {
        (Ok(file), Ok(dir)) => file || dir,
        _ => false,
    }
}

fn external_filename_is_sensitive(path: &PyPath) -> bool {
    let filename = path.name().to_lowercase();
    let stem = PyPath::new(&filename).stem().to_owned();
    if is_external_sensitive(&filename) || is_external_sensitive(&stem) {
        return true;
    }
    stem.replace(['-', '.'], "_").split('_').any(|token| {
        !token.is_empty()
            && (is_external_sensitive(token) || is_external_sensitive(&format!(".{token}")))
    })
}

/// `resolve_source_candidate_path`. `base` is `(cwd or Path.cwd())`.
pub(crate) fn resolve_source_candidate_path(
    target: &str,
    cwd: Option<&PyPath>,
    home_dir: Option<&PyPath>,
    ctx: &Ctx,
) -> Option<PyPath> {
    let stripped = strip_quotes(py_strip(target));
    if stripped.is_empty() {
        return None;
    }
    if stripped.starts_with('~') {
        let home = home_dir?;
        if stripped == "~" {
            return pyfs::resolve(home);
        }
        let rest = stripped.strip_prefix("~/")?;
        return pyfs::resolve(&home.join(rest));
    }
    let target_path = PyPath::new(stripped);
    if target_path.is_absolute() {
        return Some(target_path);
    }
    let base = pyfs::resolve(cwd.unwrap_or(&ctx.process_cwd))?;
    Some(base.join(&target_path.to_string()))
}

/// `resolve_known_skill_doc_path`: a `skill://` URI to its installed document.
pub(crate) fn resolve_known_skill_doc_path(
    target: &str,
    home_dir: Option<&PyPath>,
    ctx: &Ctx,
) -> Option<PyPath> {
    if ["$", "`", "<", ">", "|", ";", "&"]
        .iter()
        .any(|marker| target.contains(marker))
    {
        return None;
    }
    let rest = target.strip_prefix("skill://")?;
    let name = py_strip(rest).trim_matches(|c| c == '\'' || c == '"');
    if name.is_empty() {
        return None;
    }
    let name = crate::home_path_text::normalize_path(name, None).replace('\\', "/");
    if name.starts_with("..") || name == "." || name.starts_with('/') {
        return None;
    }
    // `Path.resolve()` anchors a relative home at the process working directory.
    let home = home_dir.unwrap_or(&ctx.default_home);
    let home = if home.is_absolute() {
        home.clone()
    } else {
        ctx.process_cwd.join(&home.to_string())
    };
    for suffix in KNOWN_SKILL_DOC_ROOT_SUFFIXES {
        let candidate_dir = home.join(suffix).join(&name);
        let candidate_file = candidate_dir.join("SKILL.md");
        if pyfs::is_file(&candidate_file) != Ok(true) {
            continue;
        }
        let (Some(real_dir), Some(real_file)) = (
            pyfs::resolve(&candidate_dir),
            pyfs::resolve(&candidate_file),
        ) else {
            continue;
        };
        if real_file.relative_to(&real_dir).is_some() {
            return Some(real_file);
        }
    }
    None
}

fn std_path(path: Option<&PyPath>) -> Option<PathBuf> {
    path.map(|value| PathBuf::from(value.to_string()))
}

/// `source_path_is_allowed` with the strict shell-read secret table.
pub(crate) fn source_path_is_allowed(
    target: &str,
    cwd: Option<&PyPath>,
    home_dir: Option<&PyPath>,
    ctx: &Ctx,
    allow_external_source: bool,
) -> SourceDecision {
    source_path_decision(target, cwd, home_dir, ctx, allow_external_source, false)
}

/// `source_path_is_allowed` with the request-classification secret table.
pub(crate) fn source_path_is_allowed_for_request(
    target: &str,
    cwd: Option<&PyPath>,
    home_dir: Option<&PyPath>,
    ctx: &Ctx,
    allow_external_source: bool,
) -> SourceDecision {
    source_path_decision(target, cwd, home_dir, ctx, allow_external_source, true)
}

fn source_path_decision(
    target: &str,
    cwd: Option<&PyPath>,
    home_dir: Option<&PyPath>,
    ctx: &Ctx,
    allow_external_source: bool,
    request_profile: bool,
) -> SourceDecision {
    let stripped = strip_quotes(py_strip(target));
    if stripped.is_empty() {
        return deny("empty_path");
    }
    let normalized_text = stripped.replace('\\', "/");
    let lexical: Vec<&str> = normalized_text
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    if lexical.contains(&"..") {
        return deny("path_traversal");
    }
    if stripped.chars().any(|c| matches!(c, '*' | '?' | '{' | '}')) {
        return deny("glob_pattern");
    }
    let cwd_std = std_path(cwd);
    let home_std = std_path(Some(home_dir.unwrap_or(&ctx.default_home)));
    let classify = if request_profile {
        classify_request_secret_path
    } else {
        classify_secret_path
    };
    if classify(stripped, cwd_std.as_deref(), home_std.as_deref()).is_some() {
        return deny("sensitive_basename");
    }
    if lexical
        .iter()
        .any(|part| is_sensitive_search_basename(&part.to_lowercase()))
    {
        return deny("sensitive_basename");
    }
    if target_is_known_skill_doc_path(stripped, home_std.as_deref()) {
        let resolved = resolve_known_skill_doc_path(stripped, home_dir, ctx)
            .or_else(|| resolve_source_candidate_path(stripped, cwd, home_dir, ctx));
        return allow("known_skill_doc_path", resolved);
    }
    if let Some(home) = home_dir {
        let safety = home.join(".hol-support").join("SAFETY.md");
        if (stripped == "~/.hol-support/SAFETY.md" || stripped == safety.to_string())
            && pyfs::is_file(&safety) == Ok(true)
            && pyfs::is_symlink(&safety) == Ok(false)
        {
            return allow("guard_safety_doc_path", pyfs::resolve(&safety));
        }
    }
    let Some(base_dir) = pyfs::resolve(cwd.unwrap_or(&ctx.process_cwd)) else {
        return deny("unresolved_path");
    };
    let external_requested = PyPath::new(stripped).is_absolute() || stripped.starts_with("~/");
    let target_path = match (stripped.strip_prefix("~/"), home_dir) {
        (Some(rest), Some(home)) => Some(home.join(rest)),
        _ => resolve_source_candidate_path(stripped, Some(&base_dir), home_dir, ctx),
    };
    let Some(target_path) = target_path else {
        return deny("unresolved_path");
    };

    let inside_lexically = target_path.relative_to(&base_dir).is_some();
    if inside_lexically {
        if path_contains_symlink(&target_path, &base_dir) {
            return deny("symlink_in_path");
        }
    } else {
        if !allow_external_source || !external_requested {
            return deny("absolute_path_outside_workspace");
        }
        if path_contains_symlink_component(&target_path) {
            return deny("symlink_in_path");
        }
    }
    let Some(candidate) = pyfs::resolve(&target_path) else {
        return deny("absolute_path_outside_workspace");
    };
    let parts: Vec<String> = if let Some(relative) = candidate.relative_to(&base_dir) {
        relative
    } else {
        return external_decision(
            stripped,
            &candidate,
            &base_dir,
            home_dir,
            allow_external_source && external_requested,
        );
    };
    if parts.is_empty() {
        return deny("empty_resolved_path");
    }
    let lowered: Vec<String> = parts.iter().map(|part| part.to_lowercase()).collect();
    if lowered
        .iter()
        .any(|part| is_sensitive_search_basename(part))
    {
        return deny("sensitive_basename");
    }
    if !hidden_parts_are_allowed_source(&lowered) {
        return deny("unsafe_hidden_dir");
    }
    let normalized = parts.join("/");
    if SOURCE_INSPECTION_PARTS.contains(&normalized.as_str()) {
        return allow("source_prefix_exact", Some(candidate));
    }
    if has_source_prefix(&normalized) {
        return allow("source_prefix", Some(candidate));
    }
    if lowered.iter().any(|part| is_source_part(part)) {
        return allow("source_inspection_part", Some(candidate));
    }
    let literal = PyPath::new(stripped);
    if is_benign_source_dotfile(&literal.name().to_lowercase()) {
        return allow("benign_source_dotfile", Some(candidate));
    }
    if is_source_extension(&literal.suffix().to_lowercase()) {
        return allow("source_extension", Some(candidate));
    }
    deny("not_source_like")
}

fn external_decision(
    stripped: &str,
    candidate: &PyPath,
    base_dir: &PyPath,
    home_dir: Option<&PyPath>,
    external_allowed: bool,
) -> SourceDecision {
    if !external_allowed {
        return deny("absolute_path_outside_workspace");
    }
    let Some(home) = home_dir else {
        return deny("external_home_unavailable");
    };
    let Some(resolved_home) = pyfs::resolve(home) else {
        return deny("external_home_unavailable");
    };
    if pyfs::exists(&resolved_home) != Ok(true) || pyfs::is_dir(&resolved_home) != Ok(true) {
        return deny("external_home_unavailable");
    }
    if candidate.relative_to(&resolved_home).is_none() {
        return deny("external_target_outside_home");
    }
    if !is_immediate_sibling_git_checkout(candidate, base_dir) {
        return deny("external_target_not_sibling_git_checkout");
    }
    let readable = pyfs::exists(candidate) == Ok(true)
        && (pyfs::is_file(candidate) == Ok(true) || pyfs::is_dir(candidate) == Ok(true));
    if !readable {
        return deny("external_target_not_readable");
    }
    let parts: Vec<String> = candidate.components().to_vec();
    let lowered: Vec<String> = parts.iter().map(|part| part.to_lowercase()).collect();
    if lowered.iter().any(|part| is_external_sensitive(part))
        || external_filename_is_sensitive(candidate)
    {
        return deny("sensitive_basename");
    }
    if !hidden_parts_are_allowed_source(&lowered) {
        return deny("unsafe_hidden_dir");
    }
    let normalized = parts.join("/");
    let source_like = has_source_prefix(&normalized)
        || lowered.iter().any(|part| is_source_part(part))
        || is_source_extension(&PyPath::new(stripped).suffix().to_lowercase());
    if !source_like {
        return deny("not_source_like");
    }
    allow("external_source_path", Some(candidate.clone()))
}

/// Convenience for callers holding std paths.
pub(crate) fn py_path(path: &Path) -> PyPath {
    PyPath::new(&path.to_string_lossy())
}

#[cfg(all(test, unix))]
mod unix_tests {
    //! Behaviour ported from the retired `tests/test_hook_source_paths.py`.
    //! Those cases exercised the Python classifier against a real filesystem,
    //! so they are reproduced here against real temporary trees.

    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use super::*;
    use crate::sfrs_token_vectors::NoEnvHost;

    struct Workspace {
        root: std::path::PathBuf,
    }

    impl Workspace {
        /// `tmp_path/home/workspace` with the `src`, `docs` and `lib` trees the
        /// retired fixture created.
        fn new(label: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "guard-source-paths-{label}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let root = fs::canonicalize(&root).unwrap();
            let workspace = root.join("home").join("workspace");
            for child in ["src", "docs", "lib"] {
                fs::create_dir_all(workspace.join(child)).unwrap();
            }
            Self { root }
        }

        fn tmp(&self) -> &Path {
            &self.root
        }

        fn home(&self) -> std::path::PathBuf {
            self.root.join("home")
        }

        fn workspace(&self) -> std::path::PathBuf {
            self.root.join("home").join("workspace")
        }

        fn write(&self, relative: &str, contents: &str) -> std::path::PathBuf {
            let path = self.workspace().join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, contents).unwrap();
            path
        }
    }

    fn write_file(path: &Path, contents: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    /// The `gitdir:` file a linked worktree keeps instead of a `.git` directory.
    fn write_worktree_git_marker(checkout_root: &Path) {
        fs::create_dir_all(checkout_root).unwrap();
        fs::write(
            checkout_root.join(".git"),
            "gitdir: ../.git/worktrees/test-checkout\n",
        )
        .unwrap();
    }

    fn decide(target: &str, cwd: Option<&Path>, home: Option<&Path>) -> SourceDecision {
        decide_external(target, cwd, home, false)
    }

    fn decide_external(
        target: &str,
        cwd: Option<&Path>,
        home: Option<&Path>,
        allow_external_source: bool,
    ) -> SourceDecision {
        let host = NoEnvHost;
        let ctx = Ctx::new(&host, "/", "/");
        let cwd = cwd.map(py_path);
        let home = home.map(py_path);
        source_path_is_allowed(
            target,
            cwd.as_ref(),
            home.as_ref(),
            &ctx,
            allow_external_source,
        )
    }

    #[test]
    fn workspace_source_files_are_allowed_with_their_reason_codes() {
        let fixture = Workspace::new("allowed");
        fixture.write("src/foo.ts", "export const x = 1;");
        fixture.write("src/component.tsx", "<div/>");
        fixture.write("src/app.py", "x = 1");
        fixture.write("docs/spec.md", "# Spec");
        fixture.write("package.json", "{}");
        fixture.write(".nvmrc", "20");
        let cwd = fixture.workspace();
        let home = fixture.home();

        for (target, reason) in [
            ("src/foo.ts", "source_prefix"),
            ("src/component.tsx", "source_prefix"),
            ("src/app.py", "source_prefix"),
            ("docs/spec.md", "source_prefix"),
            ("package.json", "source_extension"),
            (".nvmrc", "benign_source_dotfile"),
        ] {
            let decision = decide(target, Some(&cwd), Some(&home));
            assert!(decision.allowed, "{target} should be allowed");
            assert_eq!(decision.reason_code, reason, "{target}");
            assert!(decision.resolved_path.is_some(), "{target}");
        }
    }

    #[test]
    fn credential_dotfiles_are_refused_as_sensitive_basenames() {
        let fixture = Workspace::new("secrets");
        let cwd = fixture.workspace();
        let home = fixture.home();
        for name in [".env", ".npmrc", ".netrc", ".git-credentials"] {
            fixture.write(name, "SECRET=abc");
            let decision = decide(name, Some(&cwd), Some(&home));
            assert!(!decision.allowed, "{name} should be refused");
            assert_eq!(decision.reason_code, "sensitive_basename", "{name}");
        }
    }

    #[test]
    fn hidden_directories_are_refused_except_github_workflows() {
        let fixture = Workspace::new("hidden");
        fixture.write(".secret/data.ts", "x");
        fixture.write(".github/workflows/publish.yml", "jobs: {}\n");
        fixture.write(".github/private/config.yml", "token: fixture\n");
        let cwd = fixture.workspace();
        let home = fixture.home();

        let workflow = decide(".github/workflows/publish.yml", Some(&cwd), Some(&home));
        assert!(workflow.allowed);
        assert_eq!(workflow.reason_code, "source_extension");

        for target in [".secret/data.ts", ".github/private/config.yml"] {
            let decision = decide(target, Some(&cwd), Some(&home));
            assert!(!decision.allowed, "{target} should be refused");
            assert_eq!(decision.reason_code, "unsafe_hidden_dir", "{target}");
        }
    }

    #[test]
    fn empty_glob_and_traversal_targets_never_resolve() {
        let fixture = Workspace::new("lexical");
        let cwd = fixture.workspace();
        let home = fixture.home();
        write_file(&fixture.tmp().join("outside.ts"), "x");

        for (target, reason) in [
            ("", "empty_path"),
            ("   ", "empty_path"),
            ("src/*.ts", "glob_pattern"),
            ("../../outside.ts", "path_traversal"),
        ] {
            let decision = decide(target, Some(&cwd), Some(&home));
            assert!(!decision.allowed, "{target:?} should be refused");
            assert_eq!(decision.reason_code, reason, "{target:?}");
        }
    }

    #[test]
    fn an_absolute_path_outside_the_workspace_is_refused_without_the_opt_in() {
        let fixture = Workspace::new("outside");
        let outside = fixture.tmp().join("outside.ts");
        write_file(&outside, "x");

        let decision = decide(
            &outside.to_string_lossy(),
            Some(&fixture.workspace()),
            Some(&fixture.home()),
        );

        assert!(!decision.allowed);
        assert_eq!(decision.reason_code, "absolute_path_outside_workspace");
    }

    #[test]
    fn a_symlink_anywhere_in_the_path_is_refused() {
        let fixture = Workspace::new("symlink");
        let outside = fixture.tmp().join("evil.txt");
        write_file(&outside, "secret");
        let link = fixture.workspace().join("src").join("link.ts");
        std::os::unix::fs::symlink(&outside, &link).unwrap();

        let workflow_link = fixture.workspace().join(".github/workflows/publish.yml");
        fs::create_dir_all(workflow_link.parent().unwrap()).unwrap();
        let workflow_target = fixture.tmp().join("outside.yml");
        write_file(&workflow_target, "token: fixture\n");
        std::os::unix::fs::symlink(&workflow_target, &workflow_link).unwrap();

        let cwd = fixture.workspace();
        for target in [
            link.to_string_lossy().into_owned(),
            "src/link.ts".to_owned(),
            ".github/workflows/publish.yml".to_owned(),
        ] {
            let decision = decide(&target, Some(&cwd), Some(&fixture.home()));
            assert!(!decision.allowed, "{target} should be refused");
            assert_eq!(decision.reason_code, "symlink_in_path", "{target}");
        }
    }

    #[test]
    fn an_external_sibling_checkout_is_allowed_only_with_the_opt_in() {
        let fixture = Workspace::new("external-ok");
        let worktree_root = fixture.home().join("sibling-source");
        let worktree_file = worktree_root.join("scripts").join("guard-test");
        write_file(&worktree_file, "#!/bin/sh\n");
        write_worktree_git_marker(&worktree_root);

        let repository_root = fixture.home().join("sibling-repository");
        let repository_file = repository_root.join("src").join("main.py");
        write_file(&repository_file, "value = 1\n");
        fs::create_dir_all(repository_root.join(".git")).unwrap();

        let cwd = fixture.workspace();
        let home = fixture.home();
        for file in [&worktree_file, &repository_file] {
            let target = file.to_string_lossy();
            let refused = decide(&target, Some(&cwd), Some(&home));
            assert!(!refused.allowed, "{target} needs the opt-in");
            assert_eq!(refused.reason_code, "absolute_path_outside_workspace");

            let decision = decide_external(&target, Some(&cwd), Some(&home), true);
            assert!(decision.allowed, "{target} should be allowed");
            assert_eq!(decision.reason_code, "external_source_path", "{target}");
        }
    }

    #[test]
    fn an_external_target_must_be_an_immediate_sibling_inside_a_resolvable_home() {
        let fixture = Workspace::new("external-bounds");
        let nested = fixture.home().join("Downloads").join("app");
        let nested_file = nested.join("src").join("main.py");
        write_file(&nested_file, "value = 1\n");
        fs::create_dir_all(nested.join(".git")).unwrap();

        let outside_home = fixture.tmp().join("outside-home").join("scripts");
        let outside_file = outside_home.join("guard-test");
        write_file(&outside_file, "#!/bin/sh\n");

        let sibling_root = fixture.home().join("sibling-source");
        let sibling_file = sibling_root.join("scripts").join("guard-test");
        write_file(&sibling_file, "#!/bin/sh\n");
        write_worktree_git_marker(&sibling_root);

        let cwd = fixture.workspace();
        let home = fixture.home();
        let missing_home = fixture.tmp().join("missing-home");

        let nested_decision = decide_external(
            &nested_file.to_string_lossy(),
            Some(&cwd),
            Some(&home),
            true,
        );
        assert!(!nested_decision.allowed);
        assert_eq!(
            nested_decision.reason_code,
            "external_target_not_sibling_git_checkout"
        );

        let outside_decision = decide_external(
            &outside_file.to_string_lossy(),
            Some(&cwd),
            Some(&home),
            true,
        );
        assert!(!outside_decision.allowed);
        assert_eq!(outside_decision.reason_code, "external_target_outside_home");

        let unresolvable = decide_external(
            &sibling_file.to_string_lossy(),
            Some(&cwd),
            Some(&missing_home),
            true,
        );
        assert!(!unresolvable.allowed);
        assert_eq!(unresolvable.reason_code, "external_home_unavailable");
    }

    #[test]
    fn the_external_opt_in_never_admits_a_relative_escape_or_a_symlink() {
        let fixture = Workspace::new("external-escape");
        let escape_root = fixture.home().join("external-source").join("scripts");
        write_file(&escape_root.join("guard-test"), "#!/bin/sh\n");

        let sibling_root = fixture.home().join("sibling-source");
        let real_file = sibling_root.join("scripts").join("guard-test");
        write_file(&real_file, "#!/bin/sh\n");
        write_worktree_git_marker(&sibling_root);
        let link = sibling_root.join("scripts").join("linked-guard-test");
        std::os::unix::fs::symlink(&real_file, &link).unwrap();

        let cwd = fixture.workspace();
        let home = fixture.home();

        let escaped = decide_external(
            "../external-source/scripts/guard-test",
            Some(&cwd),
            Some(&home),
            true,
        );
        assert!(!escaped.allowed);
        assert_eq!(escaped.reason_code, "path_traversal");

        let linked = decide_external(&link.to_string_lossy(), Some(&cwd), Some(&home), true);
        assert!(!linked.allowed);
        assert_eq!(linked.reason_code, "symlink_in_path");
    }

    #[test]
    fn external_sensitive_names_are_refused_without_substring_false_positives() {
        let fixture = Workspace::new("external-names");
        let sibling_root = fixture.home().join("sibling-source");
        write_worktree_git_marker(&sibling_root);
        let cwd = fixture.workspace();
        let home = fixture.home();

        let credential_file = sibling_root.join("credentials").join("config.ts");
        write_file(&credential_file, "credential = 'value'\n");
        let decision = decide_external(
            &credential_file.to_string_lossy(),
            Some(&cwd),
            Some(&home),
            true,
        );
        assert!(!decision.allowed);
        assert_eq!(decision.reason_code, "sensitive_basename");

        for name in ["secrets.json", "credentials.yaml", "auth_token.ts"] {
            let path = sibling_root.join(name);
            write_file(&path, "value = 1\n");
            let decision = decide_external(&path.to_string_lossy(), Some(&cwd), Some(&home), true);
            assert!(!decision.allowed, "{name} should be refused");
            assert_eq!(decision.reason_code, "sensitive_basename", "{name}");
        }

        for name in ["authentication.ts", "tokenizer.ts", "secretary.ts"] {
            let path = sibling_root.join(name);
            write_file(&path, "value = 1\n");
            let decision = decide_external(&path.to_string_lossy(), Some(&cwd), Some(&home), true);
            assert!(decision.allowed, "{name} should be allowed");
            assert_eq!(decision.reason_code, "external_source_path", "{name}");
        }
    }

    #[test]
    fn path_contains_symlink_reports_links_and_escapes() {
        let fixture = Workspace::new("contains-symlink");
        let workspace = py_path(&fixture.workspace());
        let target = fixture.tmp().join("evil.txt");
        write_file(&target, "secret");
        let link = fixture.workspace().join("link.ts");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let plain = fixture.write("src/foo.ts", "x");
        let outside = fixture.tmp().join("outside.ts");
        write_file(&outside, "x");

        assert!(path_contains_symlink(&py_path(&link), &workspace));
        assert!(!path_contains_symlink(&py_path(&plain), &workspace));
        assert!(path_contains_symlink(&py_path(&outside), &workspace));
    }

    #[test]
    fn candidate_resolution_follows_the_working_directory_and_home() {
        let fixture = Workspace::new("resolve");
        let host = NoEnvHost;
        let ctx = Ctx::new(&host, "/", "/");
        let workspace = py_path(&fixture.workspace());
        let home = py_path(&fixture.home());

        let relative = resolve_source_candidate_path("src/foo.ts", Some(&workspace), None, &ctx);
        assert_eq!(relative, Some(workspace.join("src").join("foo.ts")));

        let absolute_text = fixture.tmp().join("foo.ts").to_string_lossy().into_owned();
        let absolute = resolve_source_candidate_path(&absolute_text, None, None, &ctx);
        assert_eq!(absolute, Some(PyPath::new(&absolute_text)));

        let tilde = resolve_source_candidate_path("~/foo.ts", None, Some(&home), &ctx);
        assert_eq!(tilde, Some(home.join("foo.ts")));

        assert_eq!(resolve_source_candidate_path("", None, None, &ctx), None);
    }
}
