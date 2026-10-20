//! Read routes to a directory that holds no repository.
//!
//! `git -C <directory> status` only prints `fatal: not a git repository` when
//! Git's own discovery walk finds no `.git` above that directory, and only
//! prints `cannot change to '<directory>'` when the directory is not there at
//! all. Neither spelling opens a file, so neither needs the repository proofs
//! that admit a route to a real checkout. Agents reach this shape constantly:
//! a scratch directory that a checkout was expected in, a sibling path that
//! has not been cloned yet, a temporary root that holds plain files.
//!
//! The walk mirrors Git's: any `.git` entry above the target — directory,
//! file or symlink — means a repository would be discovered, and the route is
//! left to [`super::git_route_within_workspace`] and its screens unchanged.

/// Whether a read-only `-C <target>` can only print an error because Git
/// discovers no repository from it.
pub(crate) fn git_route_without_repository(
    target: &str,
    context: super::super::PathContext<'_>,
) -> bool {
    if target.is_empty() || super::super::sensitive_read_path_argument(target) {
        return false;
    }
    let Some(path) = expanded_route(target, context) else {
        return false;
    };
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        // `git -C` prints the directory it could not enter and stops.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return true,
        Err(_) => return false,
    };
    if !metadata.is_dir() {
        // A `-C` to a file, a symlink to one, or a socket never starts Git.
        return !metadata.file_type().is_symlink();
    }
    let Ok(path) = std::fs::canonicalize(&path) else {
        return false;
    };
    !path
        .ancestors()
        .any(|ancestor| std::fs::symlink_metadata(ancestor.join(".git")).is_ok())
}

/// The path `-C` names, with `~` and a relative target resolved against the
/// declared working directory. A `~` spelling is proved only against the
/// declared home, as every other read route is.
fn expanded_route(
    target: &str,
    context: super::super::PathContext<'_>,
) -> Option<std::path::PathBuf> {
    if let Some(rest) = target.strip_prefix('~') {
        if !rest.is_empty() && !rest.starts_with('/') {
            return None;
        }
        let home = context.home_dir?;
        return Some(std::path::Path::new(home).join(rest.trim_start_matches('/')));
    }
    let path = std::path::Path::new(target);
    if path.is_absolute() {
        return Some(path.to_path_buf());
    }
    let cwd = context.cwd?;
    if !std::path::Path::new(cwd).is_absolute() {
        return None;
    }
    Some(std::path::Path::new(cwd).join(path))
}
