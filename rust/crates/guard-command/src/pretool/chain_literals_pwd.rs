//! `ln -s "$(pwd)/node_modules" ../wt/node_modules` names the working
//! directory through an expansion, so the whole command stayed opaque. Until
//! something in the list can change the directory, `$(pwd)`, `` `pwd` ``,
//! `$PWD` and `${PWD}` all expand to the session's verified working
//! directory. Writing that path in their place lets each step be judged on
//! the path it really names. Anything this pass does not fully understand
//! returns `None`, so the expansion stays opaque.
//!
//! Two substitutions print a path derived from that directory and nothing
//! else. `$(dirname "$PWD")` prints its parent, computed the way `dirname`
//! computes it, from the text alone. `$(git rev-parse --show-toplevel)`
//! prints the root of the worktree holding it, found the way Git finds it:
//! the nearest `.git` above the real directory. A `.git` Git could read
//! differently, through a link, an include, a configured worktree or a
//! layout this pass does not check, keeps the command opaque instead of
//! guessing. Each producer must also be allowed as its own command (for
//! `dirname`, which reads no file, a run the workspace sandbox contains also
//! counts), so lockdown, managed policy and extension controls on it still
//! hold.
//!
//! The arguments of a `cd` expand before it runs, so a `cd` that holds the
//! last use still sees the directory the uses were written against:
//! `cd "$(git rev-parse --show-toplevel)" && git status --short` is judged as
//! that `cd` to the literal root.

use std::path::Path;

use super::lex::{items, names_variable, tokenize};
use super::{assignment, listed, KEYWORDS, MAX_COMMAND_CHARS, PRECOMMANDS, STATE_COMMANDS};

const MAX_DIRECTORY_CHARS: usize = 1024;
/// A `.git` file or configuration larger than this is not read.
const MAX_GIT_FILE_BYTES: u64 = 64 * 1024;

/// Builtins that change the shell's directory or its idea of it.
const DIRECTORY_COMMANDS: &str = "cd chdir dirs popd pushd";

/// The spellings of the parent directory's substitution.
const PARENT_USES: &[&str] = &[
    "$(dirname \"$PWD\")",
    "$(dirname $PWD)",
    "$(dirname \"${PWD}\")",
    "$(dirname ${PWD})",
];
const TOPLEVEL_USE: &str = "$(git rev-parse --show-toplevel)";
const TOPLEVEL_COMMAND: &str = "git rev-parse --show-toplevel";

/// What a recognized use expands to.
#[derive(Clone, Copy, PartialEq)]
enum Use {
    Directory,
    Parent,
    Toplevel,
}

/// The values each kind of use prints, resolved on first use.
struct Values<'a, F> {
    cwd: &'a str,
    allowed: F,
    parent: Option<Option<String>>,
    toplevel: Option<Option<String>>,
}

impl<F: Fn(&str) -> bool> Values<'_, F> {
    fn value(&mut self, kind: Use) -> Option<String> {
        let cwd = self.cwd;
        match kind {
            Use::Directory => Some(cwd.to_owned()),
            Use::Parent => {
                let allowed = &self.allowed;
                self.parent
                    .get_or_insert_with(|| {
                        allowed(&format!("dirname {cwd}"))
                            .then(|| parent(cwd))
                            .flatten()
                    })
                    .clone()
            }
            Use::Toplevel => {
                let allowed = &self.allowed;
                self.toplevel
                    .get_or_insert_with(|| {
                        allowed(TOPLEVEL_COMMAND)
                            .then(|| repository_root(cwd))
                            .flatten()
                    })
                    .clone()
            }
        }
    }
}

/// The command with each working-directory expansion replaced by the path it
/// prints; `None` when nothing is replaced, the directory is not a plain
/// absolute literal, a derived path is unknown or its producer is not
/// allowed, or any step before a replaced use could change the directory.
pub(super) fn project(command: &str, cwd: &str, allowed: impl Fn(&str) -> bool) -> Option<String> {
    if !literal_directory(cwd)
        || !command.is_ascii()
        || command.len() > MAX_COMMAND_CHARS
        || command.bytes().any(|b| b.is_ascii_control() && b != b'\t')
        // A changed `IFS` splits an unquoted use where the literal is whole,
        // and any other mention of `PWD` might set it.
        || names_variable(command, |name| name == "IFS" || name == "PWD")
    {
        return None;
    }
    let chars: Vec<char> = command.chars().collect();
    let mut values = Values {
        cwd,
        allowed,
        parent: None,
        toplevel: None,
    };
    let (projected, last_use) = replace_uses(&chars, &mut values)?;
    let projected_chars: Vec<char> = projected.chars().collect();
    let tokens = tokenize(&projected_chars)?;
    let list = items(&tokens)?;
    // Every replacement ends no later than `last_use` in the projection, so
    // each step that starts before it runs before or alongside a use.
    for (stages, _) in &list {
        let first = stages.first()?.first()?.0;
        if first >= last_use {
            break;
        }
        for stage in stages {
            let leading = stage
                .iter()
                .take_while(|&&(from, to)| assignment(&projected_chars[from..to]).is_some())
                .count();
            // The lexer keeps redirections as words, so one before the
            // command word (`2>/dev/null cd /etc`) would hide that word.
            if stage[..stage.len().min(leading + 1)]
                .iter()
                .any(|&(from, to)| {
                    projected_chars[from..to]
                        .iter()
                        .any(|c| matches!(c, '<' | '>'))
                })
            {
                return None;
            }
            let Some(&(from, to)) = stage.get(leading) else {
                continue;
            };
            let word: String = projected_chars[from..to]
                .iter()
                .filter(|&&c| !matches!(c, '\'' | '"' | '\\'))
                .collect();
            // A lone `cd` that holds the last use expands every use before
            // it changes the directory. In a pipeline it could run beside a
            // stage that reads the directory, so only a plain step counts.
            let holds_last_use = stage.last().is_some_and(|&(_, end)| last_use <= end);
            if word == "cd" && leading == 0 && stages.len() == 1 && holds_last_use {
                continue;
            }
            if word.contains('$')
                || listed(DIRECTORY_COMMANDS, &word)
                || listed(STATE_COMMANDS, &word)
                || listed(KEYWORDS, &word)
                || listed(PRECOMMANDS, &word)
                // zsh's AUTO_CD runs a bare directory name as `cd`.
                || Path::new(cwd).join(&word).is_dir()
            {
                return None;
            }
        }
    }
    Some(projected)
}

/// An absolute path whose characters the shell never splits, globs, quotes
/// or expands, and which still names a directory.
fn literal_directory(cwd: &str) -> bool {
    literal_path(cwd) && std::fs::canonicalize(cwd).is_ok_and(|path| path.is_dir())
}

/// An absolute path whose characters the shell never splits, globs, quotes
/// or expands, with no `..` to climb out of what it names.
fn literal_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= MAX_DIRECTORY_CHARS
        && !path.split('/').any(|part| part == "..")
        && path.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '_' | '.' | '/' | '@' | '%' | '+' | ':' | ',' | '-')
        })
}

/// What `dirname` prints for an absolute path: the text before its last
/// component, without trailing slashes, or `/`. The shell sets `$PWD` to a
/// canonical spelling, so a path with a `.` component or a doubled slash,
/// whose text differs from that spelling, has no known parent.
fn parent(path: &str) -> Option<String> {
    if path.split('/').any(|part| part == ".") || path.contains("//") {
        return None;
    }
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return Some("/".to_owned());
    }
    let (head, _) = trimmed.rsplit_once('/')?;
    let head = head.trim_end_matches('/');
    Some(if head.is_empty() { "/" } else { head }.to_owned())
}

/// The worktree root `git rev-parse --show-toplevel` prints for `cwd`: the
/// real directory holding the nearest `.git`, spelled without links, as Git
/// prints it. `None` when there is none, or
/// when the first `.git` found is anything Git could resolve to another root.
fn repository_root(cwd: &str) -> Option<String> {
    let start = std::fs::canonicalize(cwd).ok()?;
    // Inside a Git directory there is no worktree to print.
    if start.components().any(|part| part.as_os_str() == ".git") {
        return None;
    }
    for directory in start.ancestors() {
        let marker = directory.join(".git");
        let metadata = match std::fs::symlink_metadata(&marker) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return None,
        };
        // The first `.git` decides. One this pass cannot prove Git reads as
        // this worktree keeps the value unknown, rather than walking past it
        // the way Git would walk past a directory it does not accept.
        let git_directory = if metadata.is_dir() {
            Some(marker)
        } else if metadata.is_file() {
            linked_git_directory(&marker, directory)
        } else {
            None
        };
        let git_directory = git_directory?;
        if !plain_git_directory(&git_directory) {
            return None;
        }
        let root = directory.to_str()?.to_owned();
        return literal_path(&root).then_some(root);
    }
    None
}

/// The Git directory a `.git` file names with `gitdir: PATH`.
fn linked_git_directory(marker: &Path, directory: &Path) -> Option<std::path::PathBuf> {
    let text = small_file(marker)?;
    let target = text
        .strip_prefix("gitdir: ")?
        .trim_end_matches(['\n', '\r']);
    if target.is_empty() || target.contains('\n') {
        return None;
    }
    let target = directory.join(target);
    std::fs::symlink_metadata(&target)
        .is_ok_and(|metadata| metadata.is_dir())
        .then_some(target)
}

/// A Git directory with its own `HEAD` whose configuration cannot move the
/// worktree root: no `core.worktree`, no per-worktree configuration and no
/// include, in it or in the common directory a linked worktree shares.
fn plain_git_directory(git_directory: &Path) -> bool {
    if !git_directory.join("HEAD").is_file() {
        return false;
    }
    let common = match std::fs::symlink_metadata(git_directory.join("commondir")) {
        Ok(_) => {
            let Some(text) = small_file(&git_directory.join("commondir")) else {
                return false;
            };
            let relative = text.trim_end_matches(['\n', '\r']);
            if relative.is_empty() || relative.contains('\n') {
                return false;
            }
            git_directory.join(relative)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => git_directory.to_path_buf(),
        Err(_) => return false,
    };
    if !common.join("objects").is_dir() || !common.join("refs").is_dir() {
        return false;
    }
    [git_directory, common.as_path()].iter().all(|base| {
        let absent = |name: &str| {
            std::fs::symlink_metadata(base.join(name))
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        };
        let path = base.join("config");
        absent("config.worktree")
            && (absent("config")
                || small_file(&path).is_some_and(|text| {
                    let text = text.to_ascii_lowercase();
                    !text.contains("worktree") && !text.contains("include")
                }))
    })
}

/// A regular file's text, when it is small and UTF-8.
fn small_file(path: &Path) -> Option<String> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_GIT_FILE_BYTES {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

/// The text with every use outside single quotes and escapes replaced, and
/// the index in that text just after the last replacement.
fn replace_uses<F: Fn(&str) -> bool>(
    chars: &[char],
    values: &mut Values<'_, F>,
) -> Option<(String, usize)> {
    let mut out = String::with_capacity(chars.len() + values.cwd.len());
    let mut last_use = None;
    let mut single = false;
    let mut double = false;
    let mut index = 0usize;
    while index < chars.len() {
        let c = chars[index];
        if single {
            single = c != '\'';
            out.push(c);
            index += 1;
            continue;
        }
        let found = match c {
            '\'' if !double => {
                single = true;
                None
            }
            '"' => {
                double = !double;
                None
            }
            '\\' => {
                out.extend(chars.get(index..index + 2).unwrap_or(&chars[index..]));
                index += 2;
                continue;
            }
            '$' | '`' => use_at(&chars[index..])?,
            _ => None,
        };
        let Some((width, kind)) = found else {
            out.push(c);
            index += 1;
            continue;
        };
        out.push_str(&values.value(kind)?);
        // Byte and character offsets agree: the text is ASCII.
        last_use = Some(out.len());
        index += width;
    }
    Some((out, last_use?))
}

/// The length and kind of a use at the start of `rest`; `Some(None)` when it
/// starts some other expansion, and `None` for a `$PWD` the shell would
/// subscript or modify (zsh's `$PWD[1]`, `$PWD:h`).
fn use_at(rest: &[char]) -> Option<Option<(usize, Use)>> {
    let starts = |text: &str| {
        rest.len() >= text.len() && rest.iter().zip(text.chars()).all(|(a, b)| *a == b)
    };
    if let Some(text) = PARENT_USES.iter().find(|text| starts(text)) {
        return Some(Some((text.len(), Use::Parent)));
    }
    if starts(TOPLEVEL_USE) {
        return Some(Some((TOPLEVEL_USE.len(), Use::Toplevel)));
    }
    if starts("$(pwd)") || starts("${PWD}") {
        return Some(Some((6, Use::Directory)));
    }
    if starts("`pwd`") {
        return Some(Some((5, Use::Directory)));
    }
    if starts("$PWD") {
        return match rest.get(4) {
            Some(c) if c.is_ascii_alphanumeric() || *c == '_' => Some(None),
            Some('[' | ':') => None,
            _ => Some(Some((4, Use::Directory))),
        };
    }
    Some(None)
}

#[cfg(test)]
#[path = "chain_literals_pwd_tests.rs"]
mod tests;
