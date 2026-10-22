//! The printing spellings of the two records Git keeps beside the history:
//! a bisect session's log and a commit's notes.
//!
//! `git bisect log` replays what the session has recorded so far, and
//! `git notes list` and `git notes show` print the notes ref. None of the
//! three touches a ref, the index or the worktree, so an agent reading where
//! a bisect stands or what a commit was annotated with asks for nothing.
//!
//! Every other spelling of either subcommand does reach something. `bisect
//! start`, `good`, `bad`, `skip` and `reset` move `HEAD` and write the
//! session's refs; `bisect run`, `visualize` and `view` run a program the
//! text names. `notes add`, `append`, `copy`, `edit`, `remove`, `prune` and
//! `merge` write the notes ref, and `edit` opens the configured editor. They
//! keep their review.

/// Whether `arguments`, the tokens after `subcommand`, name a printing form
/// of that record.
pub(crate) fn read_form(subcommand: &str, arguments: &[String]) -> bool {
    match subcommand {
        "bisect" => bisect_read_form(arguments),
        "notes" => notes_read_form(arguments),
        _ => false,
    }
}

/// A bisect session has one printing form: `log`, which takes no options.
fn bisect_read_form(arguments: &[String]) -> bool {
    arguments.iter().map(String::as_str).eq(["log"])
}

/// Bare `git notes` is `git notes list`. Both printing forms take `--ref`,
/// which chooses which notes ref is read, and both take at most one object:
/// `list` prints every note without one, and `show` defaults to `HEAD`. An
/// option neither form documents is not read here, so the command keeps its
/// review.
fn notes_read_form(arguments: &[String]) -> bool {
    let words: Vec<&str> = arguments.iter().map(String::as_str).collect();
    match words.split_first() {
        None => true,
        Some((&"list" | &"show", rest)) => matches!(objects(rest), Some(0 | 1)),
        _ => false,
    }
}

/// How many objects the tokens name, or `None` when one of them is an option
/// these two forms do not take. `--ref` selects the notes ref and is the only
/// option either documents; it carries a value, attached or next.
fn objects(rest: &[&str]) -> Option<usize> {
    let mut objects = 0;
    let mut index = 0;
    while let Some(word) = rest.get(index) {
        index += 1;
        let Some(long) = word.strip_prefix("--") else {
            if word.starts_with('-') || !object_name(word) {
                return None;
            }
            objects += 1;
            continue;
        };
        match long.split_once('=') {
            Some(("ref", value)) => {
                if !object_name(value) {
                    return None;
                }
            }
            None if long == "ref" => {
                if !rest.get(index).is_some_and(|value| object_name(value)) {
                    return None;
                }
                index += 1;
            }
            _ => return None,
        }
    }
    Some(objects)
}

/// A word Git reads as an object or a ref: the characters a ref name and the
/// revision suffixes `HEAD~2`, `HEAD^`, `@{u}` and `branch@{1}` are spelled
/// with, and nothing a shell or a path traversal needs.
fn object_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.starts_with('-')
        && !value.contains("..")
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "/_-.^~@{}".contains(character))
}

#[cfg(test)]
mod tests {
    use super::read_form;

    fn words(command: &str) -> Vec<String> {
        command.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn a_bisect_session_prints_only_its_log() {
        assert!(read_form("bisect", &words("log")));
    }

    #[test]
    fn every_other_bisect_spelling_keeps_its_review() {
        for arguments in [
            "",
            "start",
            "start HEAD HEAD~10",
            "good",
            "bad HEAD",
            "skip",
            "reset",
            "run ./flaky.sh",
            "visualize",
            "view",
            "log --stat",
            "log extra",
        ] {
            assert!(!read_form("bisect", &words(arguments)), "{arguments}");
        }
    }

    #[test]
    fn a_note_prints_as_a_listing_or_a_single_note() {
        for arguments in [
            "",
            "list",
            "list HEAD",
            "list --ref build",
            "list --ref=build HEAD",
            "show",
            "show HEAD",
            "show HEAD~2",
            "show --ref build HEAD",
        ] {
            assert!(read_form("notes", &words(arguments)), "{arguments}");
        }
    }

    #[test]
    fn a_note_that_writes_or_names_an_unread_option_keeps_its_review() {
        for arguments in [
            "add -m fix HEAD",
            "append -m more HEAD",
            "copy HEAD~1 HEAD",
            "edit HEAD",
            "remove HEAD",
            "prune",
            "merge other",
            "list -n",
            "list --pretty=raw",
            "show --ref",
            "show HEAD extra",
            "show ../outside",
            "show --ref ../outside HEAD",
        ] {
            assert!(!read_form("notes", &words(arguments)), "{arguments}");
        }
    }

    #[test]
    fn no_other_record_reads_through_this_door() {
        assert!(!read_form("stash", &words("list")));
    }
}
