//! `rsync` forms the workspace sandbox can contain. `rsync -a src/ build/`
//! is the copy `cp -R src/ build/` already makes, written the way build
//! scripts write it, and the sandbox keeps it off the network and out of
//! every directory the workspace does not hold. The program is still a
//! network client, so this module admits only the local-copy shape: no
//! option that reaches another host or runs a program, no operand written
//! as a remote path, and no option that reads rules or file lists this text
//! never showed.
//!
//! `--delete` and its relatives stay out. The destructive-shell rule that
//! makes `rm -rf` prove its targets are missing or ignored by Git does not
//! match `rsync`, so a deleting transfer could take committed-but-unpushed
//! or uncommitted work with it and leave nothing to recover from. The same
//! goes for `--remove-source-files`, `--backup-dir` and the `*-dest`
//! options, which name a tree outside the pair of operands.

/// Short options that only describe how the copy is made.
const SHORT: &str = "abcdDEghiklKLmnoOpPqrsStuvWxXzAHJN";

/// Long options that carry no value and start no program.
const LONG: [&str; 41] = [
    "--archive",
    "--verbose",
    "--quiet",
    "--recursive",
    "--relative",
    "--dirs",
    "--links",
    "--copy-links",
    "--copy-dirlinks",
    "--keep-dirlinks",
    "--hard-links",
    "--perms",
    "--executability",
    "--acls",
    "--xattrs",
    "--owner",
    "--group",
    "--devices",
    "--specials",
    "--times",
    "--atimes",
    "--crtimes",
    "--omit-dir-times",
    "--omit-link-times",
    "--one-file-system",
    "--update",
    "--checksum",
    "--size-only",
    "--whole-file",
    "--sparse",
    "--prune-empty-dirs",
    "--itemize-changes",
    "--human-readable",
    "--progress",
    "--partial",
    "--stats",
    "--compress",
    "--dry-run",
    "--existing",
    "--ignore-existing",
    "--mkpath",
];

/// Long options whose value is a pattern or a number, never a path this
/// text does not show and never a program.
const LONG_VALUES: [&str; 7] = [
    "--exclude",
    "--include",
    "--max-size",
    "--min-size",
    "--bwlimit",
    "--modify-window",
    "--timeout",
];

/// Whether `segment` is a local `rsync` copy: described by the options
/// above and naming two or more operands no shell expansion or remote
/// spelling could move off this host.
pub(crate) fn local_copy_segment(segment: &crate::CommandSegmentV1) -> bool {
    segment
        .executable
        .as_deref()
        .map(super::executable_basename)
        == Some("rsync")
        && segment.wrapper_chain.is_empty()
        && !segment.path_overridden
        && local_copy(&segment.arguments)
}

/// Whether `arguments` (after `rsync`) are a local copy: described by the
/// options above and naming two or more operands no shell expansion or
/// remote spelling could move off this host.
pub(crate) fn local_copy(arguments: &[String]) -> bool {
    let mut words = arguments.iter();
    let mut operands = 0;
    let mut options_ended = false;
    while let Some(word) = words.next() {
        if options_ended {
            if !local_operand(word) {
                return false;
            }
            operands += 1;
            continue;
        }
        if word == "--" {
            options_ended = true;
            continue;
        }
        if let Some(name) = word.strip_prefix("--") {
            let (name, joined) = match name.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (name, None),
            };
            let name = format!("--{name}");
            if LONG.contains(&name.as_str()) {
                if joined.is_some() {
                    return false;
                }
                continue;
            }
            if !LONG_VALUES.contains(&name.as_str()) {
                return false;
            }
            let value = match joined {
                Some(value) => value,
                None => match words.next() {
                    Some(value) => value.as_str(),
                    None => return false,
                },
            };
            if !inert_value(value) {
                return false;
            }
            continue;
        }
        if let Some(letters) = word.strip_prefix('-') {
            if letters.is_empty() || !letters.chars().all(|letter| SHORT.contains(letter)) {
                return false;
            }
            continue;
        }
        if !local_operand(word) {
            return false;
        }
        operands += 1;
    }
    operands >= 2
}

/// A pattern or number written out in full. An expansion could hold an
/// option or an operand this text never showed.
fn inert_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('-')
        && !value.contains(['$', '`', '\n'])
}

/// An operand that names a path on this host. `rsync` reads a word as a
/// remote spec when its first `:` comes before its first `/`
/// (`build.example.com:/srv`), when it holds `::` (a daemon module) or when
/// it is a `rsync://` URL, so each of those keeps its review. An expansion
/// could spell any of them, so it does too.
fn local_operand(word: &str) -> bool {
    if word.is_empty() || word.starts_with('-') || word.contains(['$', '`', '\n']) {
        return false;
    }
    if word.contains("::") {
        return false;
    }
    match (word.find(':'), word.find('/')) {
        (Some(_), None) => false,
        (Some(colon), Some(slash)) => colon > slash,
        (None, _) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::local_copy;

    fn words(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn local_copies_are_contained() {
        for text in [
            "-a src/ build/",
            "-av src/ build/",
            "-azP src/ build/",
            "-aAX src/ build/",
            "--archive --verbose src/ build/",
            "-a --exclude node_modules src/ build/",
            "-a --exclude=node_modules --exclude=.git src/ build/",
            "-a --include '*.ts' src/ build/",
            "-rtv assets/ public/assets/",
            "-a --dry-run src/ build/",
            "-a --max-size 10m src/ build/",
            "-a lib/ docs/ dist/",
            "-a -- src/ build/",
            "-a ./a:b/ build/",
        ] {
            assert!(local_copy(&words(text)), "{text}");
        }
    }

    #[test]
    fn remote_deleting_and_unread_rule_forms_keep_review() {
        for text in [
            "-a src/ build.example.com:/srv/app/",
            "-a build.example.com:/srv/app/ build/",
            "-a src/ build.example.com::backup/",
            "-a rsync://build.example.com/backup/ build/",
            "-a src/ user@build.example.com:~/app/",
            "-av --delete dist/ public/assets/",
            "-a --delete-after dist/ public/assets/",
            "-a --remove-source-files src/ build/",
            "-a -e ssh src/ build/",
            "-ae ssh src/ build/",
            "-a --rsh=ssh src/ build/",
            "-a --rsync-path=/usr/bin/rsync src/ build/",
            "--daemon",
            "-a --config=rsyncd.conf src/ build/",
            "-a --files-from=list.txt src/ build/",
            "-a --exclude-from=.rsyncignore src/ build/",
            "-a --filter=merge rules.txt src/ build/",
            "-aF src/ build/",
            "-a -M--log-file=/tmp/x src/ build/",
            "-a --link-dest=../prev src/ build/",
            "-a --backup-dir=../old src/ build/",
            "-a $SOURCE build/",
            "-a src/ $DEST",
            "-a --exclude=$PATTERN src/ build/",
            "-a --max-size src/",
            "-a src/",
            "-a",
            "-a --archive=yes src/ build/",
            "-a -- -rf build/",
        ] {
            assert!(!local_copy(&words(text)), "{text}");
        }
    }
}
