//! Read-only lookup checks for the commands that rewrite or resolve a path
//! word (`developer_inspection.py`: the path-word command rules).

use std::path::Path;

use crate::sfrs_read_only_filters::read_only_lookup_target_is_safe;

/// `_read_only_lookup_path_word_args_are_safe`.
///
/// `basename` and `dirname` rewrite their operand as a string. Coreutils never
/// stats the path for either one, so the operand carries no read to check, and
/// only the option set has to stay narrow enough that it cannot grow one.
pub(crate) fn read_only_lookup_path_word_args_are_safe(command: &str, args: &[String]) -> bool {
    let mut operands = 0usize;
    let mut after_options = false;
    let mut remaining = args.iter();
    while let Some(arg) = remaining.next() {
        if after_options {
            operands += 1;
            continue;
        }
        if arg == "--" {
            after_options = true;
            continue;
        }
        if command == "basename" && arg == "-s" {
            if remaining.next().is_none() {
                return false;
            }
            continue;
        }
        if arg.starts_with('-') && arg.len() > 1 {
            let recognized = if command == "basename" {
                matches!(arg.as_str(), "-a" | "--multiple" | "-z" | "--zero")
                    || arg.starts_with("--suffix=")
            } else {
                matches!(arg.as_str(), "-z" | "--zero")
            };
            if !recognized {
                return false;
            }
            continue;
        }
        operands += 1;
    }
    operands > 0
}

/// `_read_only_lookup_resolved_path_args_are_safe`.
///
/// `readlink` and `realpath` do reach the filesystem: they resolve the operand
/// and print where it lands, which reports existence and symlink targets. The
/// operand therefore takes the same read check as `ls`, and the options that
/// would carry a path of their own stay outside the recognized set.
pub(crate) fn read_only_lookup_resolved_path_args_are_safe(
    command: &str,
    args: &[String],
    home_dir: Option<&Path>,
) -> bool {
    let mut targets: Vec<&str> = Vec::new();
    let mut after_options = false;
    for arg in args {
        if after_options {
            targets.push(arg);
            continue;
        }
        if arg == "--" {
            after_options = true;
            continue;
        }
        if arg.starts_with('-') && arg.len() > 1 {
            let recognized = if command == "readlink" {
                matches!(
                    arg.as_str(),
                    "-f" | "--canonicalize"
                        | "-e"
                        | "--canonicalize-existing"
                        | "-m"
                        | "--canonicalize-missing"
                        | "-n"
                        | "--no-newline"
                        | "-q"
                        | "-s"
                        | "--quiet"
                        | "--silent"
                        | "-z"
                        | "--zero"
                )
            } else {
                matches!(
                    arg.as_str(),
                    "-e" | "--canonicalize-existing"
                        | "-m"
                        | "--canonicalize-missing"
                        | "-L"
                        | "--logical"
                        | "-P"
                        | "--physical"
                        | "-q"
                        | "--quiet"
                        | "-s"
                        | "--strip"
                        | "--no-symlinks"
                        | "-z"
                        | "--zero"
                )
            };
            if !recognized {
                return false;
            }
            continue;
        }
        targets.push(arg);
    }
    !targets.is_empty()
        && targets
            .iter()
            .all(|target| read_only_lookup_target_is_safe(target, true, home_dir))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).to_string()).collect()
    }

    #[test]
    fn a_rewritten_path_word_needs_no_read_check() {
        for command in ["basename", "dirname"] {
            assert!(read_only_lookup_path_word_args_are_safe(
                command,
                &words(&["/etc/ssh/sshd_config"])
            ));
            assert!(read_only_lookup_path_word_args_are_safe(
                command,
                &words(&["-z", "src/app"])
            ));
            assert!(!read_only_lookup_path_word_args_are_safe(command, &[]));
            assert!(!read_only_lookup_path_word_args_are_safe(
                command,
                &words(&["--handle=/etc/shadow", "x"])
            ));
        }
        assert!(read_only_lookup_path_word_args_are_safe(
            "basename",
            &words(&["-s", ".rs", "src/main.rs"])
        ));
        assert!(!read_only_lookup_path_word_args_are_safe(
            "basename",
            &words(&["-s"])
        ));
        // `-a` belongs to `basename` alone, so `dirname` must not inherit it.
        assert!(!read_only_lookup_path_word_args_are_safe(
            "dirname",
            &words(&["-a", "src/app"])
        ));
    }

    #[test]
    fn a_resolved_path_word_takes_the_read_check() {
        assert!(read_only_lookup_resolved_path_args_are_safe(
            "realpath",
            &words(&["."]),
            None
        ));
        assert!(read_only_lookup_resolved_path_args_are_safe(
            "readlink",
            &words(&["-f", "src/app"]),
            None
        ));
        // The operand is read, so the boundary `ls` enforces applies here too.
        assert!(!read_only_lookup_resolved_path_args_are_safe(
            "realpath",
            &words(&["../../etc/passwd"]),
            None
        ));
        assert!(!read_only_lookup_resolved_path_args_are_safe(
            "readlink",
            &words(&["-f", ".ssh/id_ed25519"]),
            None
        ));
        // An option carrying a path of its own stays outside the set.
        assert!(!read_only_lookup_resolved_path_args_are_safe(
            "realpath",
            &words(&["--relative-to=/etc", "."]),
            None
        ));
        assert!(!read_only_lookup_resolved_path_args_are_safe(
            "realpath",
            &[],
            None
        ));
    }
}
