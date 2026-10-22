use crate::pretool::source_reads::sensitive_command_input;

/// A pattern handed to a filter that reads only standard input names no file,
/// so a listing piped into it is ordinary work rather than a sensitive read.
#[test]
fn a_stdin_filter_pattern_is_not_a_sensitive_target() {
    for command in [
        "ls -R . | grep -v .git",
        "ls -R . | grep .git",
        "ls -R . | sort | grep -v .git",
        "ls -R . | rg .git",
        "git status --short | grep -v .git",
    ] {
        assert!(
            !sensitive_command_input(command),
            "{command} still reads as a sensitive target"
        );
    }
}

/// Only the filter's own arguments are set aside. A producer that names a
/// sensitive file keeps its signal, a credential word keeps its signal
/// wherever it appears, and a matcher that opens a file of its own is not a
/// stdin filter at all.
#[test]
fn only_a_proven_stdin_filter_sheds_its_pattern() {
    for command in [
        "cat .env | grep DATABASE",
        "ls -la | grep -i secret.txt | head -5",
        "ls -R ~/.ssh | grep -v known_hosts",
        "ls -R . | grep AWS_SECRET_ACCESS_KEY",
        "ls -R . | grep -f .git/info/exclude",
        "ls -R . | grep --file=.ssh/patterns",
        "ls -R . | grep -r .git /etc",
        "ls -R . | PATTERN=.git grep $PATTERN",
    ] {
        assert!(
            sensitive_command_input(command),
            "{command} lost a signal the filter exemption must keep"
        );
    }
}
