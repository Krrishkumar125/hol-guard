use crate::pretool::source_reads::sensitive_command_input;

/// A pattern handed to a filter that reads only standard input names no file,
/// so a listing piped into it is ordinary work rather than a sensitive read.
#[test]
fn a_stdin_filter_pattern_is_not_a_sensitive_target() {
    for command in [
        "ls -R . | grep -v .env",
        "ls -R . | grep .env",
        "ls -R . | sort | grep -v .env",
        "ls -R . | rg .env",
        "git status --short | grep -v .env",
    ] {
        assert!(
            !sensitive_command_input(command),
            "{command} still reads as a sensitive target"
        );
    }
}

/// Only the filter's own arguments are set aside. A producer that names a
/// sensitive file keeps its signal, a credential word keeps its signal
/// wherever it appears, a matcher that opens a file of its own is not a stdin
/// filter at all, and a word the shell can still act on — an attached
/// redirect, an unquoted glob — is not a pattern yet.
#[test]
fn only_a_proven_stdin_filter_sheds_its_pattern() {
    for command in [
        "cat .env | grep DATABASE",
        "ls -la | grep -i secret.txt | head -5",
        "ls -R ~/.ssh | grep -v known_hosts",
        "ls -R . | grep AWS_SECRET_ACCESS_KEY",
        "ls -R . | grep -f .env",
        "ls -R . | grep --file=.env",
        "ls -R . | grep -r .env /etc",
        "ls -R . | grep .env<.env",
        "ls -a . | grep -v .env*",
        "ls -R . | grep -v .env{,.local}",
        "ls -R . | PATTERN=.env grep $PATTERN",
    ] {
        assert!(
            sensitive_command_input(command),
            "{command} lost a signal the filter exemption must keep"
        );
    }
}
