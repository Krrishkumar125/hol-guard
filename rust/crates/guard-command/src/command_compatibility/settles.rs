//! Whether an explicit extension Allow may settle uncertainty about a segment,
//! for every command extension rather than one owner at a time.
//!
//! Uncertainty means Guard attributed the segment to a rule it could not fully
//! classify. An explicit Allow for that rule's permission is the user's consent
//! to the action class, so it may settle the segment only while the segment's
//! own shape stays inside what the text proves: no steering environment, no
//! interpreter or nested executor that runs text the attribution only sampled,
//! and no option that changes which authority answers (a remote Docker daemon,
//! another cluster, a proxy program) or runs a program Guard never read. Any
//! shape outside that proof keeps its review, whatever permission is enabled.

use super::{basename, environment, CommandSegmentV1};

/// Programs that run text they receive, or a program named by a later
/// argument, so they can assemble any command. An uncertain attribution of
/// their segment only sampled that text, so it never settles.
const INTERPRETERS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "fish",
    "dash",
    "ksh",
    "csh",
    "tcsh",
    "ash",
    "pwsh",
    "powershell",
    "cmd",
    "node",
    "nodejs",
    "deno",
    "bun",
    "ruby",
    "perl",
    "php",
    "lua",
    "osascript",
    "awk",
    "gawk",
    "mawk",
    "nawk",
    "env",
    "xargs",
    "eval",
];

fn inert_environment(segment: &CommandSegmentV1) -> bool {
    segment
        .environment_names
        .iter()
        .all(|name| environment::inert_environment_name(name))
}

/// kubectl/oc global flags that take a value and may precede the subcommand.
const KUBECTL_GLOBAL_VALUE_FLAGS: &[&str] = &[
    "--as",
    "--as-group",
    "--as-uid",
    "--cache-dir",
    "--certificate-authority",
    "--client-certificate",
    "--client-key",
    "--cluster",
    "--context",
    "--kubeconfig",
    "--namespace",
    "--password",
    "--profile",
    "--proxy-url",
    "--request-timeout",
    "--server",
    "--tls-server-name",
    "--token",
    "--user",
    "--username",
    "-n",
];

/// kubectl/oc flags that change which authority answers, or whose credentials
/// it answers with. Like a non-default Docker context, they name a different
/// authority than the one the user reviewed, so they keep their review.
const KUBECTL_AUTHORITY_FLAGS: &[&str] = &[
    "--as",
    "--as-group",
    "--as-uid",
    "--certificate-authority",
    "--client-certificate",
    "--client-key",
    "--cluster",
    "--context",
    "--kubeconfig",
    "--password",
    "--proxy-url",
    "--server",
    "--token",
    "--user",
    "--username",
];

fn flag_name(argument: &str) -> &str {
    argument.split('=').next().unwrap_or(argument)
}

/// Value of an option given as `--name=value`, `-fvalue`, or `--name value`.
fn option_value<'a>(arguments: &'a [String], index: usize, argument: &'a str) -> Option<&'a str> {
    if let Some((_, value)) = argument.split_once('=') {
        return Some(value);
    }
    let name = flag_name(argument);
    if argument.len() > name.len() {
        return Some(&argument[name.len()..]);
    }
    arguments.get(index + 1).map(String::as_str)
}

/// Whether a `gh` segment stays inside what its text proves. Field values
/// loaded from files (`-F`/`--field name=@path`), bodies loaded with
/// `--input` or any `--*-file` option, jq programs that reach the
/// environment or load a module, and shell expansion inside a value all put
/// content Guard never read into the request, so they never settle. Literal
/// `--raw-field` values (an `@mention` is text, not a file) and GraphQL
/// variables declared in the document stay settleable.
fn github_segment_settles_uncertainty(segment: &CommandSegmentV1) -> bool {
    if !inert_environment(segment) {
        return false;
    }
    let arguments = &segment.arguments;
    // A `$name` settles only as a GraphQL variable the same text declares
    // (`mutation($id:ID!)`); any other `$` — `$HOME`, `${...}`, `$(...)` —
    // is a value the shell or the server resolves, not the text Guard read.
    let full_text = arguments.join(" ");
    let declares_variable = |name: &str| full_text.contains(&format!("${name}:"));
    for (index, argument) in arguments.iter().enumerate() {
        if argument.contains("$(")
            || argument.contains('`')
            || argument.contains("${")
            || argument.contains("$'")
            || argument.contains("$\"")
        {
            return false;
        }
        for (position, _) in argument.match_indices('$') {
            let rest = &argument[position + 1..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty()
                && (name
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic() || c == '_'))
                && !declares_variable(&name)
            {
                return false;
            }
        }
        let name = flag_name(argument);
        if name == "--input" || name.ends_with("-file") {
            return false;
        }
        if matches!(name, "-F" | "--field") {
            let Some(value) = option_value(arguments, index, argument) else {
                return false;
            };
            let field_value = value.split_once('=').map_or(value, |(_, rest)| rest);
            if field_value.starts_with('@') {
                return false;
            }
        }
        if matches!(name, "--jq" | "-q") {
            let Some(value) = option_value(arguments, index, argument) else {
                return false;
            };
            let lowered = value.to_ascii_lowercase();
            if lowered.contains("env")
                || lowered.contains("getenv")
                || lowered.contains("import")
                || lowered.contains("include")
            {
                return false;
            }
        }
    }
    true
}

fn kubernetes_segment_settles_uncertainty(segment: &CommandSegmentV1) -> bool {
    if !inert_environment(segment) {
        return false;
    }
    let arguments = &segment.arguments;
    let mut index = 0;
    let mut subcommand: Option<&str> = None;
    while let Some(argument) = arguments.get(index) {
        index += 1;
        if subcommand.is_some() {
            // Only read shapes settle, and only with output the command
            // renders itself: no raw API path, no file of resources to act
            // on, and no output format that reads a template file.
            let name = flag_name(argument);
            if matches!(name, "--raw" | "-f" | "--filename" | "-k" | "--kustomize") {
                return false;
            }
            if matches!(name, "-o" | "--output") {
                let value = argument
                    .split_once('=')
                    .map(|(_, value)| value)
                    .or_else(|| arguments.get(index).map(String::as_str));
                if !value.is_some_and(super::domains::output_format_reads_no_file) {
                    return false;
                }
            }
            continue;
        }
        if argument == "--" {
            return false;
        }
        if argument.starts_with("--") {
            let name = flag_name(argument);
            if KUBECTL_AUTHORITY_FLAGS.contains(&name) {
                return false;
            }
            if KUBECTL_GLOBAL_VALUE_FLAGS.contains(&name) && !argument.contains('=') {
                index += 1;
            }
            continue;
        }
        if argument.starts_with('-') && argument.len() > 1 {
            if argument == "-n" {
                index += 1;
            }
            continue;
        }
        subcommand = Some(argument);
    }
    matches!(subcommand, Some("get" | "describe"))
}

fn network_segment_settles_uncertainty(segment: &CommandSegmentV1) -> bool {
    if !inert_environment(segment) {
        return false;
    }
    let arguments: Vec<&str> = segment.arguments.iter().map(String::as_str).collect();
    let any = |names: &[&str]| {
        arguments
            .iter()
            .any(|argument| names.iter().any(|name| flag_name(argument) == *name))
    };
    let option_value_mentions_proxy = arguments.iter().enumerate().any(|(index, argument)| {
        let lowered = argument.to_ascii_lowercase();
        (lowered.starts_with("-oproxy") && lowered.len() > 3)
            || (flag_name(argument) == "-o"
                && arguments
                    .get(index + 1)
                    .is_some_and(|value| value.to_ascii_lowercase().contains("proxy")))
    });
    match basename(segment).as_str() {
        // A config file carries instructions this text never showed.
        "curl" => !any(&["-K", "--config"]),
        "wget" => !any(&["-i", "--input-file", "--config"]),
        // `-e`/`-c` run a program; a script file runs commands from disk.
        "nc" | "netcat" => {
            !any(&["--exec", "--sh-exec"])
                && !arguments.iter().any(|argument| {
                    argument.starts_with('-')
                        && !argument.starts_with("--")
                        && argument[1..].chars().any(|flag| matches!(flag, 'e' | 'c'))
                })
        }
        "scp" => !any(&["-S", "-F", "-J"]) && !option_value_mentions_proxy,
        "sftp" => !any(&["-S", "-F", "-J", "-b"]) && !option_value_mentions_proxy,
        "rsync" => !any(&["-e", "--rsh", "--rsync-path", "--daemon", "--config"]),
        "ftp" => !any(&["-s"]),
        _ => true,
    }
}

/// Whether an explicit extension Allow may settle uncertainty about this
/// segment, whichever extension owns the uncertain rule. Owners with their
/// own authority or program-running shapes (Git, Docker, kubectl, the
/// network tools) keep their narrower proofs; every other program settles
/// only with an inert environment and no interpreter in the segment.
pub(crate) fn segment_settles_uncertainty(
    segment: &CommandSegmentV1,
    context: crate::pretool::PathContext<'_>,
) -> bool {
    match basename(segment).as_str() {
        "git" => {
            super::git::subcommand_settles_uncertainty(segment)
                && !super::git::runs_configured_program(segment)
                && super::git_repository_routes_verified(segment, context)
        }
        "docker" => super::domains::docker_segment_settles_uncertainty(segment),
        "gh" => github_segment_settles_uncertainty(segment),
        "kubectl" | "oc" => kubernetes_segment_settles_uncertainty(segment),
        "curl" | "wget" | "nc" | "netcat" | "scp" | "rsync" | "sftp" | "ftp" => {
            network_segment_settles_uncertainty(segment)
        }
        name if INTERPRETERS.contains(&name) || name.starts_with("python") => false,
        "find" => {
            inert_environment(segment)
                && !segment.arguments.iter().any(|argument| {
                    matches!(flag_name(argument), "-exec" | "-execdir" | "-ok" | "-okdir")
                })
        }
        _ => inert_environment(segment),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CommandSpanV1;

    fn segment(executable: &str, arguments: &[&str]) -> CommandSegmentV1 {
        CommandSegmentV1 {
            text: String::new(),
            tokens: Vec::new(),
            executable: Some(executable.to_owned()),
            arguments: arguments.iter().map(ToString::to_string).collect(),
            environment_names: Vec::new(),
            wrapper_chain: Vec::new(),
            path_overridden: false,
            execution_context: "root".to_owned(),
            pipeline_index: 0,
            span: CommandSpanV1 {
                source: "normalized".to_owned(),
                start: 0,
                end: 0,
            },
        }
    }

    fn settles(executable: &str, arguments: &[&str]) -> bool {
        segment_settles_uncertainty(
            &segment(executable, arguments),
            crate::pretool::PathContext::default(),
        )
    }

    #[test]
    fn every_owner_family_has_a_settleable_shape() {
        assert!(settles(
            "kubectl",
            &["-n", "prod", "describe", "secret", "db"]
        ));
        assert!(settles(
            "curl",
            &["-T", "report.txt", "https://example.invalid/up"]
        ));
        assert!(settles("rm", &["-rf", "build"]));
        assert!(settles("gh", &["some-unmodeled-command"]));
        assert!(settles("docker", &["ps"]));
    }

    #[test]
    fn unbounded_shapes_never_settle() {
        // A different authority answers.
        assert!(!settles(
            "kubectl",
            &["--context", "prod", "get", "secret", "db"]
        ));
        // Not a read shape.
        assert!(!settles("kubectl", &["exec", "web-0", "--", "cat", "x"]));
        // A template file the command would read.
        assert!(!settles(
            "kubectl",
            &["get", "secret", "db", "-o", "go-template-file=./tmpl"]
        ));
        // Instructions or programs from files Guard never read.
        assert!(!settles("curl", &["-K", "curlrc", "-T", "f", "https://h"]));
        assert!(!settles(
            "gh",
            &["api", "x/y/git/blobs", "-F", "content=@file.txt"]
        ));
        assert!(!settles("gh", &["api", "graphql", "--input", "-"]));
        assert!(!settles("gh", &["api", "user", "--jq", "env.GH_TOKEN"]));
        assert!(!settles("rsync", &["-e", "sh", "f", "host:/tmp/"]));
        assert!(!settles("nc", &["-e", "/bin/sh", "host", "4444"]));
        assert!(!settles("find", &[".", "-exec", "rm", "{}", ";"]));
        // Interpreters run text the attribution only sampled.
        assert!(!settles("python3", &["-c", "import os"]));
        assert!(!settles("sh", &["-c", "rm -rf build"]));
    }

    #[test]
    fn a_steering_environment_prefix_never_settles() {
        let mut steered = segment("rm", &["-rf", "build"]);
        steered.environment_names = vec!["SOME_STEER".to_owned()];
        assert!(!segment_settles_uncertainty(
            &steered,
            crate::pretool::PathContext::default()
        ));
        let mut steered_docker = segment("docker", &["ps"]);
        steered_docker.environment_names = vec!["DOCKER_HOST".to_owned()];
        assert!(!segment_settles_uncertainty(
            &steered_docker,
            crate::pretool::PathContext::default()
        ));
    }
}
