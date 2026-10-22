//! `docker logs` and `docker compose logs` of named containers or services,
//! bounded by time or line limits.
//!
//! They print what a workload already wrote and change nothing: no container
//! starts, no image is pulled, no project file is resolved. That is the same
//! read `kubectl logs` is proven as, and the output stays in the session,
//! which any later step that sends it elsewhere still has to pass on its own.
//!
//! `--follow` never ends and stays out, which also keeps Compose's root
//! `-f <file>` out: after the verb Cobra reads `-f` as `--follow`, before it
//! the option sits ahead of the subcommand, where every option keeps its
//! review. `--details` prints the extra attributes a driver was given, so it
//! stays reviewed too, and so does every option outside the lists below.

/// `docker logs` options that take no value.
const CONTAINER_FLAGS: [&str; 2] = ["-t", "--timestamps"];

/// `docker compose logs` options that take no value.
const SERVICE_FLAGS: [&str; 4] = ["-t", "--timestamps", "--no-color", "--no-log-prefix"];

/// Options whose value only bounds the printed output.
const CONTAINER_VALUES: [&str; 4] = ["-n", "--tail", "--since", "--until"];
const SERVICE_VALUES: [&str; 5] = ["-n", "--tail", "--since", "--until", "--index"];

/// `docker logs <container>` prints one container's output.
pub(super) fn safe_container_logs(words: &[&str]) -> bool {
    options_safe(words, &CONTAINER_FLAGS, &CONTAINER_VALUES, 1, 1)
}

/// `docker compose logs [service...]` prints the project's services, or the
/// named ones. The project itself comes from the working directory.
pub(super) fn safe_service_logs(words: &[&str]) -> bool {
    options_safe(words, &SERVICE_FLAGS, &SERVICE_VALUES, 0, 16)
}

fn options_safe(
    words: &[&str],
    flags: &[&str],
    values: &[&str],
    least: usize,
    most: usize,
) -> bool {
    let mut positionals = 0usize;
    let mut index = 0;
    while index < words.len() {
        let word = words[index];
        index += 1;
        if !word.starts_with('-') {
            positionals += 1;
            if !target_name(word) {
                return false;
            }
            continue;
        }
        if flags.contains(&word) {
            continue;
        }
        let (name, inline) = match word.split_once('=') {
            Some((name, value)) if name.starts_with("--") => (name, Some(value)),
            _ => (word, None),
        };
        if !values.contains(&name) {
            return false;
        }
        let value = match inline {
            Some(value) => value,
            None => match words.get(index) {
                Some(value) => {
                    index += 1;
                    *value
                }
                None => return false,
            },
        };
        if !value_safe(name, value) {
            return false;
        }
    }
    (least..=most).contains(&positionals)
}

fn value_safe(name: &str, value: &str) -> bool {
    match name {
        "-n" | "--tail" => {
            value == "all" || (value.len() <= 6 && value.bytes().all(|byte| byte.is_ascii_digit()))
        }
        "--index" => value.len() <= 3 && value.bytes().all(|byte| byte.is_ascii_digit()),
        // A time bound is a duration, a UNIX timestamp or an RFC 3339 time.
        "--since" | "--until" => {
            !value.is_empty()
                && value.len() <= 64
                && !value.starts_with('-')
                && value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b':' | b'-' | b'+')
                })
        }
        _ => false,
    }
}

/// A container or Compose service name.
fn target_name(word: &str) -> bool {
    !word.is_empty()
        && word.len() <= 128
        && word
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && word
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}
