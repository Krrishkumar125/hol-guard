use super::launcher_program;

fn words(command: &str) -> Vec<String> {
    command.split(' ').map(str::to_owned).collect()
}

/// Each prefix's documented options are walked, and the program behind them
/// is the word the command runs.
#[test]
fn a_documented_launcher_names_the_program_behind_it() {
    for (command, program) in [
        ("nice npm run build", 1),
        ("nice -n 10 npm run build", 3),
        ("nice -n -5 cargo build", 3),
        ("nice -n10 cargo build", 2),
        ("nice -10 cargo build", 2),
        ("nice --adjustment=19 pytest -q", 2),
        ("nice --adjustment 19 pytest -q", 3),
        ("nice -- npm test", 2),
        ("nohup npm run dev", 1),
        ("stdbuf -oL pytest -q", 2),
        ("stdbuf -o L pytest -q", 3),
        ("stdbuf -i0 -oL -e0 cargo test", 4),
        ("stdbuf --output=L --error=0 npm test", 3),
        ("stdbuf -o 4K npm test", 3),
        ("nice -n 10 nohup npm run build", 3),
    ] {
        assert_eq!(
            launcher_program(&words(command), 0),
            Some(program),
            "{command} did not name its program"
        );
    }
}

/// A prefix spelled as a path, an option no grammar documents, a value
/// outside the shape the prefix takes, and a prefix running nothing at all
/// each leave the command as uncertain as it arrived.
#[test]
fn an_undocumented_word_leaves_the_launcher_in_place() {
    for command in [
        "./nice -n 10 npm test",
        "/tmp/tools/stdbuf -oL npm test",
        "nice",
        "nice -n 10",
        "nice --version",
        "nice --help",
        "nice -",
        "nice -x npm test",
        "nice -n 300 npm test",
        "nice -n L npm test",
        "nice --adjustment=nineteen npm test",
        "nohup -f npm run dev",
        "nohup --version",
        "stdbuf npm test",
        "stdbuf -oL",
        "stdbuf -o /dev/null npm test",
        "stdbuf -oQ npm test",
        "stdbuf -n0 npm test",
        "stdbuf --buffer=L npm test",
        "nice -n 10 FOO=bar npm test",
        "nice -n 10 -- -q",
    ] {
        assert_eq!(
            launcher_program(&words(command), 0),
            None,
            "{command} was read as a documented launcher"
        );
    }
}

/// The scan starts where the caller says, so assignments and an earlier
/// prefix do not move the program this reads.
#[test]
fn the_scan_starts_at_the_word_the_caller_names() {
    assert_eq!(
        launcher_program(&words("env FOO=bar nice -n 10 npm test"), 2),
        Some(5)
    );
    assert_eq!(launcher_program(&words("npm run build"), 0), None);
}
