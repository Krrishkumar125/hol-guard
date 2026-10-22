//! Prefixes that run the program the text already names.
//!
//! `nice -n 10 cargo build`, `nohup npm test` and `stdbuf -oL pytest -q` each
//! run the program the text already names, as this user and in this directory.
//! They decide when it gets the processor, whether a hangup reaches it, and how
//! its output is buffered — not what it may do — so the owners of the command
//! are the owners of the program behind the prefix.
//!
//! Reading that requires knowing which word is the program, and each prefix
//! carries its own options, so the program is not at a fixed offset. Each
//! grammar below is walked over the words it documents. A word the grammar does
//! not cover leaves a program the text does not name, so the command keeps the
//! wrapper's own uncertainty rather than a guess about which word runs.
//!
//! `setsid` is not here: it puts the program in a session of its own, where a
//! run outlives the shell that started it, which is a change to how the program
//! is supervised rather than to how it is scheduled.

/// One prefix's option grammar: the short letters that carry a value, its long
/// spellings that do, whether a bare number is its own option, and which words
/// those values may be.
pub(super) struct Prefix {
    name: &'static str,
    short_values: &'static str,
    long_values: &'static [&'static str],
    numeric_flag: bool,
    value: fn(&str) -> bool,
}

const PREFIXES: &[Prefix] = &[
    Prefix {
        name: "nice",
        short_values: "n",
        long_values: &["adjustment"],
        // `nice -10 cargo build` is the adjustment spelled on its own.
        numeric_flag: true,
        value: adjustment,
    },
    Prefix {
        name: "nohup",
        short_values: "",
        long_values: &[],
        numeric_flag: false,
        value: adjustment,
    },
    Prefix {
        name: "stdbuf",
        short_values: "ioe",
        long_values: &["input", "output", "error"],
        numeric_flag: false,
        value: buffer_size,
    },
];

/// The grammar for this word, when the word is the system program rather than a
/// file that happens to be named for it. The shell resolves a bare `nice` on
/// `PATH`, and the two system directories hold the same program; `./nice`,
/// `bin/nice` and `/tmp/nice` are whatever those files hold, so they stay
/// wrappers and keep the command under review.
pub(super) fn trusted(token: &str) -> Option<&'static Prefix> {
    PREFIXES.iter().find(|prefix| {
        token == prefix.name
            || token.strip_prefix("/usr/bin/") == Some(prefix.name)
            || token.strip_prefix("/bin/") == Some(prefix.name)
    })
}

/// The index of the program this prefix runs, once its own options are read.
///
/// `-n 10`, `-n10`, `--adjustment 10`, `--adjustment=10`, the historical `-10`
/// and `--` all belong to `nice` and none of them names a program. An option
/// this grammar does not document, a value the option does not take, a missing
/// program and a leading assignment each leave a program the text does not
/// name, so each one keeps the command uncertain.
pub(super) fn program(
    prefix: &Prefix,
    tokens: &[String],
    mut index: usize,
) -> Result<usize, &'static str> {
    while let Some(option) = tokens.get(index) {
        if option == "--" {
            index += 1;
            break;
        }
        if prefix.numeric_flag
            && option
                .strip_prefix('+')
                .is_some_and(|digits| (prefix.value)(digits))
        {
            index += 1;
            continue;
        }
        let Some(body) = option.strip_prefix('-').filter(|body| !body.is_empty()) else {
            break;
        };
        if let Some(long) = body.strip_prefix('-') {
            let (name, attached) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (long, None),
            };
            if !prefix.long_values.contains(&name) {
                return Err("transparent_wrapper_not_yet_supported");
            }
            index += match attached {
                Some(value) if (prefix.value)(value) => 1,
                Some(_) => return Err("transparent_wrapper_not_yet_supported"),
                None if tokens
                    .get(index + 1)
                    .is_some_and(|value| (prefix.value)(value)) =>
                {
                    2
                }
                None => return Err("transparent_wrapper_not_yet_supported"),
            };
            continue;
        }
        if prefix.numeric_flag && (prefix.value)(body) {
            index += 1;
            continue;
        }
        let Some(letter) = body
            .chars()
            .next()
            .filter(|letter| letter.is_ascii() && prefix.short_values.contains(*letter))
        else {
            return Err("transparent_wrapper_not_yet_supported");
        };
        let attached = &body[letter.len_utf8()..];
        index += match attached {
            value if !value.is_empty() && (prefix.value)(value) => 1,
            "" if tokens
                .get(index + 1)
                .is_some_and(|value| (prefix.value)(value)) =>
            {
                2
            }
            _ => return Err("transparent_wrapper_not_yet_supported"),
        };
    }
    let Some(program) = tokens.get(index) else {
        return Err("transparent_wrapper_not_yet_supported");
    };
    if program.is_empty() || program.starts_with('-') || crate::assignment_name(program).is_some() {
        return Err("transparent_wrapper_not_yet_supported");
    }
    Ok(index)
}

/// A priority `nice` reads: an optional sign and at most two digits, which is
/// every value the scheduler accepts.
fn adjustment(value: &str) -> bool {
    let digits = value.strip_prefix(['-', '+']).unwrap_or(value);
    !digits.is_empty() && digits.len() <= 2 && digits.bytes().all(|byte| byte.is_ascii_digit())
}

/// A buffering mode `stdbuf` reads: `L` for line buffered, `0` for unbuffered,
/// or a size, which may carry one of the unit suffixes `coreutils` documents.
fn buffer_size(value: &str) -> bool {
    if value == "L" {
        return true;
    }
    let digits = value.trim_end_matches(|byte: char| byte.is_ascii_alphabetic());
    !digits.is_empty()
        && digits.len() <= 20
        && digits.bytes().all(|byte| byte.is_ascii_digit())
        && value.len() - digits.len() <= 2
}
