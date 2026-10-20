//! Credential fields answered in prose rather than assigned a value.
//!
//! Agents summarize what they read: `- Token: No.`, `Password: not set`,
//! `Mentions an API key: none`. The credential-assignment rule reads the word
//! after the colon as the assigned value, so an honest report that a file holds
//! no secret was returned to the model as a secret match and the output was
//! withheld. The answer words here are a closed list, so nothing an attacker
//! could choose as a credential passes: a real secret is not spelled `no`.

/// Answer and state words a report uses in place of a value. Lower case, and
/// matched whole, so `nonce` or `yesterday` is still a value.
const ANSWER_WORDS: &[&str] = &[
    "absent",
    "empty",
    "false",
    "missing",
    "n",
    "n/a",
    "na",
    "never",
    "nil",
    "no",
    "none",
    "nope",
    "not",
    "nothing",
    "null",
    "omitted",
    "optional",
    "present",
    "redacted",
    "required",
    "tbd",
    "todo",
    "unknown",
    "unset",
    "unspecified",
    "y",
    "yes",
];

/// Longest answer considered, so a long literal never qualifies by luck.
const MAX_VALUE_CHARS: usize = 16;

/// Whether a credential-assignment match states an answer about the field
/// instead of assigning a value to it.
///
/// Only the unquoted colon form qualifies. A quoted value (`"token": "no"`) is
/// data a program reads, and `=` is an assignment an environment or shell file
/// makes, so both keep their match. `tail` is the text after the match: an
/// answer the value runs on past is not the whole value.
pub(crate) fn is_prose_answer(matched: &str, tail: &str) -> bool {
    let Some(index) = matched.find([':', '=']) else {
        return false;
    };
    if matched.as_bytes()[index] != b':' {
        return false;
    }
    let value = matched[index + 1..].trim();
    if value.is_empty() || value.chars().count() > MAX_VALUE_CHARS || value.starts_with(['"', '\''])
    {
        return false;
    }
    if !ends_value(tail) {
        return false;
    }
    let answer = value
        .trim_end_matches(['.', ',', ';', '!', '?', ')', ']'])
        .to_ascii_lowercase();
    if answer.is_empty()
        || !answer
            .chars()
            .all(|character| character.is_ascii_alphabetic() || character == '/')
    {
        return false;
    }
    ANSWER_WORDS.contains(&answer.as_str())
}

/// Whether `tail` begins where the answer ends. The rule's unquoted arm stops
/// at a space, `"`, `'`, `,` or `}`, so anything else directly after the match
/// is more of the same value and the answer wording proves nothing about it.
fn ends_value(tail: &str) -> bool {
    tail.chars()
        .next()
        .is_none_or(|next| next.is_whitespace() || matches!(next, ',' | '}' | ')' | ']' | ';'))
}

#[cfg(test)]
mod tests {
    use super::is_prose_answer;
    use crate::scan_text;
    use guard_rules::MAX_SCAN_BYTES;

    fn credential_assignment(text: &str) -> bool {
        scan_text(text, true, true, MAX_SCAN_BYTES, None)
            .matches
            .iter()
            .any(|matched| matched.classifier == "credential-assignment")
    }

    #[test]
    fn answer_words_report_a_field_rather_than_assign_it() {
        assert!(is_prose_answer("Token: No.", ""));
        assert!(is_prose_answer("token: no", "\n"));
        assert!(is_prose_answer("Secret: none", ""));
        assert!(is_prose_answer("password: unset", ""));
        assert!(is_prose_answer("api_key: N/A", ""));
        assert!(is_prose_answer("Token:No.", ""));
        assert!(is_prose_answer("credential: absent", ";"));
    }

    #[test]
    fn real_values_and_other_forms_keep_their_match() {
        assert!(!is_prose_answer("password: swordfish", ""));
        assert!(!is_prose_answer("token: nonce", ""));
        assert!(!is_prose_answer("TOKEN=no", ""));
        assert!(!is_prose_answer(r#""token": "no""#, ""));
        assert!(!is_prose_answer("token: no", "pe-q7Lm2Xv9"));
        assert!(!is_prose_answer("token: no1", ""));
        assert!(!is_prose_answer("token:", ""));
    }

    #[test]
    fn a_report_that_a_file_holds_no_secret_is_not_secret_output() {
        let report = concat!(
            "Read the README and checked for credentials.\n",
            "- Token: No.\n",
            "- API key: none\n",
            "- Password: not set\n",
        );
        assert!(!credential_assignment(report));
    }

    #[test]
    fn a_real_credential_beside_an_answer_still_matches() {
        let visible = "q7Lm2Xv9Rt4Kp8Wz";
        assert!(credential_assignment(&format!(
            "- Token: No.\npassword: {visible}\n"
        )));
    }
}
