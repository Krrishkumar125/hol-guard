//! A conditional runs a subset of the command lists written inside it: the
//! branch whose test succeeds. Writing those lists out as one plain list
//! therefore runs at least as much as the construct ever can, so admitting
//! the flat list admits the construct, and the conditional grants no
//! authority of its own.
//!
//! A loop is only the same shape when it is known to stop and its body cannot
//! build up across iterations, because one flattened pass stands for every
//! iteration. `while read NAME; do ...; done < FILE` is that shape: the read
//! ends at the file's end, and a body that writes nothing leaves each
//! iteration doing the work the single pass already describes. Every other
//! loop keeps its review.
//!
//! Each list item still faces the ordinary proofs, and anything this
//! recognizer does not fully understand returns `None`, which keeps the
//! existing review behavior.

use super::for_loop_unroll::body::{body_items, redirect_tail, substitute};

/// Enough room for a conditional with a handful of `elif` arms.
const MAX_ITEMS: usize = 48;
const MAX_FLATTENED_BYTES: usize = 8192;

/// The flattened command list for a top-level `if` construct or a bounded
/// `while read` loop, or `None` when the command is anything else.
pub(super) fn flatten(command: &str) -> Option<String> {
    if command
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
    {
        return None;
    }
    // A value the construct itself binds — the name a `while read` loop fills
    // from its input — is not bound in the flat list, so an expansion there
    // would stand for different text than the one the construct ran. No
    // expansion at all is the rule that keeps the two forms the same work.
    if command.contains(['$', '`']) {
        return None;
    }
    let text = command.trim();
    if let Some(rest) = keyword(text, "if") {
        return flatten_conditional(rest);
    }
    if let Some(rest) = keyword(text, "while") {
        return flatten_loop(rest);
    }
    None
}

/// `if LIST; then LIST; [elif LIST; then LIST;]... [else LIST;] fi`.
fn flatten_conditional(rest: &str) -> Option<String> {
    let mut parts: Vec<(String, &'static str)> = Vec::new();
    let mut rest = rest;
    loop {
        let (test, _, after_test) = body_items(rest, "", &["then"])?;
        collect(&mut parts, test)?;
        let (branch, closer, after_branch) = body_items(after_test, "", &["elif", "else", "fi"])?;
        collect(&mut parts, branch)?;
        match closer {
            "elif" => rest = after_branch,
            "else" => {
                let (alternative, _, after_alternative) = body_items(after_branch, "", &["fi"])?;
                collect(&mut parts, alternative)?;
                return assemble(&parts, after_alternative);
            }
            _ => return assemble(&parts, after_branch),
        }
    }
}

/// `while read NAME...; do LIST; done < FILE`, the one loop shape a single
/// flattened pass describes. The read ends at the file's end, so the loop
/// stops on its own, and a body that opens no output keeps every iteration
/// doing the work that one pass already stands for. A loop whose test is
/// anything else may never end, and a body that writes would repeat its
/// effect for as long as it runs, so neither is flattened.
fn flatten_loop(rest: &str) -> Option<String> {
    let (test, _, after_test) = body_items(rest, "", &["do"])?;
    let (body, _, tail) = body_items(after_test, "", &["done"])?;
    if !driven_by_a_read(&test) || !redirect_tail(tail)?.starts_with('<') {
        return None;
    }
    if body
        .iter()
        .any(|(text, _)| text.contains('>') || text.contains('<'))
    {
        return None;
    }
    let mut parts: Vec<(String, &'static str)> = Vec::new();
    collect(&mut parts, test)?;
    collect(&mut parts, body)?;
    assemble(&parts, tail)
}

/// Whether a loop's test is the single `read` that empties the redirected
/// input, which is what makes the iteration count finite.
fn driven_by_a_read(test: &[(String, &'static str)]) -> bool {
    matches!(test, [(text, _)] if text.split_whitespace().next() == Some("read"))
}

/// Add a list's items, rejecting an empty list and any item whose command
/// word is not a plain word. A nested construct leaves its keyword in command
/// position, so this is also what keeps nesting on the unmodeled path.
fn collect(
    parts: &mut Vec<(String, &'static str)>,
    items: Vec<(String, &'static str)>,
) -> Option<()> {
    if items.is_empty() || parts.len() + items.len() > MAX_ITEMS {
        return None;
    }
    for (text, separator) in items {
        parts.push((substitute(&text, "")?, separator));
    }
    Some(())
}

/// Join the collected items, giving each one the redirection that followed
/// the construct. The construct applied that redirection to every command it
/// ran, so each flattened item carries it too.
fn assemble(parts: &[(String, &'static str)], tail: &str) -> Option<String> {
    let tail = redirect_tail(tail)?;
    if parts.is_empty() {
        return None;
    }
    let mut out = String::new();
    for (text, separator) in parts {
        out.push_str(text);
        if !tail.is_empty() {
            out.push(' ');
            out.push_str(&tail);
        }
        out.push_str(separator);
        if out.len() > MAX_FLATTENED_BYTES {
            return None;
        }
    }
    Some(out.trim_end_matches([' ', ';']).to_owned())
}

/// Consume `keyword` followed by whitespace.
fn keyword<'a>(text: &'a str, keyword: &str) -> Option<&'a str> {
    let rest = text.strip_prefix(keyword)?;
    rest.starts_with([' ', '\t', '\n'])
        .then(|| rest.trim_start_matches([' ', '\t', '\n']))
}

#[cfg(test)]
#[path = "control_flow_flatten_tests.rs"]
mod tests;
