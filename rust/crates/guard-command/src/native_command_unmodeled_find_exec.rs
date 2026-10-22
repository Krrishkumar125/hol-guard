//! Reading the program a `find -exec` runs out of the command text.
use super::command_basename;
use super::xargs::{command_index, plain_program};
use std::collections::BTreeSet;

/// find's actions that run a program named by the words after them.
pub(super) const EXEC_ACTIONS: &[&str] = &["-exec", "-execdir", "-ok", "-okdir"];

/// The programs every `-exec` action in the text names, by basename, or
/// `None` when one of them names none.
///
/// `find` hands the paths it found to the program the text already shows, the
/// way standard input hands `xargs` its operands, and those paths come from
/// the roots this same text names. So `find src -type f -exec basename {} \;`
/// runs the `basename` the text shows and owns what `basename` owns. An
/// `-exec` whose operand is itself an interpreter (`find . -exec sh -c ...`),
/// one built from an expansion or a glob, and one with no operand at all run
/// whatever they read, so those stay unbounded. An `-exec` that belongs to
/// something other than a `find` this text names as its own command, as in
/// `echo -exec rm`, is not read either.
pub(super) fn find_exec_programs(shell: &str) -> Option<BTreeSet<String>> {
    let mut programs = BTreeSet::new();
    let mut found = false;
    // find ends an `-exec` body at an unquoted `;`, so splitting on it leaves
    // the action and the program it names together in the same piece.
    for piece in shell.split(['\n', ';', '&', '|', '(', ')', '`']) {
        let words: Vec<&str> = piece.split_whitespace().collect();
        let actions: Vec<usize> = words
            .iter()
            .enumerate()
            .filter(|(_, word)| EXEC_ACTIONS.contains(*word))
            .map(|(index, _)| index)
            .collect();
        if actions.is_empty() {
            continue;
        }
        found = true;
        // A wrapper, an option or a redirect `command_index` does not read
        // past could leave a `find` unrecognized while another piece's one
        // made the text look bounded, so an unrecognized piece stays unread.
        if command_index(&words).map(|index| command_basename(words[index]))
            != Some("find".to_owned())
        {
            return None;
        }
        for action in actions {
            let operand = *words.get(action + 1)?;
            // `{}` is find's own placeholder for the path it found, and `+`
            // and `;` end the body: neither names a program.
            if operand.contains(['{', '}']) || matches!(operand, "+" | "\\") {
                return None;
            }
            if !plain_program(operand) {
                return None;
            }
            let program = command_basename(operand);
            // A `.cmd` launcher runs the program it is named for, the way
            // `command_basename` already reads a `.exe` suffix.
            if let Some(stem) = program.strip_suffix(".cmd") {
                programs.insert(stem.to_owned());
            }
            programs.insert(program);
        }
    }
    found.then_some(programs)
}
