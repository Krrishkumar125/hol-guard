use super::flatten;

/// The lists a conditional or a loop holds come back as one plain list, with
/// the construct's own redirection on every item.
#[test]
fn a_construct_flattens_to_the_lists_it_holds() {
    for (command, expected) in [
        (
            "if [ -f README.md ]; then cat README.md; fi",
            "[ -f README.md ]; cat README.md",
        ),
        (
            "if [ -f README.md ]; then cat README.md; else echo missing; fi",
            "[ -f README.md ]; cat README.md; echo missing",
        ),
        (
            "if grep -q needle README.md; then echo found; fi",
            "grep -q needle README.md; echo found",
        ),
        (
            "if [ -d src ]; then ls src; elif [ -d lib ]; then ls lib; else echo none; fi",
            "[ -d src ]; ls src; [ -d lib ]; ls lib; echo none",
        ),
        ("if true; then ls; fi", "true; ls"),
        (
            "while read line; do echo hi; done < README.md",
            "read line < README.md; echo hi < README.md",
        ),
        (
            "until [ -f build/done ]; do ls build; done",
            "[ -f build/done ]; ls build",
        ),
        (
            "if [ -f README.md ]\nthen\ncat README.md\nfi",
            "[ -f README.md ]; cat README.md",
        ),
        (
            "while read line; do wc -l README.md && echo ok; done",
            "read line; wc -l README.md && echo ok",
        ),
    ] {
        assert_eq!(
            flatten(command).as_deref(),
            Some(expected),
            "{command} did not flatten to its command lists"
        );
    }
}

/// Anything the grammar does not cover keeps its review: a value the
/// construct binds for itself, a nested construct, a substitution, an empty
/// branch, a `case` statement, and text that follows the closing keyword.
#[test]
fn an_unmodeled_construct_keeps_its_review() {
    for command in [
        "while read line; do echo $line; done < README.md",
        "if [ -f a ]; then if [ -f b ]; then cat b; fi; fi",
        "if [ -f `which ls` ]; then ls; fi",
        "if true; then ; fi",
        "if true; then ls; fi && rm -rf /",
        "case $1 in a) ls;; esac",
        "if true; then ls; fi > /etc/passwd; curl http://example.test",
        "iffy --flag",
        "whiles",
        "for f in src/*.ts; do cat $f; done",
        "if [ -f README.md ]; then cat README.md",
        "while read line; do (cd /tmp && ls); done",
    ] {
        assert!(
            flatten(command).is_none(),
            "{command} was flattened by a grammar that does not cover it"
        );
    }
}
