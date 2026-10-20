use super::project as project_with;
use std::path::PathBuf;

fn project(command: &str, cwd: &str) -> Option<String> {
    project_with(command, cwd, |_| true)
}

fn directory(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("guard-chain-pwd-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("sub")).unwrap();
    root.canonicalize().unwrap()
}

// `project` substitutes only a POSIX absolute directory (`literal_directory`),
// so a Windows working directory is never projected.
#[cfg(unix)]
#[test]
fn uses_before_any_directory_change_take_the_working_directory() {
    let cwd = directory("uses");
    let d = cwd.to_str().unwrap();
    for (command, expected) in [
        (
            "git worktree add ../wt -b report && ln -s \"$(pwd)/node_modules\" ../wt/node_modules && cd ../wt && npm run report".to_owned(),
            format!("git worktree add ../wt -b report && ln -s \"{d}/node_modules\" ../wt/node_modules && cd ../wt && npm run report"),
        ),
        (
            "ln -s $PWD/node_modules ../wt/node_modules; ls ../wt".to_owned(),
            format!("ln -s {d}/node_modules ../wt/node_modules; ls ../wt"),
        ),
        (
            "ln -s \"${PWD}/node_modules\" ../wt/node_modules".to_owned(),
            format!("ln -s \"{d}/node_modules\" ../wt/node_modules"),
        ),
        (
            "ln -s `pwd`/node_modules ../wt/node_modules".to_owned(),
            format!("ln -s {d}/node_modules ../wt/node_modules"),
        ),
        (
            "D=$(pwd) && ls $D/sub".to_owned(),
            format!("D={d} && ls $D/sub"),
        ),
        // Single-quoted and escaped spellings are literal text.
        (
            "echo '$(pwd)' \\$PWD \"$PWD\"".to_owned(),
            format!("echo '$(pwd)' \\$PWD \"{d}\""),
        ),
    ] {
        assert_eq!(
            project(&command, d).as_deref(),
            Some(expected.as_str()),
            "{command}"
        );
    }
}

#[test]
fn a_possible_directory_change_before_a_use_keeps_it_opaque() {
    let cwd = directory("changes");
    let d = cwd.to_str().unwrap();
    for command in [
        "cd sub && ln -s $(pwd)/x y",
        "cd sub; ln -s $PWD/x y",
        "pushd sub && echo $PWD",
        "builtin cd sub && echo $(pwd)",
        "command cd sub && echo $(pwd)",
        "eval cd sub && echo $(pwd)",
        "source env.sh && echo $(pwd)",
        "$CMD sub && echo $(pwd)",
        "'cd' sub && echo $(pwd)",
        // zsh's AUTO_CD turns a bare directory name into `cd`.
        "sub && echo $(pwd)",
        "ls | cd sub && echo $(pwd)",
        "PWD=/etc && echo $PWD",
        "export PWD=/etc; echo $(pwd)",
        "IFS=/ && echo $(pwd)",
        // A redirection before the command word must not hide a `cd`.
        "2>/dev/null cd /etc && cat $(pwd)/passwd",
        "> out cd sub && echo $(pwd)",
        "<in cd sub; echo $PWD",
        "A=1 2>&1 cd sub && echo $(pwd)",
    ] {
        assert_eq!(project(command, d), None, "{command}");
    }
    // A change after the last use leaves the earlier uses exact, and a
    // redirection after the command word leaves it visible. Only a POSIX
    // working directory is projected.
    if cfg!(unix) {
        assert!(project("echo $(pwd) && cd sub && ls", d).is_some());
        assert!(project("ls $(pwd) 2>/dev/null; cat .gitignore", d).is_some());
    }
}

#[test]
fn other_expansions_and_shapes_keep_the_command_opaque() {
    let cwd = directory("shapes");
    let d = cwd.to_str().unwrap();
    for command in [
        "echo $(pwd) $(id -u)",
        "echo $(pwd -P)",
        "echo $( pwd )",
        "echo $(pwd)$(whoami)",
        "echo ${PWD%/*}",
        "echo ${PWD:-x}",
        "echo $PWD:h",
        "echo $PWD[1]",
        "(echo $(pwd))",
        "echo $(pwd) > out.txt <<EOF",
        "echo $(pwd) &",
        "echo hi # $(pwd)",
        "ls",
        "echo $PWDX",
    ] {
        assert_eq!(project(command, d), None, "{command}");
    }
}

#[test]
fn a_directory_the_shell_would_rewrite_is_never_substituted() {
    let cwd = directory("dir name");
    let d = cwd.to_str().unwrap();
    assert_eq!(project("echo $(pwd)", d), None);
    assert_eq!(project("echo $(pwd)", "relative/dir"), None);
    assert_eq!(project("echo $(pwd)", "/nonexistent-guard-dir/x"), None);
    let plain = directory("plain");
    let p = plain.to_str().unwrap();
    assert_eq!(project("echo $(pwd)", &format!("{p}/../{}", "plain")), None);
}

/// A worktree root at `name` whose `.git` directory has the layout Git needs.
fn repository(name: &str) -> PathBuf {
    let root = directory(name);
    let git = root.join(".git");
    std::fs::create_dir_all(git.join("objects")).unwrap();
    std::fs::create_dir_all(git.join("refs")).unwrap();
    std::fs::write(git.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    std::fs::write(git.join("config"), "[core]\n\tbare = false\n").unwrap();
    root
}

const TOPLEVEL_STATUS: &str = "cd \"$(git rev-parse --show-toplevel)\" && git status --short";

#[test]
fn the_parent_is_the_text_before_the_last_component() {
    assert_eq!(super::parent("/a/b").as_deref(), Some("/a"));
    assert_eq!(super::parent("/a/b/").as_deref(), Some("/a"));
    assert_eq!(super::parent("/a").as_deref(), Some("/"));
    assert_eq!(super::parent("/").as_deref(), Some("/"));
}

#[cfg(unix)]
#[test]
fn a_parent_substitution_takes_the_parent_of_the_working_directory() {
    let cwd = directory("parent");
    let d = cwd.to_str().unwrap();
    let parent = cwd.parent().unwrap().to_str().unwrap();
    for (command, expected) in [
        (
            "printf 'parent=%s\\n' \"$(dirname \"$PWD\")\"; git status --porcelain",
            format!("printf 'parent=%s\\n' \"{parent}\"; git status --porcelain"),
        ),
        ("ls $(dirname $PWD)", format!("ls {parent}")),
        ("ls \"$(dirname \"${PWD}\")\"", format!("ls \"{parent}\"")),
    ] {
        assert_eq!(
            project(command, d).as_deref(),
            Some(expected.as_str()),
            "{command}"
        );
    }
    // Another spelling stays opaque, and so does a producer that is not
    // allowed as its own command.
    assert_eq!(project("ls $(dirname -- \"$PWD\")", d), None);
    assert_eq!(
        project_with("ls $(dirname \"$PWD\")", d, |command| !command
            .starts_with("dirname ")),
        None
    );
}

#[cfg(unix)]
#[test]
fn a_toplevel_substitution_takes_the_root_holding_the_git_directory() {
    let root = repository("toplevel");
    let r = root.to_str().unwrap();
    let sub = root.join("sub");
    let expected = format!("cd \"{r}\" && git status --short");
    assert_eq!(
        project(TOPLEVEL_STATUS, sub.to_str().unwrap()).as_deref(),
        Some(expected.as_str())
    );
    assert_eq!(
        project(TOPLEVEL_STATUS, r).as_deref(),
        Some(expected.as_str())
    );
    // The root keeps the session's spelling of the working directory.
    let alias = std::env::temp_dir().join(format!(
        "guard-chain-pwd-{}-toplevel-alias",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&alias);
    std::os::unix::fs::symlink(&root, &alias).unwrap();
    let a = alias.to_str().unwrap();
    assert_eq!(
        project(TOPLEVEL_STATUS, &format!("{a}/sub")).as_deref(),
        Some(format!("cd \"{a}\" && git status --short").as_str())
    );
    let _ = std::fs::remove_file(&alias);
}

#[cfg(unix)]
#[test]
fn a_linked_worktree_resolves_through_its_git_file() {
    let main = repository("linked-main");
    let admin = main.join(".git/worktrees/wt");
    std::fs::create_dir_all(&admin).unwrap();
    std::fs::write(admin.join("HEAD"), "ref: refs/heads/wt\n").unwrap();
    std::fs::write(admin.join("commondir"), "../..\n").unwrap();
    let worktree = directory("linked-wt");
    std::fs::write(
        worktree.join(".git"),
        format!("gitdir: {}\n", admin.to_str().unwrap()),
    )
    .unwrap();
    let w = worktree.to_str().unwrap();
    assert_eq!(
        project(TOPLEVEL_STATUS, &format!("{w}/sub")).as_deref(),
        Some(format!("cd \"{w}\" && git status --short").as_str())
    );
    // A shared configuration that sets the worktree moves the root.
    std::fs::write(main.join(".git/config"), "[core]\n\tworktree = /etc\n").unwrap();
    assert_eq!(project(TOPLEVEL_STATUS, w), None);
}

#[cfg(unix)]
#[test]
fn a_git_directory_git_could_read_differently_keeps_the_root_unknown() {
    let configured = repository("configured");
    std::fs::write(
        configured.join(".git/config"),
        "[core]\n\tWorkTree = /etc\n",
    )
    .unwrap();
    let included = repository("included");
    std::fs::write(
        included.join(".git/config"),
        "[include]\n\tpath = /tmp/other\n",
    )
    .unwrap();
    let per_worktree = repository("per-worktree");
    std::fs::write(per_worktree.join(".git/config.worktree"), "").unwrap();
    let headless = repository("headless");
    std::fs::remove_file(headless.join(".git/HEAD")).unwrap();
    let linked = repository("linked-git");
    let target = repository("linked-target");
    std::fs::remove_dir_all(linked.join(".git")).unwrap();
    std::os::unix::fs::symlink(target.join(".git"), linked.join(".git")).unwrap();
    for root in [&configured, &included, &per_worktree, &headless, &linked] {
        let cwd = root.join("sub");
        assert_eq!(
            project(TOPLEVEL_STATUS, cwd.to_str().unwrap()),
            None,
            "{}",
            root.display()
        );
    }
    // Inside the Git directory, or with no `.git` at all, there is no root.
    let inside = repository("inside");
    assert_eq!(
        project(TOPLEVEL_STATUS, inside.join(".git/refs").to_str().unwrap()),
        None
    );
    let plain = directory("no-git");
    assert_eq!(super::repository_root(plain.to_str().unwrap()), None);
}

#[cfg(unix)]
#[test]
fn only_a_plain_cd_holding_the_last_use_may_change_the_directory() {
    let root = repository("cd-rules");
    let sub = root.join("sub");
    let s = sub.to_str().unwrap();
    for command in [
        // A use after the `cd` would read the new directory.
        "cd \"$(git rev-parse --show-toplevel)\" && echo $(pwd)",
        "cd sub && cd \"$(git rev-parse --show-toplevel)\"",
        "ls | cd \"$(git rev-parse --show-toplevel)\" && git status",
        "builtin cd \"$(git rev-parse --show-toplevel)\" && git status",
        "A=1 cd \"$(git rev-parse --show-toplevel)\" && git status",
        "pushd \"$(git rev-parse --show-toplevel)\" && git status",
    ] {
        assert_eq!(project(command, s), None, "{command}");
    }
    assert_eq!(
        project_with(TOPLEVEL_STATUS, s, |command| command
            != "git rev-parse --show-toplevel"),
        None
    );
}
