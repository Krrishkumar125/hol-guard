//! Credential locations, the words that name them, and the project files whose
//! names only read like one.

const SENSITIVE_PATHS: [&str; 9] = [
    ".aws/",
    ".ssh/",
    ".docker/",
    ".kube/",
    ".env",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
];

/// Words that name a credential wherever they appear, including inside prose.
const SENSITIVE_WORDS: [&str; 7] = [
    "credential",
    "secret",
    "password",
    "api_key",
    "api-key",
    "token",
    "private_key",
];

/// Extensions of files that hold program text rather than a credential, so a
/// name such as `tokenizer.rs` or `password-reset-email.tsx` reads as source.
const SOURCE_EXTENSIONS: [&str; 26] = [
    "ts", "tsx", "js", "jsx", "mjs", "cjs", "rs", "go", "py", "rb", "java", "kt", "swift", "c",
    "h", "cc", "cpp", "hpp", "cs", "php", "css", "scss", "less", "vue", "svelte", "md",
];

/// A credential location named anywhere in the value, even inside prose.
pub(super) fn sensitive_path(value: &str) -> bool {
    let value = value.to_ascii_lowercase().replace('\\', "/");
    // A dotted read of a port variable (`process.env.PORT`) names no `.env` file.
    let value = crate::environment_secret_dump::without_node_port_reads(&value);
    SENSITIVE_PATHS.iter().any(|needle| value.contains(needle))
}

pub(super) fn sensitive(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    sensitive_path(value)
        || SENSITIVE_WORDS
            .iter()
            .any(|needle| lowered.contains(needle))
}

/// Whether every credential word in `text` comes from a project file the
/// command names, such as `src/tokenizer.ts`. A write to such a file is the
/// edit the agent was asked to make: the name describes what the code is
/// about, and no credential location, variable or prose carries the word.
pub(super) fn only_source_file_names(text: &str, tokens: &[String]) -> bool {
    if !sensitive(text) {
        return true;
    }
    let mut names: Vec<&str> = tokens
        .iter()
        .map(String::as_str)
        .filter(|token| sensitive(token) && source_file_name(token))
        .collect();
    if names.is_empty() {
        return false;
    }
    // A shorter name can sit inside a longer one, so the longest goes first.
    names.sort_unstable_by_key(|name| std::cmp::Reverse(name.len()));
    let mut remainder = text.to_owned();
    for name in names {
        remainder = remainder.replace(name, " ");
    }
    !sensitive(&remainder)
}

/// Whether the word is a project file this workspace holds: a relative path
/// written in ordinary path characters, naming no credential location.
fn source_file_name(word: &str) -> bool {
    if word.is_empty()
        || word.len() > 256
        || word.starts_with('-')
        || word.starts_with('/')
        || word.starts_with('~')
        || word.contains("..")
        || sensitive_path(word)
        || !word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'))
    {
        return false;
    }
    // A bare word could be a credential an argument carries, so the name has
    // to show a directory or the extension of a file holding program text.
    word.contains('/') || source_extension(word)
}

fn source_extension(word: &str) -> bool {
    let Some((stem, extension)) = word.rsplit_once('.') else {
        return false;
    };
    !stem.is_empty()
        && SOURCE_EXTENSIONS
            .iter()
            .any(|known| extension.eq_ignore_ascii_case(known))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    fn only(text: &str) -> bool {
        only_source_file_names(text, &words(text))
    }

    #[test]
    fn a_command_naming_no_credential_word_needs_no_name() {
        assert!(only("cp src/index.ts dist/index.ts"));
    }

    #[test]
    fn source_files_whose_names_read_like_credentials_are_project_files() {
        assert!(only("touch src/auth/token-store.ts"));
        assert!(only("cp src/password-reset-email.tsx dist/"));
        assert!(only("sed -i s/a/b/ crates/parser/src/tokenizer.rs"));
        assert!(only("cp ui/design-tokens.scss build/"));
        assert!(only("mv docs/credentials.md docs/auth.md"));
        assert!(only("cp src/tokens.css src/api-key-form.tsx build/"));
    }

    #[test]
    fn a_directory_path_is_a_project_file_whatever_it_holds() {
        assert!(only("cp app/secrets/readme build/"));
    }

    #[test]
    fn credential_locations_keep_the_word() {
        assert!(!only("cp src/token.ts ~/.ssh/token.ts"));
        assert!(!only("cp src/token.ts ../../.aws/credentials"));
        assert!(!only("echo API_KEY=x > .env"));
        assert!(!only("cp src/token.ts /etc/app/token.ts"));
    }

    #[test]
    fn a_variable_or_literal_keeps_the_word() {
        assert!(!only("echo $GITHUB_TOKEN > src/token.ts"));
        assert!(!only("echo secret123 > src/token.ts"));
        assert!(!only("cp src/token.ts build/ --password=hunter2"));
    }

    #[test]
    fn prose_keeps_the_word() {
        assert!(!only_source_file_names(
            "gh pr comment 1 --body \"credential rotation\" > src/token.ts",
            &[
                "gh".to_owned(),
                "pr".to_owned(),
                "comment".to_owned(),
                "1".to_owned(),
                "--body".to_owned(),
                "credential rotation".to_owned(),
                ">".to_owned(),
                "src/token.ts".to_owned(),
            ],
        ));
    }

    #[test]
    fn a_bare_name_without_a_directory_or_source_extension_keeps_the_word() {
        assert!(!only("cp tokens.json build/tokens.json.bak"));
        assert!(!only("touch secret.txt"));
        assert!(!only("cp mytoken build/"));
    }

    #[test]
    fn a_glob_or_substitution_keeps_the_word() {
        assert!(!only("cp src/*token* build/"));
        assert!(!only("cp src/$NAME/token.ts build/"));
    }
}
