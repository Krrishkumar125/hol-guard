//! A URL's password slot that holds no password.
//!
//! `scheme://user:password@host` puts a real credential in front of an agent
//! when `git remote -v`, `.git/config` or a sync script prints it. Templates
//! and docs fill the same slot with a substitution (`${TOKEN}`, `{password}`,
//! `%s`), a mask (`***`) or the slot's own name (`user:password@`), and none of
//! those reveal anything.

use crate::masked_value;

const SLOT_NAMES: &[&str] = &[
    "password", "passwd", "pass", "pwd", "pw", "secret", "token", "apikey", "api_key", "api-key",
];

/// Whether the password in a `url-credential` match is a stand-in.
pub(crate) fn is_placeholder(matched: &str) -> bool {
    let Some(password) = password(matched) else {
        return false;
    };
    password.starts_with(['$', '{', '%', '('])
        || password
            .chars()
            .all(|character| matches!(character, '*' | '•' | '●' | 'x' | 'X'))
        || masked_value::is_masked(password)
        || SLOT_NAMES
            .iter()
            .any(|name| password.eq_ignore_ascii_case(name))
}

fn password(matched: &str) -> Option<&str> {
    let (_, rest) = matched.split_once("://")?;
    let userinfo = &rest[..rest.rfind('@')?];
    let (_, password) = userinfo.split_once(':')?;
    Some(password)
}

#[cfg(test)]
mod tests {
    use crate::scan_text;
    use guard_rules::MAX_SCAN_BYTES;

    fn url_credential(text: &str) -> bool {
        scan_text(text, true, true, MAX_SCAN_BYTES, None)
            .matches
            .iter()
            .any(|matched| matched.classifier == "url-credential")
    }

    fn password() -> String {
        ["Kq7Xr2", "mWp9Lq4z"].concat()
    }

    #[test]
    fn a_password_in_a_url_is_a_credential() {
        let password = password();
        for text in [
            format!("origin\thttps://alice:{password}@git.lan/alice/notes.git (push)"),
            format!("\turl = https://alice:{password}@git.lan/alice/notes.git"),
            format!("DATABASE_URL=postgres://app:{password}@db.lan:5432/app"),
            format!("sync.sh:12:git push https://alice:{password}@git.lan/alice/notes.git"),
            format!("redis://:{password}@cache.lan:6379/0"),
        ] {
            assert!(url_credential(&text), "{text:?}");
        }
    }

    #[test]
    fn a_url_without_a_password_is_not_a_credential() {
        for text in [
            "git@github.com:org/repo.git",
            "ssh://git@git.lan:22/alice/notes.git",
            "https://alice@git.lan/alice/notes.git",
            "http://[::1]:8080/health",
            "http://localhost:8080/path?next=a@b",
            "https://user:@git.lan/repo.git",
        ] {
            assert!(!url_credential(text), "{text:?}");
        }
    }

    #[test]
    fn a_stand_in_password_is_not_a_credential() {
        for text in [
            "https://alice:${GITEA_TOKEN}@git.lan/alice/notes.git",
            "https://alice:$GITEA_TOKEN@git.lan/alice/notes.git",
            "f\"postgres://{user}:{password}@{host}/app\"",
            "\"https://%s:%s@%s\" % (user, token, host)",
            "https://alice:***@git.lan/alice/notes.git",
            "https://alice:xxxxxxxx@git.lan/alice/notes.git",
            "https://username:password@git.lan/repo.git",
            "https://oauth2:TOKEN@gitlab.lan/group/repo.git",
            "https://<user>:<token>@git.lan/repo.git",
        ] {
            assert!(!url_credential(text), "{text:?}");
        }
    }
}
