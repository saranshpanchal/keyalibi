//! GitHub token shape: 4-char prefix + 36 Base62 characters.
//!
//! The last 6 of those 36 are the IEEE CRC32 of everything before them,
//! encoded as 6 Base62 digits (alphabet `0-9A-Za-z`, most-significant digit
//! first, zero-padded). This matches the checksum scheme GitHub documents for
//! `ghp_`, `gho_`, `ghu_`, `ghs_`, and `ghr_` tokens.

use super::BASE62;
use crc32fast::Hasher;

pub const GITHUB_PREFIXES: &[&str] = &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"];

pub fn github_prefix_of(value: &str) -> Option<&'static str> {
    GITHUB_PREFIXES
        .iter()
        .copied()
        .find(|prefix| value.starts_with(prefix))
}

pub fn github_checksum(body: &str) -> String {
    let mut hasher = Hasher::new();
    hasher.update(body.as_bytes());
    encode_crc(hasher.finalize())
}

pub fn validate_github_token(token: &str) -> bool {
    let Some(prefix) = github_prefix_of(token) else {
        return false;
    };
    let rest = &token[prefix.len()..];
    if rest.len() != 36 || !rest.bytes().all(|b| BASE62.contains(&b)) {
        return false;
    }
    let split = token.len() - 6;
    let (body, sum) = token.split_at(split);
    github_checksum(body) == sum
}

fn encode_crc(mut n: u32) -> String {
    let mut buf = [b'0'; 6];
    for slot in buf.iter_mut().rev() {
        *slot = BASE62[(n % 62) as usize];
        n /= 62;
    }
    // The alphabet is ASCII, so this cannot fail.
    String::from_utf8(buf.to_vec()).expect("base62 alphabet is ascii")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_crc_vectors() {
        let body = format!("ghp_{}", "A".repeat(30));
        assert_eq!(github_checksum(&body), "1yBYBE");
        assert!(validate_github_token(&format!("{body}1yBYBE")));
        assert!(!validate_github_token(&format!("{body}1yBYBF")));

        let body2 = "gho_0123456789ABCDEFGHIJKLMNOPQRST";
        assert_eq!(body2.len(), 34);
        assert_eq!(github_checksum(body2), "4L3uIW");
        assert!(validate_github_token(&format!("{body2}4L3uIW")));
    }
}
