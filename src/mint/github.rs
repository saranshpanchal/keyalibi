//! GitHub token shape: 4-char prefix + 36 Base62 characters.
//!
//! The last 6 of those 36 are the IEEE CRC32 of the 30-character random part
//! only (the prefix is not included), encoded as 6 Base62 digits (alphabet
//! `0-9A-Za-z`, most-significant digit first, zero-padded). This matches the
//! scheme GitHub published for `ghp_`, `gho_`, `ghu_`, `ghs_`, and `ghr_`
//! tokens. A published sample uses secret `IqIMNOZH6zOwIEB4T9A2g4EHMy8Ji4`
//! and checksum `2q4HA5` (CRC32 `0x9b121895`). The prefix is not part of
//! the checksum; including it produces the different value `3YCP9K`.

use super::BASE62;
use crc32fast::Hasher;

pub const GITHUB_PREFIXES: &[&str] = &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"];

pub fn github_prefix_of(value: &str) -> Option<&'static str> {
    GITHUB_PREFIXES
        .iter()
        .copied()
        .find(|prefix| value.starts_with(prefix))
}

/// CRC32 of the 30-character random secret, not of the `ghp_`-style prefix.
pub fn github_checksum(random_part: &str) -> String {
    let mut hasher = Hasher::new();
    hasher.update(random_part.as_bytes());
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
    let (random, sum) = rest.split_at(30);
    github_checksum(random) == sum
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
        // Public sample from the Kaitai description of GitHub's format.
        // CRC32(secret) == 0x9b121895 == 2q4HA5. Including the prefix yields
        // the different value 3YCP9K, which is not the token's checksum.
        let secret = "IqIMNOZH6zOwIEB4T9A2g4EHMy8Ji4";
        assert_eq!(secret.len(), 30);
        assert_eq!(github_checksum(secret), "2q4HA5");
        let token = format!("ghp_{secret}2q4HA5");
        assert!(validate_github_token(&token));
        let prefix_checksum = format!("ghp_{secret}3YCP9K");
        assert!(!validate_github_token(&prefix_checksum));
        let tampered = format!("ghp_{secret}2q4HA6");
        assert!(!validate_github_token(&tampered));
    }
}
