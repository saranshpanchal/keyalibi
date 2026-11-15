//! Phantom layouts for each provider.
//!
//! Where a public format exists, the phantom follows it (length, alphabet,
//! checksum). A `KEYALIBI` marker is embedded when the alphabet allows it so
//! a human reading a log can see the value is a stand-in. The proxy does not
//! trust the marker: it matches the exact phantom string it minted.

use super::github::{github_checksum, github_prefix_of, validate_github_token};
use super::{MintInput, Provider, Session, BASE62};
use crate::Error;
use secrecy::ExposeSecret;

const MARKER: &str = "KEYALIBI";

pub fn mint_value(session: &Session, input: &MintInput) -> (String, Option<String>) {
    let label = format!("{}:{}", input.env_var, input.provider.as_str());
    let real = input.real.expose_secret();
    match input.provider {
        Provider::Github => (mint_github(session, &label, real), None),
        Provider::Aws => {
            let prefix = if real.starts_with("ASIA") {
                "ASIA"
            } else {
                "AKIA"
            };
            let access = mint_aws_access_key(session, &label, prefix);
            let secret = mint_aws_secret(session, &format!("{label}:secret"));
            (access, Some(secret))
        }
        Provider::Stripe => (mint_stripe(session, &label, real), None),
        Provider::Anthropic => (mint_anthropic(session, &label), None),
        Provider::Openai => (mint_openai(session, &label, real), None),
        Provider::Slack => (mint_slack(session, &label, real), None),
        Provider::Google => (mint_google(session, &label), None),
        Provider::Generic => (mint_generic(session, &label, real), None),
    }
}

pub fn validate_phantom(provider: Provider, token: &str) -> bool {
    match provider {
        Provider::Github => validate_github_token(token),
        Provider::Aws => validate_aws_access_key(token),
        Provider::Stripe => validate_stripe(token),
        Provider::Anthropic => validate_anthropic(token),
        Provider::Openai => validate_openai(token),
        Provider::Slack => validate_slack(token),
        Provider::Google => validate_google(token),
        Provider::Generic => token.starts_with("KEYALIBI_P_") || !token.is_empty(),
    }
}

pub(crate) fn encode_alphabet(bytes: &[u8], alphabet: &[u8], n: usize) -> String {
    let mut out = String::with_capacity(n);
    for (i, _) in (0..n).enumerate() {
        let b = bytes[i % bytes.len()];
        out.push(alphabet[(b as usize) % alphabet.len()] as char);
    }
    out
}

fn take(session: &Session, label: &str, n: usize, alphabet: &[u8]) -> String {
    let bytes = session.bytes(label, n.max(1));
    encode_alphabet(bytes.as_bytes(), alphabet, n)
}

fn mint_github(session: &Session, label: &str, real: &str) -> String {
    let prefix = github_prefix_of(real).unwrap_or("ghp_");
    let body_rand = take(session, label, 30, BASE62);
    // GitHub's CRC32 covers only the 30-character random part, not the prefix.
    let sum = github_checksum(&body_rand);
    format!("{prefix}{body_rand}{sum}")
}

fn mint_aws_access_key(session: &Session, label: &str, prefix: &str) -> String {
    const ALPH: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    format!("{prefix}{}", take(session, label, 16, ALPH))
}

fn mint_aws_secret(session: &Session, label: &str) -> String {
    const ALPH: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    take(session, label, 40, ALPH)
}

fn validate_aws_access_key(token: &str) -> bool {
    let rest = token
        .strip_prefix("AKIA")
        .or_else(|| token.strip_prefix("ASIA"));
    let Some(rest) = rest else {
        return false;
    };
    rest.len() == 16 && rest.bytes().all(|b| matches!(b, b'A'..=b'Z' | b'2'..=b'7'))
}

fn mint_stripe(session: &Session, label: &str, real: &str) -> String {
    let prefix = stripe_prefix(real);
    let left = take(session, &format!("{label}:l"), 12, BASE62);
    let right = take(session, &format!("{label}:r"), 12, BASE62);
    format!("{prefix}{left}{MARKER}{right}")
}

fn stripe_prefix(real: &str) -> &'static str {
    for prefix in ["sk_live_", "sk_test_", "rk_live_", "rk_test_"] {
        if real.starts_with(prefix) {
            return match prefix {
                "sk_live_" => "sk_live_",
                "sk_test_" => "sk_test_",
                "rk_live_" => "rk_live_",
                _ => "rk_test_",
            };
        }
    }
    "sk_test_"
}

fn validate_stripe(token: &str) -> bool {
    let Some(rest) = ["sk_live_", "sk_test_", "rk_live_", "rk_test_"]
        .iter()
        .find_map(|p| token.strip_prefix(p))
    else {
        return false;
    };
    rest.len() >= 24 && rest.contains(MARKER) && rest.bytes().all(|b| BASE62.contains(&b))
}

fn mint_anthropic(session: &Session, label: &str) -> String {
    const ALPH: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
    // 93 characters, with the marker occupying 8 of them, then the literal AA.
    let left = take(session, &format!("{label}:l"), 40, ALPH);
    let right = take(session, &format!("{label}:r"), 45, ALPH);
    debug_assert_eq!(left.len() + MARKER.len() + right.len(), 93);
    format!("sk-ant-api03-{left}{MARKER}{right}AA")
}

fn validate_anthropic(token: &str) -> bool {
    let Some(rest) = token.strip_prefix("sk-ant-api03-") else {
        return false;
    };
    let Some(body) = rest.strip_suffix("AA") else {
        return false;
    };
    body.len() == 93
        && body.contains(MARKER)
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn mint_openai(session: &Session, label: &str, real: &str) -> String {
    if real.starts_with("sk-proj-") || !real.starts_with("sk-") {
        let left = take(session, &format!("{label}:l"), 28, BASE62);
        let right = take(session, &format!("{label}:r"), 28, BASE62);
        format!("sk-proj-{left}{MARKER}{right}")
    } else {
        let left = take(session, &format!("{label}:l"), 20, BASE62);
        let right = take(session, &format!("{label}:r"), 20, BASE62);
        format!("sk-{left}{MARKER}{right}")
    }
}

fn validate_openai(token: &str) -> bool {
    if let Some(rest) = token.strip_prefix("sk-proj-") {
        return rest.len() >= 24
            && rest.contains(MARKER)
            && rest.bytes().all(|b| BASE62.contains(&b));
    }
    if let Some(rest) = token.strip_prefix("sk-") {
        if rest.starts_with("ant-") {
            return false;
        }
        return rest.len() >= 24
            && rest.contains(MARKER)
            && rest.bytes().all(|b| BASE62.contains(&b));
    }
    false
}

fn mint_slack(session: &Session, label: &str, real: &str) -> String {
    let prefix = if real.starts_with("xoxp-") {
        "xoxp-"
    } else if real.starts_with("xapp-") {
        "xapp-"
    } else {
        "xoxb-"
    };
    let tail = take(session, label, 24, BASE62);
    // Marker is base62, so it can sit in the secret segment.
    if prefix == "xapp-" {
        format!("{prefix}1-{tail}{MARKER}")
    } else {
        format!("{prefix}1000000000000-1000000000000-{tail}{MARKER}")
    }
}

fn validate_slack(token: &str) -> bool {
    (token.starts_with("xoxb-") || token.starts_with("xoxp-") || token.starts_with("xapp-"))
        && token.contains(MARKER)
}

fn mint_google(session: &Session, label: &str) -> String {
    const ALPH: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
    // AIza + 35 chars. Marker is 8, so 14 + 8 + 13 = 35.
    let left = take(session, &format!("{label}:l"), 14, ALPH);
    let right = take(session, &format!("{label}:r"), 13, ALPH);
    format!("AIza{left}{MARKER}{right}")
}

fn validate_google(token: &str) -> bool {
    let Some(rest) = token.strip_prefix("AIza") else {
        return false;
    };
    rest.len() == 35
        && rest.contains(MARKER)
        && rest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn mint_generic(session: &Session, label: &str, real: &str) -> String {
    if real.len() >= 16 && charset_preservable(real) {
        return preserve_shape(session, label, real);
    }
    let tail = take(session, label, 24, BASE62);
    format!("KEYALIBI_P_{}_{tail}", session.tag)
}

fn charset_preservable(real: &str) -> bool {
    real.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+' | '/' | '='))
}

fn preserve_shape(session: &Session, label: &str, real: &str) -> String {
    let entropy = session.bytes(label, real.len());
    let bytes = entropy.as_bytes();
    let mut out: Vec<u8> = real
        .bytes()
        .enumerate()
        .map(|(i, b)| map_class(b, bytes[i % bytes.len()]))
        .collect();
    // Overlay the marker when the destination class can hold uppercase letters.
    if real.len() >= MARKER.len() + 4 {
        let start = 2;
        let region = &real.as_bytes()[start..start + MARKER.len()];
        if region.iter().all(|b| b.is_ascii_alphabetic()) {
            out[start..start + MARKER.len()].copy_from_slice(MARKER.as_bytes());
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| format!("KEYALIBI_P_{}", session.tag))
}

fn map_class(original: u8, entropy: u8) -> u8 {
    let alphabet: &[u8] = if original.is_ascii_digit() {
        b"0123456789"
    } else if original.is_ascii_lowercase() {
        b"abcdefghijklmnopqrstuvwxyz"
    } else if original.is_ascii_uppercase() {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    } else {
        return original;
    };
    alphabet[(entropy as usize) % alphabet.len()]
}

pub fn assert_minted(provider: Provider, token: &str) -> crate::Result<()> {
    if validate_phantom(provider, token) {
        Ok(())
    } else {
        Err(Error::new(format!(
            "minted {} phantom failed format validation",
            provider.as_str()
        )))
    }
}
