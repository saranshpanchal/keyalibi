//! Session-scoped phantom credentials.
//!
//! Phantoms are deterministic for a `(session seed, env var)` pair so a
//! restarted request inside the same supervisor sees a stable value, and they
//! are shaped so common SDK offline checks accept them. The real secret never
//! leaves [`SecretRecord`], which lives only in the supervisor.

mod github;
mod tokens;

pub use github::{github_checksum, validate_github_token, GITHUB_PREFIXES};
pub use tokens::validate_phantom;

use crate::harden::{mlock_secret, LockedBytes};
use crate::Error;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::SystemTime;

pub const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Provider family. Drives phantom shape, default allowlist, and upstream route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Github,
    Aws,
    Stripe,
    Anthropic,
    Openai,
    Slack,
    Google,
    Generic,
}

impl Provider {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Github => "github",
            Self::Aws => "aws",
            Self::Stripe => "stripe",
            Self::Anthropic => "anthropic",
            Self::Openai => "openai",
            Self::Slack => "slack",
            Self::Google => "google",
            Self::Generic => "generic",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value.trim().to_ascii_lowercase().as_str() {
            "github" | "gh" => Self::Github,
            "aws" => Self::Aws,
            "stripe" => Self::Stripe,
            "anthropic" => Self::Anthropic,
            "openai" => Self::Openai,
            "slack" => Self::Slack,
            "google" | "gemini" => Self::Google,
            "generic" => Self::Generic,
            _ => return None,
        })
    }

    pub fn default_hosts(self) -> &'static [&'static str] {
        match self {
            Self::Github => &["api.github.com", "github.com", "uploads.github.com"],
            Self::Aws => &["*.amazonaws.com", "*.amazonaws.com.cn"],
            Self::Stripe => &["api.stripe.com", "files.stripe.com"],
            Self::Anthropic => &["api.anthropic.com"],
            Self::Openai => &["api.openai.com"],
            Self::Slack => &["slack.com", "*.slack.com", "api.slack.com"],
            Self::Google => &[
                "*.googleapis.com",
                "generativelanguage.googleapis.com",
                "oauth2.googleapis.com",
            ],
            Self::Generic => &[],
        }
    }

    pub fn default_upstream(self) -> &'static str {
        match self {
            Self::Github => "https://api.github.com",
            Self::Aws => "https://sts.amazonaws.com",
            Self::Stripe => "https://api.stripe.com",
            Self::Anthropic => "https://api.anthropic.com",
            Self::Openai => "https://api.openai.com",
            Self::Slack => "https://slack.com",
            Self::Google => "https://generativelanguage.googleapis.com",
            Self::Generic => "https://invalid.keyalibi.local",
        }
    }

    /// Environment variable a typical SDK reads as its base URL.
    pub fn base_url_env(self) -> Option<&'static str> {
        match self {
            Self::Openai => Some("OPENAI_BASE_URL"),
            Self::Anthropic => Some("ANTHROPIC_BASE_URL"),
            Self::Stripe => Some("STRIPE_API_BASE"),
            Self::Github => Some("GITHUB_API_URL"),
            Self::Aws => Some("AWS_ENDPOINT_URL"),
            Self::Slack => Some("SLACK_API_URL"),
            Self::Google => Some("GOOGLE_API_BASE"),
            Self::Generic => None,
        }
    }
}

/// Inputs required to mint one phantom (or an AWS pair).
#[derive(Debug, Clone)]
pub struct MintInput {
    pub env_var: String,
    pub aux_env: Option<String>,
    pub provider: Provider,
    pub real: SecretString,
    pub real_aux: Option<SecretString>,
    pub allowed_hosts: Vec<String>,
}

/// Supervisor-side record. `real` is zeroized on drop and its bytes are mlocked.
pub struct SecretRecord {
    pub env_var: String,
    pub aux_env: Option<String>,
    pub provider: Provider,
    pub phantom: String,
    pub real: SecretString,
    pub phantom_aux: Option<String>,
    pub real_aux: Option<SecretString>,
    pub allowed_hosts: Vec<String>,
    pub mint_time: SystemTime,
}

impl SecretRecord {
    pub fn real_str(&self) -> &str {
        self.real.expose_secret()
    }

    pub fn real_aux_str(&self) -> Option<&str> {
        self.real_aux.as_ref().map(|s| s.expose_secret())
    }
}

/// Entropy source for one `keyalibi run` invocation.
#[derive(Clone)]
pub struct Session {
    seed: [u8; 32],
    pub tag: String,
}

impl Session {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        Self::from_seed(seed)
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        let tag = tokens::encode_alphabet(&seed, BASE62, 6);
        Self { seed, tag }
    }

    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    pub(crate) fn bytes(&self, label: &str, len: usize) -> LockedBytes {
        let mut out = Vec::with_capacity(len);
        let mut counter = 0u32;
        while out.len() < len {
            let mut hasher = Sha256::new();
            hasher.update(self.seed);
            hasher.update(b"|");
            hasher.update(label.as_bytes());
            hasher.update(b"|");
            hasher.update(counter.to_be_bytes());
            out.extend_from_slice(&hasher.finalize());
            counter = counter.wrapping_add(1);
        }
        out.truncate(len);
        LockedBytes::new(out)
    }
}

pub fn mint(session: &Session, input: MintInput) -> crate::Result<SecretRecord> {
    if input.real.expose_secret().is_empty() && input.provider != Provider::Generic {
        return Err(Error::new(format!(
            "{} is empty; refusing to mint a phantom for an empty secret",
            input.env_var
        )));
    }
    mlock_secret(&input.real);
    if let Some(aux) = &input.real_aux {
        mlock_secret(aux);
    }
    let (phantom, phantom_aux) = tokens::mint_value(session, &input);
    tokens::assert_minted(input.provider, &phantom)?;
    if phantom == input.real.expose_secret() {
        return Err(Error::new(format!(
            "refusing to mint {}: phantom collided with the real secret",
            input.env_var
        )));
    }
    Ok(SecretRecord {
        env_var: input.env_var,
        aux_env: input.aux_env,
        provider: input.provider,
        phantom,
        real: input.real,
        phantom_aux,
        real_aux: input.real_aux,
        allowed_hosts: input.allowed_hosts,
        mint_time: SystemTime::now(),
    })
}

/// Classify an env binding. Database URLs are returned as `None` because an
/// HTTP proxy cannot swap Postgres or Redis credentials.
pub fn detect_provider(env_name: &str, value: &str) -> Option<Provider> {
    if is_database_credential(env_name, value) {
        return None;
    }
    let name = env_name.to_ascii_uppercase();
    let value_trim = value.trim();

    if name == "AWS_SECRET_ACCESS_KEY" || name == "AWS_SESSION_TOKEN" {
        return None;
    }
    if name == "AWS_ACCESS_KEY_ID"
        || value_trim.starts_with("AKIA")
        || value_trim.starts_with("ASIA")
    {
        return Some(Provider::Aws);
    }
    if name.contains("ANTHROPIC") || value_trim.starts_with("sk-ant-") {
        return Some(Provider::Anthropic);
    }
    if name.contains("STRIPE")
        || value_trim.starts_with("sk_live_")
        || value_trim.starts_with("sk_test_")
        || value_trim.starts_with("rk_live_")
        || value_trim.starts_with("rk_test_")
    {
        return Some(Provider::Stripe);
    }
    if value_trim.starts_with("ghp_")
        || value_trim.starts_with("gho_")
        || value_trim.starts_with("ghu_")
        || value_trim.starts_with("ghs_")
        || value_trim.starts_with("ghr_")
        || name == "GITHUB_TOKEN"
        || name == "GH_TOKEN"
        || name.contains("GITHUB")
    {
        return Some(Provider::Github);
    }
    if name.contains("OPENAI")
        || value_trim.starts_with("sk-proj-")
        || (value_trim.starts_with("sk-") && !value_trim.starts_with("sk-ant-"))
    {
        return Some(Provider::Openai);
    }
    if name.contains("SLACK")
        || value_trim.starts_with("xoxb-")
        || value_trim.starts_with("xoxp-")
        || value_trim.starts_with("xapp-")
    {
        return Some(Provider::Slack);
    }
    if name.contains("GOOGLE") || name.contains("GEMINI") || value_trim.starts_with("AIza") {
        return Some(Provider::Google);
    }
    if (looks_high_entropy(value_trim)
        || name.contains("API_KEY")
        || name.contains("SECRET")
        || name.contains("TOKEN"))
        && value_trim.len() >= 12
    {
        return Some(Provider::Generic);
    }
    None
}

pub fn is_database_credential(env_name: &str, value: &str) -> bool {
    let name = env_name.to_ascii_uppercase();
    let value = value.trim().to_ascii_lowercase();
    if value.starts_with("postgres://")
        || value.starts_with("postgresql://")
        || value.starts_with("redis://")
        || value.starts_with("rediss://")
        || value.starts_with("mysql://")
        || value.starts_with("mongodb://")
        || value.starts_with("mongodb+srv://")
    {
        return true;
    }
    (name.contains("DATABASE")
        || name.contains("POSTGRES")
        || name.contains("REDIS")
        || name.contains("MYSQL")
        || name.contains("MONGO"))
        && value.contains("://")
}

fn looks_high_entropy(value: &str) -> bool {
    if value.len() < 20 || value.contains(' ') || value.contains('\n') {
        return false;
    }
    let has_alpha = value.chars().any(|c| c.is_ascii_alphabetic());
    let has_digit = value.chars().any(|c| c.is_ascii_digit());
    has_alpha && has_digit
}

pub fn paired_env_for(env_name: &str, provider: Provider) -> Option<&'static str> {
    if provider == Provider::Aws && env_name == "AWS_ACCESS_KEY_ID" {
        Some("AWS_SECRET_ACCESS_KEY")
    } else {
        None
    }
}
