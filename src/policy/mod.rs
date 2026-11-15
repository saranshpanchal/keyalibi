//! `.keyalibi.toml` policy: which env vars are secrets, which hosts may
//! receive the real value, and which credential files the jail masks.

use crate::mint::{self, Provider};
use crate::{Error, Result};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

pub const POLICY_FILENAME: &str = ".keyalibi.toml";

pub const DEFAULT_ENV_FILES: &[&str] = &[
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".env.test",
];

pub const DEFAULT_MASKS: &[&str] = &[
    "~/.aws/credentials",
    "~/.aws/config",
    "~/.config/gh/hosts.yml",
    "~/.npmrc",
    "~/.pypirc",
    "~/.netrc",
    "~/.docker/config.json",
    "~/.kube/config",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExfilAction {
    None,
    Sigstop,
    Sigkill,
}

impl Default for ExfilAction {
    fn default() -> Self {
        Self::None
    }
}

impl ExfilAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Sigstop => "sigstop",
            Self::Sigkill => "sigkill",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkPolicy {
    #[serde(default)]
    pub allow_loopback: bool,
    #[serde(default)]
    pub allow_private: bool,
    #[serde(default)]
    pub allow_link_local: bool,
    #[serde(default)]
    pub allow_cidrs: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl Cidr {
    pub fn parse(value: &str) -> Result<Self> {
        let (addr, prefix) = value
            .split_once('/')
            .ok_or_else(|| Error::new(format!("cidr `{value}` needs a /prefix")))?;
        let addr: IpAddr = addr
            .parse()
            .map_err(|_| Error::new(format!("cidr `{value}` has a bad address")))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| Error::new(format!("cidr `{value}` has a bad prefix")))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(Error::new(format!("cidr `{value}` prefix is too large")));
        }
        Ok(Self { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let net = u128::from(net);
                let ip = u128::from(ip);
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                (net & mask) == (ip & mask)
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxySection {
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default = "default_true")]
    pub mitm: bool,
}

fn default_listen() -> String {
    "127.0.0.1:0".to_string()
}

fn default_true() -> bool {
    true
}

impl Default for ProxySection {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            mitm: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretSpec {
    pub env: String,
    pub provider: Provider,
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    #[serde(default)]
    pub paired_env: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MaskSection {
    #[serde(default = "default_masks")]
    pub paths: Vec<String>,
}

fn default_masks() -> Vec<String> {
    DEFAULT_MASKS.iter().map(|s| (*s).to_string()).collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvFileSection {
    #[serde(default = "default_env_files")]
    pub names: Vec<String>,
}

fn default_env_files() -> Vec<String> {
    DEFAULT_ENV_FILES.iter().map(|s| (*s).to_string()).collect()
}

impl Default for EnvFileSection {
    fn default() -> Self {
        Self {
            names: default_env_files(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub on_exfiltration: ExfilAction,
    #[serde(default)]
    pub network: NetworkPolicy,
    #[serde(default)]
    pub proxy: ProxySection,
    #[serde(default)]
    pub upstreams: BTreeMap<String, String>,
    #[serde(default)]
    pub secrets: Vec<SecretSpec>,
    #[serde(default)]
    pub mask: MaskSection,
    #[serde(default)]
    pub env_files: EnvFileSection,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            on_exfiltration: ExfilAction::None,
            network: NetworkPolicy::default(),
            proxy: ProxySection::default(),
            upstreams: default_upstream_map(),
            secrets: Vec::new(),
            mask: MaskSection::default(),
            env_files: EnvFileSection::default(),
        }
    }
}

impl Policy {
    pub fn cidrs(&self) -> Result<Vec<Cidr>> {
        self.network
            .allow_cidrs
            .iter()
            .map(|c| Cidr::parse(c))
            .collect()
    }
}

pub fn default_upstream_map() -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for provider in [
        Provider::Openai,
        Provider::Anthropic,
        Provider::Stripe,
        Provider::Github,
        Provider::Aws,
        Provider::Slack,
        Provider::Google,
    ] {
        map.insert(
            provider.as_str().to_string(),
            provider.default_upstream().to_string(),
        );
    }
    map
}

pub fn host_allowed(host: &str, patterns: &[String]) -> bool {
    let host = normalize_host(host);
    patterns.iter().any(|pattern| {
        let pattern = normalize_host(pattern);
        if let Some(suffix) = pattern.strip_prefix("*.") {
            host.ends_with(&format!(".{suffix}"))
        } else {
            host == pattern
        }
    })
}

pub fn normalize_host(host: &str) -> String {
    let mut host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        host = inner.to_string();
    }
    if let Some((name, port)) = host.rsplit_once(':') {
        if !name.contains(':') && port.chars().all(|c| c.is_ascii_digit()) {
            return name.trim_end_matches('.').to_string();
        }
    }
    host
}

/// A secret value discovered in the environment or an env file.
#[derive(Clone)]
pub struct LoadedSecret {
    pub env: String,
    pub provider: Provider,
    pub value: SecretString,
    pub aux_env: Option<String>,
    pub aux_value: Option<SecretString>,
    pub allowed_hosts: Vec<String>,
}

pub fn load_policy(explicit: Option<&Path>, workspace: &Path) -> Result<Policy> {
    if let Some(path) = explicit {
        return read_policy(path);
    }
    let discovered = workspace.join(POLICY_FILENAME);
    if discovered.is_file() {
        return read_policy(&discovered);
    }
    Ok(discover_policy(workspace))
}

pub fn read_policy(path: &Path) -> Result<Policy> {
    let text = fs::read_to_string(path)
        .map_err(|e| Error::new(format!("reading {}: {e}", path.display())))?;
    let mut policy: Policy = toml::from_str(&text)?;
    if policy.upstreams.is_empty() {
        policy.upstreams = default_upstream_map();
    } else {
        for (key, value) in default_upstream_map() {
            policy.upstreams.entry(key).or_insert(value);
        }
    }
    for spec in &mut policy.secrets {
        if spec.allowed_hosts.is_empty() {
            spec.allowed_hosts = spec
                .provider
                .default_hosts()
                .iter()
                .map(|h| (*h).to_string())
                .collect();
        }
        if spec.paired_env.is_none() {
            spec.paired_env = mint::paired_env_for(&spec.env, spec.provider).map(str::to_string);
        }
    }
    // Validate CIDRs early.
    let _ = policy.cidrs()?;
    Ok(policy)
}

pub fn discover_policy(workspace: &Path) -> Policy {
    Policy {
        secrets: detect_specs(workspace),
        ..Policy::default()
    }
}

pub fn init_workspace(workspace: &Path, force: bool) -> Result<PathBuf> {
    let dest = workspace.join(POLICY_FILENAME);
    if dest.exists() && !force {
        return Err(Error::new(format!(
            "{} already exists (pass --force to overwrite). Real secrets were not written.",
            dest.display()
        )));
    }
    let policy = Policy {
        secrets: detect_specs(workspace),
        ..Policy::default()
    };
    write_policy(&dest, &policy)?;
    Ok(dest)
}

pub fn write_policy(path: &Path, policy: &Policy) -> Result<()> {
    let body = toml::to_string_pretty(policy)?;
    let text = format!(
        "# KeyAlibi policy. Real secret values are never stored in this file.\n\
         # Host allowlists name who may receive the real credential.\n\
         # Database URLs are omitted on purpose: HTTP proxying cannot swap them.\n\n\
         {body}"
    );
    fs::write(path, text)?;
    Ok(())
}

fn detect_specs(workspace: &Path) -> Vec<SecretSpec> {
    let mut values: BTreeMap<String, String> = BTreeMap::new();
    for name in DEFAULT_ENV_FILES
        .iter()
        .copied()
        .chain([".env.example", ".env.sample"])
    {
        let path = workspace.join(name);
        if let Ok(pairs) = read_env_pairs(&path) {
            for (k, v) in pairs {
                values.entry(k).or_insert(v);
            }
        }
    }
    for (k, v) in std::env::vars() {
        values.entry(k).or_insert(v);
    }

    let mut specs = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for (key, value) in &values {
        if key == "AWS_SECRET_ACCESS_KEY" || key == "AWS_SESSION_TOKEN" {
            continue;
        }
        let Some(provider) = mint::detect_provider(key, value) else {
            continue;
        };
        if !seen.insert(key.clone()) {
            continue;
        }
        let hosts = provider
            .default_hosts()
            .iter()
            .map(|h| (*h).to_string())
            .collect();
        specs.push(SecretSpec {
            env: key.clone(),
            provider,
            allowed_hosts: hosts,
            paired_env: mint::paired_env_for(key, provider).map(str::to_string),
        });
    }
    specs
}

pub fn load_secrets(policy: &Policy, workspace: &Path) -> Result<Vec<LoadedSecret>> {
    let mut file_values: BTreeMap<String, String> = BTreeMap::new();
    for name in &policy.env_files.names {
        let path = workspace.join(name);
        if let Ok(pairs) = read_env_pairs(&path) {
            for (k, v) in pairs {
                // Earlier files win over later ones; the process environment wins overall.
                file_values.entry(k).or_insert(v);
            }
        }
    }
    let mut loaded = Vec::new();
    for spec in &policy.secrets {
        let Some(value) = lookup_value(&spec.env, &file_values) else {
            eprintln!(
                "keyalibi: {} is listed in the policy but has no value in the environment or env files; skipping",
                spec.env
            );
            continue;
        };
        if value.is_empty() {
            eprintln!("keyalibi: {} is empty; skipping", spec.env);
            continue;
        }
        if mint::is_database_credential(&spec.env, &value) {
            eprintln!(
                "keyalibi: {} looks like a database URL. It was left untouched; an HTTP proxy cannot swap it.",
                spec.env
            );
            continue;
        }
        let (aux_env, aux_value) = if let Some(paired) = &spec.paired_env {
            match lookup_value(paired, &file_values) {
                Some(v) if !v.is_empty() => (Some(paired.clone()), Some(SecretString::from(v))),
                _ => {
                    eprintln!(
                        "keyalibi: {} is paired with {paired}, which has no value; the access key will still be minted",
                        spec.env
                    );
                    (Some(paired.clone()), None)
                }
            }
        } else {
            (None, None)
        };
        let hosts = if spec.allowed_hosts.is_empty() {
            spec.provider
                .default_hosts()
                .iter()
                .map(|h| (*h).to_string())
                .collect()
        } else {
            spec.allowed_hosts.clone()
        };
        loaded.push(LoadedSecret {
            env: spec.env.clone(),
            provider: spec.provider,
            value: SecretString::from(value),
            aux_env,
            aux_value,
            allowed_hosts: hosts,
        });
    }
    Ok(loaded)
}

fn lookup_value(key: &str, file_values: &BTreeMap<String, String>) -> Option<String> {
    if let Ok(v) = std::env::var(key) {
        if !v.is_empty() {
            return Some(v);
        }
    }
    file_values.get(key).cloned()
}

pub fn read_env_pairs(path: &Path) -> Result<Vec<(String, String)>> {
    if !path.is_file() {
        return Err(Error::new(format!("{} is not a file", path.display())));
    }
    let mut out = Vec::new();
    let iter = dotenvy::from_path_iter(path).map_err(|e| Error::new(e.to_string()))?;
    for item in iter {
        let (k, v) = item.map_err(|e| Error::new(e.to_string()))?;
        out.push((k, v));
    }
    Ok(out)
}

/// Rewrite env-file text so listed keys carry phantom values. Comments and
/// unrelated keys are preserved. The real value is not copied through.
pub fn rewrite_env_contents(contents: &str, replacements: &BTreeMap<String, String>) -> String {
    let mut out = String::with_capacity(contents.len());
    for line in contents.split_inclusive('\n') {
        out.push_str(&rewrite_env_line(line, replacements));
    }
    out
}

fn rewrite_env_line(line: &str, replacements: &BTreeMap<String, String>) -> String {
    let (newline, body) = if let Some(rest) = line.strip_suffix('\n') {
        ("\n", rest)
    } else {
        ("", line)
    };
    let trimmed = body.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return line.to_string();
    }
    let export = trimmed.strip_prefix("export ").unwrap_or(trimmed);
    let Some((key, _)) = export.split_once('=') else {
        return line.to_string();
    };
    let key = key.trim();
    let Some(value) = replacements.get(key) else {
        return line.to_string();
    };
    let indent_len = body.len() - body.trim_start().len();
    let indent = &body[..indent_len];
    let prefix = if trimmed.starts_with("export ") {
        "export "
    } else {
        ""
    };
    format!("{indent}{prefix}{key}={}{newline}", format_env_value(value))
}

fn format_env_value(value: &str) -> String {
    if value
        .chars()
        .any(|c| c.is_whitespace() || matches!(c, '#' | '"' | '\''))
    {
        let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"{escaped}\"")
    } else {
        value.to_string()
    }
}

pub fn expand_home(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_hosts() {
        let hosts = vec!["*.amazonaws.com".to_string(), "api.openai.com".to_string()];
        assert!(host_allowed("s3.us-east-1.amazonaws.com", &hosts));
        assert!(host_allowed("API.OpenAI.com.", &hosts));
        assert!(!host_allowed("amazonaws.com", &hosts));
        assert!(!host_allowed("evilamazonaws.com", &hosts));
        assert!(!host_allowed("amazonaws.com.evil.com", &hosts));
    }

    #[test]
    fn cidr_contains_loopback_only_when_asked() {
        let cidr = Cidr::parse("127.0.0.0/8").unwrap();
        assert!(cidr.contains("127.0.0.1".parse().unwrap()));
        assert!(!cidr.contains("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn rewrite_replaces_only_listed_keys() {
        let mut map = BTreeMap::new();
        map.insert("OPENAI_API_KEY".to_string(), "sk-phantom".to_string());
        let text = "\
# comment\n\
OPENAI_API_KEY=sk-real\n\
export OTHER=keep\n";
        let out = rewrite_env_contents(text, &map);
        assert!(out.contains("OPENAI_API_KEY=sk-phantom\n"));
        assert!(out.contains("export OTHER=keep\n"));
        assert!(out.contains("# comment\n"));
        assert!(!out.contains("sk-real"));
    }
}
