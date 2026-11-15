use keyalibi::mint::{self, MintInput, Provider, Session};
use secrecy::SecretString;

fn mint(provider: Provider, env: &str, real: &str) -> keyalibi::mint::SecretRecord {
    let session = Session::from_seed([4u8; 32]);
    mint::mint(
        &session,
        MintInput {
            env_var: env.into(),
            aux_env: None,
            provider,
            real: SecretString::from(real.to_string()),
            real_aux: None,
            allowed_hosts: provider
                .default_hosts()
                .iter()
                .map(|h| (*h).to_string())
                .collect(),
            inject: Vec::new(),
        },
    )
    .unwrap()
}

#[test]
fn github_checksum_roundtrip_and_tamper() {
    let record = mint(
        Provider::Github,
        "GITHUB_TOKEN",
        "ghp_nottherealsecret0123456789abcd",
    );
    assert!(
        mint::validate_github_token(&record.phantom),
        "{}",
        record.phantom
    );
    assert_eq!(record.phantom.len(), 40);
    let mut chars: Vec<u8> = record.phantom.into_bytes();
    let idx = chars.len() - 1;
    chars[idx] = if chars[idx] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(chars).unwrap();
    assert!(!mint::validate_github_token(&tampered));

    let secret = "IqIMNOZH6zOwIEB4T9A2g4EHMy8Ji4";
    assert_eq!(mint::github_checksum(secret), "2q4HA5");
    assert!(mint::validate_github_token(&format!("ghp_{secret}2q4HA5")));
    assert!(!mint::validate_github_token(&format!(
        "ghp_{secret}3YCP9K"
    )));
}

#[test]
fn provider_shapes() {
    let stripe = mint(Provider::Stripe, "STRIPE_API_KEY", "sk_live_example");
    assert!(
        mint::validate_phantom(Provider::Stripe, &stripe.phantom),
        "{}",
        stripe.phantom
    );
    assert!(stripe.phantom.starts_with("sk_live_"));
    assert!(stripe.phantom.contains("KEYALIBI"));

    let anthropic = mint(
        Provider::Anthropic,
        "ANTHROPIC_API_KEY",
        "sk-ant-api03-real",
    );
    assert!(
        mint::validate_phantom(Provider::Anthropic, &anthropic.phantom),
        "{}",
        anthropic.phantom
    );
    assert!(anthropic.phantom.starts_with("sk-ant-api03-"));
    assert!(anthropic.phantom.ends_with("AA"));

    let openai = mint(
        Provider::Openai,
        "OPENAI_API_KEY",
        "sk-proj-realopenaikeyvalue",
    );
    assert!(
        mint::validate_phantom(Provider::Openai, &openai.phantom),
        "{}",
        openai.phantom
    );
    assert!(openai.phantom.starts_with("sk-proj-"));
    assert!(openai.phantom.contains("KEYALIBI"));

    let legacy = mint(
        Provider::Openai,
        "OPENAI_API_KEY",
        "sk-reallegacyopenaikeyvalue12",
    );
    assert!(legacy.phantom.starts_with("sk-") && !legacy.phantom.starts_with("sk-proj-"));
    assert!(mint::validate_phantom(Provider::Openai, &legacy.phantom));

    let slack = mint(Provider::Slack, "SLACK_BOT_TOKEN", "xoxb-1-2-real");
    assert!(slack.phantom.starts_with("xoxb-"));
    assert!(mint::validate_phantom(Provider::Slack, &slack.phantom));

    let google = mint(Provider::Google, "GOOGLE_API_KEY", "AIzaRealKeyPlaceholder");
    assert!(google.phantom.starts_with("AIza"));
    assert_eq!(google.phantom.len(), 39);
    assert!(mint::validate_phantom(Provider::Google, &google.phantom));
}

#[test]
fn aws_access_key_and_secret_shape() {
    let session = Session::from_seed([8u8; 32]);
    let record = mint::mint(
        &session,
        MintInput {
            env_var: "AWS_ACCESS_KEY_ID".into(),
            aux_env: Some("AWS_SECRET_ACCESS_KEY".into()),
            provider: Provider::Aws,
            real: SecretString::from("ASIAREALACCESSKEYEX".to_string()),
            real_aux: Some(SecretString::from(
                "realSecret0123456789realSecret0123456789".to_string(),
            )),
            allowed_hosts: vec!["*.amazonaws.com".into()],
            inject: Vec::new(),
        },
    )
    .unwrap();
    assert!(record.phantom.starts_with("ASIA"), "{}", record.phantom);
    assert_eq!(record.phantom.len(), 20);
    assert!(mint::validate_phantom(Provider::Aws, &record.phantom));
    let secret = record.phantom_aux.expect("phantom secret");
    assert_eq!(secret.len(), 40);
    assert_ne!(secret, "realSecret0123456789realSecret0123456789");
}

#[test]
fn same_session_is_deterministic() {
    let a = mint(Provider::Github, "GH_TOKEN", "gho_real");
    let b = mint(Provider::Github, "GH_TOKEN", "gho_real");
    assert_eq!(a.phantom, b.phantom);
    let other = Session::from_seed([5u8; 32]);
    let c = mint::mint(
        &other,
        MintInput {
            env_var: "GH_TOKEN".into(),
            aux_env: None,
            provider: Provider::Github,
            real: SecretString::from("gho_real".to_string()),
            real_aux: None,
            allowed_hosts: vec!["api.github.com".into()],
            inject: Vec::new(),
        },
    )
    .unwrap();
    assert_ne!(a.phantom, c.phantom);
}

#[test]
fn database_urls_are_not_phantom_providers() {
    assert!(mint::detect_provider("DATABASE_URL", "postgres://user:pass@localhost/db").is_none());
    assert!(mint::detect_provider("REDIS_URL", "redis://localhost:6379").is_none());
    assert_eq!(
        mint::detect_provider("OPENAI_API_KEY", "sk-proj-example"),
        Some(Provider::Openai)
    );
}
