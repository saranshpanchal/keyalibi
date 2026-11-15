//! Command line entry points: `run`, `init`, `verify`, `audit`, and `tui`.

use crate::audit::{format_ts, AuditLog, NewEvent};
use crate::jail::{self, JailPlan, Overlay};
use crate::mint::{self, MintInput, SecretRecord, Session};
use crate::policy::{self, expand_home, rewrite_env_contents, Policy};
use crate::proxy::{self, ProxyConfig, SessionCa, Upstream};
use crate::{Error, Result};
use clap::{Parser, Subcommand};
use secrecy::ExposeSecret;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "keyalibi",
    version,
    about = "Your process has an alibi because the real key was never inside it."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Inject phantom credentials and run a command behind the egress proxy.
    Run {
        /// Policy file. Defaults to ./.keyalibi.toml, or auto-detection when that file is absent.
        #[arg(long, value_name = "FILE")]
        policy: Option<PathBuf>,
        /// Command to execute. Put options for the command after `--`.
        #[arg(trailing_var_arg = true, required = true, allow_hyphen_values = true)]
        cmd: Vec<String>,
    },
    /// Scan env files and write .keyalibi.toml. Secret values are not copied.
    Init {
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Overwrite an existing policy file.
        #[arg(long)]
        force: bool,
    },
    /// Prove phantoms, upstream swap, and exfiltration blocking on localhost.
    Verify,
    /// Print recent audit events.
    Audit {
        #[arg(long)]
        db: Option<PathBuf>,
        #[arg(long, default_value_t = 40)]
        limit: usize,
    },
    /// Live dashboard of injections, swaps, and blocked exfiltrations.
    Tui {
        #[arg(long)]
        db: Option<PathBuf>,
    },
}

pub fn entry() -> Result<i32> {
    match Cli::parse().command {
        Commands::Run { policy, cmd } => cmd_run(policy, cmd),
        Commands::Init { dir, force } => {
            let dir = dir.unwrap_or(std::env::current_dir()?);
            let path = policy::init_workspace(&dir, force)?;
            println!(
                "wrote {} (allowlists only; secret values were not stored)",
                path.display()
            );
            Ok(0)
        }
        Commands::Verify => Ok(crate::verify::run()?),
        Commands::Audit { db, limit } => {
            cmd_audit(db, limit)?;
            Ok(0)
        }
        Commands::Tui { db } => {
            crate::tui::run(&resolve_db(db)?)?;
            Ok(0)
        }
    }
}

fn cmd_run(policy_path: Option<PathBuf>, cmd: Vec<String>) -> Result<i32> {
    let workspace = std::env::current_dir()?;
    let policy = policy::load_policy(policy_path.as_deref(), &workspace)?;
    let loaded = policy::load_secrets(&policy, &workspace)?;
    let session = Session::generate();
    let records = mint_records(&session, loaded)?;
    if records.is_empty() {
        eprintln!(
            "keyalibi: no secret values were found. The command will still run behind the proxy."
        );
    }

    let listener = std::net::TcpListener::bind(&policy.proxy.listen)?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let ca = SessionCa::generate()?;
    let state_dir = workspace.join(".keyalibi");
    let (bundle, ca_only) = ca.write_trust_files(&state_dir)?;
    let audit_path = state_dir.join("audit.db");

    let env = child_environment(&records, addr.port(), &bundle, &ca_only, &session.tag);
    let overlays = env_overlays(&policy, &workspace, &records)?;
    let masks = mask_paths(&policy);
    let command = cmd.join(" ");
    let plan = JailPlan {
        workspace: workspace.clone(),
        argv: cmd,
        env,
        overlays,
        masks,
        capture: false,
    };
    let launch = jail::launch(plan)?;
    let child_pid = launch.pid;

    let config = proxy_config(
        &policy,
        records,
        audit_path.clone(),
        child_pid,
        command.clone(),
        ca,
    )?;
    let state = Arc::new(proxy::ProxyState::from_config(config, addr)?);
    let _ = state.audit.record(NewEvent {
        kind: "jail",
        severity: "info",
        child_pid: Some(child_pid),
        command: command.clone(),
        destination: String::new(),
        env_var: String::new(),
        detail: if launch.namespaced {
            "user and mount namespaces enabled".into()
        } else {
            launch
                .warning
                .clone()
                .unwrap_or_else(|| "filesystem jail unavailable".into())
        },
    });
    for secret in &state.secrets {
        let _ = state.audit.record(NewEvent {
            kind: "mint",
            severity: "info",
            child_pid: Some(child_pid),
            command: command.clone(),
            destination: secret.allowed_hosts.join(","),
            env_var: secret.env_var.clone(),
            detail: format!("{} phantom minted", secret.provider.as_str()),
        });
    }

    let runtime = tokio::runtime::Runtime::new()?;
    let status = runtime.block_on(async move {
        let server = tokio::spawn(proxy::serve_std(listener, Arc::clone(&state)));
        let status = tokio::task::spawn_blocking(move || launch.wait())
            .await
            .map_err(|_| Error::new("child wait panicked"))??;
        server.abort();
        Ok::<_, Error>(status)
    })?;
    Ok(status.code().unwrap_or(1))
}

fn cmd_audit(db: Option<PathBuf>, limit: usize) -> Result<()> {
    let path = resolve_db(db)?;
    if !path.exists() {
        println!("no audit log at {}", path.display());
        return Ok(());
    }
    let log = AuditLog::open(&path)?;
    let counts = log.counts()?;
    println!(
        "mint={} swap={} scrub={} block={} other={}",
        counts.mint, counts.swap, counts.scrub, counts.block, counts.other
    );
    for event in log.recent(limit)? {
        println!(
            "{} {} {:<8} pid={} env={} dest={} {}",
            format_ts(event.ts),
            event.severity,
            event.kind,
            event
                .child_pid
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".into()),
            event.env_var,
            event.destination,
            event.detail
        );
    }
    Ok(())
}

pub fn resolve_db(db: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(db) = db {
        return Ok(db);
    }
    Ok(std::env::current_dir()?.join(".keyalibi").join("audit.db"))
}

pub fn mint_records(
    session: &Session,
    loaded: Vec<policy::LoadedSecret>,
) -> Result<Vec<SecretRecord>> {
    let mut records = Vec::new();
    for item in loaded {
        records.push(mint::mint(
            session,
            MintInput {
                env_var: item.env,
                aux_env: item.aux_env,
                provider: item.provider,
                real: item.value,
                real_aux: item.aux_value,
                allowed_hosts: item.allowed_hosts,
            },
        )?);
    }
    Ok(records)
}

pub fn proxy_config(
    policy: &Policy,
    records: Vec<SecretRecord>,
    audit_path: PathBuf,
    child_pid: i32,
    child_command: String,
    ca: SessionCa,
) -> Result<ProxyConfig> {
    let mut upstreams = HashMap::new();
    for (name, url) in &policy.upstreams {
        upstreams.insert(name.clone(), Upstream::new(url));
    }
    Ok(ProxyConfig {
        secrets: records,
        network: policy.network.clone(),
        cidrs: policy.cidrs()?,
        upstreams,
        audit_path,
        on_exfiltration: policy.on_exfiltration,
        child_pid,
        child_command,
        mitm: policy.proxy.mitm,
        ca,
    })
}

pub fn child_environment(
    records: &[SecretRecord],
    port: u16,
    bundle: &Path,
    ca_only: &Path,
    session_tag: &str,
) -> Vec<(String, String)> {
    let mut map: BTreeMap<String, String> = std::env::vars().collect();
    let reals: Vec<String> = records
        .iter()
        .flat_map(|record| {
            let mut values = Vec::new();
            if record.real_str().len() >= 8 {
                values.push(record.real_str().to_string());
            }
            if let Some(aux) = record.real_aux_str() {
                if aux.len() >= 8 {
                    values.push(aux.to_string());
                }
            }
            values
        })
        .collect();
    for value in map.values_mut() {
        for real in &reals {
            if value.contains(real) {
                *value = value.replace(real, "[redacted]");
            }
        }
    }
    for record in records {
        map.insert(record.env_var.clone(), record.phantom.clone());
        if let (Some(name), Some(phantom)) = (&record.aux_env, &record.phantom_aux) {
            map.insert(name.clone(), phantom.clone());
        }
    }
    let base = format!("http://127.0.0.1:{port}");
    map.insert(
        "OPENAI_BASE_URL".into(),
        format!("{base}/upstream/openai/v1"),
    );
    map.insert(
        "OPENAI_API_BASE".into(),
        format!("{base}/upstream/openai/v1"),
    );
    map.insert(
        "ANTHROPIC_BASE_URL".into(),
        format!("{base}/upstream/anthropic"),
    );
    map.insert("STRIPE_API_BASE".into(), format!("{base}/upstream/stripe"));
    map.insert("GITHUB_API_URL".into(), format!("{base}/upstream/github"));
    map.insert("AWS_ENDPOINT_URL".into(), format!("{base}/upstream/aws"));
    map.insert("SLACK_API_URL".into(), format!("{base}/upstream/slack"));
    map.insert("GOOGLE_API_BASE".into(), format!("{base}/upstream/google"));
    map.insert("GEMINI_API_BASE".into(), format!("{base}/upstream/google"));
    map.insert("HTTP_PROXY".into(), base.clone());
    map.insert("HTTPS_PROXY".into(), base.clone());
    map.insert("http_proxy".into(), base.clone());
    map.insert("https_proxy".into(), base.clone());
    let no_proxy = "localhost,127.0.0.1,::1";
    map.insert("NO_PROXY".into(), no_proxy.into());
    map.insert("no_proxy".into(), no_proxy.into());
    map.insert("NODE_USE_ENV_PROXY".into(), "1".into());
    map.insert("SSL_CERT_FILE".into(), bundle.display().to_string());
    map.insert("REQUESTS_CA_BUNDLE".into(), bundle.display().to_string());
    map.insert("CURL_CA_BUNDLE".into(), bundle.display().to_string());
    map.insert("DENO_CERT".into(), bundle.display().to_string());
    map.insert("CARGO_HTTP_CAINFO".into(), bundle.display().to_string());
    map.insert("NODE_EXTRA_CA_CERTS".into(), ca_only.display().to_string());
    map.insert("KEYALIBI_SESSION".into(), session_tag.into());
    map.insert("KEYALIBI_PROXY".into(), base);
    map.into_iter().collect()
}

pub fn env_overlays(
    policy: &Policy,
    workspace: &Path,
    records: &[SecretRecord],
) -> Result<Vec<Overlay>> {
    let mut replacements = BTreeMap::new();
    for record in records {
        replacements.insert(record.env_var.clone(), record.phantom.clone());
        if let (Some(name), Some(phantom)) = (&record.aux_env, &record.phantom_aux) {
            replacements.insert(name.clone(), phantom.clone());
        }
    }
    let mut overlays = Vec::new();
    for name in &policy.env_files.names {
        let path = workspace.join(name);
        if !path.is_file() {
            continue;
        }
        let text = std::fs::read_to_string(&path)?;
        overlays.push(Overlay {
            target: path,
            contents: rewrite_env_contents(&text, &replacements),
        });
    }
    Ok(overlays)
}

pub fn mask_paths(policy: &Policy) -> Vec<PathBuf> {
    policy
        .mask
        .paths
        .iter()
        .map(|path| expand_home(path))
        .filter(|path| path.is_file())
        .collect()
}

/// Used by tests that need the real value without pulling it into a log.
pub fn real_preview_forbidden(record: &SecretRecord) -> bool {
    record.phantom.contains(record.real.expose_secret())
}
