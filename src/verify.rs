//! `keyalibi verify` runs the three proofs on localhost:
//! the child sees a checksum-valid phantom, an allowlisted upstream receives
//! the real secret, and a phantom sent to any other host is blocked.

use crate::audit::AuditLog;
use crate::cli::{self, child_environment};
use crate::jail::{self, JailPlan, Overlay};
use crate::mint::{self, MintInput, Provider, Session};
use crate::policy::{self, NetworkPolicy, Policy};
use crate::proxy::{self, ProxyConfig, SessionCa, Upstream};
use crate::{Error, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use std::io::Write;

const REAL_OPENAI: &str = "sk-REALSECRETVALUE1234567890ABCDEF";

struct Check {
    name: &'static str,
    status: Status,
    detail: String,
}

enum Status {
    Pass,
    Fail,
    Skip,
}

pub fn run() -> Result<i32> {
    let mut checks = Vec::new();
    match prove() {
        Ok(items) => checks = items,
        Err(err) => checks.push(Check {
            name: "verify",
            status: Status::Fail,
            detail: err.to_string(),
        }),
    }
    let mut failed = false;
    for check in &checks {
        let label = match check.status {
            Status::Pass => "pass",
            Status::Fail => {
                failed = true;
                "fail"
            }
            Status::Skip => "skip",
        };
        println!("[{label}] {}: {}", check.name, check.detail);
    }
    if failed {
        Ok(1)
    } else {
        Ok(0)
    }
}

fn prove() -> Result<Vec<Check>> {
    let mut checks = Vec::new();
    let session = Session::from_seed([9u8; 32]);
    checks.extend(format_checks(&session)?);

    let dir = std::env::temp_dir().join(format!(
        "keyalibi-verify-{}-{}",
        std::process::id(),
        crate::audit::unix_now()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let env_path = dir.join(".env");
    std::fs::write(
        &env_path,
        format!("OPENAI_API_KEY={REAL_OPENAI}\nOTHER=keep\n"),
    )?;

    let policy = Policy {
        network: NetworkPolicy {
            allow_loopback: true,
            ..NetworkPolicy::default()
        },
        secrets: vec![policy::SecretSpec {
            env: "OPENAI_API_KEY".into(),
            provider: Provider::Openai,
            allowed_hosts: vec!["api.openai.com".into()],
            paired_env: None,
            inject: Vec::new(),
        }],
        ..Policy::default()
    };
    // Load from the temp workspace, not the caller's environment.
    let loaded = load_from_file(&policy, &env_path)?;
    let records = cli::mint_records(&session, loaded)?;
    let record = records
        .iter()
        .find(|record| record.env_var == "OPENAI_API_KEY")
        .ok_or_else(|| Error::new("openai secret was not minted"))?;
    let phantom = record.phantom.clone();
    let real = record.real.expose_secret().to_string();
    if phantom == real || phantom.contains(&real) {
        checks.push(fail("child env", "phantom collided with the real secret"));
    } else if !mint::validate_phantom(Provider::Openai, &phantom) {
        checks.push(fail("child env", "phantom failed the OpenAI shape check"));
    } else {
        checks.push(pass(
            "child env",
            "phantom is checksum-shaped and does not contain the real secret",
        ));
    }

    let ca = SessionCa::generate()?;
    let (bundle, ca_only) = ca.write_trust_files(&dir.join("state"))?;
    let env = child_environment(&records, 9, &bundle, &ca_only, &session.tag);
    let captured = jail::capture(JailPlan {
        workspace: dir.clone(),
        argv: vec!["/bin/cat".into(), ".env".into()],
        env: env.clone(),
        overlays: vec![Overlay {
            target: env_path.clone(),
            contents: format!("OPENAI_API_KEY={phantom}\nOTHER=keep\n"),
        }],
        masks: Vec::new(),
        capture: true,
    })?;
    let host_after = std::fs::read_to_string(&env_path)?;
    if host_after.contains(&real) && !host_after.contains(&phantom) {
        checks.push(pass(
            "host .env",
            "original file still holds the real secret",
        ));
    } else {
        checks.push(fail("host .env", "host file was modified"));
    }
    if captured.namespaced {
        let stdout = String::from_utf8_lossy(&captured.stdout);
        if stdout.contains(&phantom) && !stdout.contains(&real) && stdout.contains("OTHER=keep") {
            checks.push(pass(
                "cat .env",
                "namespaced child read the phantom overlay",
            ));
        } else {
            checks.push(fail(
                "cat .env",
                format!(
                    "unexpected overlay output: {}",
                    String::from_utf8_lossy(&captured.stderr)
                ),
            ));
        }
    } else {
        checks.push(Check {
            name: "cat .env",
            status: Status::Skip,
            detail: captured
                .warning
                .unwrap_or_else(|| "user namespaces unavailable".into()),
        });
    }

    let child_view = env_value(&env, "OPENAI_API_KEY");
    if child_view.as_deref() == Some(phantom.as_str()) {
        checks.push(pass(
            "env injection",
            "child environment carries the phantom",
        ));
    } else {
        checks.push(fail(
            "env injection",
            "child environment did not carry the phantom",
        ));
    }

    let runtime = tokio::runtime::Runtime::new()?;
    let net = runtime.block_on(network_checks(
        &policy,
        records,
        phantom.clone(),
        real.clone(),
        ca,
    ))?;
    checks.extend(net);

    let _ = std::fs::remove_dir_all(&dir);
    let _ = Write::flush(&mut std::io::stdout());
    Ok(checks)
}

fn network_checks(
    policy: &Policy,
    records: Vec<SecretRecordOwned>,
    phantom: String,
    real: String,
    ca: SessionCa,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<Check>>> + Send>> {
    let policy = policy.clone();
    Box::pin(async move {
        let mut checks = Vec::new();
        let (mock_addr, seen) = spawn_echo().await?;
        let mut upstreams = HashMap::new();
        upstreams.insert(
            "openai".into(),
            Upstream::new(format!("http://{mock_addr}")).with_allow_as("api.openai.com"),
        );
        upstreams.insert(
            "stripe".into(),
            Upstream::new(format!("http://{mock_addr}")).with_allow_as("evil.example"),
        );
        let audit_path = std::env::temp_dir().join(format!(
            "keyalibi-verify-audit-{}-{}.db",
            std::process::id(),
            crate::audit::unix_now()
        ));
        let _ = std::fs::remove_file(&audit_path);
        let network = NetworkPolicy {
            allow_loopback: true,
            ..policy.network.clone()
        };
        let config = ProxyConfig {
            secrets: records,
            network,
            cidrs: Vec::new(),
            upstreams,
            audit_path: audit_path.clone(),
            on_exfiltration: policy::ExfilAction::None,
            child_pid: 0,
            child_command: "keyalibi verify".into(),
            mitm: false,
            ca,
        };
        let proxy = proxy::spawn(config, audit_path.clone()).await?;
        let allowed = proxy_exchange(
            proxy.addr,
            "POST",
            "/upstream/openai/v1/chat",
            &[("authorization", &format!("Bearer {phantom}"))],
            format!("{{\"api_key\":\"{phantom}\"}}"),
        )
        .await?;
        let status = allowed.0;
        let text = allowed.1;
        let recorded = seen
            .lock()
            .map_err(|_| Error::new("mock lock poisoned"))?
            .clone();
        let auth_swapped = recorded.iter().any(|hit| {
            let mut lines = hit.splitn(3, '\n');
            let _path = lines.next();
            let auth = lines.next().unwrap_or("");
            auth.contains(&real) && !auth.contains(&phantom)
        });
        let body_kept = recorded.iter().any(|hit| {
            let mut lines = hit.splitn(3, '\n');
            let _path = lines.next();
            let _auth = lines.next();
            let body = lines.next().unwrap_or("");
            body.contains(&phantom) && !body.contains(&real)
        });
        if status.is_success()
            && auth_swapped
            && body_kept
            && text.contains(&phantom)
            && !text.contains(&real)
        {
            checks.push(pass(
                "upstream swap",
                "credential header was swapped; the body kept the phantom; the client saw no real secret",
            ));
        } else {
            checks.push(fail(
                "upstream swap",
                format!(
                    "status={status} client_has_real={} mock_has_real={}",
                    text.contains(&real),
                    recorded.iter().any(|h| h.contains(&real))
                ),
            ));
        }
        let before = seen
            .lock()
            .map_err(|_| Error::new("mock lock poisoned"))?
            .len();
        let blocked = proxy_exchange(
            proxy.addr,
            "POST",
            "/upstream/stripe/v1/charges",
            &[("authorization", &format!("Bearer {phantom}"))],
            phantom.clone(),
        )
        .await?;
        let blocked_status = blocked.0.as_u16();
        let blocked_body = blocked.1;
        let encoded = STANDARD.encode(phantom.as_bytes());
        let blocked_b64 = proxy_exchange(
            proxy.addr,
            "POST",
            "/upstream/stripe/v1/charges",
            &[],
            encoded,
        )
        .await?;
        let b64_status = blocked_b64.0.as_u16();
        let b64_body = blocked_b64.1;
        let after = seen
            .lock()
            .map_err(|_| Error::new("mock lock poisoned"))?
            .len();
        if blocked_status == 451
            && blocked_body.contains("Exfiltration Blocked by KeyAlibi")
            && b64_status == 451
            && b64_body.contains("Exfiltration Blocked by KeyAlibi")
            && after == before
        {
            checks.push(pass(
                "exfiltration block",
                "raw and base64 phantoms to a non-allowlisted host returned 451",
            ));
        } else {
            checks.push(fail(
                "exfiltration block",
                format!(
                    "raw={blocked_status} b64={b64_status} forwarded={}",
                    after != before
                ),
            ));
        }
        let log = AuditLog::open(&audit_path)?;
        let recent = log.recent(20)?;
        if recent
            .iter()
            .any(|event| event.kind == "block" && event.severity == "critical")
        {
            checks.push(pass("audit", "critical block event was recorded"));
        } else {
            checks.push(fail("audit", "no critical block event"));
        }
        drop(proxy);
        let _ = std::fs::remove_file(&audit_path);
        Ok(checks)
    })
}

type SecretRecordOwned = crate::mint::SecretRecord;

async fn proxy_exchange(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: String,
) -> Result<(http::StatusCode, String)> {
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|err| Error::new(err.to_string()))?;
    let io = TokioIo::new(stream);
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|err| Error::new(err.to_string()))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut builder = http::Request::builder().method(method).uri(path);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder
        .body(Full::new(Bytes::from(body)))
        .map_err(|err| Error::new(err.to_string()))?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|err| Error::new(err.to_string()))?;
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .map_err(|err| Error::new(err.to_string()))?
        .to_bytes();
    Ok((status, String::from_utf8_lossy(&bytes).into_owned()))
}

async fn spawn_echo() -> Result<(
    std::net::SocketAddr,
    std::sync::Arc<std::sync::Mutex<Vec<String>>>,
)> {
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full, StreamBody};
    use hyper::body::Frame;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen_task = std::sync::Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let seen_task = std::sync::Arc::clone(&seen_task);
            tokio::spawn(async move {
                let service = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let seen_task = std::sync::Arc::clone(&seen_task);
                    async move {
                        let auth = req
                            .headers()
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_string();
                        let path = req.uri().to_string();
                        let collected = req.into_body().collect().await;
                        let body = collected
                            .map(|c| String::from_utf8_lossy(&c.to_bytes()).into_owned())
                            .unwrap_or_default();
                        if let Ok(mut guard) = seen_task.lock() {
                            guard.push(format!("{path}\n{auth}\n{body}"));
                        }
                        let echo = format!("AUTH={auth}\nBODY={body}\n");
                        let mid = echo.len() / 2;
                        let first = echo[..mid].to_string();
                        let second = echo[mid..].to_string();
                        let stream = futures_util::stream::iter(vec![
                            Ok::<_, Infallible>(Frame::data(Bytes::from(first))),
                            Ok(Frame::data(Bytes::from(second))),
                        ]);
                        let mut response =
                            hyper::Response::new(BodyExt::boxed(StreamBody::new(stream)));
                        response.headers_mut().insert(
                            "x-echo",
                            hyper::header::HeaderValue::from_str(&auth)
                                .unwrap_or(hyper::header::HeaderValue::from_static("")),
                        );
                        let _ = Full::<Bytes>::new(Bytes::new());
                        Ok::<_, Infallible>(response)
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    Ok((addr, seen))
}

fn load_from_file(
    policy: &Policy,
    env_path: &std::path::Path,
) -> Result<Vec<policy::LoadedSecret>> {
    let pairs = policy::read_env_pairs(env_path)?;
    let mut loaded = Vec::new();
    for spec in &policy.secrets {
        if let Some((_, value)) = pairs.iter().find(|(key, _)| key == &spec.env) {
            loaded.push(policy::LoadedSecret {
                env: spec.env.clone(),
                provider: spec.provider,
                value: SecretString::from(value.clone()),
                aux_env: spec.paired_env.clone(),
                aux_value: None,
                allowed_hosts: spec.allowed_hosts.clone(),
                inject: spec.inject.clone(),
            });
        }
    }
    let _ = NetworkPolicy::default();
    Ok(loaded)
}

fn env_value(env: &[(String, String)], key: &str) -> Option<String> {
    env.iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.clone())
}

fn format_checks(session: &Session) -> Result<Vec<Check>> {
    let mut checks = Vec::new();
    let samples = [
        (
            Provider::Github,
            "GITHUB_TOKEN",
            "ghp_realsecretvalueplaceholder1",
        ),
        (Provider::Stripe, "STRIPE_API_KEY", "sk_live_example"),
        (
            Provider::Anthropic,
            "ANTHROPIC_API_KEY",
            "sk-ant-api03-realplaceholder",
        ),
        (Provider::Openai, "OPENAI_API_KEY", REAL_OPENAI),
        (Provider::Slack, "SLACK_BOT_TOKEN", "xoxb-real"),
        (
            Provider::Google,
            "GOOGLE_API_KEY",
            "AIzaRealPlaceholderValue",
        ),
    ];
    for (provider, env, real) in samples {
        let record = mint::mint(
            session,
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
        )?;
        if mint::validate_phantom(provider, &record.phantom) && record.phantom != real {
            checks.push(pass(
                provider.as_str(),
                "phantom matches the provider shape",
            ));
        } else {
            checks.push(fail(provider.as_str(), "phantom failed shape validation"));
        }
    }
    let aws = mint::mint(
        session,
        MintInput {
            env_var: "AWS_ACCESS_KEY_ID".into(),
            aux_env: Some("AWS_SECRET_ACCESS_KEY".into()),
            provider: Provider::Aws,
            real: SecretString::from("AKIAREALACCESSKEYEX".to_string()),
            real_aux: Some(SecretString::from(
                "realAwsSecretValue0123456789abcdefghij".to_string(),
            )),
            allowed_hosts: vec!["*.amazonaws.com".into()],
            inject: Vec::new(),
        },
    )?;
    let access_ok = mint::validate_phantom(Provider::Aws, &aws.phantom);
    let secret_ok = aws
        .phantom_aux
        .as_ref()
        .map(|s| s.len() == 40)
        .unwrap_or(false);
    if access_ok && secret_ok {
        checks.push(pass(
            "aws",
            "access key shape and 40-character phantom secret",
        ));
    } else {
        checks.push(fail("aws", "aws phantom failed shape validation"));
    }
    Ok(checks)
}

fn pass(name: &'static str, detail: impl Into<String>) -> Check {
    Check {
        name,
        status: Status::Pass,
        detail: detail.into(),
    }
}

fn fail(name: &'static str, detail: impl Into<String>) -> Check {
    Check {
        name,
        status: Status::Fail,
        detail: detail.into(),
    }
}
