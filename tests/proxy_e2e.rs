use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use keyalibi::audit::AuditLog;
use keyalibi::mint::{self, MintInput, Provider, Session};
use keyalibi::policy::{ExfilAction, NetworkPolicy};
use keyalibi::proxy::{self, ProxyConfig, SessionCa, Upstream};
use secrecy::SecretString;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const REAL: &str = "sk-REALSECRETVALUE1234567890ABCDEF";

#[tokio::test]
async fn swaps_on_allowlisted_host_and_scrubs_the_response() {
    let (phantom, proxy, seen, audit_path) = harness().await;
    let response = exchange(
        proxy.addr,
        "POST",
        "/upstream/openai/v1/chat",
        &[
            ("authorization", format!("Bearer {phantom}")),
            ("x-extra", phantom.clone()),
        ],
        format!("{{\"k\":\"{phantom}\"}}"),
    )
    .await;
    assert!(response.status.is_success(), "{}", response.status);
    let echoed = response
        .headers
        .get("x-echo")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = response.body;
    assert!(echoed.contains(&phantom), "{echoed}");
    assert!(!echoed.contains(REAL), "{echoed}");
    assert!(body.contains(&phantom), "{body}");
    assert!(!body.contains(REAL), "{body}");
    let recorded = seen.lock().unwrap().clone();
    assert!(
        recorded.iter().any(|hit| hit.contains(REAL)),
        "{recorded:?}"
    );
    assert!(
        recorded.iter().all(|hit| !hit.contains(&phantom)),
        "{recorded:?}"
    );
    let _ = std::fs::remove_file(&audit_path);
}

#[tokio::test]
async fn blocks_raw_and_base64_exfiltration() {
    let (phantom, proxy, seen, audit_path) = harness().await;
    let before = seen.lock().unwrap().len();
    let raw = exchange(
        proxy.addr,
        "POST",
        "/upstream/stripe/v1/charges",
        &[("authorization", format!("Bearer {phantom}"))],
        phantom.clone(),
    )
    .await;
    assert_eq!(raw.status.as_u16(), 451);
    let raw_body = raw.body;
    assert!(
        raw_body.contains("Exfiltration Blocked by KeyAlibi"),
        "{raw_body}"
    );

    let encoded = STANDARD.encode(phantom.as_bytes());
    let b64 = exchange(
        proxy.addr,
        "POST",
        "/upstream/stripe/v1/charges",
        &[],
        encoded,
    )
    .await;
    assert_eq!(b64.status.as_u16(), 451);
    let b64_body = b64.body;
    assert!(
        b64_body.contains("Exfiltration Blocked by KeyAlibi"),
        "{b64_body}"
    );
    assert_eq!(seen.lock().unwrap().len(), before);

    let log = AuditLog::open(&audit_path).unwrap();
    let events = log.recent(20).unwrap();
    assert!(
        events
            .iter()
            .any(|event| event.kind == "block" && event.severity == "critical"),
        "{events:?}"
    );
    let _ = std::fs::remove_file(&audit_path);
}

struct Exchange {
    status: hyper::StatusCode,
    headers: hyper::HeaderMap,
    body: String,
}

async fn exchange(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, String)],
    body: String,
) -> Exchange {
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut builder = hyper::Request::builder().method(method).uri(path);
    for (name, value) in headers {
        builder = builder.header(*name, value);
    }
    let request = builder.body(Full::new(Bytes::from(body))).unwrap();
    let response = sender.send_request(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    Exchange {
        status,
        headers,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

async fn harness() -> (
    String,
    proxy::RunningProxy,
    Arc<Mutex<Vec<String>>>,
    std::path::PathBuf,
) {
    let session = Session::from_seed([3u8; 32]);
    let record = mint::mint(
        &session,
        MintInput {
            env_var: "OPENAI_API_KEY".into(),
            aux_env: None,
            provider: Provider::Openai,
            real: SecretString::from(REAL.to_string()),
            real_aux: None,
            allowed_hosts: vec!["api.openai.com".into()],
        },
    )
    .unwrap();
    let phantom = record.phantom.clone();
    let (addr, seen) = echo_server().await;
    let mut upstreams = HashMap::new();
    upstreams.insert(
        "openai".into(),
        Upstream::new(format!("http://{addr}")).with_allow_as("api.openai.com"),
    );
    upstreams.insert(
        "stripe".into(),
        Upstream::new(format!("http://{addr}")).with_allow_as("evil.example"),
    );
    let network = NetworkPolicy {
        allow_loopback: true,
        ..NetworkPolicy::default()
    };
    let audit_path = std::env::temp_dir().join(format!(
        "keyalibi-e2e-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let ca = SessionCa::generate().unwrap();
    let config = ProxyConfig {
        secrets: vec![record],
        network,
        cidrs: Vec::new(),
        upstreams,
        audit_path: audit_path.clone(),
        on_exfiltration: ExfilAction::None,
        child_pid: 0,
        child_command: "cargo test".into(),
        mitm: false,
        ca,
    };
    let proxy = proxy::spawn(config, audit_path.clone()).await.unwrap();
    (phantom, proxy, seen, audit_path)
}

async fn echo_server() -> (std::net::SocketAddr, Arc<Mutex<Vec<String>>>) {
    use bytes::Bytes;
    use http_body_util::{BodyExt, StreamBody};
    use hyper::body::Frame;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen_task = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let seen_task = Arc::clone(&seen_task);
            tokio::spawn(async move {
                let service = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let seen_task = Arc::clone(&seen_task);
                    async move {
                        let auth = req
                            .headers()
                            .get("authorization")
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or("")
                            .to_string();
                        let extra = req
                            .headers()
                            .get("x-extra")
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or("")
                            .to_string();
                        let collected = req.into_body().collect().await.unwrap().to_bytes();
                        let body = String::from_utf8_lossy(&collected).into_owned();
                        seen_task
                            .lock()
                            .unwrap()
                            .push(format!("{auth}\n{extra}\n{body}"));
                        let echo = format!("AUTH={auth}\nEXTRA={extra}\nBODY={body}\n");
                        let mid = (echo.len() / 2).max(1);
                        let stream = futures_util::stream::iter(vec![
                            Ok::<_, Infallible>(Frame::data(Bytes::from(echo[..mid].to_string()))),
                            Ok(Frame::data(Bytes::from(echo[mid..].to_string()))),
                        ]);
                        let mut response =
                            hyper::Response::new(BodyExt::boxed(StreamBody::new(stream)));
                        response.headers_mut().insert(
                            "x-echo",
                            hyper::header::HeaderValue::from_str(&auth).unwrap(),
                        );
                        Ok::<_, Infallible>(response)
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (addr, seen)
}
