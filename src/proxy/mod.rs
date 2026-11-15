//! Localhost egress proxy.
//!
//! Topology A rewrites provider base URLs onto `http://127.0.0.1:<port>/upstream/<provider>/...`
//! and needs no CA. Topology B is an HTTP proxy that terminates TLS only for
//! allowlisted hosts.

mod body;
mod ca;
mod forward;
mod scrub;
mod sigv4;
mod ssrf;
mod tripwire;
mod tunnel;

pub use ca::SessionCa;
pub use forward::{scrub_pairs, swap_pairs};

use crate::audit::AuditLog;
use crate::mint::SecretRecord;
use crate::policy::{Cidr, ExfilAction, NetworkPolicy};
use crate::proxy::body::ProxyBody;
use crate::proxy::tripwire::Rewriter;
use crate::{Error, Result};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::AtomicI32;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

#[derive(Debug, Clone)]
pub struct Upstream {
    pub base_url: String,
    pub allow_as: Option<String>,
}

impl Upstream {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            base_url: url.into(),
            allow_as: None,
        }
    }

    pub fn with_allow_as(mut self, host: impl Into<String>) -> Self {
        self.allow_as = Some(host.into());
        self
    }
}

pub struct ProxyConfig {
    pub secrets: Vec<SecretRecord>,
    pub network: NetworkPolicy,
    pub cidrs: Vec<Cidr>,
    pub upstreams: HashMap<String, Upstream>,
    pub audit_path: PathBuf,
    pub on_exfiltration: ExfilAction,
    pub child_pid: i32,
    pub child_command: String,
    pub mitm: bool,
    pub ca: SessionCa,
}

pub struct ProxyState {
    pub secrets: Vec<SecretRecord>,
    pub swap: Rewriter,
    pub scrub: Rewriter,
    pub network: NetworkPolicy,
    pub cidrs: Vec<Cidr>,
    pub upstreams: HashMap<String, Upstream>,
    pub audit: AuditLog,
    pub child_pid: AtomicI32,
    pub child_command: String,
    pub on_exfiltration: ExfilAction,
    pub ca: SessionCa,
    pub mitm: bool,
    pub listen: SocketAddr,
}

impl ProxyState {
    pub fn from_config(config: ProxyConfig, listen: SocketAddr) -> Result<Self> {
        let swap = Rewriter::from_pairs(&swap_pairs(&config.secrets));
        let scrub = Rewriter::from_pairs(&scrub_pairs(&config.secrets));
        swap_mlock(&swap);
        swap_mlock(&scrub);
        Ok(Self {
            secrets: config.secrets,
            swap,
            scrub,
            network: config.network,
            cidrs: config.cidrs,
            upstreams: config.upstreams,
            audit: AuditLog::open(&config.audit_path)?,
            child_pid: AtomicI32::new(config.child_pid),
            child_command: config.child_command,
            on_exfiltration: config.on_exfiltration,
            ca: config.ca,
            mitm: config.mitm,
            listen,
        })
    }
}

fn swap_mlock(rewriter: &Rewriter) {
    for pattern in &rewriter.patterns {
        crate::harden::mlock_slice(pattern.as_bytes());
    }
}

pub struct RunningProxy {
    pub addr: SocketAddr,
    pub audit_path: PathBuf,
    task: JoinHandle<()>,
}

impl Drop for RunningProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn spawn(config: ProxyConfig, audit_path: PathBuf) -> Result<RunningProxy> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|err| Error::new(format!("bind proxy: {err}")))?;
    let addr = listener
        .local_addr()
        .map_err(|err| Error::new(err.to_string()))?;
    let state = Arc::new(ProxyState::from_config(config, addr)?);
    let task = tokio::spawn(serve(listener, state));
    Ok(RunningProxy {
        addr,
        audit_path,
        task,
    })
}

pub async fn serve(listener: TcpListener, state: Arc<ProxyState>) {
    while let Ok((stream, _)) = listener.accept().await {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req: hyper::Request<Incoming>| {
                let state = Arc::clone(&state);
                async move { Ok::<_, Infallible>(dispatch(req, state).await) }
            });
            let _ = http1::Builder::new()
                .serve_connection(io, service)
                .with_upgrades()
                .await;
        });
    }
}

pub async fn serve_std(listener: std::net::TcpListener, state: Arc<ProxyState>) -> Result<()> {
    listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(listener)?;
    serve(listener, state).await;
    Ok(())
}

async fn dispatch(req: hyper::Request<Incoming>, state: Arc<ProxyState>) -> Response<ProxyBody> {
    if req.method() == hyper::Method::CONNECT {
        tunnel::begin_connect(req, state).await
    } else {
        forward::dispatch_http(req, state).await
    }
}

use http::Response;
