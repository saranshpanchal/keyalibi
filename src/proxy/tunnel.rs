//! Topology B: HTTP CONNECT. Allowlisted hosts are TLS-terminated with the
//! session CA. Everything else is a raw TCP tunnel after the ClientHello SNI
//! is checked, so package managers keep working.

use crate::policy::host_allowed;
use crate::proxy::body::{text_response, ProxyBody};
use crate::proxy::forward::dispatch_http;
use crate::proxy::ssrf;
use crate::proxy::ProxyState;
use http::{Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::io::{self, Cursor};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

pub async fn begin_connect(req: Request<Incoming>, state: Arc<ProxyState>) -> Response<ProxyBody> {
    let Some(authority) = req.uri().authority().cloned() else {
        return text_response(
            StatusCode::BAD_REQUEST,
            "KeyAlibi CONNECT is missing a host\n",
        );
    };
    let host = authority.host().to_string();
    let port = authority.port_u16().unwrap_or(443);
    if port == state.listen.port() && is_loopback_host(&host) {
        return text_response(
            StatusCode::LOOP_DETECTED,
            "KeyAlibi refused a CONNECT to itself\n",
        );
    }
    if let Err(err) = ssrf::resolve_pinned(&host, port, &state.network, &state.cidrs).await {
        return text_response(
            StatusCode::FORBIDDEN,
            format!("KeyAlibi network policy blocked CONNECT: {err}\n"),
        );
    }
    let allowlisted = state
        .secrets
        .iter()
        .any(|secret| host_allowed(&host, &secret.allowed_hosts));
    let on_upgrade = hyper::upgrade::on(req);
    let mitm = state.mitm && allowlisted;
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                let io = TokioIo::new(upgraded);
                if mitm {
                    if let Err(err) = intercept(io, host, port, state).await {
                        eprintln!("keyalibi: tls intercept ended: {err}");
                    }
                } else if let Err(err) = tunnel(io, host, port, state).await {
                    eprintln!("keyalibi: tunnel ended: {err}");
                }
            }
            Err(err) => eprintln!("keyalibi: CONNECT upgrade failed: {err}"),
        }
    });
    text_response(StatusCode::OK, "")
}

async fn intercept<T>(
    client: T,
    host: String,
    port: u16,
    state: Arc<ProxyState>,
) -> crate::Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let config = state.ca.server_config_for(&host)?;
    let acceptor = TlsAcceptor::from(config);
    let tls = acceptor
        .accept(client)
        .await
        .map_err(|err| crate::Error::new(format!("intercept handshake: {err}")))?;
    let io = TokioIo::new(tls);
    let host_for_req = host.clone();
    let service = service_fn(move |req: Request<Incoming>| {
        let state = Arc::clone(&state);
        let host_for_req = host_for_req.clone();
        async move {
            let absolute = absolute_target(&host_for_req, port, &req);
            let (mut parts, body) = req.into_parts();
            if let Ok(uri) = absolute.parse() {
                parts.uri = uri;
            }
            let rebuilt = Request::from_parts(parts, body);
            Ok::<_, std::convert::Infallible>(dispatch_http(rebuilt, state).await)
        }
    });
    let _ = http1::Builder::new().serve_connection(io, service).await;
    Ok(())
}

fn absolute_target(host: &str, port: u16, req: &Request<Incoming>) -> String {
    let path = if req.uri().path().is_empty() {
        "/"
    } else {
        req.uri().path()
    };
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    if port == 443 {
        format!("https://{host}{path}{query}")
    } else {
        format!("https://{host}:{port}{path}{query}")
    }
}

async fn tunnel<T>(
    mut client: T,
    host: String,
    port: u16,
    state: Arc<ProxyState>,
) -> crate::Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut peeked = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut peeked))
        .await
        .map_err(|_| crate::Error::new("timed out waiting for client bytes"))?
        .map_err(|err| crate::Error::new(err.to_string()))?;
    peeked.truncate(n);
    if let Some(sni) = parse_sni(&peeked) {
        if host_allowed_by_state(&sni, &state) && state.mitm {
            let prefixed = Prefixed {
                prefix: Cursor::new(peeked),
                inner: client,
            };
            return Box::pin(intercept(prefixed, sni, port, state)).await;
        }
        if normalize_loose(&sni) != normalize_loose(&host) {
            return Err(crate::Error::new(
                "CONNECT host does not match TLS SNI; tunnel refused",
            ));
        }
    }
    let resolved = ssrf::resolve_pinned(&host, port, &state.network, &state.cidrs).await?;
    let mut upstream = TcpStream::connect(resolved.addr)
        .await
        .map_err(|err| crate::Error::new(format!("tunnel connect: {err}")))?;
    if !peeked.is_empty() {
        upstream
            .write_all(&peeked)
            .await
            .map_err(|err| crate::Error::new(err.to_string()))?;
    }
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    Ok(())
}

fn host_allowed_by_state(host: &str, state: &ProxyState) -> bool {
    state
        .secrets
        .iter()
        .any(|secret| host_allowed(host, &secret.allowed_hosts))
}

fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_matches(|c| c == '[' || c == ']');
    host == "localhost" || host == "127.0.0.1" || host == "::1"
}

fn normalize_loose(host: &str) -> String {
    crate::policy::normalize_host(host)
}

/// Extract a DNS name from a TLS ClientHello, if the buffer contains one.
pub fn parse_sni(data: &[u8]) -> Option<String> {
    if data.len() < 43 || data[0] != 0x16 {
        return None;
    }
    let mut hs = &data[5..];
    if hs.first().copied() != Some(0x01) || hs.len() < 42 {
        return None;
    }
    hs = &hs[4..];
    hs = hs.get(2 + 32..)?;
    let sid_len = *hs.first()? as usize;
    hs = hs.get(1 + sid_len..)?;
    if hs.len() < 2 {
        return None;
    }
    let cs_len = u16::from_be_bytes([hs[0], hs[1]]) as usize;
    hs = hs.get(2 + cs_len..)?;
    let comp_len = *hs.first()? as usize;
    hs = hs.get(1 + comp_len..)?;
    if hs.len() < 2 {
        return None;
    }
    let ext_len = u16::from_be_bytes([hs[0], hs[1]]) as usize;
    let mut ext = hs.get(2..2 + ext_len.min(hs.len().saturating_sub(2)))?;
    while ext.len() >= 4 {
        let etype = u16::from_be_bytes([ext[0], ext[1]]);
        let elen = u16::from_be_bytes([ext[2], ext[3]]) as usize;
        if ext.len() < 4 + elen {
            return None;
        }
        let body = &ext[4..4 + elen];
        if etype == 0 && body.len() >= 5 {
            let name_len = u16::from_be_bytes([body[3], body[4]]) as usize;
            if body[2] == 0 && body.len() >= 5 + name_len {
                return String::from_utf8(body[5..5 + name_len].to_vec()).ok();
            }
        }
        ext = &ext[4 + elen..];
    }
    None
}

struct Prefixed<T> {
    prefix: Cursor<Vec<u8>>,
    inner: T,
}

impl<T: AsyncRead + Unpin> AsyncRead for Prefixed<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.prefix.position() < self.prefix.get_ref().len() as u64 {
            let mut tmp = vec![0u8; buf.remaining()];
            match std::io::Read::read(&mut self.prefix, &mut tmp) {
                Ok(0) => {}
                Ok(n) => {
                    buf.put_slice(&tmp[..n]);
                    return Poll::Ready(Ok(()));
                }
                Err(err) => return Poll::Ready(Err(err)),
            }
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Prefixed<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
