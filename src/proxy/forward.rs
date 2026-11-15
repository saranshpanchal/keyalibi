//! HTTP request path shared by Topology A (`/upstream/<provider>/...`) and
//! cleartext absolute-form proxying.

use crate::audit::NewEvent;
use crate::mint::{Provider, SecretRecord};
use crate::policy::{host_allowed, ExfilAction};
use crate::proxy::body::{blocked_response, full, text_response, ProxyBody};
use crate::proxy::ca::SessionCa;
use crate::proxy::scrub::StreamScrubber;
use crate::proxy::sigv4::{self, looks_like_presign, looks_like_sigv4};
use crate::proxy::ssrf::{self, Resolved};
use crate::proxy::tripwire::{Pair, Rewriter};
use crate::proxy::ProxyState;
use crate::{Error, Result};
use bytes::Bytes;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper_util::rt::TokioIo;
use std::io::{Read, Write};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const MAX_BODY: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Destination {
    pub dial_host: String,
    pub dial_port: u16,
    pub tls: bool,
    pub logical_host: String,
    pub path: String,
    pub query: String,
}

pub async fn dispatch_http(
    req: Request<Incoming>,
    state: std::sync::Arc<ProxyState>,
) -> Response<ProxyBody> {
    match handle(req, &state).await {
        Ok(response) => response,
        Err(err) => text_response(
            StatusCode::BAD_GATEWAY,
            format!("KeyAlibi upstream error: {err}\n"),
        ),
    }
}

async fn handle(req: Request<Incoming>, state: &ProxyState) -> Result<Response<ProxyBody>> {
    if req.uri().path() == "/keyalibi/health" {
        return Ok(text_response(StatusCode::OK, "ok\n"));
    }
    let dest = match route(&req, state) {
        Ok(dest) => dest,
        Err(response) => return Ok(response),
    };
    let (parts, body) = req.into_parts();
    let body_bytes = match collect_limited(body).await {
        Ok(bytes) => bytes,
        Err(err) => {
            return Ok(text_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("KeyAlibi: {err}\n"),
            ))
        }
    };

    let scan = scan_buffer(&parts.uri, &parts.headers, &body_bytes);
    let hits = state.swap.matching_ids(&scan);
    if let Some(secret) = first_violation(&state.secrets, &hits, &dest.logical_host) {
        let detail = format!(
            "env={} destination={} child_pid={} command={}",
            secret.env_var,
            dest.logical_host,
            state.child_pid.load(std::sync::atomic::Ordering::Relaxed),
            state.child_command
        );
        let _ = state.audit.record(NewEvent {
            kind: "block",
            severity: "critical",
            child_pid: nonzero_pid(state),
            command: state.child_command.clone(),
            destination: dest.logical_host.clone(),
            env_var: secret.env_var.clone(),
            detail: "phantom token destined for a non-allowlisted host".into(),
        });
        signal_child(state);
        return Ok(blocked_response(&detail));
    }

    let path = rewrite_string(&state.swap, &dest.path);
    let mut query = rewrite_string(&state.swap, &dest.query);
    let mut headers = rewrite_headers(&state.swap, &parts.headers);
    let body_swapped = state.swap.rewrite(&body_bytes);
    strip_hop_headers(&mut headers);
    headers.remove(http::header::ACCEPT_ENCODING);
    headers.remove(http::header::HOST);
    headers.remove(http::header::CONTENT_LENGTH);
    let host_value = host_header(&dest);
    headers.insert(
        http::header::HOST,
        HeaderValue::from_str(&host_value).map_err(|_| Error::new("invalid host header"))?,
    );
    headers.insert(
        http::header::ACCEPT_ENCODING,
        HeaderValue::from_static("identity"),
    );
    headers.insert(
        http::header::CONTENT_LENGTH,
        HeaderValue::from_str(&body_swapped.len().to_string())
            .map_err(|_| Error::new("invalid content length"))?,
    );

    if let Some(secret) = aws_secret(&state.secrets, &hits) {
        if let Err(err) = resign_aws(
            parts.method.as_str(),
            &path,
            &mut query,
            &mut headers,
            &body_swapped,
            secret,
        ) {
            return Ok(text_response(
                StatusCode::NOT_IMPLEMENTED,
                format!("KeyAlibi could not re-sign this AWS request: {err}\n"),
            ));
        }
    }

    for id in &hits {
        let secret = &state.secrets[*id];
        let _ = state.audit.record(NewEvent {
            kind: "swap",
            severity: "info",
            child_pid: nonzero_pid(state),
            command: state.child_command.clone(),
            destination: dest.logical_host.clone(),
            env_var: secret.env_var.clone(),
            detail: "phantom swapped for an allowlisted upstream".into(),
        });
    }

    let resolved = ssrf::resolve_pinned(
        &dest.dial_host,
        dest.dial_port,
        &state.network,
        &state.cidrs,
    )
    .await
    .map_err(|err| Error::new(err.to_string()))?;
    if points_at_proxy(resolved.addr, state.listen) {
        return Ok(text_response(
            StatusCode::LOOP_DETECTED,
            "KeyAlibi refused a request that targets the proxy itself\n",
        ));
    }

    let upstream = send_upstream(
        &dest,
        &resolved,
        &parts.method,
        &path,
        &query,
        &headers,
        Bytes::from(body_swapped),
        &state.ca,
    )
    .await?;
    finish_response(upstream, state, !hits.is_empty()).await
}

fn route(
    req: &Request<Incoming>,
    state: &ProxyState,
) -> std::result::Result<Destination, Response<ProxyBody>> {
    if let Some(rest) = req.uri().path().strip_prefix("/upstream/") {
        return route_upstream(rest, req.uri().query().unwrap_or(""), state);
    }
    if req.uri().scheme().is_some() {
        return route_absolute(req.uri())
            .map_err(|err| text_response(StatusCode::BAD_REQUEST, format!("KeyAlibi: {err}\n")));
    }
    Err(text_response(
        StatusCode::BAD_REQUEST,
        "KeyAlibi expected /upstream/<provider>/... or an absolute-form proxy request\n",
    ))
}

fn route_upstream(
    rest: &str,
    query: &str,
    state: &ProxyState,
) -> std::result::Result<Destination, Response<ProxyBody>> {
    let (provider, tail) = match rest.split_once('/') {
        Some((provider, tail)) => (provider, tail),
        None => (rest, ""),
    };
    if provider.is_empty() {
        return Err(text_response(
            StatusCode::BAD_REQUEST,
            "KeyAlibi missing upstream provider\n",
        ));
    }
    let Some(upstream) = state.upstreams.get(provider) else {
        return Err(text_response(
            StatusCode::NOT_FOUND,
            format!("KeyAlibi has no upstream named {provider}\n"),
        ));
    };
    let base = match url::Url::parse(&upstream.base_url) {
        Ok(url) => url,
        Err(err) => {
            return Err(text_response(
                StatusCode::BAD_GATEWAY,
                format!("KeyAlibi upstream {provider} is not a valid URL: {err}\n"),
            ))
        }
    };
    let Some(dial_host) = base.host_str().map(|h| h.to_string()) else {
        return Err(text_response(
            StatusCode::BAD_GATEWAY,
            format!("KeyAlibi upstream {provider} has no host\n"),
        ));
    };
    let Some(dial_port) = base.port_or_known_default() else {
        return Err(text_response(
            StatusCode::BAD_GATEWAY,
            format!("KeyAlibi upstream {provider} has no port\n"),
        ));
    };
    let logical_host = upstream
        .allow_as
        .clone()
        .unwrap_or_else(|| dial_host.clone());
    Ok(Destination {
        dial_host,
        dial_port,
        tls: base.scheme() == "https",
        logical_host,
        path: join_paths(base.path(), tail),
        query: query.to_string(),
    })
}

pub fn route_absolute(uri: &Uri) -> Result<Destination> {
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| Error::new("absolute URL is missing a scheme"))?;
    let authority = uri
        .authority()
        .ok_or_else(|| Error::new("absolute URL is missing a host"))?;
    let host = authority.host().to_string();
    let tls = scheme == "https";
    if scheme != "http" && scheme != "https" {
        return Err(Error::new(format!("unsupported scheme {scheme}")));
    }
    let port = authority.port_u16().unwrap_or(if tls { 443 } else { 80 });
    let path = if uri.path().is_empty() {
        "/".to_string()
    } else {
        uri.path().to_string()
    };
    Ok(Destination {
        dial_host: host.clone(),
        dial_port: port,
        tls,
        logical_host: host,
        path,
        query: uri.query().unwrap_or("").to_string(),
    })
}

fn join_paths(base_path: &str, tail: &str) -> String {
    let base = base_path.trim_end_matches('/');
    let tail = tail.trim_start_matches('/');
    if tail.is_empty() {
        if base.is_empty() {
            return "/".to_string();
        }
        return if base.starts_with('/') {
            base.to_string()
        } else {
            format!("/{base}")
        };
    }
    if base.is_empty() || base == "/" {
        format!("/{tail}")
    } else if base.starts_with('/') {
        format!("{base}/{tail}")
    } else {
        format!("/{base}/{tail}")
    }
}

fn scan_buffer(uri: &Uri, headers: &HeaderMap, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(uri.to_string().as_bytes());
    out.push(b'\n');
    for (name, value) in headers.iter() {
        out.extend_from_slice(name.as_str().as_bytes());
        out.push(b':');
        out.extend_from_slice(value.as_bytes());
        out.push(b'\n');
    }
    out.extend_from_slice(body);
    out
}

fn first_violation<'a>(
    secrets: &'a [SecretRecord],
    hits: &[usize],
    host: &str,
) -> Option<&'a SecretRecord> {
    hits.iter().find_map(|id| {
        let secret = secrets.get(*id)?;
        if host_allowed(host, &secret.allowed_hosts) {
            None
        } else {
            Some(secret)
        }
    })
}

fn aws_secret<'a>(secrets: &'a [SecretRecord], hits: &[usize]) -> Option<&'a SecretRecord> {
    hits.iter().find_map(|id| {
        let secret = secrets.get(*id)?;
        if secret.provider == Provider::Aws && secret.real_aux_str().is_some() {
            Some(secret)
        } else {
            None
        }
    })
}

fn resign_aws(
    method: &str,
    path: &str,
    query: &mut String,
    headers: &mut HeaderMap,
    body: &[u8],
    secret: &SecretRecord,
) -> Result<()> {
    let real_access = secret.real_str();
    let real_secret = secret
        .real_aux_str()
        .ok_or_else(|| Error::new("AWS secret access key is not loaded"))?;
    if looks_like_sigv4(headers) {
        sigv4::resign_authorization(method, path, query, headers, body, real_access, real_secret)?;
        return Ok(());
    }
    if looks_like_presign(query) {
        *query = sigv4::resign_query(
            method,
            path,
            query,
            &host_from_headers(headers),
            real_access,
            real_secret,
        )?;
    }
    Ok(())
}

fn host_from_headers(headers: &HeaderMap) -> String {
    headers
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost")
        .to_string()
}

fn rewrite_string(rewriter: &Rewriter, value: &str) -> String {
    match String::from_utf8(rewriter.rewrite(value.as_bytes())) {
        Ok(text) => text,
        Err(err) => String::from_utf8_lossy(err.as_bytes()).into_owned(),
    }
}

fn rewrite_headers(rewriter: &Rewriter, headers: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in headers.iter() {
        if is_hop(name) {
            continue;
        }
        let rewritten = rewriter.rewrite(value.as_bytes());
        if let Ok(header) = HeaderValue::from_bytes(&rewritten) {
            out.append(name, header);
        }
    }
    out
}

fn strip_hop_headers(headers: &mut HeaderMap) {
    let names: Vec<HeaderName> = headers
        .keys()
        .filter(|name| is_hop(name))
        .cloned()
        .collect();
    for name in names {
        headers.remove(name);
    }
}

fn is_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
            | "proxy-connection"
    )
}

fn host_header(dest: &Destination) -> String {
    let default_port = if dest.tls { 443 } else { 80 };
    if dest.dial_port == default_port || dest.logical_host != dest.dial_host {
        dest.logical_host.clone()
    } else {
        format!("{}:{}", dest.logical_host, dest.dial_port)
    }
}

fn points_at_proxy(addr: std::net::SocketAddr, listen: std::net::SocketAddr) -> bool {
    addr.port() == listen.port()
        && (addr.ip() == listen.ip() || (addr.ip().is_loopback() && listen.ip().is_loopback()))
}

#[allow(clippy::too_many_arguments)]
async fn send_upstream(
    dest: &Destination,
    resolved: &Resolved,
    method: &Method,
    path: &str,
    query: &str,
    headers: &HeaderMap,
    body: Bytes,
    ca: &SessionCa,
) -> Result<Response<Incoming>> {
    let tcp = tokio::time::timeout(Duration::from_secs(20), TcpStream::connect(resolved.addr))
        .await
        .map_err(|_| Error::new(format!("connect to {} timed out", dest.dial_host)))?
        .map_err(|err| Error::new(format!("connect to {} failed: {err}", dest.dial_host)))?;
    let _ = tcp.set_nodelay(true);
    let target = request_uri(path, query);
    let mut builder = Request::builder().method(method).uri(target);
    for (name, value) in headers.iter() {
        builder = builder.header(name, value);
    }
    let request = builder
        .body(Full::new(body))
        .map_err(|err| Error::new(err.to_string()))?;
    if dest.tls {
        let connector = TlsConnector::from(ca.client_config());
        let server_name = SessionCa::server_name(&dest.dial_host)?;
        let tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|err| Error::new(format!("upstream tls: {err}")))?;
        dispatch_io(TokioIo::new(tls), request).await
    } else {
        dispatch_io(TokioIo::new(tcp), request).await
    }
}

async fn dispatch_io<I>(io: I, request: Request<Full<Bytes>>) -> Result<Response<Incoming>>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake::<_, Full<Bytes>>(io).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(sender.send_request(request).await?)
}

fn request_uri(path: &str, query: &str) -> String {
    let path = if path.is_empty() { "/" } else { path };
    if query.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{query}")
    }
}

async fn finish_response(
    response: Response<Incoming>,
    state: &ProxyState,
    swapped: bool,
) -> Result<Response<ProxyBody>> {
    let (parts, body) = response.into_parts();
    let encoding = parts
        .headers
        .get(http::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if encoding == "gzip" || encoding == "x-gzip" {
        return gzip_response(parts, body, state).await;
    }
    if !encoding.is_empty() && encoding != "identity" && swapped {
        return Ok(text_response(
            StatusCode::BAD_GATEWAY,
            "KeyAlibi refused a compressed response it cannot scrub\n",
        ));
    }
    let headers = scrub_headers(&state.scrub, &parts.headers);
    if swapped {
        let _ = state.audit.record(NewEvent {
            kind: "scrub",
            severity: "info",
            child_pid: nonzero_pid(state),
            command: state.child_command.clone(),
            destination: String::new(),
            env_var: String::new(),
            detail: "response stream passed through the scrubber".into(),
        });
    }
    let mut out = Response::new(scrub_stream(body, state.scrub.clone()));
    *out.status_mut() = parts.status;
    *out.headers_mut() = headers;
    out.headers_mut().remove(http::header::CONTENT_LENGTH);
    out.headers_mut().remove(http::header::TRANSFER_ENCODING);
    out.headers_mut().remove(http::header::CONNECTION);
    Ok(out)
}

async fn gzip_response(
    parts: http::response::Parts,
    body: Incoming,
    state: &ProxyState,
) -> Result<Response<ProxyBody>> {
    let bytes = collect_limited(body).await?;
    let mut decoder = GzDecoder::new(bytes.as_ref());
    let mut plain = Vec::new();
    decoder
        .read_to_end(&mut plain)
        .map_err(|err| Error::new(format!("gzip decode: {err}")))?;
    let scrubbed = state.scrub.rewrite(&plain);
    let changed = scrubbed != plain;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&scrubbed)
        .map_err(|err| Error::new(format!("gzip encode: {err}")))?;
    let compressed = encoder
        .finish()
        .map_err(|err| Error::new(format!("gzip finish: {err}")))?;
    if changed {
        let _ = state.audit.record(NewEvent {
            kind: "scrub",
            severity: "info",
            child_pid: nonzero_pid(state),
            command: state.child_command.clone(),
            destination: String::new(),
            env_var: String::new(),
            detail: "gzip response scrubbed".into(),
        });
    }
    let mut headers = scrub_headers(&state.scrub, &parts.headers);
    headers.remove(http::header::CONTENT_LENGTH);
    headers.remove(http::header::TRANSFER_ENCODING);
    headers.insert(
        http::header::CONTENT_LENGTH,
        HeaderValue::from_str(&compressed.len().to_string())
            .map_err(|_| Error::new("invalid gzip length"))?,
    );
    let mut out = Response::new(full(compressed));
    *out.status_mut() = parts.status;
    *out.headers_mut() = headers;
    Ok(out)
}

fn scrub_headers(rewriter: &Rewriter, headers: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in headers.iter() {
        if is_hop(name)
            || name == http::header::CONTENT_LENGTH
            || name == http::header::TRANSFER_ENCODING
        {
            continue;
        }
        let rewritten = rewriter.rewrite(value.as_bytes());
        if let Ok(header) = HeaderValue::from_bytes(&rewritten) {
            out.append(name, header);
        }
    }
    out
}

fn scrub_stream(body: Incoming, rewriter: Rewriter) -> ProxyBody {
    let stream = futures_util::stream::unfold(
        (body, StreamScrubber::new(rewriter), false),
        |(mut body, mut scrubber, done)| async move {
            if done {
                return None;
            }
            loop {
                match body.frame().await {
                    Some(Ok(frame)) => {
                        let Ok(data) = frame.into_data() else {
                            let tail = scrubber.finish();
                            if tail.is_empty() {
                                return None;
                            }
                            return Some((
                                Ok::<_, std::convert::Infallible>(Frame::data(Bytes::from(tail))),
                                (body, scrubber, true),
                            ));
                        };
                        let out = scrubber.push(&data);
                        if !out.is_empty() {
                            return Some((
                                Ok(Frame::data(Bytes::from(out))),
                                (body, scrubber, false),
                            ));
                        }
                    }
                    Some(Err(_)) => {
                        let tail = scrubber.finish();
                        if tail.is_empty() {
                            return None;
                        }
                        return Some((Ok(Frame::data(Bytes::from(tail))), (body, scrubber, true)));
                    }
                    None => {
                        let tail = scrubber.finish();
                        if tail.is_empty() {
                            return None;
                        }
                        return Some((Ok(Frame::data(Bytes::from(tail))), (body, scrubber, true)));
                    }
                }
            }
        },
    );
    BodyExt::boxed(StreamBody::new(stream))
}

async fn collect_limited(mut body: Incoming) -> Result<Bytes> {
    let mut collected = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|err| Error::new(err.to_string()))?;
        if let Ok(data) = frame.into_data() {
            if collected.len().saturating_add(data.len()) > MAX_BODY {
                return Err(Error::new("body exceeds 16 MiB"));
            }
            collected.extend_from_slice(&data);
        }
    }
    Ok(Bytes::from(collected))
}

fn nonzero_pid(state: &ProxyState) -> Option<i32> {
    let pid = state.child_pid.load(std::sync::atomic::Ordering::Relaxed);
    if pid > 0 {
        Some(pid)
    } else {
        None
    }
}

fn signal_child(state: &ProxyState) {
    let signal = match state.on_exfiltration {
        ExfilAction::None => return,
        ExfilAction::Sigstop => libc::SIGSTOP,
        ExfilAction::Sigkill => libc::SIGKILL,
    };
    let pid = state.child_pid.load(std::sync::atomic::Ordering::Relaxed);
    if pid <= 1 {
        return;
    }
    // SAFETY: `pid` is the supervised child, placed in its own process group.
    // A negative argument delivers the signal to that group, not the supervisor.
    unsafe {
        libc::kill(-pid, signal);
    }
}

pub fn swap_pairs(secrets: &[SecretRecord]) -> Vec<Pair> {
    let mut pairs = Vec::new();
    for (id, secret) in secrets.iter().enumerate() {
        push_pair(&mut pairs, id, &secret.phantom, secret.real_str());
        if let (Some(phantom), Some(real)) = (&secret.phantom_aux, secret.real_aux_str()) {
            push_pair(&mut pairs, id, phantom, real);
        }
    }
    pairs
}

pub fn scrub_pairs(secrets: &[SecretRecord]) -> Vec<Pair> {
    let mut pairs = Vec::new();
    for (id, secret) in secrets.iter().enumerate() {
        if secret.real_str().len() >= 8 {
            push_pair(&mut pairs, id, secret.real_str(), &secret.phantom);
        }
        if let (Some(real), Some(phantom)) = (secret.real_aux_str(), &secret.phantom_aux) {
            if real.len() >= 8 {
                push_pair(&mut pairs, id, real, phantom);
            }
        }
    }
    pairs
}

fn push_pair(pairs: &mut Vec<Pair>, id: usize, from: &str, to: &str) {
    if from.is_empty() || from == to {
        return;
    }
    pairs.push(Pair {
        from: from.to_string(),
        to: to.to_string(),
        id,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_provider_tail_onto_base_path() {
        assert_eq!(join_paths("", "v1/chat"), "/v1/chat");
        assert_eq!(join_paths("/", "v1/chat"), "/v1/chat");
        assert_eq!(join_paths("/v1", "chat"), "/v1/chat");
        assert_eq!(join_paths("", ""), "/");
    }
}
