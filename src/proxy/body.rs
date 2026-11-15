use bytes::Bytes;
use http::{header, HeaderValue, Response, StatusCode};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use std::convert::Infallible;

pub type ProxyBody = BoxBody<Bytes, Infallible>;

pub fn full(bytes: impl Into<Bytes>) -> ProxyBody {
    Full::new(bytes.into())
        .map_err(|never: Infallible| match never {})
        .boxed()
}

pub fn text_response(status: StatusCode, message: impl Into<String>) -> Response<ProxyBody> {
    let message = message.into();
    let len = message.len();
    let mut response = Response::new(full(message));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(value) = HeaderValue::from_str(&len.to_string()) {
        response.headers_mut().insert(header::CONTENT_LENGTH, value);
    }
    response
}

pub fn blocked_response(detail: &str) -> Response<ProxyBody> {
    text_response(
        StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
        format!("Exfiltration Blocked by KeyAlibi\n{detail}\n"),
    )
}
