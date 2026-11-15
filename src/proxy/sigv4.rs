//! AWS Signature Version 4 (AWS4-HMAC-SHA256) re-signing.
//!
//! The child signs with the phantom secret. That signature is useless to AWS
//! and, more importantly, the phantom secret is not a credential we are
//! willing to put on the wire. When the destination is allowlisted we rebuild
//! the canonical request and sign it with the real secret.
//!
//! Streaming signed payloads (`STREAMING-AWS4-*`) and SigV4A
//! (`AWS4-ECDSA-P256-SHA256`) are rejected. Those authenticators bind bytes
//! the proxy cannot reconstruct.

use crate::{Error, Result};
use hmac::{Hmac, Mac};
use http::HeaderMap;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

#[cfg_attr(not(test), allow(dead_code))]
const EMPTY_PAYLOAD_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Re-sign an `Authorization: AWS4-HMAC-SHA256 ...` header in place.
///
/// `headers` must already contain the upstream `host` and any swapped
/// `x-amz-*` values. The payload hash header is refreshed from `body` when it
/// is a hex digest (not `UNSIGNED-PAYLOAD`).
pub fn resign_authorization(
    method: &str,
    path: &str,
    query: &str,
    headers: &mut HeaderMap,
    body: &[u8],
    real_access_key: &str,
    real_secret: &str,
) -> Result<()> {
    let authorization = header_string(headers, "authorization")
        .ok_or_else(|| Error::new("missing Authorization header for SigV4 re-sign"))?;
    if authorization.contains("AWS4-ECDSA-P256-SHA256") {
        return Err(Error::new(
            "SigV4A (AWS4-ECDSA-P256-SHA256) cannot be re-signed by KeyAlibi",
        ));
    }
    if !authorization.starts_with("AWS4-HMAC-SHA256 ")
        && !authorization.starts_with("AWS4-HMAC-SHA256")
    {
        return Err(Error::new("Authorization is not AWS4-HMAC-SHA256"));
    }
    let credential = auth_field(&authorization, "Credential")
        .ok_or_else(|| Error::new("SigV4 Authorization is missing Credential"))?;
    let signed_headers = auth_field(&authorization, "SignedHeaders")
        .ok_or_else(|| Error::new("SigV4 Authorization is missing SignedHeaders"))?;
    let scope = credential_scope(&credential)?;
    refresh_payload_hash(headers, body)?;
    let payload_hash =
        header_string(headers, "x-amz-content-sha256").unwrap_or_else(|| sha256_hex(body));
    if payload_hash.starts_with("STREAMING-") {
        return Err(Error::new(
            "streaming SigV4 payloads cannot be re-signed by KeyAlibi",
        ));
    }
    let amz_date = header_string(headers, "x-amz-date")
        .ok_or_else(|| Error::new("SigV4 request is missing x-amz-date"))?;
    let signed: Vec<&str> = signed_headers
        .split(';')
        .filter(|s| !s.is_empty())
        .collect();
    let canonical = canonical_request(method, path, query, headers, &signed, &payload_hash)?;
    let string_to_sign = string_to_sign(&amz_date, &scope, &canonical);
    let signature = hex_hmac(
        &signing_key(real_secret, &scope.date, &scope.region, &scope.service),
        string_to_sign.as_bytes(),
    );
    let value = format!(
        "AWS4-HMAC-SHA256 Credential={real_access_key}/{scope_str}, SignedHeaders={signed_headers}, Signature={signature}",
        scope_str = scope.display(),
    );
    headers.insert(
        "authorization",
        value
            .parse()
            .map_err(|_| Error::new("built an invalid Authorization header"))?,
    );
    Ok(())
}

/// Re-sign a query-string (presigned) URL. Returns the new query string,
/// without a leading `?`.
pub fn resign_query(
    method: &str,
    path: &str,
    query: &str,
    host: &str,
    real_access_key: &str,
    real_secret: &str,
) -> Result<String> {
    let mut pairs = parse_query(query);
    let algo = query_get(&pairs, "X-Amz-Algorithm").unwrap_or_default();
    if algo == "AWS4-ECDSA-P256-SHA256" {
        return Err(Error::new(
            "SigV4A presigned URLs cannot be re-signed by KeyAlibi",
        ));
    }
    if algo != "AWS4-HMAC-SHA256" {
        return Err(Error::new(
            "presigned URL is not AWS4-HMAC-SHA256; KeyAlibi will not forward it unchanged",
        ));
    }
    let credential = query_get(&pairs, "X-Amz-Credential")
        .ok_or_else(|| Error::new("presigned URL is missing X-Amz-Credential"))?;
    let scope = credential_scope(&percent_decode(&credential))?;
    let signed = query_get(&pairs, "X-Amz-SignedHeaders").unwrap_or_else(|| "host".into());
    let amz_date = query_get(&pairs, "X-Amz-Date")
        .ok_or_else(|| Error::new("presigned URL is missing X-Amz-Date"))?;
    let payload_hash =
        query_get(&pairs, "X-Amz-Content-Sha256").unwrap_or_else(|| "UNSIGNED-PAYLOAD".into());
    if payload_hash.starts_with("STREAMING-") {
        return Err(Error::new(
            "streaming presigned URLs cannot be re-signed by KeyAlibi",
        ));
    }
    query_set(
        &mut pairs,
        "X-Amz-Credential",
        &format!("{real_access_key}/{}", scope.display()),
    );
    pairs.retain(|(k, _)| !k.eq_ignore_ascii_case("X-Amz-Signature"));
    let mut headers = HeaderMap::new();
    headers.insert(
        "host",
        host.parse()
            .map_err(|_| Error::new("invalid host for presign"))?,
    );
    let signed_names: Vec<&str> = signed.split(';').filter(|s| !s.is_empty()).collect();
    let canonical_query = canonical_query_pairs(&pairs);
    let canonical = canonical_request(
        method,
        path,
        &canonical_query,
        &headers,
        &signed_names,
        &payload_hash,
    )?;
    let string_to_sign = string_to_sign(&amz_date, &scope, &canonical);
    let signature = hex_hmac(
        &signing_key(real_secret, &scope.date, &scope.region, &scope.service),
        string_to_sign.as_bytes(),
    );
    pairs.push(("X-Amz-Signature".into(), signature));
    Ok(encode_pairs(&pairs))
}

pub fn looks_like_sigv4(headers: &HeaderMap) -> bool {
    header_string(headers, "authorization")
        .map(|v| v.contains("AWS4-HMAC-SHA256") || v.contains("AWS4-ECDSA"))
        .unwrap_or(false)
}

pub fn looks_like_presign(query: &str) -> bool {
    query.contains("X-Amz-Signature=") || query.contains("X-Amz-Algorithm=")
}

struct Scope {
    date: String,
    region: String,
    service: String,
}

impl Scope {
    fn display(&self) -> String {
        format!(
            "{}/{}/{}/aws4_request",
            self.date, self.region, self.service
        )
    }
}

fn credential_scope(credential: &str) -> Result<Scope> {
    // ACCESS/date/region/service/aws4_request
    let parts: Vec<&str> = credential.split('/').collect();
    if parts.len() != 5 || parts[4] != "aws4_request" {
        return Err(Error::new(
            "SigV4 credential scope is not access/date/region/service/aws4_request",
        ));
    }
    Ok(Scope {
        date: parts[1].to_string(),
        region: parts[2].to_string(),
        service: parts[3].to_string(),
    })
}

fn refresh_payload_hash(headers: &mut HeaderMap, body: &[u8]) -> Result<()> {
    let Some(current) = header_string(headers, "x-amz-content-sha256") else {
        return Ok(());
    };
    if current == "UNSIGNED-PAYLOAD" || current.starts_with("STREAMING-") {
        return Ok(());
    }
    let digest = sha256_hex(body);
    headers.insert(
        "x-amz-content-sha256",
        digest
            .parse()
            .map_err(|_| Error::new("invalid payload hash header"))?,
    );
    Ok(())
}

pub fn canonical_request(
    method: &str,
    path: &str,
    query: &str,
    headers: &HeaderMap,
    signed_headers: &[&str],
    payload_hash: &str,
) -> Result<String> {
    let mut names: Vec<&str> = signed_headers.to_vec();
    names.sort_unstable();
    let mut header_block = String::new();
    for name in &names {
        let value = joined_header(headers, name)?;
        header_block.push_str(&name.to_ascii_lowercase());
        header_block.push(':');
        header_block.push_str(&value);
        header_block.push('\n');
    }
    let signed = names
        .iter()
        .map(|n| n.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(";");
    let canonical_uri = aws_encode_path(path);
    let canonical_query = canonical_query_string(query);
    Ok(format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method.to_ascii_uppercase(),
        canonical_uri,
        canonical_query,
        header_block,
        signed,
        payload_hash
    ))
}

fn string_to_sign(amz_date: &str, scope: &Scope, canonical: &str) -> String {
    format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date,
        scope.display(),
        sha256_hex(canonical.as_bytes())
    )
}

pub fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_secret = format!("AWS4{secret}");
    let k_date = hmac_sha256(k_secret.as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

fn joined_header(headers: &HeaderMap, name: &str) -> Result<String> {
    let mut values = Vec::new();
    for value in headers.get_all(name) {
        let text = value
            .to_str()
            .map_err(|_| Error::new(format!("signed header {name} is not ascii")))?;
        values.push(trim_aws(text));
    }
    if values.is_empty() {
        return Err(Error::new(format!(
            "signed header {name} is missing from the request"
        )));
    }
    Ok(values.join(","))
}

fn trim_aws(value: &str) -> String {
    let mut out = String::new();
    let mut prev_space = false;
    for c in value.trim().chars() {
        if c.is_whitespace() {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            out.push(c);
            prev_space = false;
        }
    }
    out
}

fn header_string(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn auth_field(authorization: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=");
    let start = authorization.find(&needle)? + needle.len();
    let rest = &authorization[start..];
    let end = rest.find([',', ' ']).unwrap_or(rest.len());
    Some(rest[..end].trim().to_string())
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hex_hmac(key: &[u8], data: &[u8]) -> String {
    hex::encode(hmac_sha256(key, data))
}

pub fn aws_encode(input: &str, encode_slash: bool) -> String {
    const HEX: &[u8] = b"0123456789ABCDEF";
    let mut out = String::new();
    for b in input.as_bytes() {
        let unreserved = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~');
        if unreserved || (!encode_slash && *b == b'/') {
            out.push(*b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
    }
    out
}

fn aws_encode_path(path: &str) -> String {
    if path.is_empty() {
        return "/".to_string();
    }
    let segments: Vec<&str> = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    let mut out = String::new();
    if path.starts_with('/') || segments.is_empty() {
        out.push('/');
    }
    for (index, segment) in segments.iter().enumerate() {
        if index > 0 {
            out.push('/');
        }
        out.push_str(&aws_encode(&percent_decode(segment), true));
    }
    if path.ends_with('/') && path.len() > 1 {
        out.push('/');
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

pub fn canonical_query_string(query: &str) -> String {
    if query.is_empty() {
        return String::new();
    }
    canonical_query_pairs(&parse_query(query))
}

fn canonical_query_pairs(pairs: &[(String, String)]) -> String {
    let mut encoded: Vec<(String, String)> = pairs
        .iter()
        .filter(|(k, _)| !k.is_empty())
        .map(|(k, v)| {
            (
                aws_encode(&percent_decode(k), true),
                aws_encode(&percent_decode(v), true),
            )
        })
        .collect();
    encoded.sort();
    encoded
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn parse_query(query: &str) -> Vec<(String, String)> {
    if query.is_empty() {
        return Vec::new();
    }
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|part| match part.split_once('=') {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => (part.to_string(), String::new()),
        })
        .collect()
}

fn encode_pairs(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn query_get(pairs: &[(String, String)], name: &str) -> Option<String> {
    pairs
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

fn query_set(pairs: &mut Vec<(String, String)>, name: &str, value: &str) {
    if let Some((_, slot)) = pairs.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case(name)) {
        *slot = value.to_string();
    } else {
        pairs.push((name.to_string(), value.to_string()));
    }
}

pub fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (from_hex(bytes[i + 1]), from_hex(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_iam_list_users_vector() {
        // AWS docs, "Examples of How to Derive a Signing Key for Signature Version 4".
        let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            "application/x-www-form-urlencoded; charset=utf-8"
                .parse()
                .unwrap(),
        );
        headers.insert("host", "iam.amazonaws.com".parse().unwrap());
        headers.insert("x-amz-date", "20150830T123600Z".parse().unwrap());
        let canonical = canonical_request(
            "GET",
            "/",
            "Action=ListUsers&Version=2010-05-08",
            &headers,
            &["content-type", "host", "x-amz-date"],
            EMPTY_PAYLOAD_HASH,
        )
        .unwrap();
        assert_eq!(
            sha256_hex(canonical.as_bytes()),
            "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"
        );
        let scope = Scope {
            date: "20150830".into(),
            region: "us-east-1".into(),
            service: "iam".into(),
        };
        let sts = string_to_sign("20150830T123600Z", &scope, &canonical);
        let key = signing_key(secret, "20150830", "us-east-1", "iam");
        let signature = hex_hmac(&key, sts.as_bytes());
        assert_eq!(
            signature,
            "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        );
    }

    #[test]
    fn resign_replaces_phantom_credential() {
        let phantom_ak = "AKIAIOSFODNN7EXAMPLE";
        let real_ak = "AKIAREALACCESSKEY1";
        let real_secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        let mut headers = HeaderMap::new();
        headers.insert("host", "iam.amazonaws.com".parse().unwrap());
        headers.insert("x-amz-date", "20150830T123600Z".parse().unwrap());
        headers.insert("x-amz-content-sha256", EMPTY_PAYLOAD_HASH.parse().unwrap());
        let auth = format!(
            "AWS4-HMAC-SHA256 Credential={phantom_ak}/20150830/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=deadbeef"
        );
        headers.insert("authorization", auth.parse().unwrap());
        resign_authorization("GET", "/", "", &mut headers, b"", real_ak, real_secret).unwrap();
        let updated = headers.get("authorization").unwrap().to_str().unwrap();
        assert!(updated.contains(real_ak));
        assert!(!updated.contains(phantom_ak));
        assert!(!updated.contains("deadbeef"));
        assert!(updated.contains("Signature="));
    }
}
