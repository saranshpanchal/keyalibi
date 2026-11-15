//! Pin DNS answers and refuse private, loopback, and link-local targets
//! unless the policy explicitly allows them. This blocks the metadata address
//! `169.254.169.254` and DNS-rebinding tricks that swap a public name for an
//! internal address between check and connect: we connect to the address we
//! already checked.

use crate::policy::{Cidr, NetworkPolicy};
use crate::{Error, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Resolved {
    pub addr: SocketAddr,
    #[allow(dead_code)]
    pub host: String,
}

pub async fn resolve_pinned(
    host: &str,
    port: u16,
    network: &NetworkPolicy,
    cidrs: &[Cidr],
) -> Result<Resolved> {
    let host = host.trim_matches(|c| c == '[' || c == ']').to_string();
    if let Ok(ip) = host.parse::<IpAddr>() {
        ensure_permitted(ip, network, cidrs)?;
        return Ok(Resolved {
            addr: SocketAddr::new(ip, port),
            host,
        });
    }
    let lookup_host = host.clone();
    let lookup = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::lookup_host((lookup_host.as_str(), port)),
    )
    .await
    .map_err(|_| Error::new(format!("dns lookup for {host} timed out")))?
    .map_err(|e| Error::new(format!("dns lookup for {host} failed: {e}")))?;
    let addrs: Vec<std::net::SocketAddr> = lookup.collect();

    let mut blocked: Vec<IpAddr> = Vec::new();
    for addr in addrs {
        if ip_permitted(addr.ip(), network, cidrs) {
            return Ok(Resolved { addr, host });
        }
        blocked.push(addr.ip());
    }
    if blocked.is_empty() {
        Err(Error::new(format!(
            "dns lookup for {host} returned no addresses"
        )))
    } else {
        Err(Error::new(format!(
            "refusing {host}: resolved to a blocked address ({})",
            blocked
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )))
    }
}

pub fn ensure_permitted(ip: IpAddr, network: &NetworkPolicy, cidrs: &[Cidr]) -> Result<()> {
    if ip_permitted(ip, network, cidrs) {
        Ok(())
    } else {
        Err(Error::new(format!(
            "refusing {ip}: blocked by the KeyAlibi network policy (private, loopback, or link-local)"
        )))
    }
}

pub fn ip_permitted(ip: IpAddr, network: &NetworkPolicy, cidrs: &[Cidr]) -> bool {
    if cidrs.iter().any(|c| c.contains(ip)) {
        return true;
    }
    let ip = unwrap_v4_mapped(ip);
    if !is_blocked(ip) {
        return true;
    }
    match ip {
        IpAddr::V4(v4) if v4.is_loopback() => network.allow_loopback,
        IpAddr::V6(v6) if v6.is_loopback() => network.allow_loopback,
        IpAddr::V4(v4) if v4.is_link_local() => network.allow_link_local,
        IpAddr::V6(v6) if is_v6_link_local(v6) => network.allow_link_local,
        IpAddr::V4(v4) if v4.is_private() || is_cgnat(v4) => network.allow_private,
        IpAddr::V6(v6) if is_v6_ula(v6) => network.allow_private,
        _ => false,
    }
}

fn unwrap_v4_mapped(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        other => other,
    }
}

pub fn is_blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                || is_cgnat(v4)
                || is_reserved_v4(v4)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || is_v6_ula(v6)
                || is_v6_link_local(v6)
                || is_v6_documentation(v6)
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| is_blocked(IpAddr::V4(v4)))
        }
    }
}

fn is_cgnat(v4: Ipv4Addr) -> bool {
    let [a, b, _, _] = v4.octets();
    a == 100 && (b & 0b1100_0000) == 64
}

fn is_reserved_v4(v4: Ipv4Addr) -> bool {
    let [a, b, _, _] = v4.octets();
    // 192.0.0.0/24 and 198.18.0.0/15 (benchmarking).
    (a == 192 && b == 0) || (a == 198 && (b == 18 || b == 19)) || a >= 240
}

fn is_v6_ula(v6: Ipv6Addr) -> bool {
    (v6.octets()[0] & 0xfe) == 0xfc
}

fn is_v6_link_local(v6: Ipv6Addr) -> bool {
    (v6.octets()[0] == 0xfe) && (v6.octets()[1] & 0xc0) == 0x80
}

fn is_v6_documentation(v6: Ipv6Addr) -> bool {
    let o = v6.octets();
    o[0] == 0x20 && o[1] == 0x01 && o[2] == 0x0d && o[3] == 0xb8
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deny() -> NetworkPolicy {
        NetworkPolicy::default()
    }

    #[test]
    fn metadata_and_private_are_blocked() {
        let policy = deny();
        let meta: IpAddr = "169.254.169.254".parse().unwrap();
        let lan: IpAddr = "10.1.2.3".parse().unwrap();
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        let public: IpAddr = "1.1.1.1".parse().unwrap();
        assert!(is_blocked(meta));
        assert!(!ip_permitted(meta, &policy, &[]));
        assert!(!ip_permitted(lan, &policy, &[]));
        assert!(!ip_permitted(loopback, &policy, &[]));
        assert!(ip_permitted(public, &policy, &[]));
    }

    #[test]
    fn loopback_allow_and_explicit_cidr() {
        let allowed = NetworkPolicy {
            allow_loopback: true,
            ..deny()
        };
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(ip_permitted(loopback, &allowed, &[]));
        let cidr = Cidr::parse("127.0.0.1/32").unwrap();
        assert!(ip_permitted(loopback, &deny(), &[cidr]));
    }
}
