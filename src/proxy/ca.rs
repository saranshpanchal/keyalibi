//! Per-session root CA. Leaf certificates are minted on demand for Topology B
//! TLS interception. The private key stays in the supervisor; only the
//! certificate PEM is written for child processes.

use crate::{Error, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::ServerConfig;
use rustls::{ClientConfig, RootCertStore};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub struct SessionCa {
    ca_pem: String,
    inner: Mutex<CaInner>,
    client_config: Arc<ClientConfig>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

struct CaInner {
    ca_cert: rcgen::Certificate,
    ca_key: KeyPair,
    leaves: HashMap<String, Arc<ServerConfig>>,
}

impl SessionCa {
    pub fn generate() -> Result<Self> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, "KeyAlibi Session CA");
        name.push(DnType::OrganizationName, "KeyAlibi");
        params.distinguished_name = name;
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_key = KeyPair::generate().map_err(|err| Error::new(err.to_string()))?;
        let ca_cert = params
            .self_signed(&ca_key)
            .map_err(|err| Error::new(err.to_string()))?;
        let ca_pem = ca_cert.pem();
        let client_config = upstream_client_config(Arc::clone(&provider))?;
        Ok(Self {
            ca_pem,
            inner: Mutex::new(CaInner {
                ca_cert,
                ca_key,
                leaves: HashMap::new(),
            }),
            client_config,
            provider,
        })
    }

    pub fn cert_pem(&self) -> &str {
        &self.ca_pem
    }

    pub fn client_config(&self) -> Arc<ClientConfig> {
        Arc::clone(&self.client_config)
    }

    /// Write `session-ca.pem` (this CA only) and `ca-bundle.pem` (system
    /// bundle plus this CA). Returns `(bundle, ca_only)`.
    pub fn write_trust_files(&self, dir: &Path) -> Result<(PathBuf, PathBuf)> {
        std::fs::create_dir_all(dir)?;
        let ca_only = dir.join("session-ca.pem");
        let bundle_path = dir.join("ca-bundle.pem");
        std::fs::write(&ca_only, &self.ca_pem)?;
        let mut bundle = String::new();
        if let Ok(system) = std::fs::read_to_string("/etc/ssl/certs/ca-certificates.crt") {
            bundle.push_str(&system);
            if !bundle.ends_with('\n') {
                bundle.push('\n');
            }
        }
        bundle.push_str(&self.ca_pem);
        if !bundle.ends_with('\n') {
            bundle.push('\n');
        }
        std::fs::write(&bundle_path, bundle)?;
        Ok((bundle_path, ca_only))
    }

    pub fn server_config_for(&self, host: &str) -> Result<Arc<ServerConfig>> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| Error::new("session CA lock poisoned"))?;
        if let Some(existing) = inner.leaves.get(host) {
            return Ok(Arc::clone(existing));
        }
        let mut params = CertificateParams::new(vec![host.to_string()])
            .map_err(|err| Error::new(err.to_string()))?;
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, host);
        params.distinguished_name = name;
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let leaf_key = KeyPair::generate().map_err(|err| Error::new(err.to_string()))?;
        let leaf = params
            .signed_by(&leaf_key, &inner.ca_cert, &inner.ca_key)
            .map_err(|err| Error::new(err.to_string()))?;
        let certs = vec![
            CertificateDer::from(leaf.der().to_vec()),
            CertificateDer::from(inner.ca_cert.der().to_vec()),
        ];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let mut server = ServerConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_safe_default_protocol_versions()
            .map_err(|err| Error::new(err.to_string()))?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|err| Error::new(format!("leaf certificate for {host}: {err}")))?;
        server.alpn_protocols = vec![b"http/1.1".to_vec()];
        let server = Arc::new(server);
        inner.leaves.insert(host.to_string(), Arc::clone(&server));
        Ok(server)
    }

    pub fn server_name(host: &str) -> Result<ServerName<'static>> {
        ServerName::try_from(host.to_string())
            .map_err(|_| Error::new(format!("invalid server name {host}")))
    }
}

fn upstream_client_config(
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|err| Error::new(err.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}
