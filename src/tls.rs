// SPDX-License-Identifier: Apache-2.0
// TLS MITM: dynamic certificate generation using CA + rustls.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use rustls::server::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use crate::ca::CaCert;

const CACHE_MAX: usize = 1000;

struct TlsCert {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

/// Simple FIFO-eviction cert cache (re-generated on eviction is cheap).
struct CertCache {
    map: HashMap<String, Arc<TlsCert>>,
    order: VecDeque<String>,
}

impl CertCache {
    fn new() -> Self {
        Self { map: HashMap::new(), order: VecDeque::new() }
    }

    fn get(&self, key: &str) -> Option<Arc<TlsCert>> {
        self.map.get(key).cloned()
    }

    fn insert(&mut self, key: String, val: Arc<TlsCert>) {
        if self.map.contains_key(&key) {
            return; // already cached
        }
        if self.map.len() >= CACHE_MAX {
            // Evict oldest entry (FIFO)
            if let Some(oldest) = self.order.pop_front() {
                self.map.remove(&oldest);
            }
        }
        self.order.push_back(key.clone());
        self.map.insert(key, val);
    }
}

pub struct Certifier {
    ca: Arc<CaCert>,
    cache: RwLock<CertCache>,
}

impl Certifier {
    pub fn new(ca: CaCert) -> Self {
        Self {
            ca: Arc::new(ca),
            cache: RwLock::new(CertCache::new()),
        }
    }

    /// Get or generate a TLS cert for the given hostname.
    fn get_cert(&self, hostname: &str) -> Result<Arc<TlsCert>, String> {
        // Check cache
        {
            let cache = self.cache.read().unwrap();
            if let Some(c) = cache.get(hostname) {
                return Ok(c);
            }
        }

        // Generate new cert
        let (cert_der, key_der) = self.ca.generate_leaf(hostname)?;
        let tls_cert = Arc::new(TlsCert { cert: cert_der, key: key_der });

        let mut cache = self.cache.write().unwrap();
        cache.insert(hostname.to_string(), tls_cert.clone());
        Ok(tls_cert)
    }

    /// Build a rustls ServerConfig for the given hostname.
    pub fn server_config(&self, hostname: &str) -> Result<Arc<ServerConfig>, String> {
        let tls_cert = self.get_cert(hostname)?;

        let certs = vec![tls_cert.cert.clone()];
        let key = tls_cert.key.clone_key();

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| format!("server config: {e}"))?;

        Ok(Arc::new(config))
    }

    /// Build a rustls ClientConfig for connecting to upstream (insecure mode).
    pub fn client_config_insecure() -> Arc<rustls::ClientConfig> {
        let dangerous_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
            .with_no_client_auth();

        Arc::new(dangerous_config)
    }

    /// Build a rustls ClientConfig for connecting to upstream with proper cert verification.
    pub fn client_config_secure() -> Arc<rustls::ClientConfig> {
        let root_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        )
    }
}

#[derive(Debug)]
struct InsecureVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}
