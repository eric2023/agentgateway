// SPDX-License-Identifier: Apache-2.0
// CA certificate loading / generation via rcgen.

use std::path::Path;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Holds the CA certificate and key in rcgen-compatible form for signing leaf certs.
pub struct CaCert {
    /// DER-encoded CA certificate (for rustls + rcgen re-parsing)
    pub cert_der: CertificateDer<'static>,
    /// DER-encoded CA private key (for rustls)
    pub key_der: PrivateKeyDer<'static>,
    /// rcgen CA key pair (for signing)
    ca_key: KeyPair,
}

impl CaCert {
    /// Load CA cert + key from PEM files, or generate new ones if missing.
    pub fn load_or_generate(cert_path: &Path, key_path: &Path) -> Result<Self, String> {
        if cert_path.exists() && key_path.exists() {
            return Self::load_pem(cert_path, key_path);
        }
        eprintln!("[CA] CA files not found, generating new CA...");
        Self::generate_and_save(cert_path, key_path)
    }

    fn load_pem(cert_path: &Path, key_path: &Path) -> Result<Self, String> {
        let cert_pem = std::fs::read_to_string(cert_path)
            .map_err(|e| format!("read cert: {e}"))?;
        let key_pem = std::fs::read_to_string(key_path)
            .map_err(|e| format!("read key: {e}"))?;

        // Parse cert DER from PEM for rustls
        let cert_der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .next()
            .ok_or("no cert in PEM")?
            .map_err(|e| format!("parse cert: {e}"))?;

        // Parse key DER from PEM for rustls
        let key_der = rustls_pemfile::private_key(&mut key_pem.as_bytes())
            .map_err(|e| format!("parse key: {e}"))?
            .ok_or("no key in PEM")?;

        // Load CA key into rcgen KeyPair.
        // rcgen's from_pem may fail on PKCS#1 ("RSA PRIVATE KEY") format;
        // use from_pem_and_sign_algo with PKCS_RSA_SHA256 to handle both.
        let ca_key = KeyPair::from_pem_and_sign_algo(&key_pem, &rcgen::PKCS_RSA_SHA256)
            .map_err(|e| format!("rcgen key pair: {e}"))?;

        eprintln!("[CA] Loaded CA from {} / {}", cert_path.display(), key_path.display());
        Ok(Self { cert_der, key_der, ca_key })
    }

    fn generate_and_save(cert_path: &Path, key_path: &Path) -> Result<Self, String> {
        if let Some(parent) = cert_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        if let Some(parent) = key_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        let mut params = CertificateParams::new(vec![]).map_err(|e| format!("params: {e}"))?;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CountryName, "CN");
        params.distinguished_name.push(DnType::OrganizationName, "AgentGateway Trusted Runtime");
        params.distinguished_name.push(DnType::CommonName, "AgentGateway Root CA");

        let now = time::OffsetDateTime::now_utc();
        params.not_before = now.checked_sub(time::Duration::days(1)).unwrap_or(now);
        params.not_after = now.checked_add(time::Duration::days(3650)).unwrap_or(now);

        let ca_key = KeyPair::generate().map_err(|e| format!("generate key: {e}"))?;
        let cert = params.self_signed(&ca_key).map_err(|e| format!("self_signed: {e}"))?;

        // Save PEM
        let cert_pem = cert.pem();
        std::fs::write(cert_path, cert_pem.as_bytes())
            .map_err(|e| format!("write cert: {e}"))?;

        let key_pem = ca_key.serialize_pem();
        std::fs::write(key_path, key_pem.as_bytes())
            .map_err(|e| format!("write key: {e}"))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600));
        }

        eprintln!("[CA] Generated new CA: {} / {}", cert_path.display(), key_path.display());

        let cert_der = cert.der().clone();
        let key_der = ca_key.serialize_der().try_into()
            .map_err(|e| format!("convert key: {e}"))?;

        Ok(Self { cert_der, key_der, ca_key })
    }

    /// Generate a leaf certificate for the given hostname, signed by the CA.
    pub fn generate_leaf(&self, hostname: &str) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), String> {
        // Re-parse CA params from DER (signed_by consumes CertificateParams)
        let ca_params = CertificateParams::from_ca_cert_der(&self.cert_der)
            .map_err(|e| format!("ca params from der: {e}"))?;

        // Create a Certificate object from CA params for use as issuer in signed_by
        let ca_cert = ca_params.self_signed(&self.ca_key)
            .map_err(|e| format!("ca self_signed: {e}"))?;

        // Leaf cert params
        let mut params = CertificateParams::new(vec![hostname.to_string()])
            .map_err(|e| format!("leaf params: {e}"))?;

        let now = time::OffsetDateTime::now_utc();
        params.not_before = now.checked_sub(time::Duration::days(1)).unwrap_or(now);
        params.not_after = now.checked_add(time::Duration::days(365)).unwrap_or(now);

        let key_pair = KeyPair::generate().map_err(|e| format!("gen leaf key: {e}"))?;

        let cert = params.signed_by(&key_pair, &ca_cert, &self.ca_key)
            .map_err(|e| format!("signed_by: {e}"))?;

        let cert_der = cert.der().clone();
        let key_der = key_pair.serialize_der().try_into()
            .map_err(|e| format!("convert leaf key: {e}"))?;

        Ok((cert_der, key_der))
    }
}
