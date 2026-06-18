//! # TLS Configuration
//!
//! Handles loading and configuring TLS/mTLS for the MCP server.
//!
//! ## Rationale
//! Ensures that the server provides a secure identity via TLS and optionally
//! requires client certificates (mTLS) for high-security environments.
//!
//! ## Security Boundaries
//! * **Identity Proof**: Requires valid private keys and certificate chains.
//! * **Mutual TLS**: Implements native client certificate verification.

use std::sync::Arc;

use axum_server::tls_rustls::RustlsConfig;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};

use crate::config::{Config, MtlsMode};

/// Build the server TLS configuration (and optional mTLS verifier) from env config.
///
/// # Security
/// * **Validation**: Fails fast if required TLS/mTLS material is missing or invalid.
///
/// # Errors
/// * Returns an error if the operation fails.
///
/// # Caveats
/// * None.
pub fn build_tls_config(config: &Config) -> Result<Option<RustlsConfig>, String> {
    let cert_pem = match config.server_tls.cert_pem.as_ref() {
        Some(value) => value,
        None => {
            if config.server_tls.key_pem.is_some()
                || config.server_tls.client_ca_pem.is_some()
                || config.auth.mtls_mode == MtlsMode::Native
            {
                return Err("KC_ADMIN_MCP_TLS_CERT is required when TLS is enabled".to_string());
            }
            return Ok(None);
        }
    };

    let key_pem = config
        .server_tls
        .key_pem
        .as_ref()
        .ok_or_else(|| "KC_ADMIN_MCP_TLS_KEY is required when TLS is enabled".to_string())?;

    let certs = load_certs(cert_pem)?;
    let key = load_key(key_pem)?;

    let verifier = if config.auth.mtls_mode == MtlsMode::Native {
        let ca_pem = config.server_tls.client_ca_pem.as_ref().ok_or_else(|| {
            "KC_ADMIN_MCP_TLS_CLIENT_CA is required when mTLS is enabled".to_string()
        })?;
        let roots = load_root_store(ca_pem)?;
        WebPkiClientVerifier::builder(roots.into())
            .build()
            .map_err(|_| "Failed to build client cert verifier".to_string())?
    } else {
        WebPkiClientVerifier::no_client_auth()
    };

    let server_config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|_| "Invalid TLS certificate or key".to_string())?;

    Ok(Some(RustlsConfig::from_config(Arc::new(server_config))))
}

/// Parse PEM certificates for the server TLS identity or mTLS CA bundle.
fn load_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "Failed to parse TLS certificate PEM".to_string())
}

/// Parse a PEM private key for the server TLS identity.
fn load_key(pem: &str) -> Result<PrivateKeyDer<'static>, String> {
    match PrivateKeyDer::from_pem_slice(pem.as_bytes()) {
        Ok(key) => Ok(key),
        Err(rustls::pki_types::pem::Error::NoItemsFound) => {
            Err("TLS private key PEM is required".to_string())
        }
        Err(_) => Err("Failed to parse TLS private key PEM".to_string()),
    }
}

/// Load a `RootCertStore` from PEM for mTLS validation.
fn load_root_store(pem: &str) -> Result<RootCertStore, String> {
    let certs = load_certs(pem)?;
    let mut store = RootCertStore::empty();
    let (added, _ignored) = store.add_parsable_certificates(certs);
    if added == 0 {
        return Err("No valid CA certificates found".to_string());
    }
    Ok(store)
}
