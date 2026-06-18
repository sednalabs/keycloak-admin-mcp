//! # Gateway TLS
//!
//! TLS and mTLS configuration for the security gateway.
//!
//! ## Rationale
//! Ensures that the gateway's administrative endpoint is protected by high-strength
//! encryption and optional client certificate requirements.
//!
//! ## Security Boundaries
//! * **mTLS Gating**: Controls whether the gateway enforces client identity via TLS.

use std::sync::Arc;

use axum_server::tls_rustls::RustlsConfig;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};

use crate::config::GatewayConfig;
use crate::errors::GatewayError;

/// Construct the Rustls configuration when TLS/mTLS is enabled.
///
/// # Security
/// * **Native Verification**: Uses `WebPkiClientVerifier` for standard mTLS enforcement.
///
/// # Errors
/// * Returns an error if the operation fails.
///
/// # Caveats
/// * None.
pub fn build_tls_config(config: &GatewayConfig) -> Result<Option<RustlsConfig>, GatewayError> {
    let cert_pem = match config.tls_cert_pem.as_ref() {
        Some(value) => value,
        None => {
            if config.tls_key_pem.is_some()
                || config.tls_client_ca_pem.is_some()
                || config.mtls_required
            {
                return Err(GatewayError::InvalidConfig(
                    "KC_GATEWAY_TLS_CERT is required when TLS is enabled".to_string(),
                ));
            }
            return Ok(None);
        }
    };
    let key_pem = config.tls_key_pem.as_ref().ok_or_else(|| {
        GatewayError::InvalidConfig(
            "KC_GATEWAY_TLS_KEY is required when TLS is enabled".to_string(),
        )
    })?;

    let certs = load_certs(cert_pem)?;
    let key = load_key(key_pem)?;

    let verifier = if config.mtls_required {
        let ca_pem = config.tls_client_ca_pem.as_ref().ok_or_else(|| {
            GatewayError::InvalidConfig(
                "KC_GATEWAY_TLS_CLIENT_CA is required when mTLS is enabled".to_string(),
            )
        })?;
        let roots = load_root_store(ca_pem)?;
        WebPkiClientVerifier::builder(roots.into())
            .build()
            .map_err(|_| {
                GatewayError::InvalidConfig("Failed to build client cert verifier".to_string())
            })?
    } else {
        WebPkiClientVerifier::no_client_auth()
    };

    let server_config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|_| GatewayError::InvalidConfig("Invalid TLS certificate or key".to_string()))?;

    Ok(Some(RustlsConfig::from_config(Arc::new(server_config))))
}

/// Parse PEM bytes into `CertificateDer` structures, failing when the certificates are malformed.
fn load_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>, GatewayError> {
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| GatewayError::InvalidConfig("Failed to parse TLS certificate PEM".to_string()))
}

/// Parse a PEM-encoded private key for server TLS and report invalid data as configuration errors.
fn load_key(pem: &str) -> Result<PrivateKeyDer<'static>, GatewayError> {
    match PrivateKeyDer::from_pem_slice(pem.as_bytes()) {
        Ok(key) => Ok(key),
        Err(rustls::pki_types::pem::Error::NoItemsFound) => Err(GatewayError::InvalidConfig(
            "TLS private key PEM is required".to_string(),
        )),
        Err(_) => Err(GatewayError::InvalidConfig(
            "Failed to parse TLS private key PEM".to_string(),
        )),
    }
}

/// Load a root store from PEM CAs for client certificate verification when mTLS is configured.
fn load_root_store(pem: &str) -> Result<RootCertStore, GatewayError> {
    let certs = load_certs(pem)?;
    let mut store = RootCertStore::empty();
    let (added, _ignored) = store.add_parsable_certificates(certs);
    if added == 0 {
        return Err(GatewayError::InvalidConfig(
            "No valid CA certificates found".to_string(),
        ));
    }
    Ok(store)
}
