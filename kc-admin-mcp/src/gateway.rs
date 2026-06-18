//! # Gateway Client
//!
//! Proxies tool requests to the `kc-admin-gateway` service.
//!
//! ## Rationale
//! The MCP server itself holds NO administrative credentials. Instead, it forwards validated
//! tool requests to the Gateway, which performs the actual Keycloak API calls using its
//! internal privileged token.
//!
//! ## Security Boundaries
//! * **Trust Anchor**: The Gateway is the only trusted component for Admin API access.
//! * **Identity Propagation**: Forwards the caller's token (for audit) and Actor ID.
//! * **mTLS**: Uses mutual TLS to authenticate itself to the Gateway.
//!
//! ## References
//! * **DESIGN**: `docs/design/admin-mcp-gateway-protocol.md`

use axum::http::Method;
use reqwest::Url;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore};
use serde_json::Value;
use thiserror::Error;
use tracing::{error, warn};

use crate::auth::AuthContext;
use crate::config::GatewayConfig;
use crate::metrics::Metrics;

/// HTTP client that proxies MCP tool requests to the gateway service.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
#[derive(Clone)]
pub struct GatewayClient {
    base_url: Url,
    client: reqwest::Client,
    metrics: Option<std::sync::Arc<Metrics>>,
}

/// Errors returned while calling the gateway service.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
#[derive(Error, Debug)]
pub enum GatewayError {
    #[error("gateway url is invalid")]
    InvalidUrl,
    #[error("gateway tls configuration invalid: {0}")]
    TlsConfig(&'static str),
    #[error("gateway request failed")]
    RequestFailed,
    #[error("gateway returned non-success status {status}")]
    Upstream {
        status: u16,
        summary: Option<String>,
    },
}

impl GatewayClient {
    /// Create a new gateway client with optional metrics recording.
    ///
    /// # Security
    /// * Loads mTLS certificates from disk (if configured) to authenticate to the Gateway.
    ///
    /// # Errors
    /// * Returns an error if the operation fails.
    ///
    /// # Caveats
    /// * None.
    pub fn new(
        config: &GatewayConfig,
        metrics: Option<std::sync::Arc<Metrics>>,
    ) -> Result<Self, GatewayError> {
        let base_url = Url::parse(&config.base_url).map_err(|_| GatewayError::InvalidUrl)?;
        let timeout = config.request_timeout;
        let client = build_client(config, timeout)?;
        Ok(Self {
            base_url,
            client,
            metrics,
        })
    }

    /// Forward a JSON request to the gateway, propagating auth headers and returning parsed JSON.
    ///
    /// # Errors
    /// Returns `GatewayError` on network failure, TLS errors, or non-200 responses from upstream.
    ///
    /// # Security
    /// * **Header Propagation**: Forwards `Authorization` (Bearer token) and `x-request-id`/`x-actor-id` for audit.
    /// * **Sanitization**: Summarizes upstream error bodies to avoid leaking internal stack traces.
    ///
    /// # Caveats
    /// * None.
    pub async fn request_json(
        &self,
        ctx: &AuthContext,
        method: Method,
        path: &str,
        query: Vec<(String, String)>,
        body: Option<Value>,
    ) -> Result<Value, GatewayError> {
        let mut url = self
            .base_url
            .join(path)
            .map_err(|_| GatewayError::InvalidUrl)?;
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query);
        }

        let method_str = method.as_str().to_string();
        let mut request = self
            .client
            .request(method, url)
            .bearer_auth(&ctx.raw_token)
            .header("x-request-id", &ctx.request_id);

        if let Some(actor_id) = ctx.actor_id.as_ref() {
            request = request.header("x-actor-id", actor_id);
        }

        if let Some(body) = body {
            request = request.json(&body);
        }

        let response = request.send().await.map_err(|err| {
            if err.is_timeout() {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.record_request_timeout("gateway");
                }
            }
            GatewayError::RequestFailed
        })?;
        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .map_err(|_| GatewayError::RequestFailed)?;
        if !status.is_success() {
            let summary = summarize_error_body(&bytes);
            warn!(
                status = status.as_u16(),
                method = %method_str,
                path = %path,
                summary = summary.as_deref().unwrap_or(""),
                "gateway request failed"
            );
            return Err(GatewayError::Upstream {
                status: status.as_u16(),
                summary,
            });
        }

        if bytes.is_empty() {
            return Ok(Value::Null);
        }

        serde_json::from_slice(&bytes).map_err(|_| GatewayError::RequestFailed)
    }
}

const ERROR_BODY_MAX_BYTES: usize = 1024;
const ERROR_SUMMARY_MAX_CHARS: usize = 256;

fn summarize_error_body(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    let slice = if bytes.len() > ERROR_BODY_MAX_BYTES {
        &bytes[..ERROR_BODY_MAX_BYTES]
    } else {
        bytes
    };
    if let Ok(value) = serde_json::from_slice::<Value>(slice) {
        if let Some(obj) = value.as_object() {
            let mut parts = Vec::new();
            for (key, label) in [
                ("error", "error"),
                ("error_description", "error_description"),
                ("errorMessage", "error_message"),
                ("message", "message"),
            ] {
                if let Some(val) = obj.get(key).and_then(|v| v.as_str()) {
                    let trimmed = sanitize_summary(val);
                    if !trimmed.is_empty() {
                        parts.push(format!("{label}={trimmed}"));
                    }
                }
            }
            if !parts.is_empty() {
                return Some(truncate_summary(&parts.join("; ")));
            }
        }
    }
    let text = String::from_utf8_lossy(slice);
    let trimmed = sanitize_summary(text.as_ref());
    if trimmed.is_empty() {
        None
    } else {
        Some(truncate_summary(&trimmed))
    }
}

fn sanitize_summary(input: &str) -> String {
    input
        .chars()
        .filter(|ch| !ch.is_control())
        .collect::<String>()
        .trim()
        .to_string()
}

fn truncate_summary(input: &str) -> String {
    if input.chars().count() <= ERROR_SUMMARY_MAX_CHARS {
        return input.to_string();
    }
    let truncated: String = input.chars().take(ERROR_SUMMARY_MAX_CHARS).collect();
    format!("{truncated}…")
}

/// Build the `reqwest::Client` used to call the gateway.
fn build_client(
    config: &GatewayConfig,
    timeout: std::time::Duration,
) -> Result<reqwest::Client, GatewayError> {
    let mut builder = reqwest::Client::builder().timeout(timeout);

    let needs_custom_tls = config.tls_ca_pem.is_some()
        || config.tls_client_cert_pem.is_some()
        || config.tls_client_key_pem.is_some();

    if needs_custom_tls {
        let tls_config = build_rustls_client_config(config)?;
        builder = builder.use_preconfigured_tls(tls_config);
    } else {
        builder = builder.use_rustls_tls();
    }

    builder.build().map_err(|err| {
        error!(error = ?err, "failed to build gateway http client");
        GatewayError::RequestFailed
    })
}

/// Construct a rustls client config from the gateway TLS settings.
fn build_rustls_client_config(config: &GatewayConfig) -> Result<ClientConfig, GatewayError> {
    let mut roots = RootCertStore::empty();
    if let Some(ca_pem) = config.tls_ca_pem.as_ref() {
        let certs = parse_certs(ca_pem)?;
        let (added, _ignored) = roots.add_parsable_certificates(certs);
        if added == 0 {
            return Err(GatewayError::TlsConfig(
                "no valid CA certificates found for gateway",
            ));
        }
    } else {
        return Err(GatewayError::TlsConfig("gateway CA is required for mTLS"));
    }

    let builder = ClientConfig::builder().with_root_certificates(roots);
    match (
        config.tls_client_cert_pem.as_ref(),
        config.tls_client_key_pem.as_ref(),
    ) {
        (Some(cert), Some(key)) => {
            let certs = parse_certs(cert)?;
            let key = parse_key(key)?;
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|_| GatewayError::TlsConfig("invalid client TLS identity".into()))
        }
        (None, None) => Ok(builder.with_no_client_auth()),
        _ => Err(GatewayError::TlsConfig(
            "client cert and key must be provided together",
        )),
    }
}

/// Parse PEM-encoded CA certificates for the gateway TLS config.
fn parse_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>, GatewayError> {
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| GatewayError::TlsConfig("invalid certificate PEM".into()))
}

/// Parse a PEM-encoded private key for mTLS client identity.
fn parse_key(pem: &str) -> Result<PrivateKeyDer<'static>, GatewayError> {
    match PrivateKeyDer::from_pem_slice(pem.as_bytes()) {
        Ok(key) => Ok(key),
        Err(rustls::pki_types::pem::Error::NoItemsFound) => {
            Err(GatewayError::TlsConfig("private key PEM required"))
        }
        Err(_) => Err(GatewayError::TlsConfig("invalid private key PEM")),
    }
}
