//! # Gateway HTTP Client
//!
//! Shared HTTP client and request logic for communication with Keycloak.
//!
//! ## Rationale
//! Centralizes HTTP configuration, including timeouts and client authentication styles.
//! This ensures that all requests to the IdP are performed consistently and securely.
//!
//! ## Security Boundaries
//! * **Client Authentication**: Implements RFC 6749 client authentication styles.
//! * **Timeout Enforcement**: Prevents request hanging and resource exhaustion.

use reqwest::{Client, Response};

use crate::config::{ClientAuthMethod, GatewayConfig};
use crate::errors::GatewayError;

/// Build a `reqwest::Client` used by the gateway for external requests (introspection, exchange).
///
/// # Errors
/// * Returns an error if the operation fails.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
pub fn build_client(cfg: &GatewayConfig) -> Result<Client, GatewayError> {
    Client::builder()
        .timeout(cfg.request_timeout)
        .build()
        .map_err(|err| GatewayError::InvalidConfig(format!("http client init failed: {err}")))
}

/// POST a form to Keycloak with the chosen client auth method (Basic or POST).
///
/// # Security
/// * **Credentials**: Correctly applies `client_secret` based on the configured auth method.
///
/// # Errors
/// * Returns an error if the operation fails.
///
/// # Caveats
/// * None.
pub async fn post_form_with_auth(
    client: &Client,
    url: &str,
    auth_method: &ClientAuthMethod,
    client_id: &str,
    client_secret: &str,
    form: Vec<(String, String)>,
) -> Result<Response, GatewayError> {
    let mut params = form;

    let mut request = client.post(url);

    match auth_method {
        ClientAuthMethod::ClientSecretBasic => {
            request = request.basic_auth(client_id, Some(client_secret));
        }
        ClientAuthMethod::ClientSecretPost => {
            params.push(("client_id".to_string(), client_id.to_string()));
            params.push(("client_secret".to_string(), client_secret.to_string()));
        }
    }

    request
        .form(&params)
        .send()
        .await
        .map_err(|err| GatewayError::Upstream(format!("request to {url} failed: {err}")))
}
