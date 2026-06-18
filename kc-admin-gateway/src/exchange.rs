//! # Token Exchange
//!
//! Handles RFC 8693 OAuth 2.0 Token Exchange for the gateway.
//!
//! ## Rationale
//! The gateway receives a broad "machine token" but needs to perform a specific administrative
//! action. This module swaps the broad token for a strictly scoped "downstream token" that
//! has only the permissions required for the requested URL.
//!
//! ## Security Boundaries
//! * **Privilege Reduction**: Ensures the upstream request carries the minimum necessary privileges.
//! * **Sanitization**: Logs exchange failures but redacts the raw token bodies.
//!
//! ## References
//! * **SPEC**: [RFC 8693](https://tools.ietf.org/html/rfc8693)

use serde::Deserialize;
use tracing::{info, warn};

use crate::config::GatewayConfig;
use crate::errors::GatewayError;
use crate::http::post_form_with_auth;
use crate::log_sanitize::sanitize_exchange_error;
use crate::logging::LOG_TARGET_AUTH;

/// Defines ExchangeResponse.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
#[derive(Debug, Deserialize)]
pub(crate) struct ExchangeResponse {
    access_token: String,
    token_type: Option<String>,
    expires_in: Option<u64>,
}

/// Exchange a token issued to the gateway for a new admin token scoped to `requested_scopes`.
/// This only runs when `exchange_enabled` is true and the exchange endpoint/tokens are configured,
/// and it logs sanitized failures before returning `GatewayError` so the caller can fail securely.
/// Notes: the resulting token is used for proxied admin requests, so no scopes are escalated beyond `requested_scopes`.
///
/// # Security
/// * **Scope Limitation**: Explicitly requests *only* the scopes derived from the URL path.
/// * **Audience restriction**: Binds the new token to the exchange audience if configured.
///
/// # Errors
/// * Returns an error if the operation fails.
///
/// # Caveats
/// * None.
pub async fn exchange_token(
    client: &reqwest::Client,
    cfg: &GatewayConfig,
    subject_token: &str,
    requested_scopes: &[&str],
    request_id: &str,
) -> Result<ExchangeResponse, GatewayError> {
    if cfg.exchange_url.is_empty() {
        return Err(GatewayError::InvalidConfig(
            "KC_GATEWAY_EXCHANGE_URL is required".to_string(),
        ));
    }

    if !cfg.exchange_enabled {
        return Err(GatewayError::InvalidConfig(
            "token exchange disabled".to_string(),
        ));
    }

    let mut form = vec![
        (
            "grant_type".to_string(),
            "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
        ),
        (
            "subject_token_type".to_string(),
            "urn:ietf:params:oauth:token-type:access_token".to_string(),
        ),
        (
            "requested_token_type".to_string(),
            "urn:ietf:params:oauth:token-type:access_token".to_string(),
        ),
        ("subject_token".to_string(), subject_token.to_string()),
    ];

    if let Some(audience) = cfg.exchange_audience.as_ref() {
        form.push(("audience".to_string(), audience.to_string()));
    }

    if let Some(resource) = cfg.exchange_resource.as_ref() {
        form.push(("resource".to_string(), resource.to_string()));
    }

    if !requested_scopes.is_empty() {
        form.push(("scope".to_string(), requested_scopes.join(" ")));
    }

    let response = post_form_with_auth(
        client,
        &cfg.exchange_url,
        &cfg.exchange_auth_method,
        &cfg.exchange_client_id,
        &cfg.exchange_client_secret,
        form,
    )
    .await?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        if cfg.log_exchange_body {
            let body = response.text().await.unwrap_or_default();
            let sanitized = sanitize_exchange_error(&body, cfg.log_exchange_body_max_bytes);
            warn!(
                target: LOG_TARGET_AUTH,
                request_id = %request_id,
                status,
                body = %sanitized,
                "token exchange failed"
            );
        } else {
            warn!(
                target: LOG_TARGET_AUTH,
                request_id = %request_id,
                status,
                "token exchange failed"
            );
        }
        return Err(GatewayError::ExchangeFailed);
    }

    response.json::<ExchangeResponse>().await.map_err(|err| {
        warn!(
            target: LOG_TARGET_AUTH,
            request_id = %request_id,
            error = ?err,
            "token exchange response parse failed"
        );
        GatewayError::ExchangeFailed
    })
}

/// Validate and emit the access token from an exchange result.
/// Rejects responses that lack a bearer token, omit `expires_in`, or report a zero lifetime and logs warnings to the auth target.
///
/// # Errors
/// * Returns an error if the operation fails.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
pub fn extract_access_token(
    exchange: ExchangeResponse,
    request_id: &str,
) -> Result<String, GatewayError> {
    if exchange.access_token.is_empty() {
        return Err(GatewayError::ExchangeFailed);
    }

    let token_type = exchange.token_type.as_deref();
    if let Some(token_type) = token_type {
        if !token_type.eq_ignore_ascii_case("Bearer") {
            warn!(
                target: LOG_TARGET_AUTH,
                request_id = %request_id,
                token_type = %token_type,
                "token exchange returned unexpected token_type"
            );
            return Err(GatewayError::ExchangeFailed);
        }
    } else {
        warn!(
            target: LOG_TARGET_AUTH,
            request_id = %request_id,
            "token exchange missing token_type"
        );
        return Err(GatewayError::ExchangeFailed);
    }

    match exchange.expires_in {
        Some(0) => {
            warn!(
                target: LOG_TARGET_AUTH,
                request_id = %request_id,
                "token exchange returned zero expires_in"
            );
            return Err(GatewayError::ExchangeFailed);
        }
        Some(expires_in) => {
            info!(
                target: LOG_TARGET_AUTH,
                request_id = %request_id,
                token_type = %token_type.unwrap_or("unknown"),
                expires_in,
                "token exchange issued access token"
            );
        }
        None => {
            warn!(
                target: LOG_TARGET_AUTH,
                request_id = %request_id,
                "token exchange missing expires_in"
            );
            return Err(GatewayError::ExchangeFailed);
        }
    }
    Ok(exchange.access_token)
}

#[cfg(test)]
mod tests {
    use super::{extract_access_token, ExchangeResponse};

    fn exchange_response(token_type: Option<&str>, expires_in: Option<u64>) -> ExchangeResponse {
        ExchangeResponse {
            access_token: "downscoped-token".to_string(),
            token_type: token_type.map(str::to_string),
            expires_in,
        }
    }

    #[test]
    fn extract_access_token_rejects_missing_token_type() {
        let exchange = exchange_response(None, Some(300));
        let result = extract_access_token(exchange, "req-test");
        assert!(result.is_err());
    }

    #[test]
    fn extract_access_token_rejects_non_bearer_token_type() {
        let exchange = exchange_response(Some("mac"), Some(300));
        let result = extract_access_token(exchange, "req-test");
        assert!(result.is_err());
    }

    #[test]
    fn extract_access_token_rejects_missing_expires_in() {
        let exchange = exchange_response(Some("bearer"), None);
        let result = extract_access_token(exchange, "req-test");
        assert!(result.is_err());
    }

    #[test]
    fn extract_access_token_rejects_zero_expires_in() {
        let exchange = exchange_response(Some("bearer"), Some(0));
        let result = extract_access_token(exchange, "req-test");
        assert!(result.is_err());
    }

    #[test]
    fn extract_access_token_accepts_bearer_with_positive_expires_in() {
        let exchange = exchange_response(Some("Bearer"), Some(300));
        let result = extract_access_token(exchange, "req-test").expect("valid exchange");
        assert_eq!(result, "downscoped-token");
    }
}
