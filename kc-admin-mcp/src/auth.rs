//! # Auth Module
//!
//! Handles request authentication and context extraction for the MCP server.
//!
//! ## Rationale
//! Bridges the raw HTTP request and the internal `AuthContext`. It uses `mcp-toolkit-auth`
//! for JWT validation but adds domain-specific checks like `azp` (Authorized Party) allow-listing
//! and mTLS header validation.
//!
//! ## Security Boundaries
//! * **Untrusted**: HTTP headers (Authorization, mTLS headers).
//! * **Enforcement**: Blocks requests before they reach any tool logic.
//!
//! ## References
//! * **SPEC**: [OAuth 2.0 (RFC 6749)](https://oauth.net/2/)

use axum::http::HeaderMap;
use mcp_toolkit_auth::{
    AuthConfig as ToolkitAuthConfig, AuthError as ToolkitAuthError, AuthMode as ToolkitAuthMode,
    Authenticator, ClientAuthMethod as ToolkitClientAuthMethod,
};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

use crate::config::{AuthMode, ClientAuthMethod, Config, MtlsMode};

/// Authentication metadata produced after validating an incoming request.
/// Exposed via request extensions and consumed by tools for scope/role gating.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct AuthContext {
    pub request_id: String,
    pub actor_id: Option<String>,
    pub raw_token: String,
    pub token_ref: String,
    pub client_id: Option<String>,
    pub subject: Option<String>,
    pub scopes: Vec<String>,
    pub roles: Vec<String>,
    pub expires_at: Option<i64>,
    pub azp: Option<String>,
    pub issuer: Option<String>,
}

/// Errors returned when the MCP server rejects a request for authentication reasons.
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
pub enum AuthError {
    #[error("missing bearer token")]
    MissingToken,
    #[error("invalid bearer token")]
    InvalidToken,
    #[error("token inactive")]
    TokenInactive,
    #[error("token expired")]
    TokenExpired,
    #[error("token not allowed")]
    Forbidden(String),
    #[error("auth not supported: {0}")]
    NotSupported(String),
    #[error("introspection failed")]
    IntrospectionFailed,
}

impl AuthError {
    /// Return the HTTP status code for this auth error.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Caveats
    /// * None.
    pub fn status_code(&self) -> axum::http::StatusCode {
        match self {
            AuthError::MissingToken
            | AuthError::InvalidToken
            | AuthError::TokenInactive
            | AuthError::TokenExpired => axum::http::StatusCode::UNAUTHORIZED,
            AuthError::Forbidden(_) => axum::http::StatusCode::FORBIDDEN,
            AuthError::NotSupported(_) => axum::http::StatusCode::SERVICE_UNAVAILABLE,
            AuthError::IntrospectionFailed => axum::http::StatusCode::BAD_GATEWAY,
        }
    }

    /// Return the stable error code string for this auth error.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Caveats
    /// * None.
    pub fn code(&self) -> &'static str {
        match self {
            AuthError::MissingToken => "auth.missing_token",
            AuthError::InvalidToken => "auth.invalid_token",
            AuthError::TokenInactive => "auth.inactive_token",
            AuthError::TokenExpired => "auth.expired_token",
            AuthError::Forbidden(_) => "auth.forbidden",
            AuthError::NotSupported(_) => "auth.not_supported",
            AuthError::IntrospectionFailed => "auth.introspection_failed",
        }
    }
}

/// Build the shared toolkit authenticator from MCP configuration.
///
/// # Security
/// * Configures the JWKS/Introspection clients used for all subsequent validation.
///
/// # Errors
/// * Returns an error if the operation fails.
///
/// # Caveats
/// * None.
pub fn build_authenticator(config: &Config) -> Result<Authenticator, String> {
    let mode = match config.auth.mode {
        AuthMode::Jwks => ToolkitAuthMode::Jwks,
        AuthMode::Introspection => ToolkitAuthMode::Introspection,
    };
    let auth_method = match config.auth.introspection_auth_method {
        ClientAuthMethod::ClientSecretBasic => ToolkitClientAuthMethod::ClientSecretBasic,
        ClientAuthMethod::ClientSecretPost => ToolkitClientAuthMethod::ClientSecretPost,
    };

    let toolkit_config = ToolkitAuthConfig {
        mode,
        strict_oauth: true,
        jwks_url: config.auth.jwks_url.clone(),
        issuer: config.auth.issuer.clone(),
        audience: config.auth.audience.clone(),
        required_scopes: Vec::new(),
        actor_claim: "sub".to_string(),
        introspection_url: opt_non_empty(&config.auth.introspection_url),
        introspection_client_id: opt_non_empty(&config.auth.introspection_client_id),
        introspection_client_secret: opt_non_empty(&config.auth.introspection_client_secret),
        introspection_auth_method: auth_method,
        introspection_cache_ttl_s: 0.0,
        introspection_force: false,
        delegation_secret: None,
        delegation_issuer: "mcp-toolkit".to_string(),
        delegation_audience: "mcp-toolkit".to_string(),
        jti_ttl_s: 0.0,
        jti_cache_size: 0,
        jti_enforce_bearer: false,
        clock_skew_s: config.auth.clock_skew_seconds as f64,
    };

    Authenticator::new(toolkit_config).map_err(|err| err.to_string())
}

/// Authenticate the inbound MCP request using bearer tokens and resource server checks.
/// Produces an `AuthContext` with scopes/roles that downstream tools inspect.
///
/// # Errors
/// Returns `AuthError` if the token is missing, expired, invalid, or if the client/azp
/// is not in the allow-list.
///
/// # Security
/// * **Clock Skew**: Enforces expiration checks.
/// * **Allow-Listing**: Validates `azp` and `client_id` against config to prevent unauthorized clients.
/// * **mTLS**: Enforces proxy header presence if configured.
///
/// # Caveats
/// * None.
pub async fn authenticate_request(
    headers: &HeaderMap,
    config: &Config,
    authenticator: &Authenticator,
    request_id: &str,
    actor_id: Option<String>,
) -> Result<AuthContext, AuthError> {
    if config.auth.dpop_required {
        return Err(AuthError::NotSupported(
            "DPoP validation is not implemented in kc-admin-mcp".to_string(),
        ));
    }

    if config.auth.mtls_mode == MtlsMode::ProxyHeader {
        let header_name = config
            .auth
            .mtls_client_cert_header
            .as_deref()
            .unwrap_or("x-forwarded-client-cert");
        if headers.get(header_name).is_none() {
            return Err(AuthError::Forbidden(
                "mTLS client certificate required".to_string(),
            ));
        }
    }

    let toolkit_ctx = authenticator
        .authenticate_headers(headers)
        .await
        .map_err(map_toolkit_error)?;

    if let Some(exp) = claim_i64(&toolkit_ctx.claims, "exp") {
        let now = unix_now();
        if exp + config.auth.clock_skew_seconds < now {
            return Err(AuthError::TokenExpired);
        }
    }

    let azp = toolkit_ctx
        .azp
        .clone()
        .or_else(|| claim_string(&toolkit_ctx.claims, "client_id"));

    if caller_allowlists_break_glass_expired(config) {
        return Err(AuthError::Forbidden(
            "break-glass caller allowlist TTL expired".to_string(),
        ));
    }

    if !config.auth.allowed_azp.is_empty() {
        let allowed = azp
            .as_ref()
            .map(|value| {
                config
                    .auth
                    .allowed_azp
                    .iter()
                    .any(|allowed| allowed == value)
            })
            .unwrap_or(false);
        if !allowed {
            return Err(AuthError::Forbidden("azp not allowed".to_string()));
        }
    }

    let client_id = claim_string(&toolkit_ctx.claims, "client_id").or_else(|| azp.clone());
    if !config.auth.allowed_client_ids.is_empty() {
        let allowed = client_id
            .as_ref()
            .map(|value| {
                config
                    .auth
                    .allowed_client_ids
                    .iter()
                    .any(|allowed| allowed == value)
            })
            .unwrap_or(false);
        if !allowed {
            return Err(AuthError::Forbidden("client_id not allowed".to_string()));
        }
    }

    Ok(AuthContext {
        request_id: request_id.to_string(),
        actor_id,
        raw_token: toolkit_ctx.raw_token,
        token_ref: toolkit_ctx.token_ref,
        client_id,
        subject: toolkit_ctx.subject,
        scopes: toolkit_ctx.scopes,
        roles: toolkit_ctx.roles,
        expires_at: claim_i64(&toolkit_ctx.claims, "exp"),
        azp,
        issuer: claim_string(&toolkit_ctx.claims, "iss"),
    })
}

fn caller_allowlists_break_glass_expired(config: &Config) -> bool {
    config.auth.allowed_azp.is_empty()
        && config.auth.allowed_client_ids.is_empty()
        && config
            .auth
            .open_caller_allowlists_expires_at
            .is_some_and(|deadline| std::time::Instant::now() >= deadline)
}

fn map_toolkit_error(err: ToolkitAuthError) -> AuthError {
    match err {
        ToolkitAuthError::MissingToken => AuthError::MissingToken,
        ToolkitAuthError::InvalidToken => AuthError::InvalidToken,
        ToolkitAuthError::TokenExpired => AuthError::TokenExpired,
        ToolkitAuthError::ReplayDetected => AuthError::Forbidden("replay detected".to_string()),
        ToolkitAuthError::MissingScopes => {
            AuthError::Forbidden("missing required scopes".to_string())
        }
        ToolkitAuthError::ConfigError(message) => AuthError::NotSupported(message),
        ToolkitAuthError::Generic {
            reason, message, ..
        } => match reason {
            Some("introspection_failed") => AuthError::IntrospectionFailed,
            Some("introspection_inactive") => AuthError::TokenInactive,
            _ => AuthError::Forbidden(message),
        },
    }
}

fn opt_non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn claim_string(claims: &Value, name: &str) -> Option<String> {
    claims
        .get(name)
        .and_then(|value| value.as_str())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn claim_i64(claims: &Value, name: &str) -> Option<i64> {
    claims.get(name).and_then(|value| {
        value
            .as_i64()
            .or_else(|| value.as_u64().map(|value| value as i64))
    })
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::caller_allowlists_break_glass_expired;
    use crate::test_support::build_config;

    #[test]
    fn caller_allowlists_break_glass_expires_open_allowlists() {
        let mut config = build_config(
            "http://gateway.test".to_string(),
            "http://keycloak.test".to_string(),
        );
        config.auth.open_caller_allowlists_expires_at =
            Some(Instant::now() - Duration::from_secs(1));

        assert!(caller_allowlists_break_glass_expired(&config));
    }

    #[test]
    fn caller_allowlists_break_glass_keeps_configured_allowlists_authoritative() {
        let mut config = build_config(
            "http://gateway.test".to_string(),
            "http://keycloak.test".to_string(),
        );
        config.auth.allowed_azp = vec!["kc-admin-mcp".to_string()];
        config.auth.open_caller_allowlists_expires_at =
            Some(Instant::now() - Duration::from_secs(1));

        assert!(!caller_allowlists_break_glass_expired(&config));
    }
}
