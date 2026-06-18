//! # Gateway Errors
//!
//! Internal error taxonomy for the security gateway.
//!
//! ## Rationale
//! Defines the failure modes of the gateway, ensuring that upstream errors
//! from Keycloak are mapped to appropriate HTTP status codes (e.g. 502 Bad Gateway).

use thiserror::Error;

/// Errors surfaced by the gateway (introspection, exchange, config issues).
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("missing bearer token")]
    MissingToken,
    #[error("introspection failed")]
    IntrospectionFailed,
    #[error("token inactive")]
    TokenInactive,
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("token scope missing: {0}")]
    MissingScopes(String),
    #[error("token exchange failed")]
    ExchangeFailed,
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("upstream error: {0}")]
    Upstream(String),
}

impl GatewayError {
    /// Return the HTTP status code for this error.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Caveats
    /// * None.
    pub fn status_code(&self) -> u16 {
        match self {
            GatewayError::MissingToken => 401,
            GatewayError::IntrospectionFailed => 502,
            GatewayError::TokenInactive => 403,
            GatewayError::Forbidden(_) => 403,
            GatewayError::MissingScopes(_) => 403,
            GatewayError::ExchangeFailed => 502,
            GatewayError::InvalidConfig(_) => 500,
            GatewayError::Upstream(_) => 502,
        }
    }
}
