//! # Gateway Auth
//!
//! Handles token validation, scope enforcement, and identity hashing for the gateway.
//!
//! ## Rationale
//! The gateway is the final gatekeeper for Keycloak admin operations. This module
//! ensures that incoming tokens have the correct scopes for the requested paths
//! and provides utilities for anonymizing identities in audit logs.
//!
//! ## Security Boundaries
//! * **Scope Gating**: Maps token scopes to required operational permissions.
//! * **Token Posture**: Incoming token extraction is delegated to the shared
//!   toolkit parser before this module enforces scopes and audit identity.
//!
//! ## References
//! * **SPEC**: [OAuth 2.0 (RFC 6749)](https://oauth.net/2/)

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::config::GatewayConfig;
use crate::errors::GatewayError;

/// Audit identity fields hashed for log storage when hashing is enabled.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
#[derive(Debug, Clone)]
pub struct AuditIdentity {
    pub subject_hash: Option<String>,
    pub client_id_hash: Option<String>,
    pub azp_hash: Option<String>,
}

/// Ensure introspected tokens cover the required scope list.
///
/// # Security
/// * **Fail-Closed**: Returns `GatewayError::MissingScopes` if even a single required scope is absent.
///
/// # Errors
/// * Returns an error if the operation fails.
///
/// # Caveats
/// * None.
pub fn enforce_scopes(
    token_scopes: &[String],
    required_scopes: &[&str],
) -> Result<(), GatewayError> {
    for scope in required_scopes {
        if !token_scopes.iter().any(|token_scope| token_scope == scope) {
            return Err(GatewayError::MissingScopes(scope.to_string()));
        }
    }
    Ok(())
}

/// Hash token identifiers for audits when the feature is configured.
///
/// # Security
/// * **Anonymization**: Uses a salted SHA-256 hash to protect PII in long-lived audit logs.
///
/// # Errors
/// * Returns an error if the operation fails.
///
/// # Caveats
/// * None.
pub fn build_audit_identity(
    cfg: &GatewayConfig,
    claims: &Value,
) -> Result<Option<AuditIdentity>, GatewayError> {
    if !cfg.audit_hash_identifiers {
        return Ok(None);
    }

    let salt = cfg.audit_hash_salt.as_ref().ok_or_else(|| {
        GatewayError::InvalidConfig(
            "KC_GATEWAY_AUDIT_HASH_SALT is required when audit hashing is enabled".to_string(),
        )
    })?;

    Ok(Some(AuditIdentity {
        subject_hash: claims
            .get("sub")
            .and_then(|v| v.as_str())
            .map(|value| hash_value(salt, value)),
        client_id_hash: claims
            .get("client_id")
            .and_then(|v| v.as_str())
            .map(|value| hash_value(salt, value)),
        azp_hash: claims
            .get("azp")
            .and_then(|v| v.as_str())
            .map(|value| hash_value(salt, value)),
    }))
}

/// Hash `value` with the configured `salt` so identifier data can be stored safely in audit logs.
fn hash_value(salt: &str, value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    hex::encode(digest)
}
