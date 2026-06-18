//! # Input Validation
//!
//! Helpers for sanitizing and validating host-provided tool arguments.
//!
//! ## Rationale
//! Protects the gateway and Keycloak API from malformed inputs and path traversal attacks.
//! All external strings used in URL paths must be validated here.
//!
//! ## Security Boundaries
//! * **Path Traversal**: Explicitly blocks `..`, `/`, and `\` in sensitive fields.
//! * **Format Strictness**: Enforces UUID and alphanumeric-only patterns for IDs and names.

use regex::Regex;
use rmcp::model::ErrorCode;
use std::sync::OnceLock;
use uuid::Uuid;

use crate::McpError;

static REALM_REGEX: OnceLock<Regex> = OnceLock::new();

fn get_realm_regex() -> &'static Regex {
    REALM_REGEX.get_or_init(|| Regex::new(r"^[a-zA-Z0-9_-]+$").expect("valid regex"))
}

/// Ensure the realm name matches the allowed pattern; used before calling Keycloak.
///
/// # Errors
/// * Returns an error if the operation fails.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
pub fn validate_realm_name(realm: &str) -> Result<(), McpError> {
    if realm.is_empty() {
        return Err(McpError::new(
            ErrorCode(-32602),
            "realm name cannot be empty".to_string(),
            None,
        ));
    }
    if !get_realm_regex().is_match(realm) {
        return Err(McpError::new(
            ErrorCode(-32602),
            format!("invalid realm name format: '{}' (must be alphanumeric, '-', or '_')", realm),
            None,
        ));
    }
    Ok(())
}

/// Ensure the provided field value is a valid UUID string.
///
/// # Errors
/// * Returns an error if the operation fails.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
pub fn validate_uuid(id: &str, field_name: &str) -> Result<(), McpError> {
    if Uuid::parse_str(id).is_err() {
        return Err(McpError::new(
            ErrorCode(-32602),
            format!("invalid {}: '{}' (must be a valid UUID)", field_name, id),
            None,
        ));
    }
    Ok(())
}

/// Reject values containing slashes or `..` to avoid path traversal when hitting gateway paths.
///
/// # Security
/// * **Traversal Prevention**: Blocks characters used to navigate directory structures or URL hierarchies.
///
/// # Errors
/// * Returns an error if the operation fails.
///
/// # Caveats
/// * None.
pub fn validate_no_path_traversal(input: &str, field_name: &str) -> Result<(), McpError> {
    if input.contains('/') || input.contains('\\') || input.contains("..") {
        return Err(McpError::new(
            ErrorCode(-32602),
            format!("invalid characters in {}: path traversal detected", field_name),
            None,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_realm_name() {
        assert!(validate_realm_name("master").is_ok());
        assert!(validate_realm_name("my-realm_123").is_ok());
        assert!(validate_realm_name("invalid/realm").is_err());
        assert!(validate_realm_name("invalid realm").is_err());
        assert!(validate_realm_name("..").is_err());
    }

    #[test]
    fn test_validate_uuid() {
        assert!(validate_uuid("550e8400-e29b-41d4-a716-446655440000", "id").is_ok());
        assert!(validate_uuid("invalid-uuid", "id").is_err());
    }

    #[test]
    fn test_validate_no_path_traversal() {
        assert!(validate_no_path_traversal("safe-name", "name").is_ok());
        assert!(validate_no_path_traversal("unsafe/name", "name").is_err());
        assert!(validate_no_path_traversal("unsafe\\name", "name").is_err());
        assert!(validate_no_path_traversal("..", "name").is_err());
    }
}
