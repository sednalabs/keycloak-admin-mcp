//! # Tool Errors
//!
//! Standardized error responses for the Keycloak Admin MCP tools.
//!
//! ## Rationale
//! Ensures that agents receive consistent error codes and messages that they can
//! reason about (e.g. `clients.not_found`). It also ensures that request IDs
//! are propagated back to the client for troubleshooting.

use mcp_toolkit_core::response_contract::ToolErrorPayload;
use mcp_toolkit_core::rmcp::model::{CallToolResult, ContentBlock};
use serde_json::{json, Value};

/// Wrap a structured error response for MCP tools.
///
/// # Security
/// * **Auditability**: Includes the `request_id` to correlate tool errors with server logs.
///
/// # Errors
/// * Does not return errors.
///
/// # Caveats
/// * None.
pub fn tool_error(code: &str, message: &str, request_id: &str) -> CallToolResult {
    CallToolResult::structured_error(json!(ToolErrorPayload::new(code, message, request_id)))
}

/// Same as `tool_error` but includes a user-facing hint string.
///
/// # Errors
/// * Does not return errors.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
pub fn tool_error_with_hint(
    code: &str,
    message: &str,
    request_id: &str,
    hint: &str,
) -> CallToolResult {
    let payload = ToolErrorPayload::new(code, message, request_id).with_hint(hint);
    CallToolResult::structured_error(json!(payload))
}

/// Wrap a structured error response for MCP tools with machine-readable context.
///
/// # Security
/// * Avoid including sensitive values in `details`; prefer IDs and bounded identifiers.
///
/// # Errors
/// * Does not return errors.
///
/// # Caveats
/// * This helper augments the shared error envelope and is additive only.
pub fn tool_error_with_context(
    code: &str,
    message: &str,
    request_id: &str,
    resource: Option<&str>,
    client_id: Option<&str>,
    scope: Option<&str>,
    details: Option<Value>,
) -> CallToolResult {
    tool_error_with_context_and_status(
        code, message, request_id, resource, client_id, scope, details, false,
    )
}

fn tool_error_with_context_and_status(
    code: &str,
    message: &str,
    request_id: &str,
    resource: Option<&str>,
    client_id: Option<&str>,
    scope: Option<&str>,
    details: Option<Value>,
    machine_hint: bool,
) -> CallToolResult {
    let payload = tool_error_payload_with_context(
        code,
        message,
        request_id,
        resource,
        client_id,
        scope,
        details,
        machine_hint,
    );
    CallToolResult::structured(json!(payload))
}

fn tool_error_payload_with_context(
    code: &str,
    message: &str,
    request_id: &str,
    resource: Option<&str>,
    client_id: Option<&str>,
    scope: Option<&str>,
    details: Option<Value>,
    machine_hint: bool,
) -> ToolErrorPayload {
    let mut payload = ToolErrorPayload::new(code, message, request_id);
    if machine_hint {
        payload = payload.with_extra("machine_hint", json!(true));
    }
    if let Some(resource) = resource {
        payload = payload.with_extra("resource", json!(resource));
    }
    if let Some(client_id) = client_id {
        payload = payload.with_extra("client_id", json!(client_id));
    }
    if let Some(scope) = scope {
        payload = payload.with_extra("scope", json!(scope));
    }
    if let Some(details) = details {
        payload = payload.with_extra("details", details);
    }
    payload
}

/// Wrap a structured error response with resource and optional remediation hints.
///
/// # Security
/// * Only include IDs or names in details by default.
///
/// # Errors
/// * Does not return errors.
///
/// # Caveats
/// * Caller can use this for workflow-oriented errors (for example, bind retries).
pub fn tool_error_with_context_and_hint(
    code: &str,
    message: &str,
    request_id: &str,
    resource: Option<&str>,
    client_id: Option<&str>,
    scope: Option<&str>,
    details: Option<Value>,
    hint: Option<&str>,
) -> CallToolResult {
    let context_details = details.or_else(|| {
        hint.map(|value| {
            let mut fields = serde_json::Map::new();
            fields.insert("hint".to_string(), json!(value));
            Value::Object(fields)
        })
    });
    let mut payload = tool_error_payload_with_context(
        code,
        message,
        request_id,
        resource,
        client_id,
        scope,
        context_details,
        false,
    );
    if let Some(hint) = hint {
        payload = payload.with_hint(hint);
    }
    CallToolResult::structured(json!(payload))
}

/// Return a text result (legacy) from a tool handler.
///
/// # Errors
/// * Does not return errors.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
pub fn tool_text_result(message: &str) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(message)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_error_uses_shared_toolkit_envelope() {
        let result = tool_error("clients.not_found", "Client not found", "req-123");

        assert_eq!(result.is_error, Some(true));
        assert_eq!(
            result.structured_content.expect("structured content"),
            json!({
                "status": "error",
                "code": "clients.not_found",
                "message": "Client not found",
                "request_id": "req-123",
            })
        );
    }

    #[test]
    fn tool_error_with_context_and_hint_preserves_existing_shape() {
        let result = tool_error_with_context_and_hint(
            "clients.ambiguous",
            "Multiple clients matched",
            "req-456",
            Some("client"),
            Some("agent-ops"),
            Some("profile"),
            None,
            Some("Retry with keycloak_id"),
        );

        assert_eq!(
            result.structured_content.expect("structured content"),
            json!({
                "status": "error",
                "code": "clients.ambiguous",
                "message": "Multiple clients matched",
                "request_id": "req-456",
                "resource": "client",
                "client_id": "agent-ops",
                "scope": "profile",
                "details": {
                    "hint": "Retry with keycloak_id",
                },
                "hint": "Retry with keycloak_id",
            })
        );
    }
}
