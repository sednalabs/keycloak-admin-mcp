//! # Tool Errors
//!
//! Standardized error responses for the Keycloak Admin MCP tools.
//!
//! ## Rationale
//! Ensures that agents receive consistent error codes and messages that they can
//! reason about (e.g. `clients.not_found`). It also ensures that request IDs
//! are propagated back to the client for troubleshooting.

use rmcp::model::{CallToolResult, Content};
use serde_json::json;
use serde_json::Value;

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
    CallToolResult::structured_error(json!({
        "status": "error",
        "code": code,
        "message": message,
        "request_id": request_id,
    }))
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
    CallToolResult::structured_error(json!({
        "status": "error",
        "code": code,
        "message": message,
        "request_id": request_id,
        "hint": hint,
    }))
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
    let mut payload = serde_json::Map::new();
    payload.insert("status".to_string(), json!("error"));
    payload.insert("code".to_string(), json!(code));
    payload.insert("message".to_string(), json!(message));
    payload.insert("request_id".to_string(), json!(request_id));
    if machine_hint {
        payload.insert("machine_hint".to_string(), json!(true));
    }
    if let Some(resource) = resource {
        payload.insert("resource".to_string(), json!(resource));
    }
    if let Some(client_id) = client_id {
        payload.insert("client_id".to_string(), json!(client_id));
    }
    if let Some(scope) = scope {
        payload.insert("scope".to_string(), json!(scope));
    }
    if let Some(details) = details {
        payload.insert("details".to_string(), details);
    }
    CallToolResult::structured(Value::Object(payload))
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
    let mut error = tool_error_with_context(
        code,
        message,
        request_id,
        resource,
        client_id,
        scope,
        context_details,
    );
    if let Some(hint) = hint {
        if let Some(content) = error.structured_content.as_mut() {
            if let serde_json::Value::Object(map) = content {
                map.insert("hint".to_string(), json!(hint));
            }
        }
    }
    error
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
    CallToolResult::success(vec![Content::text(message)])
}
