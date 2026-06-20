//! # Gateway Handlers
//!
//! HTTP request handlers for the admin gateway.
//!
//! ## Rationale
//! Implements the core proxy logic: Authentication -> Authorization -> Exchange -> Forwarding.
//! It ensures that every request is audited and that no request reaches Keycloak without
//! explicit scope validation.
//!
//! ## Security Boundaries
//! * **Input Validation**: Rejects matrix parameters and malformed paths.
//! * **Audit**: Logs every decision (Allow/Deny) to the immutable audit log.
//! * **Fail-Closed**: Any error in the chain results in a 403 Forbidden or 502 Bad Gateway.
//!
//! ## References
//! * **DESIGN**: `docs/design/admin-mcp-gateway-protocol.md`

use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{header::AUTHORIZATION, HeaderMap, Method, Request, Response, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use mcp_toolkit_auth::{parse_strict_bearer_authorization, Authenticator};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::auth::{enforce_scopes, AuditIdentity};
use crate::config::GatewayConfig;
use crate::errors::GatewayError;
use crate::exchange::{exchange_token, extract_access_token};
use crate::http::build_client;
use crate::log_sanitize::sanitize_log_value;
use crate::logging::{
    log_auth_finish, log_auth_start, log_exchange_finish, log_exchange_start, log_request_finish,
    log_request_start,
};

const BODY_LIMIT_BYTES: usize = 10 * 1024 * 1024;

/// Shared application state for the gateway handlers (config/client/authenticator).
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
pub struct AppState {
    pub config: GatewayConfig,
    pub client: reqwest::Client,
    pub authenticator: Arc<Authenticator>,
}

impl AppState {
    /// Create a new handler state embedding the HTTP client/authenticator.
    ///
    /// # Security
    /// * **Client Construction**: Configures the HTTP client with strict timeouts and TLS settings.
    ///
    /// # Errors
    /// * Returns an error if the operation fails.
    ///
    /// # Caveats
    /// * None.
    pub fn new(config: GatewayConfig, authenticator: Authenticator) -> Result<Self, GatewayError> {
        let client = build_client(&config)?;
        Ok(Self {
            config,
            client,
            authenticator: Arc::new(authenticator),
        })
    }
}

/// Health check handler (used for monitoring).
///
/// # Errors
/// * Does not return errors.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
pub async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

/// Proxy handler that introspects machine tokens, exchanges when needed, and forwards admin requests.
///
/// # Security
/// * **Orchestration**: Manages the entire security pipeline (Auth -> Audit -> Exchange -> Proxy).
/// * **Fail-Safe**: Catches all errors and ensures they are audited before returning a response.
///
/// # Errors
/// * Does not return errors.
///
/// # Caveats
/// * None.
pub async fn proxy_admin(State(state): State<Arc<AppState>>, req: Request<Body>) -> Response<Body> {
    let request_id = extract_request_id(req.headers());
    let actor_id = extract_actor_id(req.headers());
    let session_id = extract_session_id(req.headers());
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let client = extract_client(req.headers());

    let request_started = log_request_start(
        "admin_proxy",
        method.as_str(),
        &path,
        &client,
        &request_id,
        actor_id.as_deref(),
        session_id.as_deref(),
    );

    match handle_proxy(
        &state,
        req,
        &request_id,
        actor_id.as_deref(),
        session_id.as_deref(),
        &client,
    )
    .await
    {
        Ok((response, audit)) => {
            log_request_finish(
                "admin_proxy",
                method.as_str(),
                &path,
                &client,
                &request_id,
                actor_id.as_deref(),
                session_id.as_deref(),
                request_started,
                response.status().as_u16(),
                false,
            );
            audit_log_success(
                &response,
                &request_id,
                actor_id.as_deref(),
                session_id.as_deref(),
                audit.as_ref(),
            );
            response
        }
        Err((err, audit)) => {
            log_request_finish(
                "admin_proxy",
                method.as_str(),
                &path,
                &client,
                &request_id,
                actor_id.as_deref(),
                session_id.as_deref(),
                request_started,
                err.status_code(),
                true,
            );
            audit_log_failure(
                &err,
                &request_id,
                actor_id.as_deref(),
                session_id.as_deref(),
                audit.as_ref(),
            );
            error_response(&err, &request_id)
        }
    }
}

/// Core proxy flow: read request, authenticate, log, audit, and replay via the gateway backend.
/// Authenticate/introspect the incoming bearer token, enforce scopes, exchange for the required admin token, and forward the request to Keycloak.
/// Rejects invalid paths (e.g., with matrix params), logs/audits each staging point, and propagates `GatewayError` to the caller so errors can be audited consistently.
///
/// # Security
/// * **Scope Gating**: Calculates required scopes from the URL path and enforces them.
/// * **Token Exchange**: Swaps the caller's token for a downscoped admin token (RFC 8693).
/// * **Matrix Params**: Explicitly blocks paths with `;` to prevent cache poisoning/ACL bypass.
async fn handle_proxy(
    state: &AppState,
    req: Request<Body>,
    request_id: &str,
    actor_id: Option<&str>,
    session_id: Option<&str>,
    client: &str,
) -> Result<(Response<Body>, Option<AuditIdentity>), (GatewayError, Option<AuditIdentity>)> {
    let (parts, body) = req.into_parts();
    let method = parts.method;
    let uri = parts.uri;
    let headers = parts.headers;

    let body_bytes = axum::body::to_bytes(body, BODY_LIMIT_BYTES)
        .await
        .map_err(|_| {
            (
                GatewayError::Upstream("request body too large".to_string()),
                None,
            )
        })?;

    let auth_started = log_auth_start(
        "admin_proxy",
        method.as_str(),
        uri.path(),
        client,
        request_id,
        "introspection",
        true,
    );

    let token = match extract_bearer_token(&headers) {
        Ok(token) => token,
        Err(err) => {
            log_auth_finish(
                "admin_proxy",
                method.as_str(),
                uri.path(),
                client,
                request_id,
                actor_id,
                session_id,
                auth_started,
                err.status_code(),
                true,
                "introspection",
                true,
                Some(auth_error_reason(&err)),
            );
            return Err((err, None));
        }
    };

    let mut auth_headers = headers.clone();
    auth_headers.remove(AUTHORIZATION);

    let context = match state
        .authenticator
        .authenticate_token(&auth_headers, &token)
        .await
    {
        Ok(ctx) => ctx,
        Err(err) => {
            let gw_err = match err {
                mcp_toolkit_auth::AuthError::MissingToken => GatewayError::MissingToken,
                mcp_toolkit_auth::AuthError::TokenExpired => GatewayError::TokenInactive,
                mcp_toolkit_auth::AuthError::InvalidToken => {
                    GatewayError::Forbidden("invalid token".to_string())
                }
                mcp_toolkit_auth::AuthError::ReplayDetected => {
                    GatewayError::Forbidden("replay detected".to_string())
                }
                _ => GatewayError::IntrospectionFailed,
            };

            log_auth_finish(
                "admin_proxy",
                method.as_str(),
                uri.path(),
                client,
                request_id,
                actor_id,
                session_id,
                auth_started,
                gw_err.status_code(),
                true,
                "introspection",
                true,
                Some(auth_error_reason(&gw_err)),
            );
            return Err((gw_err, None));
        }
    };

    if let Err(err) = enforce_issuer_audience(&state.config, &context.claims) {
        log_auth_finish(
            "admin_proxy",
            method.as_str(),
            uri.path(),
            client,
            request_id,
            actor_id,
            session_id,
            auth_started,
            err.status_code(),
            true,
            "introspection",
            true,
            Some(auth_error_reason(&err)),
        );
        return Err((err, None));
    }

    let audit =
        crate::auth::build_audit_identity(&state.config, &context.claims).map_err(|e| (e, None))?;

    // Manual AZP check
    if azp_allowlist_break_glass_expired(&state.config) {
        let err = GatewayError::Forbidden("break-glass AZP allowlist TTL expired".to_string());
        log_auth_finish(
            "admin_proxy",
            method.as_str(),
            uri.path(),
            client,
            request_id,
            actor_id,
            session_id,
            auth_started,
            err.status_code(),
            true,
            "introspection",
            true,
            Some(auth_error_reason(&err)),
        );
        return Err((err, audit));
    }

    let azp = context.azp.clone().or(context
        .claims
        .get("client_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string()));
    if !state.config.allowed_azp.is_empty() {
        let allowed = azp
            .as_ref()
            .map(|value| {
                state
                    .config
                    .allowed_azp
                    .iter()
                    .any(|allowed| allowed == value)
            })
            .unwrap_or(false);
        if !allowed {
            let err = GatewayError::Forbidden("azp not in allowed list".to_string());
            log_auth_finish(
                "admin_proxy",
                method.as_str(),
                uri.path(),
                client,
                request_id,
                actor_id,
                session_id,
                auth_started,
                err.status_code(),
                true,
                "introspection",
                true,
                Some(auth_error_reason(&err)),
            );
            return Err((err, audit));
        }
    }

    let path = uri.path();
    if contains_matrix_params(path) {
        log_auth_finish(
            "admin_proxy",
            method.as_str(),
            path,
            client,
            request_id,
            actor_id,
            session_id,
            auth_started,
            200,
            false,
            "introspection",
            true,
            Some("invalid_path"),
        );
        return Err((
            GatewayError::Forbidden("invalid path segment".to_string()),
            audit,
        ));
    }
    let segments = path_segments(path);
    if segments.is_empty() {
        log_auth_finish(
            "admin_proxy",
            method.as_str(),
            path,
            client,
            request_id,
            actor_id,
            session_id,
            auth_started,
            200,
            false,
            "introspection",
            true,
            Some("missing_realm"),
        );
        return Err((
            GatewayError::Forbidden("missing realm segment in path".to_string()),
            audit,
        ));
    }
    if !is_allowlisted_admin_path(&segments) {
        log_auth_finish(
            "admin_proxy",
            method.as_str(),
            path,
            client,
            request_id,
            actor_id,
            session_id,
            auth_started,
            200,
            false,
            "introspection",
            true,
            Some("path_not_allowlisted"),
        );
        return Err((
            GatewayError::Forbidden("path is not in the gateway allowlist".to_string()),
            audit,
        ));
    }

    let required_scopes = required_scopes(&method, &segments, uri.query(), &context.scopes);
    if let Err(err) = enforce_scopes(&context.scopes, &required_scopes) {
        log_auth_finish(
            "admin_proxy",
            method.as_str(),
            path,
            client,
            request_id,
            actor_id,
            session_id,
            auth_started,
            err.status_code(),
            true,
            "introspection",
            true,
            Some(auth_error_reason(&err)),
        );
        return Err((err, audit.clone()));
    }

    log_auth_finish(
        "admin_proxy",
        method.as_str(),
        path,
        client,
        request_id,
        actor_id,
        session_id,
        auth_started,
        200,
        false,
        "introspection",
        true,
        None,
    );

    let scopes = required_scopes.join(" ");
    let exchange_started = log_exchange_start(
        "admin_proxy",
        method.as_str(),
        path,
        client,
        request_id,
        &scopes,
    );
    let exchange = match exchange_token(
        &state.client,
        &state.config,
        &context.raw_token,
        &required_scopes,
        request_id,
    )
    .await
    {
        Ok(exchange) => exchange,
        Err(err) => {
            log_exchange_finish(
                "admin_proxy",
                method.as_str(),
                path,
                client,
                request_id,
                &scopes,
                exchange_started,
                err.status_code(),
                true,
                Some(exchange_error_reason(&err)),
            );
            return Err((err, audit.clone()));
        }
    };
    log_exchange_finish(
        "admin_proxy",
        method.as_str(),
        path,
        client,
        request_id,
        &scopes,
        exchange_started,
        200,
        false,
        None,
    );
    let admin_token =
        extract_access_token(exchange, request_id).map_err(|err| (err, audit.clone()))?;

    let upstream_url =
        build_upstream_url(&state.config, &uri).map_err(|err| (err, audit.clone()))?;
    let mut upstream = state.client.request(method, upstream_url).body(body_bytes);

    for (name, value) in headers.iter() {
        if should_forward_header(name.as_str()) {
            upstream = upstream.header(name, value);
        }
    }

    upstream = upstream
        .header(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {admin_token}"),
        )
        .header("x-request-id", request_id);

    if let Some(actor_id) = actor_id {
        upstream = upstream.header("x-actor-id", actor_id);
    }

    let response = upstream
        .send()
        .await
        .map_err(|err| (GatewayError::Upstream(err.to_string()), audit.clone()))?;

    let status = response.status();
    let response_headers = response.headers().clone();
    let body = response
        .bytes()
        .await
        .map_err(|err| (GatewayError::Upstream(err.to_string()), audit.clone()))?;

    Ok((
        build_response(status, response_headers, body, request_id),
        audit,
    ))
}

/// Format a JSON error response for gateway failures.
fn error_response(err: &GatewayError, request_id: &str) -> Response<Body> {
    let status =
        StatusCode::from_u16(err.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let payload = Json(json!({
        "error": err.to_string(),
        "request_id": request_id,
    }));

    let mut response = payload.into_response();
    *response.status_mut() = status;
    response
}

/// Emit audit/log entries for successfully proxied requests.
fn audit_log_success(
    response: &Response<Body>,
    request_id: &str,
    actor_id: Option<&str>,
    session_id: Option<&str>,
    audit: Option<&AuditIdentity>,
) {
    if let Some(audit) = audit {
        tracing::info!(
            target: crate::logging::LOG_TARGET_ACCESS,
            request_id = %request_id,
            actor_id = actor_id.unwrap_or("unknown"),
            session_id = session_id.unwrap_or("unknown"),
            subject_hash = audit.subject_hash.as_deref().unwrap_or("unknown"),
            client_id_hash = audit.client_id_hash.as_deref().unwrap_or("unknown"),
            azp_hash = audit.azp_hash.as_deref().unwrap_or("unknown"),
            status = %response.status(),
            "admin request succeeded"
        );
        return;
    }

    tracing::info!(
        target: crate::logging::LOG_TARGET_ACCESS,
        request_id = %request_id,
        actor_id = actor_id.unwrap_or("unknown"),
        session_id = session_id.unwrap_or("unknown"),
        status = %response.status(),
        "admin request succeeded"
    );
}

/// Emit audit/log entries for failed proxy requests.
fn audit_log_failure(
    err: &GatewayError,
    request_id: &str,
    actor_id: Option<&str>,
    session_id: Option<&str>,
    audit: Option<&AuditIdentity>,
) {
    if let Some(audit) = audit {
        tracing::warn!(
            target: crate::logging::LOG_TARGET_ACCESS,
            request_id = %request_id,
            actor_id = actor_id.unwrap_or("unknown"),
            session_id = session_id.unwrap_or("unknown"),
            subject_hash = audit.subject_hash.as_deref().unwrap_or("unknown"),
            client_id_hash = audit.client_id_hash.as_deref().unwrap_or("unknown"),
            azp_hash = audit.azp_hash.as_deref().unwrap_or("unknown"),
            error = %err,
            status = err.status_code(),
            "admin request denied"
        );
        return;
    }

    tracing::warn!(
        target: crate::logging::LOG_TARGET_ACCESS,
        request_id = %request_id,
        actor_id = actor_id.unwrap_or("unknown"),
        session_id = session_id.unwrap_or("unknown"),
        error = %err,
        status = err.status_code(),
        "admin request denied"
    );
}

/// Convert the upstream gateway response into an `axum::Response`.
fn build_response(
    status: reqwest::StatusCode,
    headers: HeaderMap,
    body: Bytes,
    request_id: &str,
) -> Response<Body> {
    let mut response = Response::builder().status(status);

    for (name, value) in headers.iter() {
        if should_forward_header(name.as_str()) {
            response = response.header(name, value);
        }
    }

    response = response.header("x-request-id", request_id);

    response.body(Body::from(body)).unwrap_or_else(|_| {
        Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Body::from("failed to build response"))
            .expect("response builder")
    })
}

/// Extract or generate a request ID for downstream logs.
fn extract_request_id(headers: &HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(sanitize_log_value)
        .unwrap_or_else(|| Uuid::new_v4().to_string())
}

/// Extract the optional actor ID header for logging.
fn extract_actor_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-actor-id")
        .and_then(|value| value.to_str().ok())
        .map(sanitize_log_value)
}

/// Extract the optional session ID header for logging.
fn extract_session_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
        .map(sanitize_log_value)
}

/// Determine the client IP for logging from standard headers.
fn extract_client(headers: &HeaderMap) -> String {
    let header = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .or_else(|| headers.get("x-client-ip"));
    let Some(value) = header.and_then(|value| value.to_str().ok()) else {
        return "-".to_string();
    };
    let first = value.split(',').next().unwrap_or(value).trim();
    if first.is_empty() {
        "-".to_string()
    } else {
        sanitize_log_value(first)
    }
}

/// Extract the bearer token from the request for introspection/exchange.
fn extract_bearer_token(headers: &HeaderMap) -> Result<String, GatewayError> {
    parse_strict_bearer_authorization(headers)
        .map(|token| token.as_str().to_string())
        .map_err(|_| GatewayError::MissingToken)
}

/// Enforce issuer/audience claims against configured expectations.
fn enforce_issuer_audience(config: &GatewayConfig, claims: &Value) -> Result<(), GatewayError> {
    if let Some(expected_issuer) = config.expected_issuer.as_ref() {
        let issuer = claims
            .get("iss")
            .and_then(|value| value.as_str())
            .map(|value| value.trim())
            .filter(|value| !value.is_empty());
        if issuer != Some(expected_issuer.as_str()) {
            return Err(GatewayError::Forbidden("issuer mismatch".to_string()));
        }
    }

    if let Some(expected_audience) = config.expected_audience.as_ref() {
        let audiences = extract_audiences(claims);
        if audiences.is_empty() || !audiences.iter().any(|aud| aud == expected_audience) {
            return Err(GatewayError::Forbidden("audience mismatch".to_string()));
        }
    }

    Ok(())
}

/// Pull audience strings from introspection claims.
fn extract_audiences(claims: &Value) -> Vec<String> {
    let Some(audience) = claims.get("aud") else {
        return Vec::new();
    };

    match audience {
        Value::String(value) => value
            .split_whitespace()
            .map(|aud| aud.trim().to_string())
            .filter(|aud| !aud.is_empty())
            .collect(),
        Value::Array(values) => values
            .iter()
            .filter_map(|value| value.as_str())
            .map(|aud| aud.trim().to_string())
            .filter(|aud| !aud.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

/// Human-readible bucket for why auth failed.
fn auth_error_reason(err: &GatewayError) -> &'static str {
    match err {
        GatewayError::MissingToken => "missing_token",
        GatewayError::IntrospectionFailed => "introspection_failed",
        GatewayError::TokenInactive => "token_inactive",
        GatewayError::Forbidden(_) => "forbidden",
        GatewayError::MissingScopes(_) => "missing_scopes",
        GatewayError::ExchangeFailed => "exchange_failed",
        GatewayError::InvalidConfig(_) => "invalid_config",
        GatewayError::Upstream(_) => "upstream_error",
    }
}

/// Error reason label for exchange logging.
fn exchange_error_reason(err: &GatewayError) -> &'static str {
    match err {
        GatewayError::ExchangeFailed => "exchange_failed",
        GatewayError::MissingScopes(_) => "missing_scopes",
        GatewayError::Forbidden(_) => "forbidden",
        GatewayError::InvalidConfig(_) => "invalid_config",
        GatewayError::Upstream(_) => "upstream_error",
        _ => "exchange_error",
    }
}

/// Predicate limiting which headers are forwarded upstream.
fn should_forward_header(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    !matches!(
        name.as_str(),
        "authorization" | "host" | "content-length" | "connection" | "transfer-encoding"
    )
}

/// Build the upstream Keycloak URL for the MCP request path.
fn build_upstream_url(
    config: &GatewayConfig,
    uri: &axum::http::Uri,
) -> Result<String, GatewayError> {
    if config.admin_base_url.is_empty() {
        return Err(GatewayError::InvalidConfig(
            "KC_GATEWAY_ADMIN_BASE_URL is required".to_string(),
        ));
    }

    let base = config.admin_base_url.trim_end_matches('/');
    let path = uri.path().trim_start_matches('/');
    let mut url = if path.is_empty() {
        base.to_string()
    } else {
        format!("{base}/{path}")
    };

    if let Some(query) = uri.query() {
        url.push('?');
        url.push_str(query);
    }

    Ok(url)
}

/// Utility to split the request path into segments for scope classification.
fn path_segments(path: &str) -> Vec<&str> {
    path.trim_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect()
}

/// Reject matrix parameters embedded in the path (security).
fn azp_allowlist_break_glass_expired(config: &GatewayConfig) -> bool {
    config.allowed_azp.is_empty()
        && config
            .allow_open_azp_expires_at
            .is_some_and(|deadline| std::time::Instant::now() >= deadline)
}

fn contains_matrix_params(path: &str) -> bool {
    path.contains(';')
}

/// Restrict proxy forwarding to explicit Keycloak Admin API route families.
///
/// The gateway intentionally forwards only documented admin routes and fails closed for all
/// other paths to keep the proxy surface narrow.
fn is_allowlisted_admin_path(segments: &[&str]) -> bool {
    matches!(
        segments,
        ["admin", "realms", ..] | ["admin", "serverinfo"] | ["admin", "metrics"]
    )
}

const USERS_READ_SCOPE: &[&str] = &["keycloak-admin:users:read"];
const USERS_WRITE_SCOPE: &[&str] = &["keycloak-admin:users:write"];
const GROUPS_READ_SCOPE: &[&str] = &["keycloak-admin:groups:read"];
const GROUPS_WRITE_SCOPE: &[&str] = &["keycloak-admin:groups:write"];
const ROLES_READ_SCOPE: &[&str] = &["keycloak-admin:roles:read"];
const ROLES_WRITE_SCOPE: &[&str] = &["keycloak-admin:roles:write"];
const CLIENTS_READ_SCOPE: &[&str] = &["keycloak-admin:clients:read"];
const CLIENTS_WRITE_SCOPE: &[&str] = &["keycloak-admin:clients:write"];
const CLIENTS_SECRETS_SCOPE: &[&str] = &["keycloak-admin:clients:secrets"];
const CLIENT_SCOPES_READ_SCOPE: &[&str] = &["keycloak-admin:client-scopes:read"];
const CLIENT_SCOPES_WRITE_SCOPE: &[&str] = &["keycloak-admin:client-scopes:write"];
const IDP_READ_SCOPE: &[&str] = &["keycloak-admin:idp:read"];
const IDP_WRITE_SCOPE: &[&str] = &["keycloak-admin:idp:write"];
const EVENTS_READ_SCOPE: &[&str] = &["keycloak-admin:events:read"];
const EVENTS_ADMIN_SCOPE: &[&str] = &["keycloak-admin:events:admin"];
const REALM_READ_SCOPE: &[&str] = &["keycloak-admin:realm:read"];
const REALM_WRITE_SCOPE: &[&str] = &["keycloak-admin:realm:write"];
const REALM_ADMIN_SCOPE: &[&str] = &["keycloak-admin:realm:admin"];
const TOKENS_READ_SCOPE: &[&str] = &["keycloak-admin:tokens:read"];
const OBSERVABILITY_READ_SCOPE: &[&str] = &["keycloak-admin:observability:read"];

const USERS_READ_REQUIREMENTS: &[&[&str]] = &[USERS_READ_SCOPE];
const USERS_WRITE_REQUIREMENTS: &[&[&str]] = &[USERS_WRITE_SCOPE];
const GROUPS_READ_REQUIREMENTS: &[&[&str]] = &[GROUPS_READ_SCOPE];
const GROUPS_WRITE_REQUIREMENTS: &[&[&str]] = &[GROUPS_WRITE_SCOPE];
const ROLES_READ_REQUIREMENTS: &[&[&str]] = &[ROLES_READ_SCOPE];
const ROLES_WRITE_REQUIREMENTS: &[&[&str]] = &[ROLES_WRITE_SCOPE];
const CLIENTS_READ_REQUIREMENTS: &[&[&str]] = &[CLIENTS_READ_SCOPE];
const CLIENTS_WRITE_REQUIREMENTS: &[&[&str]] = &[CLIENTS_WRITE_SCOPE];
const CLIENTS_SECRETS_REQUIREMENTS: &[&[&str]] = &[CLIENTS_SECRETS_SCOPE];
const CLIENT_SCOPES_READ_REQUIREMENTS: &[&[&str]] = &[CLIENT_SCOPES_READ_SCOPE];
const CLIENT_SCOPES_WRITE_REQUIREMENTS: &[&[&str]] = &[CLIENT_SCOPES_WRITE_SCOPE];
const IDP_READ_REQUIREMENTS: &[&[&str]] = &[IDP_READ_SCOPE];
const IDP_WRITE_REQUIREMENTS: &[&[&str]] = &[IDP_WRITE_SCOPE];
const EVENTS_READ_REQUIREMENTS: &[&[&str]] = &[EVENTS_READ_SCOPE];
const EVENTS_ADMIN_REQUIREMENTS: &[&[&str]] = &[EVENTS_ADMIN_SCOPE];
const REALM_READ_REQUIREMENTS: &[&[&str]] = &[REALM_READ_SCOPE];
const REALM_WRITE_REQUIREMENTS: &[&[&str]] = &[REALM_WRITE_SCOPE];
const REALM_ADMIN_REQUIREMENTS: &[&[&str]] = &[REALM_ADMIN_SCOPE];
const TOKENS_READ_REQUIREMENTS: &[&[&str]] = &[TOKENS_READ_SCOPE];
const OBSERVABILITY_READ_REQUIREMENTS: &[&[&str]] = &[OBSERVABILITY_READ_SCOPE];

const REALM_ROLE_LOOKUP_REQUIREMENTS: &[&[&str]] = &[
    ROLES_READ_SCOPE,
    ROLES_WRITE_SCOPE,
    GROUPS_WRITE_SCOPE,
    CLIENTS_WRITE_SCOPE,
    CLIENT_SCOPES_WRITE_SCOPE,
];
const CLIENT_LOOKUP_REQUIREMENTS: &[&[&str]] =
    &[CLIENTS_READ_SCOPE, CLIENTS_WRITE_SCOPE, GROUPS_WRITE_SCOPE];
const CLIENT_ROLE_LOOKUP_REQUIREMENTS: &[&[&str]] =
    &[CLIENTS_READ_SCOPE, CLIENTS_WRITE_SCOPE, GROUPS_WRITE_SCOPE];
const CLIENT_SCOPE_LOOKUP_REQUIREMENTS: &[&[&str]] = &[
    CLIENT_SCOPES_READ_SCOPE,
    CLIENT_SCOPES_WRITE_SCOPE,
    CLIENTS_WRITE_SCOPE,
    REALM_ADMIN_SCOPE,
];

/// Decide which Keycloak admin scopes are required for the proxied endpoint.
fn required_scopes(
    method: &Method,
    segments: &[&str],
    query: Option<&str>,
    token_scopes: &[String],
) -> Vec<&'static str> {
    let candidates = scope_candidates(method, segments, query);
    select_scope_candidate(candidates, token_scopes).to_vec()
}

/// Return the ordered acceptable scope sets for a proxied endpoint.
fn scope_candidates(
    method: &Method,
    segments: &[&str],
    query: Option<&str>,
) -> &'static [&'static [&'static str]] {
    let is_read = matches!(method, &Method::GET | &Method::HEAD | &Method::OPTIONS);

    if matches!(method, &Method::GET) {
        if is_realm_role_lookup_path(segments) {
            return REALM_ROLE_LOOKUP_REQUIREMENTS;
        }
        if is_client_role_lookup_path(segments) {
            return CLIENT_ROLE_LOOKUP_REQUIREMENTS;
        }
        if is_client_lookup_path(segments) && query_has_param(query, "clientId") {
            return CLIENT_LOOKUP_REQUIREMENTS;
        }
        if is_client_scope_lookup_path(segments) {
            return CLIENT_SCOPE_LOOKUP_REQUIREMENTS;
        }
    }

    if is_realm_event_config_path(segments) {
        return rw_scope_candidates(is_read, REALM_READ_REQUIREMENTS, REALM_WRITE_REQUIREMENTS);
    }

    match scope_family(segments) {
        ScopeFamily::Users => {
            rw_scope_candidates(is_read, USERS_READ_REQUIREMENTS, USERS_WRITE_REQUIREMENTS)
        }
        ScopeFamily::Groups => {
            rw_scope_candidates(is_read, GROUPS_READ_REQUIREMENTS, GROUPS_WRITE_REQUIREMENTS)
        }
        ScopeFamily::Roles => {
            rw_scope_candidates(is_read, ROLES_READ_REQUIREMENTS, ROLES_WRITE_REQUIREMENTS)
        }
        ScopeFamily::Clients => {
            if is_client_secret_path(segments) {
                CLIENTS_SECRETS_REQUIREMENTS
            } else {
                rw_scope_candidates(
                    is_read,
                    CLIENTS_READ_REQUIREMENTS,
                    CLIENTS_WRITE_REQUIREMENTS,
                )
            }
        }
        ScopeFamily::ClientScopes => rw_scope_candidates(
            is_read,
            CLIENT_SCOPES_READ_REQUIREMENTS,
            CLIENT_SCOPES_WRITE_REQUIREMENTS,
        ),
        ScopeFamily::Idp => {
            rw_scope_candidates(is_read, IDP_READ_REQUIREMENTS, IDP_WRITE_REQUIREMENTS)
        }
        ScopeFamily::Events => {
            rw_scope_candidates(is_read, EVENTS_READ_REQUIREMENTS, EVENTS_ADMIN_REQUIREMENTS)
        }
        ScopeFamily::Realm => {
            rw_scope_candidates(is_read, REALM_READ_REQUIREMENTS, REALM_WRITE_REQUIREMENTS)
        }
        ScopeFamily::Tokens => {
            if is_read {
                TOKENS_READ_REQUIREMENTS
            } else {
                REALM_ADMIN_REQUIREMENTS
            }
        }
        ScopeFamily::Observability => OBSERVABILITY_READ_REQUIREMENTS,
    }
}

/// Choose the first acceptable scope set already present on the caller token.
fn select_scope_candidate<'a>(
    candidates: &'a [&'static [&'static str]],
    token_scopes: &[String],
) -> &'a [&'static str] {
    let first_candidate = candidates.first().copied().unwrap_or(REALM_ADMIN_SCOPE);
    candidates
        .iter()
        .copied()
        .find(|candidate| has_all_scopes(token_scopes, candidate))
        .unwrap_or(first_candidate)
}

/// Return true when the token carries every scope in the candidate set.
fn has_all_scopes(token_scopes: &[String], candidate: &[&str]) -> bool {
    candidate
        .iter()
        .all(|scope| token_scopes.iter().any(|token_scope| token_scope == scope))
}

/// Choose read vs write scope candidates.
fn rw_scope_candidates(
    is_read: bool,
    read_scopes: &'static [&'static [&'static str]],
    write_scopes: &'static [&'static [&'static str]],
) -> &'static [&'static [&'static str]] {
    if is_read {
        read_scopes
    } else {
        write_scopes
    }
}

/// Return true when the path is dealing with client-secret endpoints.
fn is_client_secret_path(segments: &[&str]) -> bool {
    segments.iter().any(|segment| *segment == "client-secret")
}

/// Return true when the URI query includes a named parameter.
fn query_has_param(query: Option<&str>, expected_name: &str) -> bool {
    let Some(query) = query else {
        return false;
    };

    query.split('&').any(|pair| {
        let name = pair.split_once('=').map(|(name, _)| name).unwrap_or(pair);
        name == expected_name
    })
}

/// Categories of admin endpoints used to look up required scopes.
#[derive(Debug)]
enum ScopeFamily {
    Users,
    Groups,
    Roles,
    Clients,
    ClientScopes,
    Idp,
    Events,
    Realm,
    Tokens,
    Observability,
}

/// Return the admin resource segment used for scope classification.
fn admin_resource_segment<'a>(segments: &'a [&'a str]) -> Option<&'a str> {
    admin_resource_index(segments).and_then(|index| segments.get(index).copied())
}

/// Return the index of the admin resource segment used for scope classification.
fn admin_resource_index(segments: &[&str]) -> Option<usize> {
    let mut index = usize::from(segments.first() == Some(&"admin"));

    if segments.get(index) == Some(&"realms") {
        index += 2;
    }

    segments.get(index).map(|_| index)
}

/// Return the resource segment and trailing path parts for realm-admin endpoints.
fn admin_resource_tail<'a>(segments: &'a [&'a str]) -> Option<&'a [&'a str]> {
    admin_resource_index(segments).map(|index| &segments[index..])
}

/// Return true for helper lookups that resolve a realm role representation.
fn is_realm_role_lookup_path(segments: &[&str]) -> bool {
    matches!(admin_resource_tail(segments), Some(["roles", _]))
}

/// Return true for helper lookups that resolve a client ID by clientId.
fn is_client_lookup_path(segments: &[&str]) -> bool {
    matches!(admin_resource_tail(segments), Some(["clients"]))
}

/// Return true for helper lookups that resolve client role representations.
fn is_client_role_lookup_path(segments: &[&str]) -> bool {
    matches!(
        admin_resource_tail(segments),
        Some(["clients", _, "roles", _])
    )
}

/// Return true for helper lookups that resolve a client-scope ID by name.
fn is_client_scope_lookup_path(segments: &[&str]) -> bool {
    matches!(admin_resource_tail(segments), Some(["client-scopes"]))
}

/// Return true when the events path is realm configuration, not event data.
fn is_realm_event_config_path(segments: &[&str]) -> bool {
    matches!(admin_resource_tail(segments), Some(["events", "config"]))
}

/// Map request paths into scope families for gating.
fn scope_family(segments: &[&str]) -> ScopeFamily {
    let Some(resource) = admin_resource_segment(segments) else {
        return ScopeFamily::Realm;
    };

    match resource {
        "users" => ScopeFamily::Users,
        "groups" => ScopeFamily::Groups,
        "roles" | "roles-by-id" => ScopeFamily::Roles,
        "clients" => ScopeFamily::Clients,
        "client-scopes" => ScopeFamily::ClientScopes,
        "identity-provider" => ScopeFamily::Idp,
        "events" => ScopeFamily::Events,
        "sessions" | "user-sessions" | "offline-sessions" | "client-session-stats" => {
            ScopeFamily::Tokens
        }
        "attack-detection" | "serverinfo" | "metrics" => ScopeFamily::Observability,
        _ => ScopeFamily::Realm,
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use axum::http::Method;

    use super::{
        azp_allowlist_break_glass_expired, contains_matrix_params, is_allowlisted_admin_path,
        path_segments, required_scopes,
    };
    use crate::config::{ClientAuthMethod, GatewayConfig};

    fn gateway_config_for_break_glass() -> GatewayConfig {
        GatewayConfig {
            host: "127.0.0.1".to_string(),
            port: 9300,
            log_level: "info".to_string(),
            request_timeout: Duration::from_secs(5),
            tls_cert_pem: None,
            tls_key_pem: None,
            tls_client_ca_pem: None,
            mtls_required: false,
            audit_hash_identifiers: false,
            audit_hash_salt: None,
            log_exchange_body: false,
            log_exchange_body_max_bytes: 2048,
            admin_base_url: "http://keycloak.test".to_string(),
            introspection_url: "http://keycloak.test/introspect".to_string(),
            introspection_client_id: "gateway-introspect".to_string(),
            introspection_client_secret: "secret".to_string(),
            introspection_auth_method: ClientAuthMethod::ClientSecretBasic,
            expected_issuer: Some("http://issuer.test".to_string()),
            expected_audience: Some("kc-admin-gateway".to_string()),
            allowed_azp: Vec::new(),
            build_production: true,
            allow_open_azp: true,
            allow_open_azp_reason: Some("temporary emergency rollout".to_string()),
            allow_open_azp_ttl_s: Some("3600".to_string()),
            allow_open_azp_expires_at: Some(Instant::now() - Duration::from_secs(1)),
            exchange_enabled: true,
            exchange_url: "http://keycloak.test/token".to_string(),
            exchange_client_id: "gateway-exchange".to_string(),
            exchange_client_secret: "secret".to_string(),
            exchange_auth_method: ClientAuthMethod::ClientSecretBasic,
            exchange_audience: None,
            exchange_resource: None,
        }
    }

    fn assert_scope(method: Method, path: &str, expected: &[&'static str]) {
        let segments = path_segments(path);
        assert_eq!(
            required_scopes(&method, &segments, None, &token_scopes(&[])),
            expected,
            "path={path}"
        );
    }

    #[test]
    fn azp_allowlist_break_glass_expires_open_allowlist() {
        let config = gateway_config_for_break_glass();

        assert!(azp_allowlist_break_glass_expired(&config));
    }

    #[test]
    fn azp_allowlist_break_glass_keeps_configured_allowlist_authoritative() {
        let mut config = gateway_config_for_break_glass();
        config.allowed_azp = vec!["kc-admin-mcp".to_string()];

        assert!(!azp_allowlist_break_glass_expired(&config));
    }

    #[test]
    fn rejects_matrix_params_in_path() {
        assert!(contains_matrix_params("/admin/realms;foo/test"));
        assert!(contains_matrix_params("/admin/realms/test;v=1"));
        assert!(!contains_matrix_params("/admin/realms/test"));
    }

    #[test]
    fn classifies_realm_scoped_resource_paths_by_resource_segment() {
        assert_scope(
            Method::GET,
            "/admin/realms/demo/clients",
            &["keycloak-admin:clients:read"],
        );
    }

    #[test]
    fn classifies_realm_child_user_paths() {
        assert_scope(
            Method::GET,
            "/admin/realms/example-realm/users",
            &["keycloak-admin:users:read"],
        );
        assert_scope(
            Method::POST,
            "/admin/realms/example-realm/users",
            &["keycloak-admin:users:write"],
        );
    }

    #[test]
    fn preserves_client_secret_enforcement_under_realm_paths() {
        let segments = path_segments("/admin/realms/demo/clients/client-1/client-secret");

        assert_eq!(
            required_scopes(&Method::GET, &segments, None, &token_scopes(&[])),
            vec!["keycloak-admin:clients:secrets"]
        );
    }

    #[test]
    fn keeps_non_realm_admin_paths_classified_correctly() {
        let segments = path_segments("/admin/serverinfo");

        assert_eq!(
            required_scopes(&Method::GET, &segments, None, &token_scopes(&[])),
            vec!["keycloak-admin:observability:read"]
        );
    }

    #[test]
    fn permits_realm_role_lookup_with_mapping_write_scopes() {
        let segments = path_segments("/admin/realms/demo/roles/auditor");

        assert_eq!(
            required_scopes(
                &Method::GET,
                &segments,
                None,
                &token_scopes(&["keycloak-admin:groups:write"])
            ),
            vec!["keycloak-admin:groups:write"]
        );
        assert_eq!(
            required_scopes(
                &Method::GET,
                &segments,
                None,
                &token_scopes(&["keycloak-admin:clients:write"])
            ),
            vec!["keycloak-admin:clients:write"]
        );
        assert_eq!(
            required_scopes(
                &Method::GET,
                &segments,
                None,
                &token_scopes(&["keycloak-admin:client-scopes:write"])
            ),
            vec!["keycloak-admin:client-scopes:write"]
        );
    }

    #[test]
    fn keeps_direct_realm_role_lookup_on_roles_read() {
        let segments = path_segments("/admin/realms/demo/roles/auditor");

        assert_eq!(
            required_scopes(
                &Method::GET,
                &segments,
                None,
                &token_scopes(&["keycloak-admin:roles:read"])
            ),
            vec!["keycloak-admin:roles:read"]
        );
    }

    #[test]
    fn permits_client_role_helpers_with_group_write_scope() {
        let client_segments = path_segments("/admin/realms/demo/clients");
        let role_segments = path_segments("/admin/realms/demo/clients/client-1/roles/auditor");

        assert_eq!(
            required_scopes(
                &Method::GET,
                &client_segments,
                None,
                &token_scopes(&["keycloak-admin:groups:write"])
            ),
            vec!["keycloak-admin:clients:read"]
        );
        assert_eq!(
            required_scopes(
                &Method::GET,
                &client_segments,
                Some("clientId=app"),
                &token_scopes(&["keycloak-admin:groups:write"])
            ),
            vec!["keycloak-admin:groups:write"]
        );
        assert_eq!(
            required_scopes(
                &Method::GET,
                &role_segments,
                None,
                &token_scopes(&["keycloak-admin:groups:write"])
            ),
            vec!["keycloak-admin:groups:write"]
        );
    }

    #[test]
    fn permits_client_scope_lookup_with_realm_admin_scope() {
        let segments = path_segments("/admin/realms/demo/client-scopes");

        assert_eq!(
            required_scopes(
                &Method::GET,
                &segments,
                None,
                &token_scopes(&["keycloak-admin:realm:admin"])
            ),
            vec!["keycloak-admin:realm:admin"]
        );
    }

    #[test]
    fn preserves_realm_scope_for_realm_root_path() {
        assert_scope(
            Method::GET,
            "/admin/realms/example-realm",
            &["keycloak-admin:realm:read"],
        );
        assert_scope(
            Method::PUT,
            "/admin/realms/example-realm",
            &["keycloak-admin:realm:write"],
        );
    }

    #[test]
    fn keeps_realm_event_config_under_realm_scopes() {
        let segments = path_segments("/admin/realms/demo/events/config");

        assert_eq!(
            required_scopes(&Method::GET, &segments, None, &token_scopes(&[])),
            vec!["keycloak-admin:realm:read"]
        );
        assert_eq!(
            required_scopes(&Method::PUT, &segments, None, &token_scopes(&[])),
            vec!["keycloak-admin:realm:write"]
        );
    }

    #[test]
    fn keeps_realm_event_history_under_event_scopes() {
        let segments = path_segments("/admin/realms/demo/events");

        assert_eq!(
            required_scopes(&Method::GET, &segments, None, &token_scopes(&[])),
            vec!["keycloak-admin:events:read"]
        );
    }

    #[test]
    fn allowlists_expected_admin_paths() {
        assert!(is_allowlisted_admin_path(&path_segments(
            "/admin/realms/example-realm/users"
        )));
        assert!(is_allowlisted_admin_path(&path_segments(
            "/admin/serverinfo"
        )));
    }

    #[test]
    fn denies_non_allowlisted_paths() {
        assert!(!is_allowlisted_admin_path(&path_segments("/internal")));
        assert!(!is_allowlisted_admin_path(&path_segments("/admin/unknown")));
    }

    #[test]
    fn route_scope_matrix_read_paths() {
        let cases = [
            (
                "/admin/realms/example-realm/users",
                "keycloak-admin:users:read",
            ),
            (
                "/admin/realms/example-realm/groups",
                "keycloak-admin:groups:read",
            ),
            (
                "/admin/realms/example-realm/roles-by-id/abc",
                "keycloak-admin:roles:read",
            ),
            (
                "/admin/realms/example-realm/clients",
                "keycloak-admin:clients:read",
            ),
            (
                "/admin/realms/example-realm/clients/abc/client-secret",
                "keycloak-admin:clients:secrets",
            ),
            (
                "/admin/realms/example-realm/client-scopes",
                "keycloak-admin:client-scopes:read",
            ),
            (
                "/admin/realms/example-realm/identity-provider/instances",
                "keycloak-admin:idp:read",
            ),
            (
                "/admin/realms/example-realm/events",
                "keycloak-admin:events:read",
            ),
            (
                "/admin/realms/example-realm/sessions/abc",
                "keycloak-admin:tokens:read",
            ),
            ("/admin/serverinfo", "keycloak-admin:observability:read"),
            ("/admin/metrics", "keycloak-admin:observability:read"),
            ("/admin/realms", "keycloak-admin:realm:read"),
            ("/admin/realms/example-realm", "keycloak-admin:realm:read"),
        ];

        for (path, expected) in cases {
            assert_scope(Method::GET, path, &[expected]);
        }
    }

    #[test]
    fn route_scope_matrix_write_paths() {
        let cases = [
            (
                "/admin/realms/example-realm/users",
                "keycloak-admin:users:write",
            ),
            (
                "/admin/realms/example-realm/groups/abc",
                "keycloak-admin:groups:write",
            ),
            (
                "/admin/realms/example-realm/roles",
                "keycloak-admin:roles:write",
            ),
            (
                "/admin/realms/example-realm/clients",
                "keycloak-admin:clients:write",
            ),
            (
                "/admin/realms/example-realm/clients/abc/client-secret",
                "keycloak-admin:clients:secrets",
            ),
            (
                "/admin/realms/example-realm/client-scopes/abc",
                "keycloak-admin:client-scopes:write",
            ),
            (
                "/admin/realms/example-realm/identity-provider/instances/oidc",
                "keycloak-admin:idp:write",
            ),
            (
                "/admin/realms/example-realm/events/config",
                "keycloak-admin:realm:write",
            ),
            (
                "/admin/realms/example-realm/sessions/abc",
                "keycloak-admin:realm:admin",
            ),
            ("/admin/realms/example-realm", "keycloak-admin:realm:write"),
        ];

        for (path, expected) in cases {
            assert_scope(Method::POST, path, &[expected]);
        }
    }

    #[test]
    fn route_scope_matrix_fail_closed_for_malformed_paths() {
        let malformed_cases = [
            "/admin/unknown",
            "/admin/realms",
            "/admin/realms/example-realm/not-a-real-family",
            "/foo/bar/baz",
        ];
        for path in malformed_cases {
            assert_scope(Method::GET, path, &["keycloak-admin:realm:read"]);
        }
    }

    fn token_scopes(scopes: &[&str]) -> Vec<String> {
        scopes.iter().map(|scope| scope.to_string()).collect()
    }
}
