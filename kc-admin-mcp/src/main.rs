//! # Keycloak Admin MCP Server
//!
//! The main entrypoint for the Keycloak Admin Model Context Protocol (MCP) server.
//!
//! ## Rationale
//! This binary exposes Keycloak administrative capabilities as MCP tools, allowing agents to
//! manage users, groups, and clients safely. It delegates all privileged operations to the
//! `kc-admin-gateway` to ensure strict policy enforcement and audit logging.
//!
//! ## Security Boundaries
//! * **Network**: Listens on a configurable HTTP/HTTPS port.
//! * **Authentication**: Validates incoming Bearer tokens using `mcp-toolkit-auth`.
//! * **Authorization**: Enforces Scope/Role checks via `auth_guard` middleware.
//!
//! ## References
//! * **DESIGN**: `docs/design/admin-mcp-architecture.md`
//! * **SECURITY**: `SECURITY.md`

mod admission;
mod audit;
mod auth;
mod config;
mod edge;
mod errors;
mod gateway;
mod log_context;
mod logging;
mod metrics;
mod provenance;
mod server;
#[cfg(test)]
mod test_support;
mod tls;
mod tools;

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use axum::middleware::Next;
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Redirect};
use axum::routing::{any, get};
use axum::Router;
use futures::stream;
use mcp_toolkit_auth::challenge::{build_bearer_challenge, BearerChallenge};
use mcp_toolkit_auth::surface::{
    AuthSurfaceConfig, AuthorizationServerMetadataSource, IssuerMetadataConfig,
};
use mcp_toolkit_auth::Authenticator;
use mcp_toolkit_core::notifications::ToolListTracker;
use mcp_toolkit_http::oauth::{
    oidc_metadata_url, AuthorizationServerMetadata, GRANT_TYPE_AUTHORIZATION_CODE,
    GRANT_TYPE_DEVICE_CODE,
};
use mcp_toolkit_http::session::{
    BoundedSessionManager, EventStore, EventStoreConfig, RecordingSessionManager,
};
use mcp_toolkit_observability::sanitize_log_value;
use rmcp::transport::common::http_header::{
    EVENT_STREAM_MIME_TYPE, HEADER_LAST_EVENT_ID, HEADER_SESSION_ID,
};
use rmcp::transport::streamable_http_server::{
    session::local::{LocalSessionManager, SessionConfig},
    session::SessionManager,
    StreamableHttpServerConfig, StreamableHttpService,
};
use std::time::Instant;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::admission::{evaluate_startup_admission, AdmissionOutcome};
use crate::audit::AuditLog;
use crate::auth::{authenticate_request, build_authenticator, AuthError};
use crate::config::{
    load_config, EventStoreMode, ResourceMetadata, ResumeMode, StreamableHttpConfig,
};
use crate::gateway::GatewayClient;
use crate::metrics::Metrics;
use crate::provenance::{capture_runtime_provenance, RuntimeAdmissionExtension, RuntimeProvenance};
use crate::server::KcAdminMcp;

pub type McpError = rmcp::ErrorData;

#[derive(Clone)]
struct AppState {
    config: Arc<config::Config>,
    authenticator: Arc<Authenticator>,
    authorization_server_metadata: AuthorizationServerMetadata,
    oidc_metadata_url: String,
    metrics: Arc<Metrics>,
    session_manager: Arc<BoundedSessionManager>,
    stateful_service: StreamableHttpService<KcAdminMcp, RecordingSessionManager>,
    stateless_service: Option<StreamableHttpService<KcAdminMcp, RecordingSessionManager>>,
    event_store: Option<EventStore>,
    resume_mode: ResumeMode,
}

impl AppState {
    fn new(
        config: Arc<config::Config>,
        cancellation_token: CancellationToken,
        runtime_provenance: Arc<RuntimeProvenance>,
        runtime_admission: RuntimeAdmissionExtension,
    ) -> Result<Self, String> {
        let authenticator = Arc::new(
            build_authenticator(&config)
                .map_err(|err| format!("failed to initialize authenticator: {err}"))?,
        );
        let authorization_server_metadata = keycloak_authorization_server_metadata(&config)
            .map_err(|err| format!("failed to derive auth-surface metadata: {err}"))?;
        keycloak_auth_surface_config(
            &config,
            authenticator.clone(),
            authorization_server_metadata.clone(),
        )
        .map_err(|err| format!("failed to validate auth-surface configuration: {err}"))?;
        let oidc_metadata_url = oidc_metadata_url(&authorization_server_metadata.issuer);
        let metrics = Arc::new(Metrics::new());
        let audit_log = Arc::new(AuditLog::new(
            config.audit_log_max,
            config.audit_log_path.clone().map(PathBuf::from),
            config.audit_checkpoint_path.clone().map(PathBuf::from),
            config.audit_log_max_bytes,
            config.audit_log_max_files,
        ));
        let gateway = GatewayClient::new(&config.gateway, Some(metrics.clone()))
            .map_err(|err| format!("failed to build gateway client: {err}"))?;

        let tool_list_tracker = Arc::new(ToolListTracker::new());
        let mut session_config = SessionConfig::default();
        session_config.channel_capacity = config.streamable_http.max_events;
        session_config.keep_alive = config.streamable_http.ttl;
        let session_manager = Arc::new(BoundedSessionManager::new(
            LocalSessionManager::default(),
            config.streamable_http.max_streams,
            config.streamable_http.resume_enabled(),
            session_config,
        ));
        let event_store = build_event_store(&config.streamable_http)?;
        let recording_session_manager = Arc::new(RecordingSessionManager::new(
            session_manager.clone(),
            event_store.clone(),
        ));
        let resume_mode = config.streamable_http.resume_mode;
        let sse_retry = config.streamable_http.retry_interval;

        let started_at = Instant::now();
        let service_config = config.clone();
        let service_gateway = gateway.clone();
        let service_metrics = metrics.clone();
        let service_audit_log = audit_log.clone();
        let service_tool_list = tool_list_tracker.clone();
        let service_started = started_at;
        let service_provenance = runtime_provenance.clone();
        let service_runtime_admission = runtime_admission.clone();
        let mut stateful_http_config = StreamableHttpServerConfig::default();
        stateful_http_config.sse_retry = sse_retry;
        stateful_http_config.cancellation_token = cancellation_token.child_token();
        let stateful_service = StreamableHttpService::new(
            move || {
                Ok(KcAdminMcp::new(
                    service_config.clone(),
                    service_gateway.clone(),
                    service_started,
                    service_metrics.clone(),
                    service_audit_log.clone(),
                    service_tool_list.clone(),
                    service_provenance.clone(),
                    service_runtime_admission.clone(),
                ))
            },
            recording_session_manager.clone(),
            stateful_http_config,
        );
        let stateless_service = if config.streamable_http.stateless_fallback {
            let stateless_config = config.clone();
            let stateless_gateway = gateway.clone();
            let stateless_metrics = metrics.clone();
            let stateless_audit_log = audit_log.clone();
            let stateless_tool_list = tool_list_tracker.clone();
            let stateless_started = started_at;
            let stateless_provenance = runtime_provenance.clone();
            let stateless_runtime_admission = runtime_admission.clone();
            let mut stateless_http_config = StreamableHttpServerConfig::default();
            stateless_http_config.sse_retry = None;
            stateless_http_config.stateful_mode = false;
            stateless_http_config.cancellation_token = cancellation_token.child_token();
            Some(StreamableHttpService::new(
                move || {
                    Ok(KcAdminMcp::new(
                        stateless_config.clone(),
                        stateless_gateway.clone(),
                        stateless_started,
                        stateless_metrics.clone(),
                        stateless_audit_log.clone(),
                        stateless_tool_list.clone(),
                        stateless_provenance.clone(),
                        stateless_runtime_admission.clone(),
                    ))
                },
                recording_session_manager.clone(),
                stateless_http_config,
            ))
        } else {
            None
        };

        Ok(Self {
            config,
            authenticator,
            authorization_server_metadata,
            oidc_metadata_url,
            metrics,
            session_manager,
            stateful_service,
            stateless_service,
            event_store,
            resume_mode,
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    logging::configure_logging();

    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        tracing::error!(panic = %info, "mcp panic");
        default_hook(info);
    }));

    if let Err(err) = rustls::crypto::aws_lc_rs::default_provider().install_default() {
        tracing::error!(error = ?err, "failed to install rustls crypto provider");
        std::process::exit(1);
    }

    let config = Arc::new(load_config().map_err(|err| {
        tracing::error!(error = %err, "invalid configuration");
        err
    })?);

    let runtime_snapshot = capture_runtime_provenance().map_err(|err| {
        std::io::Error::other(format!(
            "failed to resolve executable path for startup admission: {err}"
        ))
    })?;
    let executable_path = runtime_snapshot.executable_path;
    let runtime_provenance = Arc::new(runtime_snapshot.provenance);
    let admission = evaluate_startup_admission(
        &config.startup_admission,
        &executable_path,
        runtime_provenance.as_ref(),
    );
    match admission.outcome {
        AdmissionOutcome::Rejected => {
            return Err(format!(
                "startup admission rejected ({:?}): {}",
                admission.reason_code, admission.detail
            )
            .into())
        }
        AdmissionOutcome::Warning | AdmissionOutcome::Bypassed => {
            tracing::warn!(
                outcome = admission.outcome.as_str(),
                profile = admission.profile.label(),
                reason_code = ?admission.reason_code,
                production_mode = config.startup_admission.production_mode,
                allow_production_bypass = config.startup_admission.allow_production_bypass,
                gate_path = %admission.gate_path.display(),
                detail = %sanitize_log_value(&admission.detail),
                "startup admission degraded"
            );
        }
        AdmissionOutcome::Disabled | AdmissionOutcome::Passed => {
            tracing::info!(
                outcome = admission.outcome.as_str(),
                profile = admission.profile.label(),
                reason_code = ?admission.reason_code,
                production_mode = config.startup_admission.production_mode,
                allow_production_bypass = config.startup_admission.allow_production_bypass,
                gate_path = %admission.gate_path.display(),
                detail = %sanitize_log_value(&admission.detail),
                "startup admission outcome"
            );
        }
    }
    let runtime_admission = RuntimeAdmissionExtension {
        enforcement_phase: config
            .startup_admission
            .mode
            .enforcement_phase()
            .to_string(),
        required_gate_level: admission.profile.label().to_string(),
        outcome: admission.outcome.as_str().to_string(),
        reason_code: admission.reason_code.clone(),
        override_active: admission.override_active,
    };
    tracing::info!(
        build_identity = %sanitize_log_value(&runtime_provenance.build.build_identity),
        source_fingerprint = %sanitize_log_value(&runtime_provenance.build.source_fingerprint),
        git_revision = %sanitize_log_value(&runtime_provenance.build.source.revision),
        git_reference = %sanitize_log_value(&runtime_provenance.build.source.reference),
        git_dirty = runtime_provenance.build.source.dirty,
        "startup provenance"
    );

    let token = CancellationToken::new();
    let state = Arc::new(
        AppState::new(
            config.clone(),
            token.child_token(),
            runtime_provenance,
            runtime_admission,
        )
        .map_err(|err| {
            tracing::error!(error = %err, "failed to initialize app state");
            err
        })?,
    );

    let mcp_router = Router::new()
        .route("/mcp", any(handle_mcp))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_guard,
        ))
        .layer(axum::middleware::from_fn(edge::edge_guard));

    let router = Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(resource_metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(resource_metadata),
        )
        .route(
            "/mcp/.well-known/oauth-protected-resource",
            get(resource_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(authorization_server_metadata),
        )
        .route(
            "/mcp/.well-known/oauth-authorization-server",
            get(authorization_server_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server/mcp",
            get(authorization_server_metadata),
        )
        .route(
            "/.well-known/openid-configuration",
            get(oidc_metadata_redirect),
        )
        .route(
            "/mcp/.well-known/openid-configuration",
            get(oidc_metadata_redirect),
        )
        .route(
            "/.well-known/openid-configuration/mcp",
            get(oidc_metadata_redirect),
        )
        .merge(mcp_router)
        .with_state(state.clone());

    let addr: SocketAddr = config.bind_addr.parse().map_err(|err| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid bind address: {err}"),
        )
    })?;

    let tls_config = match tls::build_tls_config(&config) {
        Ok(config) => config,
        Err(err) => {
            tracing::error!(error = %err, "invalid TLS configuration");
            std::process::exit(1);
        }
    };

    tracing::info!(
        bind_addr = %config.bind_addr,
        tls = tls_config.is_some(),
        "kc-admin-mcp listening"
    );

    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();
    let shutdown_token = token.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        shutdown_token.cancel();
        shutdown_handle.graceful_shutdown(None);
    });

    if let Some(tls_config) = tls_config {
        axum_server::bind_rustls(addr, tls_config)
            .handle(handle)
            .serve(router.into_make_service())
            .await?;
    } else {
        axum_server::bind(addr)
            .handle(handle)
            .serve(router.into_make_service())
            .await?;
    }

    Ok(())
}

async fn resource_metadata(State(state): State<Arc<AppState>>) -> Response<Body> {
    let metadata = ResourceMetadata {
        resource: state.config.resource_url.clone(),
        authorization_servers: vec![state.authorization_server_metadata.issuer.clone()],
        scopes_supported: state.config.scopes_supported.clone(),
    };
    json_response(&metadata)
}

async fn authorization_server_metadata(State(state): State<Arc<AppState>>) -> Response<Body> {
    json_response(&state.authorization_server_metadata)
}

async fn oidc_metadata_redirect(State(state): State<Arc<AppState>>) -> Response<Body> {
    Redirect::temporary(&state.oidc_metadata_url).into_response()
}

fn keycloak_authorization_server_metadata(
    config: &config::Config,
) -> Result<AuthorizationServerMetadata, String> {
    let issuer = keycloak_auth_surface_issuer(config)?;

    Ok(AuthorizationServerMetadata {
        issuer: issuer.clone(),
        authorization_endpoint: format!("{issuer}/protocol/openid-connect/auth"),
        token_endpoint: format!("{issuer}/protocol/openid-connect/token"),
        registration_endpoint: Some(format!("{issuer}/clients-registrations/openid-connect")),
        jwks_uri: Some(format!("{issuer}/protocol/openid-connect/certs")),
        introspection_endpoint: Some(format!("{issuer}/protocol/openid-connect/token/introspect")),
        device_authorization_endpoint: Some(format!(
            "{issuer}/protocol/openid-connect/auth/device"
        )),
        grant_types_supported: Some(vec![
            GRANT_TYPE_AUTHORIZATION_CODE.to_string(),
            GRANT_TYPE_DEVICE_CODE.to_string(),
        ]),
        client_id_metadata_document_supported: None,
        token_endpoint_auth_methods_supported: None,
        code_challenge_methods_supported: None,
    })
}

fn keycloak_auth_surface_issuer(config: &config::Config) -> Result<String, String> {
    let authorization_servers: Vec<String> = config
        .authorization_servers
        .iter()
        .map(|value| value.trim().trim_end_matches('/'))
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect();

    match authorization_servers.as_slice() {
        [issuer] => Ok(issuer.clone()),
        [] => config
            .auth
            .issuer
            .as_ref()
            .map(|value| value.trim().trim_end_matches('/'))
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .ok_or_else(|| "No authorization server is configured.".to_string()),
        many => Err(format!(
            "kc-admin-mcp auth surface requires exactly one authorization server; got {}",
            many.len()
        )),
    }
}

fn keycloak_auth_surface_config(
    config: &config::Config,
    authenticator: Arc<Authenticator>,
    authorization_server_metadata: AuthorizationServerMetadata,
) -> Result<AuthSurfaceConfig, String> {
    let public_base_url = auth_surface_public_base_url(&config.resource_url)?;
    AuthSurfaceConfig::single_issuer_from_metadata_source(
        public_base_url,
        IssuerMetadataConfig {
            resource_path: "/mcp".to_string(),
            metadata_source: AuthorizationServerMetadataSource::Explicit(
                authorization_server_metadata,
            ),
            realm: "kc-admin-mcp".to_string(),
            scopes_supported: config.scopes_supported.clone(),
            allowed_client_ids: config
                .auth
                .allowed_client_ids
                .iter()
                .cloned()
                .collect::<HashSet<_>>(),
            authenticator,
            resource_url_override: Some(config.resource_url.clone()),
        },
    )
    .map(|auth_surface| auth_surface.with_detected_allow_insecure_http())
    .map_err(|err| err.to_string())
}

fn auth_surface_public_base_url(resource_url: &str) -> Result<String, String> {
    let trimmed = resource_url.trim().trim_end_matches('/');
    let Some(public_base_url) = trimmed.strip_suffix("/mcp") else {
        return Err(format!(
            "KC_ADMIN_MCP_RESOURCE_URL must end with /mcp for auth-surface publication; got {resource_url}"
        ));
    };
    if public_base_url.is_empty() {
        return Err(format!(
            "KC_ADMIN_MCP_RESOURCE_URL must include a base URL before /mcp; got {resource_url}"
        ));
    }
    Ok(public_base_url.to_string())
}

fn json_response<T: serde::Serialize>(payload: &T) -> Response<Body> {
    let body = serde_json::to_vec(payload).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap()
}

fn session_id_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get(HEADER_SESSION_ID)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
}

fn last_event_id_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get(HEADER_LAST_EVENT_ID)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
}

fn is_initialize_payload(body: &[u8]) -> bool {
    if body.is_empty() {
        return false;
    }
    let Ok(payload) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    match payload {
        serde_json::Value::Object(map) => map
            .get("method")
            .and_then(|value| value.as_str())
            .map(|method| method == "initialize")
            .unwrap_or(false),
        _ => false,
    }
}

async fn read_initialize_payload_bytes(
    body: Body,
    limit_bytes: usize,
) -> Result<Bytes, axum::Error> {
    axum::body::to_bytes(body, limit_bytes).await
}

fn jsonrpc_request_id(body: &[u8]) -> Option<serde_json::Value> {
    if body.is_empty() {
        return None;
    }
    let Ok(payload) = serde_json::from_slice::<serde_json::Value>(body) else {
        return None;
    };
    match payload {
        serde_json::Value::Object(map) => {
            if map
                .get("jsonrpc")
                .and_then(|value| value.as_str())
                .map(|value| value == "2.0")
                .unwrap_or(false)
            {
                Some(map.get("id").cloned().unwrap_or(serde_json::Value::Null))
            } else {
                None
            }
        }
        _ => None,
    }
}

async fn forward_service<M>(
    service: StreamableHttpService<KcAdminMcp, M>,
    req: Request<Body>,
) -> Response<Body>
where
    M: SessionManager,
{
    let response = service.handle(req).await;
    response.map(Body::new)
}

async fn handle_mcp(State(state): State<Arc<AppState>>, req: Request<Body>) -> Response<Body> {
    let method = req.method().clone();
    let session_id = session_id_from_headers(req.headers());

    match method {
        Method::POST => {
            if let Some(session_id) = session_id.clone() {
                if session_exists(&state, &session_id).await {
                    return forward_service(state.stateful_service.clone(), req).await;
                }
                if let Some(stateless) = state.stateless_service.clone() {
                    return forward_service(stateless, req).await;
                }
                let (_, body) = req.into_parts();
                let bytes = match axum::body::to_bytes(body, usize::MAX).await {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        return session_error(
                            StatusCode::NOT_FOUND,
                            "Invalid or expired session ID.",
                            "Re-initialize with POST /mcp to obtain a new session id.",
                            None,
                        );
                    }
                };
                return session_error(
                    StatusCode::NOT_FOUND,
                    "Invalid or expired session ID.",
                    "Re-initialize with POST /mcp to obtain a new session id.",
                    jsonrpc_request_id(&bytes),
                );
            }

            let (parts, body) = req.into_parts();
            let bytes = match read_initialize_payload_bytes(
                body,
                state.config.streamable_http.initialize_body_limit_bytes,
            )
            .await
            {
                Ok(bytes) => bytes,
                Err(_) => {
                    return session_error(
                        StatusCode::BAD_REQUEST,
                        "Failed to read request body.",
                        "Retry the request.",
                        None,
                    );
                }
            };
            if is_initialize_payload(&bytes) {
                let req = Request::from_parts(parts, Body::from(bytes));
                return forward_service(state.stateful_service.clone(), req).await;
            }
            if let Some(stateless) = state.stateless_service.clone() {
                let req = Request::from_parts(parts, Body::from(bytes));
                return forward_service(stateless, req).await;
            }
            session_error(
                StatusCode::BAD_REQUEST,
                "Missing session ID.",
                "Initialize with POST /mcp to obtain a new session id.",
                jsonrpc_request_id(&bytes),
            )
        }
        Method::GET | Method::DELETE => {
            let Some(session_id) = session_id else {
                return session_error(
                    StatusCode::BAD_REQUEST,
                    "Missing session ID.",
                    "Initialize with POST /mcp to obtain a new session id.",
                    None,
                );
            };
            if !session_exists(&state, &session_id).await {
                if matches!(method, Method::GET) && state.resume_mode == ResumeMode::Replay {
                    if let Some(last_event_id) = last_event_id_from_headers(req.headers()) {
                        if let Some(response) =
                            replay_from_event_store(&state, &session_id, &last_event_id).await
                        {
                            return response;
                        }
                    }
                }
                return session_error(
                    StatusCode::NOT_FOUND,
                    "Invalid or expired session ID.",
                    "Re-initialize with POST /mcp to obtain a new session id.",
                    None,
                );
            }
            forward_service(state.stateful_service.clone(), req).await
        }
        _ => session_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "Method not allowed.",
            "Use POST /mcp to initialize, then reuse the session id for later requests.",
            None,
        ),
    }
}

fn session_error(
    status: StatusCode,
    message: &str,
    hint: &str,
    jsonrpc_id: Option<serde_json::Value>,
) -> Response<Body> {
    let body = if let Some(id) = jsonrpc_id {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32600,
                "message": message,
                "data": {
                    "hint": hint,
                    "http_status": status.as_u16(),
                }
            }
        })
    } else {
        serde_json::json!({
            "status": "error",
            "error": message,
            "hint": hint,
        })
    };
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap_or_else(|_| Response::new(Body::from("{\"status\":\"error\"}")))
}

async fn session_exists(state: &AppState, session_id: &str) -> bool {
    state
        .session_manager
        .has_session(&session_id.into())
        .await
        .unwrap_or(false)
}

fn build_event_store(config: &StreamableHttpConfig) -> Result<Option<EventStore>, String> {
    if !config.replay_enabled() {
        return Ok(None);
    }
    let store_config = EventStoreConfig {
        max_streams: config.max_streams,
        max_events: config.max_events,
        ttl: config.ttl,
        encryption: config.event_store_key.clone(),
    };
    match config.event_store_mode {
        EventStoreMode::Off => Ok(None),
        EventStoreMode::Memory => Ok(Some(EventStore::memory(store_config))),
        EventStoreMode::Sqlite => {
            let Some(path) = config.event_store_path.clone() else {
                return Err(
                    "KC_ADMIN_MCP_HTTP_EVENT_STORE_PATH must be set for sqlite event store."
                        .to_string(),
                );
            };
            EventStore::sqlite(path, store_config)
                .map(Some)
                .map_err(|err| err.to_string())
        }
    }
}

async fn replay_from_event_store(
    state: &AppState,
    session_id: &str,
    last_event_id: &str,
) -> Option<Response<Body>> {
    let store = state.event_store.as_ref()?;
    let events = match store.replay_after(session_id, last_event_id).await {
        Ok(events) => events,
        Err(err) => {
            tracing::warn!(error = %err, "event store replay failed");
            return None;
        }
    };
    if events.is_empty() {
        return None;
    }
    let stream = stream::iter(events.into_iter().map(|message| {
        let mut event = if let Some(ref msg) = message.message {
            let data = serde_json::to_string(msg.as_ref()).unwrap_or_default();
            Event::default().data(data)
        } else {
            Event::default().data("")
        };
        if let Some(id) = message.event_id.clone() {
            event = event.id(id);
        }
        if let Some(retry) = message.retry {
            event = event.retry(retry);
        }
        Ok::<Event, std::convert::Infallible>(event)
    }));

    let response = Sse::new(stream).into_response();

    let mut response = response;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(EVENT_STREAM_MIME_TYPE),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    Some(response.map(Body::new))
}

async fn auth_guard(
    State(state): State<Arc<AppState>>,
    mut req: Request<Body>,
    next: Next,
) -> Response<Body> {
    let request_id = request_id(&req);
    let actor_id = actor_id(&req);
    let session_id = header_value(req.headers(), "mcp-session-id");
    let method = Some(req.method().to_string());
    let path = Some(req.uri().path().to_string());
    let start = Instant::now();

    let context = log_context::LogContext::new(
        request_id.clone(),
        actor_id.clone(),
        session_id,
        method,
        path,
    );

    log_context::with_context(context, async move {
        match authenticate_request(
            req.headers(),
            &state.config,
            &state.authenticator,
            &request_id,
            actor_id.clone(),
        )
        .await
        {
            Ok(ctx) => {
                req.extensions_mut().insert(ctx);
                let mut response = next.run(req).await;
                if let Ok(value) = header::HeaderValue::from_str(&request_id) {
                    response.headers_mut().insert("x-request-id", value);
                }
                tracing::info!(
                    target: logging::LOG_TARGET_ACCESS,
                    status = response.status().as_u16(),
                    duration_ms = start.elapsed().as_millis() as u64,
                    "http.request"
                );
                response
            }
            Err(err) => {
                tracing::warn!(
                    target: logging::LOG_TARGET_AUTH,
                    request_id = %request_id,
                    actor_id = actor_id.as_deref().unwrap_or("unknown"),
                    error = %err,
                    code = err.code(),
                    status = err.status_code().as_u16(),
                    "auth rejected request"
                );
                let response =
                    auth_error_response(&state.config, &state.metrics, &request_id, &err);
                tracing::info!(
                    target: logging::LOG_TARGET_ACCESS,
                    status = response.status().as_u16(),
                    duration_ms = start.elapsed().as_millis() as u64,
                    "http.request"
                );
                response
            }
        }
    })
    .await
}

fn auth_error_response(
    config: &config::Config,
    metrics: &Metrics,
    request_id: &str,
    err: &AuthError,
) -> Response<Body> {
    metrics.record_auth_reject(err.code());
    let payload = serde_json::json!({
        "status": "error",
        "code": err.code(),
        "message": err.to_string(),
        "request_id": request_id,
    });
    let body = Body::from(payload.to_string());
    let mut response = Response::builder()
        .status(err.status_code())
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-request-id", request_id)
        .body(body)
        .unwrap();

    let challenge = build_www_authenticate(config);
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, challenge);
    response
}

fn build_www_authenticate(config: &config::Config) -> header::HeaderValue {
    let challenge =
        BearerChallenge::resource_metadata("kc-admin-mcp", &config.resource_metadata_url);
    build_bearer_challenge(&challenge)
}

fn request_id(req: &Request<Body>) -> String {
    header_value(req.headers(), "x-request-id").unwrap_or_else(|| Uuid::new_v4().to_string())
}

fn actor_id(req: &Request<Body>) -> Option<String> {
    header_value(req.headers(), "x-actor-id")
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        is_initialize_payload, jsonrpc_request_id, keycloak_auth_surface_issuer,
        keycloak_authorization_server_metadata, read_initialize_payload_bytes, session_error,
        GRANT_TYPE_AUTHORIZATION_CODE, GRANT_TYPE_DEVICE_CODE,
    };
    use axum::body::{to_bytes, Body};
    use axum::http::StatusCode;
    use serde_json::json;

    #[test]
    fn detects_initialize_payload() {
        let payload = br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#;
        assert!(is_initialize_payload(payload));
    }

    #[test]
    fn rejects_non_initialize_payload() {
        let payload = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
        assert!(!is_initialize_payload(payload));
    }

    #[tokio::test]
    async fn initialize_probe_rejects_oversized_body() {
        let oversized = vec![b'a'; 33];
        let result = read_initialize_payload_bytes(Body::from(oversized), 32).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn initialize_probe_accepts_configured_large_body() {
        let larger_than_legacy_limit = vec![b'a'; 1024 * 1024 + 1];
        let result = read_initialize_payload_bytes(
            Body::from(larger_than_legacy_limit),
            crate::config::DEFAULT_INITIALIZE_BODY_LIMIT_BYTES,
        )
        .await;
        assert!(result.is_ok());
    }

    #[test]
    fn jsonrpc_request_id_extracts_id_from_jsonrpc_payload() {
        let payload = br#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{}}"#;
        let id = jsonrpc_request_id(payload).expect("jsonrpc id");
        assert_eq!(id, json!(7));
    }

    #[test]
    fn jsonrpc_request_id_returns_none_for_non_jsonrpc_payload() {
        let payload = br#"{"status":"error","hint":"not jsonrpc"}"#;
        assert!(jsonrpc_request_id(payload).is_none());
    }

    #[tokio::test]
    async fn session_error_emits_jsonrpc_error_shape_when_id_present() {
        let response = session_error(
            StatusCode::BAD_REQUEST,
            "Missing session ID.",
            "Initialize with POST /mcp to obtain a new session id.",
            Some(json!("abc-123")),
        );
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        let payload: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(payload["jsonrpc"], "2.0");
        assert_eq!(payload["id"], "abc-123");
        assert_eq!(payload["error"]["code"], -32600);
        assert_eq!(payload["error"]["message"], "Missing session ID.");
    }

    #[test]
    fn authorization_server_metadata_uses_configured_keycloak_issuer() {
        let mut config = crate::test_support::build_config(
            "https://mcp.example".to_string(),
            "https://keycloak.example".to_string(),
        );
        config.authorization_servers = vec!["https://auth.example/realms/example/".to_string()];

        let metadata = keycloak_authorization_server_metadata(&config).expect("metadata");

        assert_eq!(metadata.issuer, "https://auth.example/realms/example");
        assert_eq!(
            metadata.authorization_endpoint,
            "https://auth.example/realms/example/protocol/openid-connect/auth"
        );
        assert_eq!(
            metadata.token_endpoint,
            "https://auth.example/realms/example/protocol/openid-connect/token"
        );
        assert_eq!(
            metadata.registration_endpoint.as_deref(),
            Some("https://auth.example/realms/example/clients-registrations/openid-connect")
        );
        assert_eq!(
            metadata.device_authorization_endpoint.as_deref(),
            Some("https://auth.example/realms/example/protocol/openid-connect/auth/device")
        );
        assert_eq!(
            metadata.grant_types_supported,
            Some(vec![
                GRANT_TYPE_AUTHORIZATION_CODE.to_string(),
                GRANT_TYPE_DEVICE_CODE.to_string()
            ])
        );
    }

    #[test]
    fn auth_surface_issuer_rejects_multiple_authorization_servers() {
        let mut config = crate::test_support::build_config(
            "https://mcp.example".to_string(),
            "https://keycloak.example".to_string(),
        );
        config.authorization_servers = vec![
            "https://auth.example/realms/one".to_string(),
            "https://auth.example/realms/two".to_string(),
        ];

        let err = keycloak_auth_surface_issuer(&config).expect_err("ambiguous issuer");
        assert!(
            err.contains("exactly one authorization server"),
            "unexpected error: {err}"
        );
    }
}
