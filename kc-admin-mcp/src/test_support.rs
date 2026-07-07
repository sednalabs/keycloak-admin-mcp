use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use axum::body::Body;
use axum::http::Request;
use axum::Router;
use mcp_toolkit_core::notifications::ToolListTracker;
use tokio::sync::oneshot;

use crate::audit::AuditLog;
use crate::auth::AuthContext;
use crate::config::{
    collect_scopes, default_scope_map, AuthConfig, AuthMode, ClientAuthMethod, Config,
    EventStoreMode, GatewayConfig, MtlsMode, ResumeMode, RoleRequirements, ServerTlsConfig,
    StartupAdmissionConfig, StartupAdmissionMode, StreamableHttpConfig, TestGateProfile,
    DEFAULT_INITIALIZE_BODY_LIMIT_BYTES,
};
use crate::gateway::GatewayClient;
use crate::metrics::Metrics;
use crate::provenance::{capture_runtime_provenance, RuntimeAdmissionExtension};
use crate::server::KcAdminMcp;

pub(crate) struct TestServer {
    pub base_url: String,
    shutdown: Option<oneshot::Sender<()>>,
}

pub(crate) const UNUSED_KEYCLOAK_BASE_URL: &str = "https://keycloak.invalid";

impl TestServer {
    pub(crate) async fn spawn(router: Router) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await
                .ok();
        });
        Self {
            base_url: format!("http://{}", addr),
            shutdown: Some(shutdown_tx),
        }
    }

    pub(crate) fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

pub(crate) fn build_config(gateway_url: String, keycloak_url: String) -> Config {
    let scope_map = default_scope_map();
    let scopes_supported = collect_scopes(&scope_map);
    let auth = AuthConfig {
        mode: AuthMode::Introspection,
        issuer: Some("https://issuer.test".to_string()),
        audience: Some("http://kc-admin-mcp.test".to_string()),
        allowed_azp: Vec::new(),
        allowed_client_ids: Vec::new(),
        open_caller_allowlists_expires_at: None,
        clock_skew_seconds: 30,
        introspection_url: "https://issuer.test/introspect".to_string(),
        introspection_client_id: "kc-admin-mcp".to_string(),
        introspection_client_secret: "kc-admin-mcp-secret".to_string(),
        introspection_auth_method: ClientAuthMethod::ClientSecretBasic,
        request_timeout: Duration::from_millis(500),
        dpop_required: false,
        mtls_mode: MtlsMode::Disabled,
        mtls_client_cert_header: None,
        jwks_url: None,
    };

    Config {
        bind_addr: "127.0.0.1:0".to_string(),
        resource_url: "http://127.0.0.1:0/mcp".to_string(),
        resource_metadata_url: "http://127.0.0.1:0/.well-known/oauth-protected-resource/mcp"
            .to_string(),
        authorization_servers: vec!["https://issuer.test".to_string()],
        scopes_supported,
        scope_map,
        role_requirements: RoleRequirements {
            read: vec![
                "kc-admin-access".to_string(),
                "kc-admin-sentinel".to_string(),
            ],
            write: vec!["kc-admin-operator".to_string()],
        },
        enable_secret_tools: false,
        auth,
        streamable_http: StreamableHttpConfig {
            event_store_mode: EventStoreMode::Off,
            resume_mode: ResumeMode::Historyless,
            initialize_body_limit_bytes: DEFAULT_INITIALIZE_BODY_LIMIT_BYTES,
            event_store_path: None,
            event_store_key: None,
            max_streams: 200,
            max_events: 200,
            ttl: Some(Duration::from_secs(120)),
            retry_interval: None,
            stateless_fallback: true,
        },
        startup_admission: StartupAdmissionConfig {
            mode: StartupAdmissionMode::Off,
            required_profile: TestGateProfile::Fast,
            fast_gate_artifact_path: std::env::temp_dir().join("kc-admin-test-fast-gate.json"),
            standard_gate_artifact_path: std::env::temp_dir()
                .join("kc-admin-test-standard-gate.json"),
            bypass: false,
            bypass_reason: None,
            bypass_ttl_s: None,
            production_mode: false,
            allow_production_bypass: false,
        },
        server_tls: ServerTlsConfig {
            cert_pem: None,
            key_pem: None,
            client_ca_pem: None,
        },
        gateway: GatewayConfig {
            base_url: gateway_url,
            request_timeout: Duration::from_millis(500),
            tls_ca_pem: None,
            tls_client_cert_pem: None,
            tls_client_key_pem: None,
        },
        keycloak_base_url: keycloak_url,
        keycloak_admin_realm: "master".to_string(),
        keycloak_client_id: "kc-admin-test".to_string(),
        audit_log_max: 100,
        audit_log_path: None,
        audit_checkpoint_path: None,
        audit_log_max_bytes: None,
        audit_log_max_files: 0,
    }
}

pub(crate) fn build_server(config: Config) -> KcAdminMcp {
    let metrics = Arc::new(Metrics::new());
    let audit_log = Arc::new(AuditLog::new(100, None, None, None, 0));
    let gateway =
        GatewayClient::new(&config.gateway, Some(metrics.clone())).expect("gateway client");
    let tool_list_tracker = Arc::new(ToolListTracker::new());
    let runtime_snapshot = capture_runtime_provenance().expect("capture runtime provenance");
    let runtime_provenance = Arc::new(runtime_snapshot.provenance);
    let runtime_admission = RuntimeAdmissionExtension {
        enforcement_phase: "off".to_string(),
        required_gate_level: "fast".to_string(),
        outcome: "disabled".to_string(),
        reason_code: Some("admission.disabled".to_string()),
        override_active: false,
    };
    KcAdminMcp::new(
        Arc::new(config),
        gateway,
        Instant::now(),
        metrics,
        audit_log,
        tool_list_tracker,
        runtime_provenance,
        runtime_admission,
    )
}

pub(crate) fn auth_context(scopes: Vec<String>) -> AuthContext {
    AuthContext {
        request_id: "req-test".to_string(),
        actor_id: Some("actor-test".to_string()),
        raw_token: "test-token".to_string(),
        token_ref: "token-ref".to_string(),
        client_id: Some("client-test".to_string()),
        subject: Some("user-test".to_string()),
        scopes,
        roles: vec![
            "kc-admin-access".to_string(),
            "kc-admin-operator".to_string(),
        ],
        expires_at: None,
        azp: Some("client-test".to_string()),
        issuer: Some("https://issuer.test".to_string()),
    }
}

pub(crate) fn parts_with_auth(ctx: AuthContext) -> axum::http::request::Parts {
    let request = Request::builder()
        .uri("/mcp")
        .body(Body::empty())
        .expect("test request");
    let (mut parts, _body) = request.into_parts();
    parts.extensions.insert(ctx);
    parts
}
