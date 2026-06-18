//! # Configuration
//!
//! Handles environment variable parsing and credential loading for the Keycloak Admin MCP server.
//!
//! ## Rationale
//! Centralizes all service settings, including auth policies, scope mappings, and gateway
//! connection details. It supports loading secrets from the `CREDENTIALS_DIRECTORY`
//! to align with systemd/container best practices.
//!
//! ## Security Boundaries
//! * **Secret Isolation**: Prefers `CREDENTIALS_DIRECTORY` over environment variables for secrets.
//! * **Scope Mapping**: Defines the authoritative mapping between MCP tools and Keycloak scopes.

use std::time::{Duration, Instant};
use std::{fs, path::PathBuf};

use serde::{Deserialize, Serialize};

/// Scope collections grouped by read/write intention.
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
pub struct ScopeSet {
    pub read: Vec<String>,
    pub write: Vec<String>,
}

/// All configurable scopes used to gate MCP tools.
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
pub struct ScopeMap {
    pub users: ScopeSet,
    pub groups: ScopeSet,
    pub roles: ScopeSet,
    pub clients: ClientScopeSet,
    pub client_scopes: ScopeSet,
    pub identity_providers: ScopeSet,
    pub realms: RealmScopeSet,
    pub events: EventScopeSet,
    pub tokens: TokensScopeSet,
    pub observability: ObservabilityScopeSet,
}

/// Client-related scope subsets including `secrets`.
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
pub struct ClientScopeSet {
    pub read: Vec<String>,
    pub write: Vec<String>,
    pub secrets: Vec<String>,
}

/// Realm-specific scope subsets.
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
pub struct RealmScopeSet {
    pub read: Vec<String>,
    pub write: Vec<String>,
    pub admin: Vec<String>,
}

/// Event-specific scope subsets.
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
pub struct EventScopeSet {
    pub read: Vec<String>,
    pub admin: Vec<String>,
}

/// Token-related scope subsets.
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
pub struct TokensScopeSet {
    pub read: Vec<String>,
}

/// Observability-related scope subsets.
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
pub struct ObservabilityScopeSet {
    pub read: Vec<String>,
}

/// Role requirements controlling who may use read/write scopes.
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
pub struct RoleRequirements {
    pub read: Vec<String>,
    pub write: Vec<String>,
}

/// Authentication modes for the MCP server.
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
pub enum AuthMode {
    Introspection,
    Jwks,
}

/// mTLS enforcement modes.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MtlsMode {
    Disabled,
    Native,
    ProxyHeader,
}

/// Client authentication styles for introspection/exchange clients.
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
pub enum ClientAuthMethod {
    ClientSecretBasic,
    ClientSecretPost,
}

/// Runtime authentication configuration (introspection endpoint, scopes, clock skew, etc.).
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
pub struct AuthConfig {
    pub mode: AuthMode,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub allowed_azp: Vec<String>,
    pub allowed_client_ids: Vec<String>,
    pub open_caller_allowlists_expires_at: Option<Instant>,
    pub clock_skew_seconds: i64,
    pub introspection_url: String,
    pub introspection_client_id: String,
    pub introspection_client_secret: String,
    pub introspection_auth_method: ClientAuthMethod,
    pub request_timeout: Duration,
    pub dpop_required: bool,
    pub mtls_mode: MtlsMode,
    pub mtls_client_cert_header: Option<String>,
    pub jwks_url: Option<String>,
}

/// TLS credential material for the MCP server.
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
pub struct ServerTlsConfig {
    pub cert_pem: Option<String>,
    pub key_pem: Option<String>,
    pub client_ca_pem: Option<String>,
}

/// Supported event store backends for SSE replay.
#[derive(Clone, Debug)]
pub enum EventStoreMode {
    Off,
    Memory,
    Sqlite,
}

/// Session resumption policy for streamable HTTP.
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum ResumeMode {
    Off,
    Historyless,
    Replay,
}

/// Default maximum bytes read while probing sessionless initialize requests.
pub const DEFAULT_INITIALIZE_BODY_LIMIT_BYTES: usize = 16 * 1024 * 1024;

/// Startup admission enforcement mode for gate evidence checks.
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum StartupAdmissionMode {
    Off,
    Warn,
    Strict,
}

impl StartupAdmissionMode {
    pub fn enforcement_phase(self) -> &'static str {
        match self {
            StartupAdmissionMode::Off => "off",
            StartupAdmissionMode::Warn => "warn",
            StartupAdmissionMode::Strict => "strict",
        }
    }
}

/// Required gate profile for startup admission checks.
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum TestGateProfile {
    Fast,
    Standard,
}

impl TestGateProfile {
    pub fn label(self) -> &'static str {
        match self {
            TestGateProfile::Fast => "fast",
            TestGateProfile::Standard => "standard",
        }
    }
}

/// Startup admission configuration for gate artifact validation.
#[derive(Clone, Debug)]
pub struct StartupAdmissionConfig {
    pub mode: StartupAdmissionMode,
    pub required_profile: TestGateProfile,
    pub fast_gate_artifact_path: PathBuf,
    pub standard_gate_artifact_path: PathBuf,
    pub bypass: bool,
    pub bypass_reason: Option<String>,
    pub bypass_ttl_s: Option<u64>,
    pub production_mode: bool,
    pub allow_production_bypass: bool,
}

/// Streamable HTTP session configuration.
#[derive(Clone, Debug)]
pub struct StreamableHttpConfig {
    pub event_store_mode: EventStoreMode,
    pub resume_mode: ResumeMode,
    pub initialize_body_limit_bytes: usize,
    pub event_store_path: Option<String>,
    pub event_store_key: Option<mcp_toolkit_http::session::EventStoreEncryption>,
    pub max_streams: usize,
    pub max_events: usize,
    pub ttl: Option<Duration>,
    pub retry_interval: Option<Duration>,
    pub stateless_fallback: bool,
}

impl StreamableHttpConfig {
    pub fn resume_enabled(&self) -> bool {
        !matches!(self.resume_mode, ResumeMode::Off)
    }

    pub fn replay_enabled(&self) -> bool {
        matches!(self.resume_mode, ResumeMode::Replay)
    }
}

/// Configuration for the internal gateway endpoint.
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
pub struct GatewayConfig {
    pub base_url: String,
    pub request_timeout: Duration,
    pub tls_ca_pem: Option<String>,
    pub tls_client_cert_pem: Option<String>,
    pub tls_client_key_pem: Option<String>,
}

/// Top-level MCP configuration loaded from env/credentials directory.
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
pub struct Config {
    pub bind_addr: String,
    pub resource_url: String,
    pub resource_metadata_url: String,
    pub authorization_servers: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub scope_map: ScopeMap,
    pub role_requirements: RoleRequirements,
    #[allow(dead_code)]
    pub enable_secret_tools: bool,
    pub auth: AuthConfig,
    pub streamable_http: StreamableHttpConfig,
    pub startup_admission: StartupAdmissionConfig,
    pub server_tls: ServerTlsConfig,
    pub gateway: GatewayConfig,
    pub keycloak_base_url: String,
    pub keycloak_admin_realm: String,
    pub keycloak_client_id: String,
    pub audit_log_max: usize,
    pub audit_log_path: Option<String>,
    pub audit_checkpoint_path: Option<String>,
    pub audit_log_max_bytes: Option<u64>,
    pub audit_log_max_files: usize,
}

/// Build `Config` from environment variables and credential files.
///
/// # Security
/// * **Fail-Closed**: Validates that required URLs (like `JWKS_URL`) are present for the chosen auth mode.
/// * **Secrets**: Prioritizes `CREDENTIALS_DIRECTORY` for sensitive values.
///
/// # Errors
/// * Returns an error if the operation fails.
///
/// # Caveats
/// * None.
pub fn load_config() -> Result<Config, String> {
    let bind_addr = env("KC_ADMIN_MCP_BIND", "127.0.0.1:9400");
    let resource_url = env("KC_ADMIN_MCP_RESOURCE_URL", "http://127.0.0.1:9400/mcp");
    let resource_metadata_url = env(
        "KC_ADMIN_MCP_RESOURCE_METADATA_URL",
        "http://127.0.0.1:9400/.well-known/oauth-protected-resource/mcp",
    );

    let scope_map = default_scope_map();
    let scopes_supported = env_list("KC_ADMIN_MCP_SCOPES_SUPPORTED", collect_scopes(&scope_map));
    let streamable_http = load_streamable_http_config()?;
    let startup_admission = load_startup_admission_config()?;

    let role_requirements = RoleRequirements {
        read: env_list("KC_ADMIN_MCP_ROLE_READ", vec!["kc-admin:read".to_string()]),
        write: env_list(
            "KC_ADMIN_MCP_ROLE_WRITE",
            vec!["kc-admin:write".to_string()],
        ),
    };

    let auth_mode = match env("KC_ADMIN_MCP_AUTH_MODE", "introspection").as_str() {
        "jwks" => AuthMode::Jwks,
        _ => AuthMode::Introspection,
    };

    let auth_method = match env(
        "KC_ADMIN_MCP_INTROSPECTION_AUTH_METHOD",
        "client_secret_basic",
    )
    .as_str()
    {
        "client_secret_post" => ClientAuthMethod::ClientSecretPost,
        _ => ClientAuthMethod::ClientSecretBasic,
    };

    let mtls_mode = {
        let mtls_mode_env = env_optional("KC_ADMIN_MCP_MTLS_MODE");
        let mtls_required_legacy = env_bool("KC_ADMIN_MCP_MTLS_REQUIRED", false);
        let mtls_header_env = env_optional("KC_ADMIN_MCP_MTLS_CLIENT_CERT_HEADER");

        let parsed = match mtls_mode_env.as_deref() {
            Some("native") => MtlsMode::Native,
            Some("proxy") | Some("proxy_header") | Some("header") => MtlsMode::ProxyHeader,
            Some("disabled") | Some("off") | Some("false") => MtlsMode::Disabled,
            Some(other) => {
                return Err(format!(
                    "KC_ADMIN_MCP_MTLS_MODE must be one of native, proxy, disabled (got {other})"
                ))
            }
            None => {
                if mtls_required_legacy {
                    MtlsMode::Native
                } else if mtls_header_env.is_some() {
                    MtlsMode::ProxyHeader
                } else {
                    MtlsMode::Disabled
                }
            }
        };

        parsed
    };

    let mtls_client_cert_header = match mtls_mode {
        MtlsMode::ProxyHeader => Some(
            env_optional("KC_ADMIN_MCP_MTLS_CLIENT_CERT_HEADER")
                .unwrap_or_else(|| "x-forwarded-client-cert".to_string()),
        ),
        _ => env_optional("KC_ADMIN_MCP_MTLS_CLIENT_CERT_HEADER"),
    };

    let mut auth = AuthConfig {
        mode: auth_mode,
        issuer: env_optional("KC_ADMIN_MCP_ISSUER"),
        audience: env_optional("KC_ADMIN_MCP_AUDIENCE"),
        allowed_azp: env_list("KC_ADMIN_MCP_ALLOWED_AZP", Vec::new()),
        allowed_client_ids: env_list("KC_ADMIN_MCP_ALLOWED_CLIENT_IDS", Vec::new()),
        clock_skew_seconds: env_i64("KC_ADMIN_MCP_CLOCK_SKEW_SECONDS", 30),
        introspection_url: env("KC_ADMIN_MCP_INTROSPECTION_URL", ""),
        introspection_client_id: env("KC_ADMIN_MCP_INTROSPECTION_CLIENT_ID", ""),
        introspection_client_secret: env_secret(
            "KC_ADMIN_MCP_INTROSPECTION_CLIENT_SECRET",
            "kc_admin_mcp_introspection_client_secret",
        ),
        introspection_auth_method: auth_method,
        request_timeout: Duration::from_millis(env_u64(
            "KC_ADMIN_MCP_INTROSPECTION_TIMEOUT_MS",
            5000,
        )),
        dpop_required: env_bool("KC_ADMIN_MCP_DPOP_REQUIRED", false),
        mtls_mode,
        mtls_client_cert_header,
        jwks_url: env_optional("KC_ADMIN_MCP_JWKS_URL"),
        open_caller_allowlists_expires_at: None,
    };

    let server_tls = ServerTlsConfig {
        cert_pem: env_secret_optional("KC_ADMIN_MCP_TLS_CERT", "kc_admin_mcp_tls_cert"),
        key_pem: env_secret_optional("KC_ADMIN_MCP_TLS_KEY", "kc_admin_mcp_tls_key"),
        client_ca_pem: env_secret_optional(
            "KC_ADMIN_MCP_TLS_CLIENT_CA",
            "kc_admin_mcp_tls_client_ca",
        ),
    };

    let gateway = GatewayConfig {
        base_url: env("KC_ADMIN_MCP_GATEWAY_URL", "http://127.0.0.1:9300"),
        request_timeout: Duration::from_millis(env_u64("KC_ADMIN_MCP_GATEWAY_TIMEOUT_MS", 5000)),
        tls_ca_pem: env_secret_optional(
            "KC_ADMIN_MCP_GATEWAY_TLS_CA",
            "kc_admin_mcp_gateway_tls_ca",
        ),
        tls_client_cert_pem: env_secret_optional(
            "KC_ADMIN_MCP_GATEWAY_TLS_CERT",
            "kc_admin_mcp_gateway_tls_cert",
        ),
        tls_client_key_pem: env_secret_optional(
            "KC_ADMIN_MCP_GATEWAY_TLS_KEY",
            "kc_admin_mcp_gateway_tls_key",
        ),
    };

    let keycloak_base_url = env("KEYCLOAK_URL", "http://127.0.0.1:8080");
    let keycloak_admin_realm = env("KEYCLOAK_ADMIN_REALM", "master");
    let keycloak_client_id = env("KEYCLOAK_ADMIN_CLIENT_ID", "");

    let audit_log_max = env_u64("KC_ADMIN_MCP_AUDIT_MAX", 500) as usize;
    let audit_log_path = env_optional("KC_ADMIN_MCP_AUDIT_LOG_PATH");
    let audit_checkpoint_path = env_optional("KC_ADMIN_MCP_AUDIT_CHECKPOINT_PATH");
    let audit_log_max_bytes = match env_u64("KC_ADMIN_MCP_AUDIT_LOG_MAX_BYTES", 0) {
        0 => None,
        value => Some(value),
    };
    let audit_log_max_files = env_u64("KC_ADMIN_MCP_AUDIT_LOG_MAX_FILES", 5) as usize;

    if matches!(auth.mode, AuthMode::Jwks)
        && auth.jwks_url.as_ref().map(|v| v.is_empty()).unwrap_or(true)
    {
        return Err("KC_ADMIN_MCP_JWKS_URL is required when auth mode is jwks".to_string());
    }
    require_oauth_identity_expectations(&auth)?;
    let mcp_build_production = startup_admission.production_mode;
    let allow_open_caller_allowlists =
        env_bool_strict("KC_ADMIN_MCP_ALLOW_OPEN_CALLER_ALLOWLISTS", false)?;
    let allow_open_caller_allowlists_reason =
        env_optional("KC_ADMIN_MCP_ALLOW_OPEN_CALLER_ALLOWLISTS_REASON");
    let allow_open_caller_allowlists_ttl_s =
        env_optional_u64_strict("KC_ADMIN_MCP_ALLOW_OPEN_CALLER_ALLOWLISTS_TTL_S")?;
    require_caller_allowlists(
        &auth,
        mcp_build_production,
        allow_open_caller_allowlists,
        allow_open_caller_allowlists_reason.as_deref(),
        allow_open_caller_allowlists_ttl_s,
    )?;
    auth.open_caller_allowlists_expires_at = allow_open_caller_allowlists_ttl_s
        .filter(|_| allow_open_caller_allowlists)
        .map(break_glass_deadline)
        .transpose()?;
    let authorization_servers = resolve_authorization_servers(
        env_list("KC_ADMIN_MCP_AUTH_SERVERS", Vec::new()),
        auth.issuer.as_deref(),
    );

    Ok(Config {
        bind_addr,
        resource_url,
        resource_metadata_url,
        authorization_servers,
        scopes_supported,
        scope_map,
        role_requirements,
        enable_secret_tools: env_bool("KC_ADMIN_MCP_ENABLE_SECRET_TOOLS", false),
        auth,
        streamable_http,
        startup_admission,
        server_tls,
        gateway,
        keycloak_base_url,
        keycloak_admin_realm,
        keycloak_client_id,
        audit_log_max,
        audit_log_path,
        audit_checkpoint_path,
        audit_log_max_bytes,
        audit_log_max_files,
    })
}

/// Load streamable HTTP session settings.
pub fn load_streamable_http_config() -> Result<StreamableHttpConfig, String> {
    let event_store_raw = env("KC_ADMIN_MCP_HTTP_EVENT_STORE", "off")
        .trim()
        .to_ascii_lowercase();
    let event_store_mode = match event_store_raw.as_str() {
        "" | "0" | "false" | "off" | "none" => EventStoreMode::Off,
        "1" | "true" | "on" | "memory" | "inmemory" => EventStoreMode::Memory,
        "sqlite" | "file" | "disk" => EventStoreMode::Sqlite,
        _ => {
            return Err(format!(
            "KC_ADMIN_MCP_HTTP_EVENT_STORE must be memory, sqlite, or off (got {event_store_raw})"
        ))
        }
    };

    let resume_raw = env("KC_ADMIN_MCP_HTTP_RESUME_MODE", "historyless")
        .trim()
        .to_ascii_lowercase();
    let resume_mode = match resume_raw.as_str() {
        "" | "0" | "false" | "off" | "none" => ResumeMode::Off,
        "historyless" | "history-less" | "no-history" | "nohistory" => ResumeMode::Historyless,
        "replay" | "history" | "historyful" => ResumeMode::Replay,
        _ => {
            return Err(format!(
            "KC_ADMIN_MCP_HTTP_RESUME_MODE must be off, historyless, or replay (got {resume_raw})"
        ))
        }
    };

    if matches!(resume_mode, ResumeMode::Replay) && matches!(event_store_mode, EventStoreMode::Off)
    {
        return Err(
            "KC_ADMIN_MCP_HTTP_RESUME_MODE=replay requires KC_ADMIN_MCP_HTTP_EVENT_STORE=memory|sqlite."
                .to_string(),
        );
    }
    if !matches!(resume_mode, ResumeMode::Replay)
        && !matches!(event_store_mode, EventStoreMode::Off)
    {
        return Err(
            "KC_ADMIN_MCP_HTTP_EVENT_STORE is only supported when KC_ADMIN_MCP_HTTP_RESUME_MODE=replay."
                .to_string(),
        );
    }

    let event_store_path = if matches!(event_store_mode, EventStoreMode::Sqlite) {
        let path = env(
            "KC_ADMIN_MCP_HTTP_EVENT_STORE_PATH",
            "data/event-store.sqlite",
        )
        .trim()
        .to_string();
        if path.is_empty() {
            return Err(
                "KC_ADMIN_MCP_HTTP_EVENT_STORE_PATH must be set when KC_ADMIN_MCP_HTTP_EVENT_STORE=sqlite."
                    .to_string(),
            );
        }
        Some(path)
    } else {
        None
    };

    let event_store_key = env_optional("KC_ADMIN_MCP_HTTP_EVENT_STORE_KEY_B64")
        .map(|value| {
            mcp_toolkit_http::session::EventStoreEncryption::from_base64(&value)
                .map_err(|err| err.to_string())
        })
        .transpose()?;

    let max_streams = env_u64("KC_ADMIN_MCP_HTTP_EVENT_STORE_MAX_STREAMS", 200).max(1) as usize;
    let max_events = env_u64("KC_ADMIN_MCP_HTTP_EVENT_STORE_MAX_EVENTS", 200).max(1) as usize;
    let initialize_body_limit_bytes = env_u64(
        "KC_ADMIN_MCP_HTTP_INITIALIZE_BODY_LIMIT_BYTES",
        DEFAULT_INITIALIZE_BODY_LIMIT_BYTES as u64,
    )
    .max(1) as usize;

    let ttl_s = env_u64("KC_ADMIN_MCP_HTTP_EVENT_STORE_TTL_S", 120);
    let ttl = if ttl_s == 0 {
        None
    } else {
        Some(Duration::from_secs(ttl_s.max(1)))
    };

    let retry_ms = env_u64("KC_ADMIN_MCP_HTTP_RETRY_INTERVAL_MS", 0);
    let retry_interval = if !matches!(resume_mode, ResumeMode::Off) && retry_ms > 0 {
        Some(Duration::from_millis(retry_ms.max(1)))
    } else {
        None
    };
    let stateless_fallback = env_bool("KC_ADMIN_MCP_HTTP_STATELESS_FALLBACK", true);

    Ok(StreamableHttpConfig {
        event_store_mode,
        resume_mode,
        initialize_body_limit_bytes,
        event_store_path,
        event_store_key,
        max_streams,
        max_events,
        ttl,
        retry_interval,
        stateless_fallback,
    })
}

/// Load startup admission settings for gate artifact enforcement.
pub fn load_startup_admission_config() -> Result<StartupAdmissionConfig, String> {
    let production_mode = env_bool_strict(
        "KC_ADMIN_MCP_BUILD_PRODUCTION",
        env_bool("MCP_BUILD_PRODUCTION", false),
    )?;
    let mode_default = if production_mode { "strict" } else { "warn" };
    let mode =
        parse_startup_admission_mode(&env("KC_ADMIN_MCP_STARTUP_ADMISSION_MODE", mode_default))?;

    let profile_default = if production_mode { "standard" } else { "fast" };
    let required_profile = parse_test_gate_profile(&env(
        "KC_ADMIN_MCP_TEST_GATE_REQUIRED_PROFILE",
        profile_default,
    ))?;

    let bypass = env_bool_strict("KC_ADMIN_MCP_STARTUP_ADMISSION_BYPASS", false)?;
    let bypass_reason = env_optional("KC_ADMIN_MCP_STARTUP_ADMISSION_BYPASS_REASON");
    let bypass_ttl_s = env_optional_u64_strict("KC_ADMIN_MCP_STARTUP_ADMISSION_BYPASS_TTL_S")?;
    let allow_production_bypass =
        env_bool_strict("KC_ADMIN_MCP_STARTUP_ADMISSION_ALLOW_PROD_BYPASS", false)?;

    if production_mode && matches!(mode, StartupAdmissionMode::Off) {
        return Err(
            "KC_ADMIN_MCP_STARTUP_ADMISSION_MODE=off is not allowed when KC_ADMIN_MCP_BUILD_PRODUCTION=1."
                .to_string(),
        );
    }
    if bypass {
        if bypass_reason
            .as_deref()
            .map(|value| value.trim().is_empty())
            .unwrap_or(true)
        {
            return Err(
                "KC_ADMIN_MCP_STARTUP_ADMISSION_BYPASS requires KC_ADMIN_MCP_STARTUP_ADMISSION_BYPASS_REASON."
                    .to_string(),
            );
        }
        if bypass_ttl_s.unwrap_or(0) == 0 {
            return Err(
                "KC_ADMIN_MCP_STARTUP_ADMISSION_BYPASS requires KC_ADMIN_MCP_STARTUP_ADMISSION_BYPASS_TTL_S>0."
                    .to_string(),
            );
        }
        if production_mode && !allow_production_bypass {
            return Err(
                "Production bypass requires KC_ADMIN_MCP_STARTUP_ADMISSION_ALLOW_PROD_BYPASS=1."
                    .to_string(),
            );
        }
    }

    Ok(StartupAdmissionConfig {
        mode,
        required_profile,
        fast_gate_artifact_path: PathBuf::from(env(
            "KC_ADMIN_MCP_TEST_GATE_FAST_ARTIFACT_PATH",
            "data/test-gates/kc-admin-mcp/fast.json",
        )),
        standard_gate_artifact_path: PathBuf::from(env(
            "KC_ADMIN_MCP_TEST_GATE_STANDARD_ARTIFACT_PATH",
            "data/test-gates/kc-admin-mcp/standard.json",
        )),
        bypass,
        bypass_reason,
        bypass_ttl_s,
        production_mode,
        allow_production_bypass,
    })
}

fn parse_startup_admission_mode(value: &str) -> Result<StartupAdmissionMode, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "off" | "0" | "false" => Ok(StartupAdmissionMode::Off),
        "warn" => Ok(StartupAdmissionMode::Warn),
        "strict" => Ok(StartupAdmissionMode::Strict),
        other => Err(format!(
            "Unsupported KC_ADMIN_MCP_STARTUP_ADMISSION_MODE={other:?}; use off, warn, or strict."
        )),
    }
}

fn parse_test_gate_profile(value: &str) -> Result<TestGateProfile, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "fast" => Ok(TestGateProfile::Fast),
        "standard" => Ok(TestGateProfile::Standard),
        other => Err(format!(
            "Unsupported KC_ADMIN_MCP_TEST_GATE_REQUIRED_PROFILE={other:?}; use fast or standard."
        )),
    }
}

fn env(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn env_optional(name: &str) -> Option<String> {
    std::env::var(name).ok().and_then(|value| {
        let trimmed = value.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

fn env_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .and_then(|value| match value.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        })
        .unwrap_or(default)
}

fn env_bool_strict(name: &str, default: bool) -> Result<bool, String> {
    let Some(raw) = std::env::var(name).ok() else {
        return Ok(default);
    };
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Ok(default);
    }
    match normalized.as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(format!("Invalid {name}={raw} (expected bool).")),
    }
}

fn env_list(name: &str, default: Vec<String>) -> Vec<String> {
    std::env::var(name)
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(|entry| entry.trim().to_string())
                .filter(|entry| !entry.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or(default)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default)
}

fn env_optional_u64_strict(name: &str) -> Result<Option<u64>, String> {
    let Some(raw) = std::env::var(name).ok() else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let parsed = trimmed
        .parse::<u64>()
        .map_err(|_| format!("Invalid {name}={raw} (expected integer)."))?;
    Ok(Some(parsed))
}

fn env_i64(name: &str, default: i64) -> i64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(default)
}

fn credential_path(name: &str) -> Option<PathBuf> {
    let dir = std::env::var("CREDENTIALS_DIRECTORY").ok()?;
    Some(PathBuf::from(dir).join(name))
}

fn read_credential(name: &str) -> Option<String> {
    let path = credential_path(name)?;
    let contents = fs::read_to_string(path).ok()?;
    Some(contents.trim_end().to_string())
}

fn env_secret(env_name: &str, credential_name: &str) -> String {
    let value = env(env_name, "");
    if !value.trim().is_empty() {
        return value;
    }
    read_credential(credential_name).unwrap_or_default()
}

fn env_secret_optional(env_name: &str, credential_name: &str) -> Option<String> {
    let value = env_optional(env_name);
    if value.is_some() {
        return value;
    }
    read_credential(credential_name)
}

fn require_oauth_identity_expectations(auth: &AuthConfig) -> Result<(), String> {
    if auth.issuer.is_none() {
        return Err("KC_ADMIN_MCP_ISSUER is required for OAuth validation.".to_string());
    }
    if auth.audience.is_none() {
        return Err("KC_ADMIN_MCP_AUDIENCE is required for OAuth validation.".to_string());
    }
    Ok(())
}

fn break_glass_deadline(ttl_s: u64) -> Result<Instant, String> {
    Instant::now()
        .checked_add(Duration::from_secs(ttl_s))
        .ok_or_else(|| "break-glass TTL is too large to represent".to_string())
}

fn require_caller_allowlists(
    auth: &AuthConfig,
    production_mode: bool,
    allow_open_caller_allowlists: bool,
    allow_open_caller_allowlists_reason: Option<&str>,
    allow_open_caller_allowlists_ttl_s: Option<u64>,
) -> Result<(), String> {
    if allow_open_caller_allowlists {
        if allow_open_caller_allowlists_reason
            .map(|value| value.trim().is_empty())
            .unwrap_or(true)
        {
            return Err(
                "KC_ADMIN_MCP_ALLOW_OPEN_CALLER_ALLOWLISTS=1 requires KC_ADMIN_MCP_ALLOW_OPEN_CALLER_ALLOWLISTS_REASON."
                    .to_string(),
            );
        }
        if allow_open_caller_allowlists_ttl_s.unwrap_or(0) == 0 {
            return Err(
                "KC_ADMIN_MCP_ALLOW_OPEN_CALLER_ALLOWLISTS=1 requires KC_ADMIN_MCP_ALLOW_OPEN_CALLER_ALLOWLISTS_TTL_S>0."
                    .to_string(),
            );
        }
    }

    if production_mode
        && !allow_open_caller_allowlists
        && auth.allowed_azp.is_empty()
        && auth.allowed_client_ids.is_empty()
    {
        return Err(
            "Production mode requires KC_ADMIN_MCP_ALLOWED_AZP and/or KC_ADMIN_MCP_ALLOWED_CLIENT_IDS (or set KC_ADMIN_MCP_ALLOW_OPEN_CALLER_ALLOWLISTS=1 as break-glass)."
                .to_string(),
        );
    }
    Ok(())
}

fn resolve_authorization_servers(mut configured: Vec<String>, issuer: Option<&str>) -> Vec<String> {
    if configured.is_empty() {
        if let Some(issuer) = issuer {
            let trimmed = issuer.trim();
            if !trimmed.is_empty() {
                configured.push(trimmed.to_string());
            }
        }
    }
    configured
}

/// Default Keycloak admin scope map used when no overrides are configured.
///
/// # Errors
/// * Does not return errors.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
pub(crate) fn default_scope_map() -> ScopeMap {
    ScopeMap {
        users: ScopeSet {
            read: vec!["keycloak-admin:users:read".to_string()],
            write: vec!["keycloak-admin:users:write".to_string()],
        },
        groups: ScopeSet {
            read: vec!["keycloak-admin:groups:read".to_string()],
            write: vec!["keycloak-admin:groups:write".to_string()],
        },
        roles: ScopeSet {
            read: vec!["keycloak-admin:roles:read".to_string()],
            write: vec!["keycloak-admin:roles:write".to_string()],
        },
        clients: ClientScopeSet {
            read: vec!["keycloak-admin:clients:read".to_string()],
            write: vec!["keycloak-admin:clients:write".to_string()],
            secrets: vec!["keycloak-admin:clients:secrets".to_string()],
        },
        client_scopes: ScopeSet {
            read: vec!["keycloak-admin:client-scopes:read".to_string()],
            write: vec!["keycloak-admin:client-scopes:write".to_string()],
        },
        identity_providers: ScopeSet {
            read: vec!["keycloak-admin:idp:read".to_string()],
            write: vec!["keycloak-admin:idp:write".to_string()],
        },
        realms: RealmScopeSet {
            read: vec!["keycloak-admin:realm:read".to_string()],
            write: vec!["keycloak-admin:realm:write".to_string()],
            admin: vec!["keycloak-admin:realm:admin".to_string()],
        },
        events: EventScopeSet {
            read: vec!["keycloak-admin:events:read".to_string()],
            admin: vec!["keycloak-admin:events:admin".to_string()],
        },
        tokens: TokensScopeSet {
            read: vec!["keycloak-admin:tokens:read".to_string()],
        },
        observability: ObservabilityScopeSet {
            read: vec!["keycloak-admin:observability:read".to_string()],
        },
    }
}

/// Collect every scope string from the configured scope map for publishing.
///
/// # Errors
/// * Does not return errors.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
pub(crate) fn collect_scopes(scope_map: &ScopeMap) -> Vec<String> {
    let mut scopes = Vec::new();
    scopes.extend(scope_map.users.read.clone());
    scopes.extend(scope_map.users.write.clone());
    scopes.extend(scope_map.groups.read.clone());
    scopes.extend(scope_map.groups.write.clone());
    scopes.extend(scope_map.roles.read.clone());
    scopes.extend(scope_map.roles.write.clone());
    scopes.extend(scope_map.clients.read.clone());
    scopes.extend(scope_map.clients.write.clone());
    scopes.extend(scope_map.clients.secrets.clone());
    scopes.extend(scope_map.client_scopes.read.clone());
    scopes.extend(scope_map.client_scopes.write.clone());
    scopes.extend(scope_map.identity_providers.read.clone());
    scopes.extend(scope_map.identity_providers.write.clone());
    scopes.extend(scope_map.realms.read.clone());
    scopes.extend(scope_map.realms.write.clone());
    scopes.extend(scope_map.realms.admin.clone());
    scopes.extend(scope_map.events.read.clone());
    scopes.extend(scope_map.events.admin.clone());
    scopes.extend(scope_map.tokens.read.clone());
    scopes.extend(scope_map.observability.read.clone());
    scopes.sort();
    scopes.dedup();
    scopes
}

/// JWKS/metadata payload served at the `.well-known/oauth-protected-resource` endpoints.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
#[derive(Serialize, Deserialize)]
pub struct ResourceMetadata {
    pub resource: String,
    pub authorization_servers: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub scopes_supported: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::{
        break_glass_deadline, require_caller_allowlists, require_oauth_identity_expectations,
        resolve_authorization_servers, AuthConfig, AuthMode, ClientAuthMethod, MtlsMode,
    };
    use std::time::{Duration, Instant};

    fn test_auth_config() -> AuthConfig {
        AuthConfig {
            mode: AuthMode::Introspection,
            issuer: Some("https://issuer.example".to_string()),
            audience: Some("kc-admin-mcp".to_string()),
            allowed_azp: vec![],
            allowed_client_ids: vec![],
            open_caller_allowlists_expires_at: None,
            clock_skew_seconds: 30,
            introspection_url: "https://issuer.example/introspect".to_string(),
            introspection_client_id: "kc-admin-mcp".to_string(),
            introspection_client_secret: "secret".to_string(),
            introspection_auth_method: ClientAuthMethod::ClientSecretBasic,
            request_timeout: Duration::from_secs(5),
            dpop_required: false,
            mtls_mode: MtlsMode::Disabled,
            mtls_client_cert_header: None,
            jwks_url: Some("https://issuer.example/jwks".to_string()),
        }
    }

    #[test]
    fn require_oauth_identity_expectations_rejects_missing_issuer() {
        let mut auth = test_auth_config();
        auth.issuer = None;
        let err = require_oauth_identity_expectations(&auth)
            .expect_err("missing issuer should fail validation");
        assert!(err.contains("KC_ADMIN_MCP_ISSUER"));
    }

    #[test]
    fn require_oauth_identity_expectations_rejects_missing_audience() {
        let mut auth = test_auth_config();
        auth.audience = None;
        let err = require_oauth_identity_expectations(&auth)
            .expect_err("missing audience should fail validation");
        assert!(err.contains("KC_ADMIN_MCP_AUDIENCE"));
    }

    #[test]
    fn require_oauth_identity_expectations_accepts_issuer_and_audience() {
        let auth = test_auth_config();
        require_oauth_identity_expectations(&auth)
            .expect("issuer + audience should pass validation");
    }

    #[test]
    fn require_caller_allowlists_rejects_open_production_profile() {
        let auth = test_auth_config();
        let err = require_caller_allowlists(&auth, true, false, None, None)
            .expect_err("open allowlists should fail in production");
        assert!(err.contains("KC_ADMIN_MCP_ALLOWED_AZP"));
    }

    #[test]
    fn require_caller_allowlists_accepts_when_azp_allowlist_configured() {
        let mut auth = test_auth_config();
        auth.allowed_azp = vec!["kc-admin-mcp-client".to_string()];
        require_caller_allowlists(&auth, true, false, None, None)
            .expect("non-empty azp allowlist should pass");
    }

    #[test]
    fn require_caller_allowlists_accepts_break_glass_override() {
        let auth = test_auth_config();
        require_caller_allowlists(
            &auth,
            true,
            true,
            Some("temporary emergency rollout"),
            Some(3600),
        )
        .expect("break-glass override should allow open production allowlists");
    }

    #[test]
    fn require_caller_allowlists_break_glass_requires_reason() {
        let auth = test_auth_config();
        let err = require_caller_allowlists(&auth, true, true, None, Some(3600))
            .expect_err("break-glass should require reason");
        assert!(err.contains("ALLOW_OPEN_CALLER_ALLOWLISTS_REASON"));
    }

    #[test]
    fn require_caller_allowlists_break_glass_requires_ttl() {
        let auth = test_auth_config();
        let err =
            require_caller_allowlists(&auth, true, true, Some("temporary emergency rollout"), None)
                .expect_err("break-glass should require ttl");
        assert!(err.contains("ALLOW_OPEN_CALLER_ALLOWLISTS_TTL_S"));
    }

    #[test]
    fn break_glass_deadline_sets_future_expiration() {
        let deadline = break_glass_deadline(3600).expect("positive ttl should produce deadline");
        assert!(deadline > Instant::now());
    }

    #[test]
    fn authorization_servers_defaults_to_issuer_when_unset() {
        let servers = resolve_authorization_servers(vec![], Some("https://issuer.example"));
        assert_eq!(servers, vec!["https://issuer.example".to_string()]);
    }

    #[test]
    fn authorization_servers_prefers_explicit_config() {
        let servers = resolve_authorization_servers(
            vec![
                "https://auth-a.example".to_string(),
                "https://auth-b.example".to_string(),
            ],
            Some("https://issuer.example"),
        );
        assert_eq!(
            servers,
            vec![
                "https://auth-a.example".to_string(),
                "https://auth-b.example".to_string(),
            ]
        );
    }
}
