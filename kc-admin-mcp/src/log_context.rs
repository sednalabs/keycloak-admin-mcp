//! # Log Context
//!
//! Task-local storage for request-scoped metadata used in structured logging.
//!
//! ## Rationale
//! Ensures that `request_id`, `actor_id`, and `tool` name are available to all
//! logging statements throughout the execution of a request, even across
//! asynchronous boundaries.
//!
//! ## Security Boundaries
//! * **Tracing**: Facilitates end-to-end auditability by correlating logs with
//!   specific tool invocations and actors.

use std::future::Future;

/// Stores request metadata for structured logging contexts.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
#[derive(Clone, Debug, Default)]
pub struct LogContext {
    pub request_id: Option<String>,
    pub actor_id: Option<String>,
    pub session_id: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub tool: Option<String>,
}

impl LogContext {
    /// Create a new log context containing request identification.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Caveats
    /// * None.
    pub fn new(
        request_id: String,
        actor_id: Option<String>,
        session_id: Option<String>,
        method: Option<String>,
        path: Option<String>,
    ) -> Self {
        Self {
            request_id: Some(request_id),
            actor_id,
            session_id,
            method,
            path,
            tool: None,
        }
    }
}

tokio::task_local! {
    static LOG_CONTEXT: LogContext;
}

/// Run a future with the provided log context bound to the task-local storage.
///
/// # Errors
/// * Does not return errors.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
pub async fn with_context<F, T>(context: LogContext, future: F) -> T
where
    F: Future<Output = T>,
{
    LOG_CONTEXT.scope(context, future).await
}

/// Temporarily attach the active tool name for nested logging while executing the future.
///
/// # Errors
/// * Does not return errors.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
pub async fn with_tool<F, T>(tool: &str, future: F) -> T
where
    F: Future<Output = T>,
{
    if let Ok(context) = LOG_CONTEXT.try_with(|ctx| ctx.clone()) {
        let mut next = context;
        next.tool = Some(tool.to_string());
        LOG_CONTEXT.scope(next, future).await
    } else {
        future.await
    }
}

/// Return the current log context if one is set (used by log middleware/metrics).
///
/// # Errors
/// * Does not return errors.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
pub fn current() -> Option<LogContext> {
    LOG_CONTEXT.try_with(|ctx| ctx.clone()).ok()
}
