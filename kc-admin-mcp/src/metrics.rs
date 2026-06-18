//! # In-Memory Metrics
//!
//! Provides real-time performance tracking and error counters for the MCP server.
//!
//! ## Rationale
//! Allows operators to monitor the health of the Keycloak Admin stack, identifying
//! slow tools or authentication failure patterns without requiring external
//! monitoring infrastructure.
//!
//! ## Security Boundaries
//! * **Privacy**: Metrics record aggregate counts and durations only; they NEVER
//!   capture sensitive payload data or tool arguments.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;

use serde::Serialize;

/// Key/value metadata attached to metric samples.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
#[derive(Clone, Debug, Serialize)]
pub struct MetricLabel {
    pub key: String,
    pub value: String,
}

/// Snapshot of a counter with labels.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
#[derive(Clone, Debug, Serialize)]
pub struct CounterSnapshot {
    pub labels: Vec<MetricLabel>,
    pub value: u64,
}

/// Snapshot of a histogram buckets/counts.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
#[derive(Clone, Debug, Serialize)]
pub struct HistogramSnapshot {
    pub labels: Vec<MetricLabel>,
    pub buckets: Vec<u64>,
    pub counts: Vec<u64>,
    pub sum: u64,
    pub count: u64,
}

/// Full metrics snapshot returned by `Metrics::snapshot`.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
#[derive(Clone, Debug, Serialize)]
pub struct MetricsSnapshot {
    pub auth_rejects_total: Vec<CounterSnapshot>,
    pub request_timeouts_total: Vec<CounterSnapshot>,
    pub tool_calls_total: Vec<CounterSnapshot>,
    pub tool_call_duration_ms: Vec<HistogramSnapshot>,
}

/// In-memory metrics registry used inside the MCP server.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
#[derive(Debug)]
pub struct Metrics {
    auth_rejects_total: CounterVec,
    request_timeouts_total: CounterVec,
    tool_calls_total: CounterVec,
    tool_call_duration_ms: HistogramVec,
}

impl Metrics {
    /// Create a new metrics registry with default buckets/counters.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Caveats
    /// * None.
    pub fn new() -> Self {
        Self {
            auth_rejects_total: CounterVec::default(),
            request_timeouts_total: CounterVec::default(),
            tool_calls_total: CounterVec::default(),
            tool_call_duration_ms: HistogramVec::new(vec![
                5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000,
            ]),
        }
    }

    /// Record that authentication rejected a request.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Caveats
    /// * None.
    pub fn record_auth_reject(&self, code: &str) {
        self.auth_rejects_total.inc(&[("code", code)], 1);
    }

    /// Record that an upstream request timed out (gateway/auth/etc.).
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Caveats
    /// * None.
    pub fn record_request_timeout(&self, component: &str) {
        self.request_timeouts_total
            .inc(&[("component", component)], 1);
    }

    /// Record tool invocation status/duration.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Caveats
    /// * None.
    pub fn record_tool_call(&self, tool: &str, status: &str, duration_ms: u64) {
        self.tool_calls_total
            .inc(&[("tool", tool), ("status", status)], 1);
        self.tool_call_duration_ms
            .observe(&[("tool", tool)], duration_ms);
    }

    /// Grab a snapshot of all recorded metrics.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Caveats
    /// * None.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            auth_rejects_total: self.auth_rejects_total.snapshot(),
            request_timeouts_total: self.request_timeouts_total.snapshot(),
            tool_calls_total: self.tool_calls_total.snapshot(),
            tool_call_duration_ms: self.tool_call_duration_ms.snapshot(),
        }
    }
}

#[derive(Clone, Debug, Eq)]
struct LabelKey(Vec<(String, String)>);

impl LabelKey {
    fn new(labels: &[(&str, &str)]) -> Self {
        Self(
            labels
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
        )
    }

    fn to_labels(&self) -> Vec<MetricLabel> {
        self.0
            .iter()
            .map(|(key, value)| MetricLabel {
                key: key.clone(),
                value: value.clone(),
            })
            .collect()
    }
}

impl PartialEq for LabelKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Hash for LabelKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for (key, value) in &self.0 {
            key.hash(state);
            value.hash(state);
        }
    }
}

#[derive(Debug, Default)]
struct CounterVec {
    inner: Mutex<HashMap<LabelKey, u64>>,
}

impl CounterVec {
    fn inc(&self, labels: &[(&str, &str)], value: u64) {
        let mut guard = self.inner.lock().expect("metrics counter lock poisoned");
        let key = LabelKey::new(labels);
        let entry = guard.entry(key).or_insert(0);
        *entry += value;
    }

    fn snapshot(&self) -> Vec<CounterSnapshot> {
        let guard = self.inner.lock().expect("metrics counter lock poisoned");
        guard
            .iter()
            .map(|(labels, value)| CounterSnapshot {
                labels: labels.to_labels(),
                value: *value,
            })
            .collect()
    }
}

#[derive(Debug)]
struct HistogramState {
    counts: Vec<u64>,
    sum: u64,
    count: u64,
}

#[derive(Debug)]
struct HistogramVec {
    buckets: Vec<u64>,
    inner: Mutex<HashMap<LabelKey, HistogramState>>,
}

impl HistogramVec {
    fn new(buckets: Vec<u64>) -> Self {
        Self {
            buckets,
            inner: Mutex::new(HashMap::new()),
        }
    }

    fn observe(&self, labels: &[(&str, &str)], value: u64) {
        let mut guard = self.inner.lock().expect("metrics histogram lock poisoned");
        let key = LabelKey::new(labels);
        let state = guard.entry(key).or_insert_with(|| HistogramState {
            counts: vec![0; self.buckets.len()],
            sum: 0,
            count: 0,
        });

        let mut idx = self.buckets.len() - 1;
        for (i, upper) in self.buckets.iter().enumerate() {
            if value <= *upper {
                idx = i;
                break;
            }
        }
        state.counts[idx] += 1;
        state.sum += value;
        state.count += 1;
    }

    fn snapshot(&self) -> Vec<HistogramSnapshot> {
        let guard = self.inner.lock().expect("metrics histogram lock poisoned");
        guard
            .iter()
            .map(|(labels, state)| HistogramSnapshot {
                labels: labels.to_labels(),
                buckets: self.buckets.clone(),
                counts: state.counts.clone(),
                sum: state.sum,
                count: state.count,
            })
            .collect()
    }
}
