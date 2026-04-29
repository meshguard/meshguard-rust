use crate::types::PolicyDecision;

/// Errors returned by MeshGuard SDK operations.
#[derive(Debug, thiserror::Error)]
pub enum MeshGuardError {
    /// Invalid or expired authentication token (HTTP 401).
    #[error("meshguard: invalid or expired token")]
    Authentication,

    /// Action was denied by policy (HTTP 403).
    ///
    /// Contains the full [`PolicyDecision`] with details about which policy
    /// and rule caused the denial.
    #[error("action \"{action}\" denied by policy \"{policy}\"{}", format_denial_detail(.rule, .reason))]
    PolicyDenied {
        action: String,
        policy: String,
        rule: String,
        reason: String,
        decision: PolicyDecision,
    },

    /// Rate limit exceeded (HTTP 429).
    #[error("meshguard: rate limit exceeded")]
    RateLimit,

    /// Unexpected HTTP error from the gateway.
    #[error("meshguard: request failed: {status} {message}")]
    Api {
        status: u16,
        message: String,
    },

    /// Network or transport error.
    #[error("meshguard: network error: {0}")]
    Network(#[from] reqwest::Error),

    /// Gateway returned an unhealthy status.
    #[error("meshguard: gateway unhealthy: {0}")]
    Unhealthy(String),

    /// Environment variable missing or invalid.
    #[error("meshguard: environment error: {0}")]
    Env(String),
}

fn format_denial_detail(rule: &str, reason: &str) -> String {
    let mut s = String::new();
    if !rule.is_empty() {
        s.push_str(&format!(" (rule: {rule})"));
    }
    if !reason.is_empty() {
        s.push_str(&format!(": {reason}"));
    }
    s
}

/// Convenience alias used throughout the SDK.
pub type Result<T> = std::result::Result<T, MeshGuardError>;
