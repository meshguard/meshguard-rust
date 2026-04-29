use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The outcome of a policy evaluation: allow or deny.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Deny,
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Decision::Allow => write!(f, "allow"),
            Decision::Deny => write!(f, "deny"),
        }
    }
}

/// Result of a policy evaluation returned by [`Client::check`](crate::MeshGuardClient::check).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyDecision {
    /// Whether the action is permitted.
    pub allowed: bool,

    /// The action that was checked.
    pub action: String,

    /// The evaluation result.
    pub decision: Decision,

    /// Name of the policy that produced this decision.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub policy: String,

    /// Specific rule within the policy that matched.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rule: String,

    /// Human-readable explanation for the decision.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,

    /// Correlation identifier for this request.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub trace_id: String,

    /// When the decision was made.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<DateTime<Utc>>,
}

/// A MeshGuard agent identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Agent {
    /// Unique agent identifier.
    pub id: String,

    /// Agent display name.
    pub name: String,

    /// Trust level (e.g., "verified", "untrusted").
    pub trust_tier: String,

    /// Actions this agent is authorized to perform.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,

    /// Labels associated with the agent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,

    /// Organization this agent belongs to.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub org_id: String,

    /// When the agent was created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
}

/// A governance policy definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Policy {
    /// Unique policy identifier.
    pub id: String,

    /// Human-readable policy name.
    pub name: String,

    /// Details about what the policy governs.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,

    /// Rules that make up this policy.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,

    /// When the policy was created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,

    /// When the policy was last modified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

/// A single rule within a policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    /// Unique rule identifier.
    pub id: String,

    /// Human-readable rule name.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,

    /// Action pattern this rule applies to.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub action: String,

    /// Rule's effect: "allow" or "deny".
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub effect: String,
}

/// An entry in the governance audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntry {
    /// Unique entry identifier.
    pub id: String,

    /// When the event occurred.
    pub timestamp: DateTime<Utc>,

    /// Action that was evaluated.
    pub action: String,

    /// Evaluation result: "allow" or "deny".
    pub decision: String,

    /// Agent that performed the action.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub agent_id: String,

    /// Policy that was evaluated.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub policy: String,

    /// Specific rule that matched.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rule: String,

    /// Explanation for the decision.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,

    /// Resource that was accessed.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub resource: String,

    /// Additional metadata.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub meta: HashMap<String, serde_json::Value>,
}

/// Parameters for creating a new agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAgentRequest {
    /// Display name for the new agent (required).
    pub name: String,

    /// Trust level. Defaults to "verified" if empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_tier: Option<String>,

    /// Labels to assign to the agent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,

    /// Actions the agent is authorized to perform.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
}

/// Configuration for an audit log query.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditQueryOptions {
    /// Maximum number of entries to return (default: 50).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,

    /// Filter by decision ("allow" or "deny").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,

    /// Filter by agent ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,

    /// Filter by action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
}
