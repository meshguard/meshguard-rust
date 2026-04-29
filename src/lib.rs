//! # MeshGuard Rust SDK
//!
//! A Rust client for the [MeshGuard](https://meshguard.app) governance gateway.
//!
//! MeshGuard enables policy-based governance for AI agents and automated
//! workflows. This SDK provides async methods for checking, enforcing, and
//! wrapping actions with policy evaluation, as well as admin operations for
//! managing agents, policies, and audit logs.
//!
//! ## Quick start
//!
//! ```no_run
//! use meshguard::MeshGuardClient;
//!
//! # async fn example() -> meshguard::Result<()> {
//! // Create from explicit values
//! let client = MeshGuardClient::new("https://dashboard.meshguard.app", "my-token");
//!
//! // Or from environment variables
//! let client = MeshGuardClient::from_env()?;
//!
//! // Check a policy (non-error on deny)
//! let decision = client.check("agent-1", "file.read", None).await?;
//! println!("Allowed: {}", decision.allowed);
//!
//! // Enforce a policy (error on deny)
//! client.enforce("agent-1", "file.write", None).await?;
//!
//! // Govern: enforce + execute
//! let result = client.govern("agent-1", "db.query", None, || {
//!     Ok("query result".to_string())
//! }).await?;
//! # Ok(())
//! # }
//! ```

pub mod admin;
pub mod client;
pub mod error;
pub mod types;

#[cfg(test)]
mod tests;

// Re-export primary types at crate root for ergonomic access.
pub use client::MeshGuardClient;
pub use error::{MeshGuardError, Result};
pub use types::{
    Agent, AuditEntry, AuditQueryOptions, CreateAgentRequest, Decision, Policy, PolicyDecision,
    Rule,
};
