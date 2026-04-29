# MeshGuard Rust SDK

Rust client for the [MeshGuard](https://meshguard.app) governance gateway.

MeshGuard enables policy-based governance for AI agents and automated workflows. This SDK provides async methods for policy evaluation, enforcement, and administration.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
meshguard = "0.1.0"
tokio = { version = "1", features = ["full"] }
```

## Quick Start

```rust
use meshguard::{MeshGuardClient, MeshGuardError};

#[tokio::main]
async fn main() -> meshguard::Result<()> {
    // Create a client from environment variables:
    //   MESHGUARD_GATEWAY_URL (optional, defaults to https://dashboard.meshguard.app)
    //   MESHGUARD_AGENT_TOKEN (required)
    let client = MeshGuardClient::from_env()?;

    // Or with explicit values:
    let client = MeshGuardClient::new("https://dashboard.meshguard.app", "your-agent-token");

    // Check gateway health
    client.health().await?;

    Ok(())
}
```

## Policy Evaluation

### Check (non-error on deny)

```rust
let decision = client.check("agent-1", "file.read", None).await?;
if decision.allowed {
    println!("Allowed by policy: {}", decision.policy);
} else {
    println!("Denied: {}", decision.reason);
}
```

### Enforce (error on deny)

```rust
// Returns Err(MeshGuardError::PolicyDenied { .. }) if denied
client.enforce("agent-1", "file.write", None).await?;
println!("Action permitted, proceeding...");
```

### Govern (enforce + execute)

```rust
let result = client.govern("agent-1", "db.query", None, || {
    // This closure only runs if the policy allows the action
    Ok("query result".to_string())
}).await?;
```

### With Metadata

```rust
use std::collections::HashMap;

let mut meta = HashMap::new();
meta.insert("path".to_string(), serde_json::json!("/etc/config"));
meta.insert("size".to_string(), serde_json::json!(1024));

let decision = client.check("agent-1", "file.read", Some(&meta)).await?;
```

## Proxy Requests

Send HTTP requests through the governance proxy:

```rust
use reqwest::Method;

let response = client.request(
    Method::POST,
    "api/data",
    Some(serde_json::json!({"key": "value"})),
).await?;
```

## Admin Operations

Admin operations require an admin token, set via `MESHGUARD_ADMIN_TOKEN` environment variable or explicitly:

```rust
use meshguard::{CreateAgentRequest, AuditQueryOptions};

let mut client = MeshGuardClient::new("https://dashboard.meshguard.app", "agent-token");
client.set_admin_token("your-admin-token");

// List agents
let agents = client.list_agents().await?;

// Create an agent
let agent = client.create_agent(CreateAgentRequest {
    name: "my-agent".into(),
    trust_tier: Some("verified".into()),
    tags: vec!["production".into()],
    capabilities: vec!["file.read".into(), "file.write".into()],
}).await?;

// Revoke an agent
client.revoke_agent(&agent.id).await?;

// List policies
let policies = client.list_policies().await?;

// Query audit log
let entries = client.audit_log(AuditQueryOptions {
    limit: Some(100),
    decision: Some("deny".into()),
    ..Default::default()
}).await?;
```

## Error Handling

All methods return `Result<T, MeshGuardError>`. The error variants are:

| Variant | HTTP Status | Description |
|---------|------------|-------------|
| `Authentication` | 401 | Invalid or expired token |
| `PolicyDenied` | 403 | Action denied by policy (only from `enforce`/`govern`) |
| `RateLimit` | 429 | Rate limit exceeded |
| `Api` | 4xx/5xx | Other API errors |
| `Network` | -- | Transport/connection errors |
| `Unhealthy` | -- | Gateway health check failed |
| `Env` | -- | Missing environment variable |

```rust
match client.enforce("agent-1", "file.delete", None).await {
    Ok(()) => println!("Allowed"),
    Err(MeshGuardError::PolicyDenied { action, policy, reason, .. }) => {
        eprintln!("Denied: {action} blocked by {policy}: {reason}");
    }
    Err(MeshGuardError::Authentication) => {
        eprintln!("Bad credentials");
    }
    Err(e) => eprintln!("Error: {e}"),
}
```

## License

MIT
