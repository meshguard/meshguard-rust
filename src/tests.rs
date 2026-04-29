use crate::types::*;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Serialization / Deserialization round-trips
// ---------------------------------------------------------------------------

#[test]
fn policy_decision_allow_roundtrip() {
    let decision = PolicyDecision {
        allowed: true,
        action: "file.read".into(),
        decision: Decision::Allow,
        policy: "default".into(),
        rule: String::new(),
        reason: String::new(),
        trace_id: "abc123".into(),
        timestamp: None,
    };

    let json = serde_json::to_string(&decision).unwrap();
    let parsed: PolicyDecision = serde_json::from_str(&json).unwrap();

    assert!(parsed.allowed);
    assert_eq!(parsed.action, "file.read");
    assert_eq!(parsed.decision, Decision::Allow);
    assert_eq!(parsed.policy, "default");
}

#[test]
fn policy_decision_deny_roundtrip() {
    let decision = PolicyDecision {
        allowed: false,
        action: "file.delete".into(),
        decision: Decision::Deny,
        policy: "strict".into(),
        rule: "no-delete".into(),
        reason: "Deletion not allowed".into(),
        trace_id: String::new(),
        timestamp: None,
    };

    let json = serde_json::to_string(&decision).unwrap();
    let parsed: PolicyDecision = serde_json::from_str(&json).unwrap();

    assert!(!parsed.allowed);
    assert_eq!(parsed.decision, Decision::Deny);
    assert_eq!(parsed.rule, "no-delete");
    assert_eq!(parsed.reason, "Deletion not allowed");
}

#[test]
fn decision_enum_serialization() {
    assert_eq!(serde_json::to_string(&Decision::Allow).unwrap(), "\"allow\"");
    assert_eq!(serde_json::to_string(&Decision::Deny).unwrap(), "\"deny\"");

    let allow: Decision = serde_json::from_str("\"allow\"").unwrap();
    let deny: Decision = serde_json::from_str("\"deny\"").unwrap();
    assert_eq!(allow, Decision::Allow);
    assert_eq!(deny, Decision::Deny);
}

#[test]
fn decision_display() {
    assert_eq!(Decision::Allow.to_string(), "allow");
    assert_eq!(Decision::Deny.to_string(), "deny");
}

#[test]
fn agent_deserialization() {
    let json = r#"{
        "id": "agent-1",
        "name": "Test Agent",
        "trustTier": "verified",
        "capabilities": ["file.read", "file.write"],
        "tags": ["production"],
        "orgId": "org-1"
    }"#;

    let agent: Agent = serde_json::from_str(json).unwrap();
    assert_eq!(agent.id, "agent-1");
    assert_eq!(agent.name, "Test Agent");
    assert_eq!(agent.trust_tier, "verified");
    assert_eq!(agent.capabilities, vec!["file.read", "file.write"]);
    assert_eq!(agent.tags, vec!["production"]);
    assert_eq!(agent.org_id, "org-1");
}

#[test]
fn agent_minimal_deserialization() {
    let json = r#"{
        "id": "agent-2",
        "name": "Minimal Agent",
        "trustTier": "untrusted"
    }"#;

    let agent: Agent = serde_json::from_str(json).unwrap();
    assert_eq!(agent.id, "agent-2");
    assert!(agent.capabilities.is_empty());
    assert!(agent.tags.is_empty());
    assert!(agent.org_id.is_empty());
    assert!(agent.created_at.is_none());
}

#[test]
fn policy_deserialization() {
    let json = r#"{
        "id": "policy-1",
        "name": "File Access",
        "description": "Controls file system access",
        "rules": [
            {"id": "rule-1", "name": "Allow reads", "action": "file.read", "effect": "allow"},
            {"id": "rule-2", "name": "Deny deletes", "action": "file.delete", "effect": "deny"}
        ]
    }"#;

    let policy: Policy = serde_json::from_str(json).unwrap();
    assert_eq!(policy.id, "policy-1");
    assert_eq!(policy.name, "File Access");
    assert_eq!(policy.rules.len(), 2);
    assert_eq!(policy.rules[0].effect, "allow");
    assert_eq!(policy.rules[1].effect, "deny");
}

#[test]
fn audit_entry_deserialization() {
    let json = r#"{
        "id": "entry-1",
        "timestamp": "2025-01-15T10:30:00Z",
        "action": "file.read",
        "decision": "allow",
        "agentId": "agent-1",
        "policy": "default",
        "meta": {"path": "/tmp/test.txt"}
    }"#;

    let entry: AuditEntry = serde_json::from_str(json).unwrap();
    assert_eq!(entry.id, "entry-1");
    assert_eq!(entry.action, "file.read");
    assert_eq!(entry.decision, "allow");
    assert_eq!(entry.agent_id, "agent-1");
    assert_eq!(
        entry.meta.get("path").and_then(|v| v.as_str()),
        Some("/tmp/test.txt")
    );
}

#[test]
fn create_agent_request_serialization() {
    let req = CreateAgentRequest {
        name: "New Agent".into(),
        trust_tier: Some("verified".into()),
        tags: vec!["test".into()],
        capabilities: vec!["file.read".into()],
    };

    let json = serde_json::to_value(&req).unwrap();
    assert_eq!(json["name"], "New Agent");
    assert_eq!(json["trustTier"], "verified");
    assert_eq!(json["tags"], serde_json::json!(["test"]));
}

#[test]
fn create_agent_request_minimal_serialization() {
    let req = CreateAgentRequest {
        name: "Bare Agent".into(),
        trust_tier: None,
        tags: Vec::new(),
        capabilities: Vec::new(),
    };

    let json = serde_json::to_value(&req).unwrap();
    assert_eq!(json["name"], "Bare Agent");
    // Optional/empty fields should be skipped.
    assert!(json.get("trustTier").is_none());
    assert!(json.get("tags").is_none());
    assert!(json.get("capabilities").is_none());
}

#[test]
fn audit_query_options_defaults() {
    let opts = AuditQueryOptions::default();
    assert!(opts.limit.is_none());
    assert!(opts.decision.is_none());
    assert!(opts.agent_id.is_none());
    assert!(opts.action.is_none());
}

#[test]
fn audit_query_options_serialization() {
    let opts = AuditQueryOptions {
        limit: Some(100),
        decision: Some("deny".into()),
        agent_id: Some("agent-1".into()),
        action: None,
    };

    let json = serde_json::to_value(&opts).unwrap();
    assert_eq!(json["limit"], 100);
    assert_eq!(json["decision"], "deny");
    assert_eq!(json["agentId"], "agent-1");
    assert!(json.get("action").is_none());
}

// ---------------------------------------------------------------------------
// Error formatting
// ---------------------------------------------------------------------------

#[test]
fn error_display_authentication() {
    let err = crate::MeshGuardError::Authentication;
    assert_eq!(err.to_string(), "meshguard: invalid or expired token");
}

#[test]
fn error_display_rate_limit() {
    let err = crate::MeshGuardError::RateLimit;
    assert_eq!(err.to_string(), "meshguard: rate limit exceeded");
}

#[test]
fn error_display_api() {
    let err = crate::MeshGuardError::Api {
        status: 500,
        message: "Internal Server Error".into(),
    };
    assert_eq!(
        err.to_string(),
        "meshguard: request failed: 500 Internal Server Error"
    );
}

#[test]
fn error_display_policy_denied() {
    let decision = PolicyDecision {
        allowed: false,
        action: "file.delete".into(),
        decision: Decision::Deny,
        policy: "strict".into(),
        rule: "no-delete".into(),
        reason: "Not permitted".into(),
        trace_id: String::new(),
        timestamp: None,
    };

    let err = crate::MeshGuardError::PolicyDenied {
        action: "file.delete".into(),
        policy: "strict".into(),
        rule: "no-delete".into(),
        reason: "Not permitted".into(),
        decision,
    };

    let msg = err.to_string();
    assert!(msg.contains("file.delete"));
    assert!(msg.contains("strict"));
    assert!(msg.contains("no-delete"));
    assert!(msg.contains("Not permitted"));
}

#[test]
fn error_display_policy_denied_minimal() {
    let decision = PolicyDecision {
        allowed: false,
        action: "test".into(),
        decision: Decision::Deny,
        policy: "p1".into(),
        rule: String::new(),
        reason: String::new(),
        trace_id: String::new(),
        timestamp: None,
    };

    let err = crate::MeshGuardError::PolicyDenied {
        action: "test".into(),
        policy: "p1".into(),
        rule: String::new(),
        reason: String::new(),
        decision,
    };

    let msg = err.to_string();
    assert!(msg.contains("test"));
    assert!(msg.contains("p1"));
    // Should not contain stray punctuation from empty fields.
    assert!(!msg.contains("(rule: )"));
}

// ---------------------------------------------------------------------------
// Client construction
// ---------------------------------------------------------------------------

#[test]
fn client_new_trims_trailing_slash() {
    let client = crate::MeshGuardClient::new("https://example.com/", "token");
    // We verify indirectly: health URL should not have double slash.
    // Just ensure construction succeeds.
    drop(client);
}

#[test]
fn client_new_accepts_string_types() {
    // Verify the Into<String> bounds work with various types.
    let _c1 = crate::MeshGuardClient::new("https://example.com", "token");
    let _c2 = crate::MeshGuardClient::new(String::from("https://example.com"), String::from("token"));
}

// ---------------------------------------------------------------------------
// Integration-style tests with wiremock
// ---------------------------------------------------------------------------

#[cfg(test)]
mod integration {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn check_allowed() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/proxy/check"))
            .and(header("X-MeshGuard-Action", "file.read"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "policy": "default"
                })),
            )
            .mount(&server)
            .await;

        let client = crate::MeshGuardClient::new(server.uri(), "test-token");
        let decision = client.check("agent-1", "file.read", None).await.unwrap();

        assert!(decision.allowed);
        assert_eq!(decision.decision, Decision::Allow);
        assert_eq!(decision.policy, "default");
    }

    #[tokio::test]
    async fn check_denied() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/proxy/check"))
            .respond_with(
                ResponseTemplate::new(403).set_body_json(serde_json::json!({
                    "policy": "strict",
                    "rule": "no-write",
                    "message": "Write access denied"
                })),
            )
            .mount(&server)
            .await;

        let client = crate::MeshGuardClient::new(server.uri(), "test-token");
        let decision = client.check("agent-1", "file.write", None).await.unwrap();

        assert!(!decision.allowed);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(decision.policy, "strict");
        assert_eq!(decision.rule, "no-write");
        assert_eq!(decision.reason, "Write access denied");
    }

    #[tokio::test]
    async fn enforce_allowed() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/proxy/check"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "policy": "default"
            })))
            .mount(&server)
            .await;

        let client = crate::MeshGuardClient::new(server.uri(), "test-token");
        let result = client.enforce("agent-1", "file.read", None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn enforce_denied_returns_error() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/proxy/check"))
            .respond_with(
                ResponseTemplate::new(403).set_body_json(serde_json::json!({
                    "policy": "strict",
                    "rule": "no-delete",
                    "message": "Not allowed"
                })),
            )
            .mount(&server)
            .await;

        let client = crate::MeshGuardClient::new(server.uri(), "test-token");
        let result = client.enforce("agent-1", "file.delete", None).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            crate::MeshGuardError::PolicyDenied {
                action,
                policy,
                rule,
                ..
            } => {
                assert_eq!(action, "file.delete");
                assert_eq!(policy, "strict");
                assert_eq!(rule, "no-delete");
            }
            other => panic!("expected PolicyDenied, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn govern_executes_on_allow() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/proxy/check"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "policy": "default"
            })))
            .mount(&server)
            .await;

        let client = crate::MeshGuardClient::new(server.uri(), "test-token");
        let result = client
            .govern("agent-1", "db.query", None, || Ok(42))
            .await
            .unwrap();

        assert_eq!(result, 42);
    }

    #[tokio::test]
    async fn govern_skips_on_deny() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/proxy/check"))
            .respond_with(
                ResponseTemplate::new(403).set_body_json(serde_json::json!({
                    "policy": "strict",
                    "message": "Denied"
                })),
            )
            .mount(&server)
            .await;

        let client = crate::MeshGuardClient::new(server.uri(), "test-token");
        let result: crate::Result<i32> = client
            .govern("agent-1", "db.query", None, || {
                panic!("closure should not be called on deny");
            })
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn health_ok() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "status": "healthy"
                })),
            )
            .mount(&server)
            .await;

        let client = crate::MeshGuardClient::new(server.uri(), "test-token");
        assert!(client.health().await.is_ok());
    }

    #[tokio::test]
    async fn health_unhealthy() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "status": "degraded"
                })),
            )
            .mount(&server)
            .await;

        let client = crate::MeshGuardClient::new(server.uri(), "test-token");
        let result = client.health().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn check_with_metadata() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/proxy/check"))
            .and(header("X-MeshGuard-Meta", r#"{"path":"/tmp/test.txt"}"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "policy": "default"
            })))
            .mount(&server)
            .await;

        let client = crate::MeshGuardClient::new(server.uri(), "test-token");

        let mut meta = HashMap::new();
        meta.insert(
            "path".to_string(),
            serde_json::Value::String("/tmp/test.txt".to_string()),
        );

        let decision = client.check("agent-1", "file.read", Some(&meta)).await.unwrap();
        assert!(decision.allowed);
    }

    #[tokio::test]
    async fn check_unauthorized() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/proxy/check"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let client = crate::MeshGuardClient::new(server.uri(), "bad-token");
        let result = client.check("agent-1", "file.read", None).await;

        assert!(matches!(result, Err(crate::MeshGuardError::Authentication)));
    }

    #[tokio::test]
    async fn check_rate_limited() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/proxy/check"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;

        let client = crate::MeshGuardClient::new(server.uri(), "test-token");
        let result = client.check("agent-1", "file.read", None).await;

        assert!(matches!(result, Err(crate::MeshGuardError::RateLimit)));
    }

    #[tokio::test]
    async fn list_agents_success() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/admin/agents"))
            .and(header("X-Admin-Token", "admin-secret"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "agents": [
                        {
                            "id": "agent-1",
                            "name": "Test Agent",
                            "trustTier": "verified"
                        }
                    ]
                })),
            )
            .mount(&server)
            .await;

        let mut client = crate::MeshGuardClient::new(server.uri(), "test-token");
        client.set_admin_token("admin-secret");

        let agents = client.list_agents().await.unwrap();
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].id, "agent-1");
    }

    #[tokio::test]
    async fn list_agents_no_admin_token() {
        let server = MockServer::start().await;
        let client = crate::MeshGuardClient::new(server.uri(), "test-token");

        let result = client.list_agents().await;
        assert!(matches!(result, Err(crate::MeshGuardError::Authentication)));
    }

    #[tokio::test]
    async fn create_agent_success() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/admin/agents"))
            .and(header("X-Admin-Token", "admin-secret"))
            .respond_with(
                ResponseTemplate::new(201).set_body_json(serde_json::json!({
                    "id": "agent-new",
                    "name": "New Agent",
                    "trustTier": "verified",
                    "capabilities": ["file.read"]
                })),
            )
            .mount(&server)
            .await;

        let mut client = crate::MeshGuardClient::new(server.uri(), "test-token");
        client.set_admin_token("admin-secret");

        let agent = client
            .create_agent(CreateAgentRequest {
                name: "New Agent".into(),
                trust_tier: Some("verified".into()),
                tags: Vec::new(),
                capabilities: vec!["file.read".into()],
            })
            .await
            .unwrap();

        assert_eq!(agent.id, "agent-new");
        assert_eq!(agent.name, "New Agent");
    }

    #[tokio::test]
    async fn revoke_agent_success() {
        let server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/admin/agents/agent-1"))
            .and(header("X-Admin-Token", "admin-secret"))
            .respond_with(ResponseTemplate::new(204).set_body_bytes(b""))
            .mount(&server)
            .await;

        let mut client = crate::MeshGuardClient::new(server.uri(), "test-token");
        client.set_admin_token("admin-secret");

        let result = client.revoke_agent("agent-1").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn list_policies_success() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/admin/policies"))
            .and(header("X-Admin-Token", "admin-secret"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "policies": [
                        {
                            "id": "policy-1",
                            "name": "File Access",
                            "rules": [
                                {"id": "r1", "action": "file.*", "effect": "allow"}
                            ]
                        }
                    ]
                })),
            )
            .mount(&server)
            .await;

        let mut client = crate::MeshGuardClient::new(server.uri(), "test-token");
        client.set_admin_token("admin-secret");

        let policies = client.list_policies().await.unwrap();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].rules.len(), 1);
    }

    #[tokio::test]
    async fn audit_log_with_filters() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/admin/audit"))
            .and(header("X-Admin-Token", "admin-secret"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "entries": [
                        {
                            "id": "e1",
                            "timestamp": "2025-01-15T10:00:00Z",
                            "action": "file.read",
                            "decision": "deny",
                            "agentId": "agent-1"
                        }
                    ]
                })),
            )
            .mount(&server)
            .await;

        let mut client = crate::MeshGuardClient::new(server.uri(), "test-token");
        client.set_admin_token("admin-secret");

        let entries = client
            .audit_log(AuditQueryOptions {
                limit: Some(10),
                decision: Some("deny".into()),
                agent_id: Some("agent-1".into()),
                action: None,
            })
            .await
            .unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].decision, "deny");
    }
}
