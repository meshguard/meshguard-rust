use reqwest::header;

use crate::error::{MeshGuardError, Result};
use crate::types::{Agent, AuditEntry, AuditQueryOptions, CreateAgentRequest, Policy};
use crate::MeshGuardClient;

impl MeshGuardClient {
    /// Returns all agents registered in the gateway.
    ///
    /// Requires an admin token.
    pub async fn list_agents(&self) -> Result<Vec<Agent>> {
        let url = format!("{}/admin/agents", self.gateway_url());
        let req = self.http_client().get(&url);
        let req = self.apply_admin_headers(req)?;

        let body = self.admin_request_bytes(req).await?;

        #[derive(serde::Deserialize)]
        struct Wrapper {
            agents: Vec<Agent>,
        }

        let wrapper: Wrapper = serde_json::from_slice(&body).map_err(|e| {
            MeshGuardError::Api {
                status: 0,
                message: format!("failed to decode agents response: {e}"),
            }
        })?;

        Ok(wrapper.agents)
    }

    /// Registers a new agent with the gateway.
    ///
    /// If `trust_tier` is `None`, the gateway defaults to "verified".
    /// Requires an admin token.
    pub async fn create_agent(&self, request: CreateAgentRequest) -> Result<Agent> {
        let url = format!("{}/admin/agents", self.gateway_url());
        let req = self
            .http_client()
            .post(&url)
            .header(header::CONTENT_TYPE, "application/json")
            .json(&request);
        let req = self.apply_admin_headers(req)?;

        let body = self.admin_request_bytes(req).await?;

        let agent: Agent = serde_json::from_slice(&body).map_err(|e| {
            MeshGuardError::Api {
                status: 0,
                message: format!("failed to decode create agent response: {e}"),
            }
        })?;

        Ok(agent)
    }

    /// Revokes (deletes) an agent by ID.
    ///
    /// Requires an admin token.
    pub async fn revoke_agent(&self, agent_id: &str) -> Result<()> {
        let url = format!("{}/admin/agents/{}", self.gateway_url(), agent_id);
        let req = self.http_client().delete(&url);
        let req = self.apply_admin_headers(req)?;

        let _body = self.admin_request_bytes(req).await?;
        Ok(())
    }

    /// Returns all policies defined in the gateway.
    ///
    /// Requires an admin token.
    pub async fn list_policies(&self) -> Result<Vec<Policy>> {
        let url = format!("{}/admin/policies", self.gateway_url());
        let req = self.http_client().get(&url);
        let req = self.apply_admin_headers(req)?;

        let body = self.admin_request_bytes(req).await?;

        #[derive(serde::Deserialize)]
        struct Wrapper {
            policies: Vec<Policy>,
        }

        let wrapper: Wrapper = serde_json::from_slice(&body).map_err(|e| {
            MeshGuardError::Api {
                status: 0,
                message: format!("failed to decode policies response: {e}"),
            }
        })?;

        Ok(wrapper.policies)
    }

    /// Retrieves audit log entries from the gateway.
    ///
    /// Pass `AuditQueryOptions::default()` for defaults (limit 50, no filters).
    /// Requires an admin token.
    pub async fn audit_log(&self, opts: AuditQueryOptions) -> Result<Vec<AuditEntry>> {
        let url = format!("{}/admin/audit", self.gateway_url());
        let mut req = self.http_client().get(&url);

        // Build query parameters.
        let limit = opts.limit.unwrap_or(50);
        let mut params: Vec<(&str, String)> = vec![("limit", limit.to_string())];

        if let Some(ref decision) = opts.decision {
            params.push(("decision", decision.clone()));
        }
        if let Some(ref agent_id) = opts.agent_id {
            params.push(("agentId", agent_id.clone()));
        }
        if let Some(ref action) = opts.action {
            params.push(("action", action.clone()));
        }

        req = req.query(&params);
        let req = self.apply_admin_headers(req)?;

        let body = self.admin_request_bytes(req).await?;

        #[derive(serde::Deserialize)]
        struct Wrapper {
            entries: Vec<AuditEntry>,
        }

        let wrapper: Wrapper = serde_json::from_slice(&body).map_err(|e| {
            MeshGuardError::Api {
                status: 0,
                message: format!("failed to decode audit log response: {e}"),
            }
        })?;

        Ok(wrapper.entries)
    }
}
