use std::collections::HashMap;
use std::time::Duration;

use chrono::Utc;
use reqwest::{header, Method, StatusCode};

use crate::error::{MeshGuardError, Result};
use crate::types::{Decision, PolicyDecision};

const DEFAULT_GATEWAY_URL: &str = "https://dashboard.meshguard.app";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const USER_AGENT: &str = "meshguard-rust/0.1.0";

/// Core MeshGuard governance gateway client.
///
/// All methods are async and require a Tokio (or compatible) runtime.
///
/// # Examples
///
/// ```no_run
/// # async fn example() -> meshguard::Result<()> {
/// let client = meshguard::MeshGuardClient::new("https://gw.example.com", "my-token");
///
/// let decision = client.check("agent-1", "file.read", None).await?;
/// if decision.allowed {
///     println!("Action allowed by policy {:?}", decision.policy);
/// }
/// # Ok(())
/// # }
/// ```
pub struct MeshGuardClient {
    gateway_url: String,
    api_key: String,
    admin_token: Option<String>,
    http: reqwest::Client,
    trace_id: String,
}

impl MeshGuardClient {
    /// Creates a new client with the given gateway URL and API key.
    ///
    /// The gateway URL should not have a trailing slash. The API key is the
    /// agent JWT token used for authentication with governance endpoints.
    pub fn new(gateway_url: impl Into<String>, api_key: impl Into<String>) -> Self {
        let gateway_url = gateway_url.into().trim_end_matches('/').to_owned();
        let http = reqwest::Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .user_agent(USER_AGENT)
            .build()
            .expect("failed to build HTTP client");

        Self {
            gateway_url,
            api_key: api_key.into(),
            admin_token: std::env::var("MESHGUARD_ADMIN_TOKEN").ok(),
            http,
            trace_id: format!("{}", Utc::now().timestamp_nanos_opt().unwrap_or(0)),
        }
    }

    /// Creates a client from environment variables.
    ///
    /// Reads `MESHGUARD_GATEWAY_URL` (falls back to the default dashboard URL)
    /// and `MESHGUARD_AGENT_TOKEN` (required).
    ///
    /// Also reads `MESHGUARD_ADMIN_TOKEN` if present, for admin operations.
    pub fn from_env() -> Result<Self> {
        let gateway_url = std::env::var("MESHGUARD_GATEWAY_URL")
            .unwrap_or_else(|_| DEFAULT_GATEWAY_URL.to_owned());
        let api_key = std::env::var("MESHGUARD_AGENT_TOKEN")
            .map_err(|_| MeshGuardError::Env("MESHGUARD_AGENT_TOKEN not set".into()))?;

        let mut client = Self::new(gateway_url, api_key);
        client.admin_token = std::env::var("MESHGUARD_ADMIN_TOKEN").ok();
        Ok(client)
    }

    /// Sets the admin token for management API calls.
    pub fn set_admin_token(&mut self, token: impl Into<String>) {
        self.admin_token = Some(token.into());
    }

    /// Sets a custom trace ID for request correlation.
    pub fn set_trace_id(&mut self, trace_id: impl Into<String>) {
        self.trace_id = trace_id.into();
    }

    // -------------------------------------------------------------------------
    // Core Governance
    // -------------------------------------------------------------------------

    /// Evaluates whether the given action is allowed by policy.
    ///
    /// This method never returns an error on policy denial. Instead, the
    /// returned [`PolicyDecision`] will have `allowed == false`. Errors are
    /// reserved for transport failures and authentication problems.
    pub async fn check(
        &self,
        agent_id: &str,
        action: &str,
        metadata: Option<&HashMap<String, serde_json::Value>>,
    ) -> Result<PolicyDecision> {
        let url = format!("{}/proxy/check", self.gateway_url);
        let mut req = self.http.get(&url);
        req = self.apply_auth_headers(req);
        req = req.header("X-MeshGuard-Action", action);

        if !agent_id.is_empty() {
            req = req.header("X-MeshGuard-Agent-ID", agent_id);
        }

        if let Some(meta) = metadata {
            let meta_json = serde_json::to_string(meta)
                .map_err(|e| MeshGuardError::Api {
                    status: 0,
                    message: format!("failed to serialize metadata: {e}"),
                })?;
            req = req.header("X-MeshGuard-Meta", meta_json);
        }

        let resp = req.send().await?;
        let now = Utc::now();

        // A 403 is a valid policy denial, not a transport error.
        if resp.status() == StatusCode::FORBIDDEN {
            let body = resp.text().await.unwrap_or_default();
            let data: DenialBody = serde_json::from_str(&body).unwrap_or_default();

            return Ok(PolicyDecision {
                allowed: false,
                action: action.to_owned(),
                decision: Decision::Deny,
                policy: data.policy,
                rule: data.rule,
                reason: data.message,
                trace_id: self.trace_id.clone(),
                timestamp: Some(now),
            });
        }

        self.handle_error_status(&resp).await?;

        let body = resp.text().await.unwrap_or_default();
        let data: AllowBody = serde_json::from_str(&body).unwrap_or_default();

        Ok(PolicyDecision {
            allowed: true,
            action: action.to_owned(),
            decision: Decision::Allow,
            policy: data.policy,
            rule: String::new(),
            reason: String::new(),
            trace_id: self.trace_id.clone(),
            timestamp: Some(now),
        })
    }

    /// Checks the action and returns an error if it is denied.
    ///
    /// On denial the returned error is [`MeshGuardError::PolicyDenied`],
    /// which contains the full [`PolicyDecision`].
    pub async fn enforce(
        &self,
        agent_id: &str,
        action: &str,
        metadata: Option<&HashMap<String, serde_json::Value>>,
    ) -> Result<()> {
        let decision = self.check(agent_id, action, metadata).await?;
        if !decision.allowed {
            return Err(MeshGuardError::PolicyDenied {
                action: action.to_owned(),
                policy: decision.policy.clone(),
                rule: decision.rule.clone(),
                reason: decision.reason.clone(),
                decision,
            });
        }
        Ok(())
    }

    /// Enforces a policy check and, if allowed, executes the given closure.
    ///
    /// If the policy denies the action, `f` is never called and a
    /// [`MeshGuardError::PolicyDenied`] error is returned.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn example() -> meshguard::Result<()> {
    /// # let client = meshguard::MeshGuardClient::new("http://localhost", "tok");
    /// let result = client.govern("agent-1", "db.query", None, || {
    ///     Ok("query result".to_string())
    /// }).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn govern<F, T>(
        &self,
        agent_id: &str,
        action: &str,
        metadata: Option<&HashMap<String, serde_json::Value>>,
        f: F,
    ) -> Result<T>
    where
        F: FnOnce() -> std::result::Result<T, MeshGuardError>,
    {
        self.enforce(agent_id, action, metadata).await?;
        f()
    }

    // -------------------------------------------------------------------------
    // Proxy Requests
    // -------------------------------------------------------------------------

    /// Sends an HTTP request through the MeshGuard governance proxy.
    ///
    /// The request is routed to `/proxy/<path>` with governance headers
    /// attached. `body` may be `None` for methods that carry no payload.
    pub async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<reqwest::Response> {
        let path = path.trim_start_matches('/');
        let url = format!("{}/proxy/{}", self.gateway_url, path);

        let mut req = self.http.request(method, &url);
        req = self.apply_auth_headers(req);

        if let Some(payload) = body {
            req = req
                .header(header::CONTENT_TYPE, "application/json")
                .json(&payload);
        }

        let resp = req.send().await?;
        Ok(resp)
    }

    // -------------------------------------------------------------------------
    // Health
    // -------------------------------------------------------------------------

    /// Checks the gateway's health endpoint.
    ///
    /// Returns `Ok(())` if the gateway reports a healthy status.
    pub async fn health(&self) -> Result<()> {
        let url = format!("{}/health", self.gateway_url);
        let resp = self.http.get(&url).send().await?;

        if resp.status() != StatusCode::OK {
            return Err(MeshGuardError::Unhealthy(format!(
                "HTTP {}",
                resp.status().as_u16()
            )));
        }

        #[derive(serde::Deserialize)]
        struct HealthResponse {
            status: String,
        }

        let health: HealthResponse = resp.json().await.map_err(|e| {
            MeshGuardError::Unhealthy(format!("invalid response: {e}"))
        })?;

        if health.status != "healthy" {
            return Err(MeshGuardError::Unhealthy(health.status));
        }

        Ok(())
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    fn apply_auth_headers(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let mut req = req.header("X-MeshGuard-Trace-ID", &self.trace_id);
        if !self.api_key.is_empty() {
            req = req.header(header::AUTHORIZATION, format!("Bearer {}", self.api_key));
        }
        req
    }

    pub(crate) fn admin_headers(
        &self,
    ) -> Result<Vec<(String, String)>> {
        let token = self
            .admin_token
            .as_deref()
            .filter(|t| !t.is_empty())
            .ok_or(MeshGuardError::Authentication)?;

        Ok(vec![
            ("X-Admin-Token".into(), token.to_owned()),
            ("X-MeshGuard-Trace-ID".into(), self.trace_id.clone()),
        ])
    }

    pub(crate) fn apply_admin_headers(
        &self,
        mut req: reqwest::RequestBuilder,
    ) -> Result<reqwest::RequestBuilder> {
        let headers = self.admin_headers()?;
        for (key, value) in headers {
            req = req.header(key, value);
        }
        Ok(req)
    }

    pub(crate) async fn handle_error_status(
        &self,
        resp: &reqwest::Response,
    ) -> Result<()> {
        let status = resp.status();
        match status {
            StatusCode::UNAUTHORIZED => Err(MeshGuardError::Authentication),
            StatusCode::TOO_MANY_REQUESTS => Err(MeshGuardError::RateLimit),
            s if s.is_client_error() || s.is_server_error() => {
                Err(MeshGuardError::Api {
                    status: s.as_u16(),
                    message: format!("HTTP {s}"),
                })
            }
            _ => Ok(()),
        }
    }

    pub(crate) async fn admin_request_bytes(
        &self,
        req: reqwest::RequestBuilder,
    ) -> Result<bytes::Bytes> {
        let resp = req.send().await?;
        let status = resp.status();

        match status {
            StatusCode::UNAUTHORIZED => return Err(MeshGuardError::Authentication),
            StatusCode::FORBIDDEN => {
                let body = resp.text().await.unwrap_or_default();
                return Err(MeshGuardError::Api {
                    status: 403,
                    message: body,
                });
            }
            StatusCode::TOO_MANY_REQUESTS => return Err(MeshGuardError::RateLimit),
            s if s.is_client_error() || s.is_server_error() => {
                let body = resp.text().await.unwrap_or_default();
                return Err(MeshGuardError::Api {
                    status: s.as_u16(),
                    message: body,
                });
            }
            _ => {}
        }

        resp.bytes().await.map_err(MeshGuardError::from)
    }

    pub(crate) fn gateway_url(&self) -> &str {
        &self.gateway_url
    }

    pub(crate) fn http_client(&self) -> &reqwest::Client {
        &self.http
    }
}

// Private deserialization helpers for Check responses.

#[derive(Debug, Default, serde::Deserialize)]
struct DenialBody {
    #[serde(default)]
    policy: String,
    #[serde(default)]
    rule: String,
    #[serde(default)]
    message: String,
}

#[derive(Debug, Default, serde::Deserialize)]
struct AllowBody {
    #[serde(default)]
    policy: String,
}
