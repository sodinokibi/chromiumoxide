//! # Web Recon Tool - Bug Bounty Edition v3
//!
//! Advanced security research tool for capturing traffic and generating raw requests.
//! Features: Full body capture, WebSocket interception, auth flow tracking, multi-format export.
//!
//! ## Usage
//! ```bash
//! cargo run --example recon -- https://target.com [--export curl|python|raw|all]
//! ```

use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::cdp::browser_protocol::network::{
    EventRequestWillBeSent, EventResponseReceived,
    EventWebSocketCreated, EventWebSocketFrameSent, EventWebSocketFrameReceived,
    EventWebSocketClosed, GetRequestPostDataParams, GetResponseBodyParams,
    RequestId,
};
use chromiumoxide::Page;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;

// ============================================================================
// Raw Request/Response Data Structures
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawRequest {
    pub id: String,
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub cookies: Vec<Cookie>,
    pub body: Option<String>,
    pub content_type: Option<String>,
    pub timestamp: u64,
    pub initiator: Option<String>,
    pub resource_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawResponse {
    pub request_id: String,
    pub url: String,
    pub status: i64,
    pub status_text: String,
    pub headers: HashMap<String, String>,
    pub mime_type: String,
    pub body: Option<String>,
    pub body_size: Option<usize>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub expires: Option<String>,
    pub http_only: bool,
    pub secure: bool,
    pub same_site: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestResponsePair {
    pub request: RawRequest,
    pub response: Option<RawResponse>,
}

// ============================================================================
// WebSocket Structures
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketConnection {
    pub request_id: String,
    pub url: String,
    pub initiator_url: Option<String>,
    pub messages: Vec<WebSocketMessage>,
    pub created_at: u64,
    pub closed_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketMessage {
    pub direction: String, // "sent" or "received"
    pub opcode: f64,
    pub payload: String,
    pub timestamp: u64,
}

// ============================================================================
// Auth Flow Structures
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginForm {
    pub url: String,
    pub action: String,
    pub method: String,
    pub fields: Vec<FormField>,
    pub has_password: bool,
    pub has_username: bool,
    pub has_email: bool,
    pub has_csrf: bool,
    pub csrf_field: Option<String>,
    pub submit_button: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationForm {
    pub url: String,
    pub action: String,
    pub method: String,
    pub fields: Vec<FormField>,
    pub password_requirements: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormField {
    pub name: String,
    pub field_type: String,
    pub id: Option<String>,
    pub placeholder: Option<String>,
    pub required: bool,
    pub pattern: Option<String>,
    pub autocomplete: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthFlow {
    pub flow_type: String,
    pub steps: Vec<AuthFlowStep>,
    pub tokens_captured: Vec<CapturedToken>,
    pub started_at: u64,
    pub completed_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthFlowStep {
    pub step_number: usize,
    pub request_id: String,
    pub url: String,
    pub method: String,
    pub action: String,
    pub tokens_received: Vec<String>,
    pub tokens_sent: Vec<String>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedToken {
    pub token_type: String,
    pub name: String,
    pub value_preview: String,
    pub full_value: Option<String>, // For CSRF tokens that need to be replayed
    pub location: String,
    pub first_seen_url: String,
    pub first_seen_request_id: Option<String>,
    pub timestamp: u64,
}

// ============================================================================
// API and Security Structures
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiEndpoint {
    pub url: String,
    pub method: String,
    pub api_type: String,
    pub has_auth: bool,
    pub request_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthFinding {
    pub auth_type: String,
    pub location: String,
    pub key_name: String,
    pub sample: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiBotFinding {
    pub service: String,
    pub indicator: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub finding_type: String,
    pub details: String,
}

// ============================================================================
// Full Report Structure
// ============================================================================

#[derive(Debug, Default, Serialize)]
pub struct ReconReport {
    pub target: String,
    pub scan_time: String,
    pub total_requests: usize,

    // Raw data for replay
    pub captured_requests: Vec<RawRequest>,
    pub captured_responses: Vec<RawResponse>,
    pub request_response_pairs: Vec<RequestResponsePair>,

    // WebSocket
    pub websocket_connections: Vec<WebSocketConnection>,

    // Auth flows
    pub login_forms: Vec<LoginForm>,
    pub registration_forms: Vec<RegistrationForm>,
    pub auth_flows: Vec<AuthFlow>,
    pub captured_tokens: Vec<CapturedToken>,

    // API discovery
    pub api_endpoints: Vec<ApiEndpoint>,
    pub graphql_operations: Vec<GraphQLOperation>,

    // Security
    pub auth_findings: Vec<AuthFinding>,
    pub antibot_findings: Vec<AntiBotFinding>,
    pub security_findings: Vec<SecurityFinding>,
    pub missing_headers: Vec<String>,

    // Interesting
    pub interesting_urls: Vec<String>,

    // Export commands
    pub curl_commands: Vec<String>,
    pub python_requests: Vec<String>,
    pub raw_http: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLOperation {
    pub url: String,
    pub operation_type: String,
    pub operation_name: Option<String>,
    pub query: Option<String>,
    pub variables: Option<serde_json::Value>,
    pub request_id: String,
}

// ============================================================================
// Pending Body Fetch
// ============================================================================

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct PendingRequest {
    request_id: String,
    has_post_data: bool,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct PendingResponse {
    request_id: String,
    url: String,
    mime_type: String,
}

// ============================================================================
// Recon Engine
// ============================================================================

struct ReconEngine {
    // Raw capture
    requests: Mutex<HashMap<String, RawRequest>>,
    responses: Mutex<HashMap<String, RawResponse>>,

    // Pending body fetches
    pending_request_bodies: Mutex<Vec<PendingRequest>>,
    pending_response_bodies: Mutex<Vec<PendingResponse>>,

    // WebSocket connections
    websockets: Mutex<HashMap<String, WebSocketConnection>>,

    // Deduplication
    seen_urls: Mutex<HashSet<String>>,

    // API discovery
    apis: Mutex<Vec<ApiEndpoint>>,
    graphql_ops: Mutex<Vec<GraphQLOperation>>,

    // Auth tracking
    auth_findings: Mutex<Vec<AuthFinding>>,
    captured_tokens: Mutex<Vec<CapturedToken>>,
    login_forms: Mutex<Vec<LoginForm>>,
    registration_forms: Mutex<Vec<RegistrationForm>>,
    auth_flows: Mutex<Vec<AuthFlow>>,
    current_auth_flow: Mutex<Option<AuthFlow>>,

    // Security
    antibot_findings: Mutex<Vec<AntiBotFinding>>,
    security_findings: Mutex<Vec<SecurityFinding>>,
    interesting_urls: Mutex<Vec<String>>,

    // Headers
    request_count: Mutex<usize>,
    checked_headers: Mutex<bool>,
    header_findings: Mutex<Vec<String>>,
}

impl ReconEngine {
    fn new() -> Self {
        Self {
            requests: Mutex::new(HashMap::new()),
            responses: Mutex::new(HashMap::new()),
            pending_request_bodies: Mutex::new(Vec::new()),
            pending_response_bodies: Mutex::new(Vec::new()),
            websockets: Mutex::new(HashMap::new()),
            seen_urls: Mutex::new(HashSet::new()),
            apis: Mutex::new(Vec::new()),
            graphql_ops: Mutex::new(Vec::new()),
            auth_findings: Mutex::new(Vec::new()),
            captured_tokens: Mutex::new(Vec::new()),
            login_forms: Mutex::new(Vec::new()),
            registration_forms: Mutex::new(Vec::new()),
            auth_flows: Mutex::new(Vec::new()),
            current_auth_flow: Mutex::new(None),
            antibot_findings: Mutex::new(Vec::new()),
            security_findings: Mutex::new(Vec::new()),
            interesting_urls: Mutex::new(Vec::new()),
            request_count: Mutex::new(0),
            checked_headers: Mutex::new(false),
            header_findings: Mutex::new(Vec::new()),
        }
    }

    // ========================================================================
    // Request Capture
    // ========================================================================

    async fn capture_request(&self, event: &EventRequestWillBeSent) {
        *self.request_count.lock().await += 1;

        let url = &event.request.url;
        let method = &event.request.method;
        let request_id = event.request_id.inner().to_string();

        let headers: HashMap<String, String> = event
            .request
            .headers
            .inner()
            .as_object()
            .map(|obj| {
                obj.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();

        let cookies = parse_cookies(headers.get("Cookie").or(headers.get("cookie")));

        let content_type = headers.get("Content-Type")
            .or(headers.get("content-type"))
            .cloned();

        let has_post_data = event.request.has_post_data.unwrap_or(false);

        // Queue for body fetch if has POST data
        if has_post_data {
            self.pending_request_bodies.lock().await.push(PendingRequest {
                request_id: request_id.clone(),
                has_post_data: true,
            });
        }

        let raw_request = RawRequest {
            id: request_id.clone(),
            url: url.clone(),
            method: method.clone(),
            headers: headers.clone(),
            cookies,
            body: None, // Will be filled later
            content_type: content_type.clone(),
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            initiator: event.initiator.url.clone(),
            resource_type: event.r#type.as_ref().map(|t| format!("{:?}", t)).unwrap_or_default(),
        };

        self.requests.lock().await.insert(request_id.clone(), raw_request);

        if is_static(url) {
            return;
        }

        // Analyze
        self.detect_api(url, method, &headers, Some(&request_id)).await;
        self.detect_graphql(url, &headers, has_post_data, &request_id).await;
        self.capture_auth_tokens(url, &headers, "request", Some(&request_id)).await;
        self.track_auth_flow_request(url, method, &headers, &request_id).await;
        self.check_interesting(url).await;
        self.detect_antibot_url(url).await;
        self.check_sensitive_url(url).await;
    }

    async fn capture_response(&self, event: &EventResponseReceived) {
        let url = &event.response.url;
        let status = event.response.status;
        let request_id = event.request_id.inner().to_string();

        let headers: HashMap<String, String> = event
            .response
            .headers
            .inner()
            .as_object()
            .map(|obj| {
                obj.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();

        let mime_type = event.response.mime_type.clone();

        // Queue for body fetch if it's a useful content type
        if should_capture_body(&mime_type) {
            self.pending_response_bodies.lock().await.push(PendingResponse {
                request_id: request_id.clone(),
                url: url.clone(),
                mime_type: mime_type.clone(),
            });
        }

        let raw_response = RawResponse {
            request_id: request_id.clone(),
            url: url.clone(),
            status,
            status_text: event.response.status_text.clone(),
            headers: headers.clone(),
            mime_type: mime_type.clone(),
            body: None,
            body_size: None,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };

        self.responses.lock().await.insert(request_id.clone(), raw_response);

        if !*self.checked_headers.lock().await {
            self.check_security_headers(&headers).await;
            *self.checked_headers.lock().await = true;
        }

        self.capture_auth_tokens(url, &headers, "response", Some(&request_id)).await;
        self.capture_set_cookie_tokens(url, &headers).await;
        self.track_auth_flow_response(url, &headers, &request_id, status).await;
        self.detect_antibot_response(&headers).await;

        if status == 401 || status == 403 {
            println!("  [AUTH-REQUIRED] {} {} {}", status, event.response.status_text, truncate(url, 60));
        } else if status >= 500 {
            println!("  [SERVER-ERROR] {} {} - Potential info leak", status, truncate(url, 60));
            self.security_findings.lock().await.push(SecurityFinding {
                finding_type: "Server Error".to_string(),
                details: format!("{} at {}", status, truncate(url, 100)),
            });
        }

        if let Some(cors) = headers.get("Access-Control-Allow-Origin").or(headers.get("access-control-allow-origin")) {
            if cors == "*" {
                println!("  [CORS] Wildcard CORS: {}", truncate(url, 60));
                self.security_findings.lock().await.push(SecurityFinding {
                    finding_type: "Wildcard CORS".to_string(),
                    details: format!("Access-Control-Allow-Origin: * at {}", truncate(url, 80)),
                });
            }
        }
    }

    // ========================================================================
    // Body Fetching (called after page load)
    // ========================================================================

    async fn fetch_pending_bodies(&self, page: &Page) {
        // Fetch request bodies
        let pending_reqs = {
            let mut pending = self.pending_request_bodies.lock().await;
            std::mem::take(&mut *pending)
        };

        for pending in pending_reqs {
            if let Ok(body) = self.fetch_request_body(page, &pending.request_id).await {
                let mut requests = self.requests.lock().await;
                if let Some(req) = requests.get_mut(&pending.request_id) {
                    if !body.is_empty() {
                        // Check if it's GraphQL and parse
                        if req.url.to_lowercase().contains("graphql") {
                            self.parse_graphql_body(&body, &pending.request_id).await;
                        }
                        println!("  [BODY] Request {} - {} bytes", truncate(&req.url, 40), body.len());
                        req.body = Some(body);
                    }
                }
            }
        }

        // Fetch response bodies
        let pending_resps = {
            let mut pending = self.pending_response_bodies.lock().await;
            std::mem::take(&mut *pending)
        };

        for pending in pending_resps {
            if let Ok((body, _base64)) = self.fetch_response_body(page, &pending.request_id).await {
                let mut responses = self.responses.lock().await;
                if let Some(resp) = responses.get_mut(&pending.request_id) {
                    if !body.is_empty() {
                        let size = body.len();
                        // Truncate large bodies for storage
                        let stored_body = if size > 50000 {
                            format!("{}... [TRUNCATED - {} bytes total]", &body[..50000], size)
                        } else {
                            body
                        };
                        println!("  [BODY] Response {} - {} bytes", truncate(&pending.url, 40), size);
                        resp.body = Some(stored_body);
                        resp.body_size = Some(size);
                    }
                }
            }
        }
    }

    async fn fetch_request_body(&self, page: &Page, request_id: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let params = GetRequestPostDataParams::new(RequestId::from(request_id.to_string()));
        let result = page.execute(params).await?;
        Ok(result.post_data.clone())
    }

    async fn fetch_response_body(&self, page: &Page, request_id: &str) -> Result<(String, bool), Box<dyn std::error::Error + Send + Sync>> {
        let params = GetResponseBodyParams::new(RequestId::from(request_id.to_string()));
        let result = page.execute(params).await?;
        Ok((result.body.clone(), result.base64_encoded))
    }

    async fn parse_graphql_body(&self, body: &str, request_id: &str) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
            let query = json.get("query").and_then(|q| q.as_str()).map(|s| s.to_string());
            let variables = json.get("variables").cloned();
            let operation_name = json.get("operationName").and_then(|n| n.as_str()).map(|s| s.to_string());

            let operation_type = query.as_ref().map(|q| {
                if q.trim().starts_with("mutation") {
                    "mutation"
                } else if q.trim().starts_with("subscription") {
                    "subscription"
                } else {
                    "query"
                }
            }).unwrap_or("unknown").to_string();

            let mut ops = self.graphql_ops.lock().await;
            if let Some(op) = ops.iter_mut().find(|o| o.request_id == request_id) {
                op.operation_type = operation_type;
                op.operation_name = operation_name;
                op.query = query;
                op.variables = variables;
                println!("  [GRAPHQL] {} - {:?}", op.operation_type, op.operation_name);
            }
        }
    }

    // ========================================================================
    // WebSocket Capture
    // ========================================================================

    async fn handle_websocket_created(&self, event: &EventWebSocketCreated) {
        let request_id = event.request_id.inner().to_string();
        println!("  [WS-CREATED] {} -> {}", request_id, event.url);

        let ws = WebSocketConnection {
            request_id: request_id.clone(),
            url: event.url.clone(),
            initiator_url: event.initiator.as_ref().and_then(|i| i.url.clone()),
            messages: Vec::new(),
            created_at: chrono::Utc::now().timestamp_millis() as u64,
            closed_at: None,
        };

        self.websockets.lock().await.insert(request_id, ws);
    }

    async fn handle_websocket_frame_sent(&self, event: &EventWebSocketFrameSent) {
        let request_id = event.request_id.inner().to_string();

        let msg = WebSocketMessage {
            direction: "sent".to_string(),
            opcode: event.response.opcode,
            payload: event.response.payload_data.clone(),
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };

        let preview = truncate(&event.response.payload_data, 50);
        println!("  [WS-SENT] {} -> {}", request_id, preview);

        if let Some(ws) = self.websockets.lock().await.get_mut(&request_id) {
            ws.messages.push(msg);
        }
    }

    async fn handle_websocket_frame_received(&self, event: &EventWebSocketFrameReceived) {
        let request_id = event.request_id.inner().to_string();

        let msg = WebSocketMessage {
            direction: "received".to_string(),
            opcode: event.response.opcode,
            payload: event.response.payload_data.clone(),
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };

        let preview = truncate(&event.response.payload_data, 50);
        println!("  [WS-RECV] {} <- {}", request_id, preview);

        if let Some(ws) = self.websockets.lock().await.get_mut(&request_id) {
            ws.messages.push(msg);
        }
    }

    async fn handle_websocket_closed(&self, event: &EventWebSocketClosed) {
        let request_id = event.request_id.inner().to_string();
        println!("  [WS-CLOSED] {}", request_id);

        if let Some(ws) = self.websockets.lock().await.get_mut(&request_id) {
            ws.closed_at = Some(chrono::Utc::now().timestamp_millis() as u64);
        }
    }

    // ========================================================================
    // Auth Flow Tracking
    // ========================================================================

    async fn track_auth_flow_request(&self, url: &str, method: &str, headers: &HashMap<String, String>, request_id: &str) {
        let url_lower = url.to_lowercase();
        let is_auth_endpoint = url_lower.contains("/login") || url_lower.contains("/signin")
            || url_lower.contains("/auth") || url_lower.contains("/oauth")
            || url_lower.contains("/token") || url_lower.contains("/session");

        if !is_auth_endpoint {
            return;
        }

        let tokens_sent: Vec<String> = {
            let captured = self.captured_tokens.lock().await;
            captured.iter()
                .filter(|t| headers.values().any(|v| v.contains(&t.value_preview) ||
                    (t.full_value.is_some() && v.contains(t.full_value.as_ref().unwrap()))))
                .map(|t| format!("{}:{}", t.token_type, t.name))
                .collect()
        };

        let step = AuthFlowStep {
            step_number: 0,
            request_id: request_id.to_string(),
            url: url.to_string(),
            method: method.to_string(),
            action: "request".to_string(),
            tokens_received: Vec::new(),
            tokens_sent,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };

        let mut current_flow = self.current_auth_flow.lock().await;
        if let Some(flow) = current_flow.as_mut() {
            let step_num = flow.steps.len();
            let mut step = step;
            step.step_number = step_num;
            flow.steps.push(step);
        } else {
            let mut new_flow = AuthFlow {
                flow_type: if url_lower.contains("oauth") { "oauth".to_string() } else { "login".to_string() },
                steps: vec![step],
                tokens_captured: Vec::new(),
                started_at: chrono::Utc::now().timestamp_millis() as u64,
                completed_at: None,
            };
            new_flow.steps[0].step_number = 0;
            *current_flow = Some(new_flow);
            println!("  [AUTH-FLOW] Started tracking auth flow");
        }
    }

    async fn track_auth_flow_response(&self, url: &str, headers: &HashMap<String, String>, request_id: &str, status: i64) {
        let mut current_flow = self.current_auth_flow.lock().await;
        if current_flow.is_none() {
            return;
        }

        let flow = current_flow.as_mut().unwrap();

        // Check for tokens in response
        let tokens_received: Vec<String> = {
            let mut tokens = Vec::new();

            // Check Set-Cookie for session tokens
            for (key, value) in headers.iter() {
                if key.to_lowercase() == "set-cookie" {
                    let cookie_name = value.split('=').next().unwrap_or("");
                    if cookie_name.to_lowercase().contains("session") || cookie_name.to_lowercase().contains("token") {
                        tokens.push(format!("cookie:{}", cookie_name));
                    }
                }
            }

            // Check for auth headers
            if headers.contains_key("Authorization") || headers.contains_key("authorization") {
                tokens.push("header:authorization".to_string());
            }

            tokens
        };

        // Add response step
        let step = AuthFlowStep {
            step_number: flow.steps.len(),
            request_id: request_id.to_string(),
            url: url.to_string(),
            method: "RESPONSE".to_string(),
            action: format!("response:{}", status),
            tokens_received: tokens_received.clone(),
            tokens_sent: Vec::new(),
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };

        flow.steps.push(step);

        // Check if flow is complete (successful auth or redirect)
        if (status == 200 || status == 302) && !tokens_received.is_empty() {
            flow.completed_at = Some(chrono::Utc::now().timestamp_millis() as u64);

            // Copy captured tokens
            let captured = self.captured_tokens.lock().await;
            flow.tokens_captured = captured.clone();

            // Store completed flow
            let completed_flow = flow.clone();
            drop(current_flow);
            self.auth_flows.lock().await.push(completed_flow);
            *self.current_auth_flow.lock().await = None;

            println!("  [AUTH-FLOW] Completed - {} steps, {} tokens",
                self.auth_flows.lock().await.last().map(|f| f.steps.len()).unwrap_or(0),
                self.auth_flows.lock().await.last().map(|f| f.tokens_captured.len()).unwrap_or(0));
        }
    }

    // ========================================================================
    // Token Capture (Enhanced)
    // ========================================================================

    async fn capture_auth_tokens(&self, url: &str, headers: &HashMap<String, String>, context: &str, request_id: Option<&str>) {
        let mut tokens = self.captured_tokens.lock().await;
        let mut findings = self.auth_findings.lock().await;
        let timestamp = chrono::Utc::now().timestamp_millis() as u64;

        // Authorization header
        if let Some(auth) = headers.get("Authorization").or(headers.get("authorization")) {
            let (token_type, auth_type_str) = if auth.starts_with("Bearer ") {
                let token = &auth[7..];
                if is_jwt(token) { ("jwt", "JWT") } else { ("bearer", "Bearer Token") }
            } else if auth.starts_with("Basic ") {
                ("basic", "Basic Auth")
            } else {
                ("custom", "Custom Auth")
            };

            if !tokens.iter().any(|t| t.token_type == token_type && t.location == "header") {
                println!("  [TOKEN] {} captured from {} header", auth_type_str, context);
                tokens.push(CapturedToken {
                    token_type: token_type.to_string(),
                    name: "Authorization".to_string(),
                    value_preview: redact(auth),
                    full_value: Some(auth.clone()),
                    location: "header".to_string(),
                    first_seen_url: url.to_string(),
                    first_seen_request_id: request_id.map(|s| s.to_string()),
                    timestamp,
                });

                if !findings.iter().any(|f| f.auth_type == auth_type_str) {
                    findings.push(AuthFinding {
                        auth_type: auth_type_str.to_string(),
                        location: "header".to_string(),
                        key_name: "Authorization".to_string(),
                        sample: redact(auth),
                    });
                }
            }
        }

        // API keys
        let api_key_headers = [
            "X-API-Key", "x-api-key", "Api-Key", "api-key",
            "X-Auth-Token", "x-auth-token", "X-Access-Token", "x-access-token",
        ];

        for key in &api_key_headers {
            if let Some(value) = headers.get(*key) {
                let key_lower = key.to_lowercase();
                if !tokens.iter().any(|t| t.name.to_lowercase() == key_lower) {
                    println!("  [TOKEN] API Key captured: {}", key);
                    tokens.push(CapturedToken {
                        token_type: "api_key".to_string(),
                        name: key.to_string(),
                        value_preview: redact(value),
                        full_value: Some(value.clone()),
                        location: "header".to_string(),
                        first_seen_url: url.to_string(),
                        first_seen_request_id: request_id.map(|s| s.to_string()),
                        timestamp,
                    });
                    findings.push(AuthFinding {
                        auth_type: "API Key".to_string(),
                        location: "header".to_string(),
                        key_name: key.to_string(),
                        sample: redact(value),
                    });
                }
            }
        }

        // CSRF tokens (capture full value for replay)
        let csrf_headers = ["X-CSRF-Token", "x-csrf-token", "X-XSRF-Token", "x-xsrf-token"];
        for key in &csrf_headers {
            if let Some(value) = headers.get(*key) {
                if !tokens.iter().any(|t| t.token_type == "csrf" && t.name.to_lowercase() == key.to_lowercase()) {
                    println!("  [TOKEN] CSRF token captured: {}", key);
                    tokens.push(CapturedToken {
                        token_type: "csrf".to_string(),
                        name: key.to_string(),
                        value_preview: redact(value),
                        full_value: Some(value.clone()), // Full value for replay
                        location: "header".to_string(),
                        first_seen_url: url.to_string(),
                        first_seen_request_id: request_id.map(|s| s.to_string()),
                        timestamp,
                    });
                    findings.push(AuthFinding {
                        auth_type: "CSRF Token".to_string(),
                        location: "header".to_string(),
                        key_name: key.to_string(),
                        sample: redact(value),
                    });
                }
            }
        }
    }

    async fn capture_set_cookie_tokens(&self, url: &str, headers: &HashMap<String, String>) {
        let mut tokens = self.captured_tokens.lock().await;
        let mut findings = self.auth_findings.lock().await;
        let timestamp = chrono::Utc::now().timestamp_millis() as u64;

        for (key, value) in headers.iter() {
            if key.to_lowercase() == "set-cookie" {
                let cookie = parse_set_cookie(value);

                let session_patterns = ["session", "sess", "sid", "token", "auth", "jwt", "csrf", "xsrf"];
                let name_lower = cookie.name.to_lowercase();

                for pattern in &session_patterns {
                    if name_lower.contains(pattern) {
                        if !tokens.iter().any(|t| t.name.to_lowercase() == name_lower && t.location == "cookie") {
                            let token_type = if name_lower.contains("csrf") || name_lower.contains("xsrf") {
                                "csrf"
                            } else if name_lower.contains("jwt") || is_jwt(&cookie.value) {
                                "jwt"
                            } else {
                                "session"
                            };

                            println!("  [TOKEN] Cookie set: {} ({}) HttpOnly:{} Secure:{}",
                                cookie.name, token_type, cookie.http_only, cookie.secure);

                            tokens.push(CapturedToken {
                                token_type: token_type.to_string(),
                                name: cookie.name.clone(),
                                value_preview: redact(&cookie.value),
                                full_value: if token_type == "csrf" { Some(cookie.value.clone()) } else { None },
                                location: "cookie".to_string(),
                                first_seen_url: url.to_string(),
                                first_seen_request_id: None,
                                timestamp,
                            });

                            findings.push(AuthFinding {
                                auth_type: format!("{} Cookie", if token_type == "session" { "Session" } else { "Auth" }),
                                location: "cookie".to_string(),
                                key_name: cookie.name.clone(),
                                sample: format!("HttpOnly:{} Secure:{} SameSite:{:?}",
                                    cookie.http_only, cookie.secure, cookie.same_site),
                            });
                        }
                        break;
                    }
                }
            }
        }
    }

    // ========================================================================
    // Detection Methods
    // ========================================================================

    async fn detect_api(&self, url: &str, method: &str, headers: &HashMap<String, String>, request_id: Option<&str>) {
        let url_lower = url.to_lowercase();

        let api_type = if url_lower.contains("graphql") || url_lower.contains("/gql") {
            "GraphQL"
        } else if url_lower.starts_with("wss://") || url_lower.starts_with("ws://") {
            "WebSocket"
        } else if url_lower.contains("/api/") || url_lower.contains("/v1/") || url_lower.contains("/v2/") || url_lower.contains("/v3/") {
            "REST"
        } else if headers.get("Content-Type").or(headers.get("content-type")).map(|ct| ct.contains("json")).unwrap_or(false) {
            "JSON"
        } else {
            return;
        };

        let has_auth = headers.contains_key("Authorization") || headers.contains_key("authorization")
            || headers.contains_key("X-API-Key") || headers.contains_key("x-api-key");

        let mut seen = self.seen_urls.lock().await;
        let api_key = format!("{}:{}", method, url);
        if !seen.contains(&api_key) {
            seen.insert(api_key);
            drop(seen);

            println!("  [API] {} {} {}", api_type, method, truncate(url, 60));

            self.apis.lock().await.push(ApiEndpoint {
                url: url.to_string(),
                method: method.to_string(),
                api_type: api_type.to_string(),
                has_auth,
                request_id: request_id.map(|s| s.to_string()),
            });

            let internal_patterns = ["/internal", "/private", "/admin", "/_", "/debug", "/config"];
            for pattern in &internal_patterns {
                if url_lower.contains(pattern) {
                    println!("    -> INTERNAL API: contains '{}'", pattern);
                }
            }
        }
    }

    async fn detect_graphql(&self, url: &str, _headers: &HashMap<String, String>, has_body: bool, request_id: &str) {
        if !url.to_lowercase().contains("graphql") && !url.to_lowercase().contains("/gql") {
            return;
        }

        if has_body {
            self.graphql_ops.lock().await.push(GraphQLOperation {
                url: url.to_string(),
                operation_type: "unknown".to_string(),
                operation_name: None,
                query: None,
                variables: None,
                request_id: request_id.to_string(),
            });
        }
    }

    async fn detect_antibot_url(&self, url: &str) {
        let url_lower = url.to_lowercase();
        let mut findings = self.antibot_findings.lock().await;

        let checks = [
            ("recaptcha", "Google reCAPTCHA"),
            ("hcaptcha", "hCaptcha"),
            ("turnstile", "Cloudflare Turnstile"),
            ("datadome", "DataDome"),
            ("perimeterx", "PerimeterX"),
            ("kasada", "Kasada"),
            ("fingerprintjs", "FingerprintJS"),
        ];

        for (pattern, service) in &checks {
            if url_lower.contains(pattern) && !findings.iter().any(|f| f.service == *service) {
                println!("  [ANTIBOT] {} detected", service);
                findings.push(AntiBotFinding {
                    service: service.to_string(),
                    indicator: format!("URL contains '{}'", pattern),
                });
            }
        }
    }

    async fn detect_antibot_response(&self, headers: &HashMap<String, String>) {
        let mut findings = self.antibot_findings.lock().await;

        let has_cf = headers.contains_key("CF-Ray") || headers.contains_key("cf-ray")
            || headers.get("Server").or(headers.get("server")).map(|s| s.to_lowercase().contains("cloudflare")).unwrap_or(false);

        if has_cf && !findings.iter().any(|f| f.service == "Cloudflare") {
            println!("  [ANTIBOT] Cloudflare detected");
            findings.push(AntiBotFinding { service: "Cloudflare".to_string(), indicator: "CF-Ray header".to_string() });
        }

        if headers.contains_key("X-Akamai-Transformed") || headers.contains_key("x-akamai-transformed") {
            if !findings.iter().any(|f| f.service == "Akamai") {
                println!("  [ANTIBOT] Akamai detected");
                findings.push(AntiBotFinding { service: "Akamai".to_string(), indicator: "Akamai headers".to_string() });
            }
        }

        if headers.contains_key("X-DataDome") || headers.contains_key("x-datadome") {
            if !findings.iter().any(|f| f.service == "DataDome") {
                println!("  [ANTIBOT] DataDome detected");
                findings.push(AntiBotFinding { service: "DataDome".to_string(), indicator: "X-DataDome header".to_string() });
            }
        }
    }

    async fn check_interesting(&self, url: &str) {
        let url_lower = url.to_lowercase();
        let patterns = [
            "/admin", "/api/internal", "/debug", "/config", "/swagger", "/openapi",
            "/graphql", "/graphiql", "/.env", "/backup", "/dump", "/export",
            "/login", "/signin", "/auth", "/oauth", "/token", "/user", "/account",
            "/register", "/signup", "/password", "/reset", "/mfa", "/2fa",
        ];

        let mut interesting = self.interesting_urls.lock().await;
        for pattern in &patterns {
            if url_lower.contains(pattern) && !interesting.iter().any(|u| u == url) {
                interesting.push(url.to_string());
                break;
            }
        }
    }

    async fn check_sensitive_url(&self, url: &str) {
        let url_lower = url.to_lowercase();
        let sensitive_params = ["api_key", "apikey", "key=", "secret", "password", "token=", "credential"];

        for param in &sensitive_params {
            if url_lower.contains(param) {
                println!("  [SENSITIVE] Secret in URL: {}", truncate(url, 50));
                self.security_findings.lock().await.push(SecurityFinding {
                    finding_type: "Secret in URL".to_string(),
                    details: format!("Parameter '{}' found", param),
                });
                break;
            }
        }
    }

    async fn check_security_headers(&self, headers: &HashMap<String, String>) {
        let mut missing = self.header_findings.lock().await;
        let headers_lower: HashMap<String, String> = headers.iter()
            .map(|(k, v)| (k.to_lowercase(), v.clone()))
            .collect();

        let required = [
            ("content-security-policy", "Content-Security-Policy"),
            ("strict-transport-security", "HSTS"),
            ("x-frame-options", "X-Frame-Options"),
            ("x-content-type-options", "X-Content-Type-Options"),
        ];

        for (header, name) in &required {
            if !headers_lower.contains_key(*header) {
                missing.push(name.to_string());
            }
        }
    }

    // ========================================================================
    // Export Generation
    // ========================================================================

    async fn generate_curl_commands(&self) -> Vec<String> {
        let requests = self.requests.lock().await;
        let mut commands = Vec::new();

        for (_, req) in requests.iter() {
            if is_static(&req.url) { continue; }

            let mut cmd = format!("curl -X {} '{}'", req.method, req.url);

            for (key, value) in &req.headers {
                let key_lower = key.to_lowercase();
                if key_lower == "host" || key_lower == "content-length" || key_lower == "connection" { continue; }
                cmd.push_str(&format!(" \\\n  -H '{}: {}'", key, value.replace('\'', "\\'")));
            }

            if let Some(body) = &req.body {
                cmd.push_str(&format!(" \\\n  -d '{}'", body.replace('\'', "\\'")));
            }

            commands.push(cmd);
        }
        commands
    }

    async fn generate_python_requests(&self) -> Vec<String> {
        let requests = self.requests.lock().await;
        let mut scripts = Vec::new();

        for (_, req) in requests.iter() {
            if is_static(&req.url) { continue; }

            let mut script = String::from("import requests\n\n");
            script.push_str("headers = {\n");
            for (key, value) in &req.headers {
                let key_lower = key.to_lowercase();
                if key_lower == "host" || key_lower == "content-length" { continue; }
                script.push_str(&format!("    '{}': '{}',\n", key, value.replace('\'', "\\'")));
            }
            script.push_str("}\n\n");

            let method_lower = req.method.to_lowercase();
            if let Some(body) = &req.body {
                script.push_str(&format!(
                    "response = requests.{}(\n    '{}',\n    headers=headers,\n    data={}\n)\n",
                    method_lower, req.url,
                    if body.starts_with('{') { format!("'''{}'''", body) } else { format!("'{}'", body) }
                ));
            } else {
                script.push_str(&format!("response = requests.{}('{}', headers=headers)\n", method_lower, req.url));
            }

            script.push_str("print(response.status_code)\nprint(response.text)\n");
            scripts.push(script);
        }
        scripts
    }

    async fn generate_raw_http(&self) -> Vec<String> {
        let requests = self.requests.lock().await;
        let mut raw_reqs = Vec::new();

        for (_, req) in requests.iter() {
            if is_static(&req.url) { continue; }

            let url_parsed = url::Url::parse(&req.url).ok();
            let path = url_parsed.as_ref().map(|u| {
                let p = u.path();
                if let Some(q) = u.query() { format!("{}?{}", p, q) } else { p.to_string() }
            }).unwrap_or("/".to_string());

            let host = url_parsed.as_ref().and_then(|u| u.host_str()).unwrap_or("unknown");

            let mut raw = format!("{} {} HTTP/1.1\r\n", req.method, path);
            raw.push_str(&format!("Host: {}\r\n", host));

            for (key, value) in &req.headers {
                if key.to_lowercase() == "host" { continue; }
                raw.push_str(&format!("{}: {}\r\n", key, value));
            }

            raw.push_str("\r\n");
            if let Some(body) = &req.body { raw.push_str(body); }

            raw_reqs.push(raw);
        }
        raw_reqs
    }

    // ========================================================================
    // Report Generation
    // ========================================================================

    async fn generate_report(&self, target: &str) -> ReconReport {
        let requests = self.requests.lock().await;
        let responses = self.responses.lock().await;
        let websockets = self.websockets.lock().await;

        let mut pairs = Vec::new();
        for (id, req) in requests.iter() {
            let resp = responses.get(id).cloned();
            pairs.push(RequestResponsePair { request: req.clone(), response: resp });
        }

        ReconReport {
            target: target.to_string(),
            scan_time: chrono::Utc::now().to_rfc3339(),
            total_requests: *self.request_count.lock().await,
            captured_requests: requests.values().cloned().collect(),
            captured_responses: responses.values().cloned().collect(),
            request_response_pairs: pairs,
            websocket_connections: websockets.values().cloned().collect(),
            login_forms: self.login_forms.lock().await.clone(),
            registration_forms: self.registration_forms.lock().await.clone(),
            auth_flows: self.auth_flows.lock().await.clone(),
            captured_tokens: self.captured_tokens.lock().await.clone(),
            api_endpoints: self.apis.lock().await.clone(),
            graphql_operations: self.graphql_ops.lock().await.clone(),
            auth_findings: self.auth_findings.lock().await.clone(),
            antibot_findings: self.antibot_findings.lock().await.clone(),
            security_findings: self.security_findings.lock().await.clone(),
            missing_headers: self.header_findings.lock().await.clone(),
            interesting_urls: self.interesting_urls.lock().await.clone(),
            curl_commands: self.generate_curl_commands().await,
            python_requests: self.generate_python_requests().await,
            raw_http: self.generate_raw_http().await,
        }
    }

    async fn add_login_form(&self, form: LoginForm) {
        println!("  [LOGIN-FORM] {} -> {}", form.url, form.action);
        if form.has_csrf { println!("    -> CSRF: {:?}", form.csrf_field); }
        self.login_forms.lock().await.push(form);
    }

    async fn add_registration_form(&self, form: RegistrationForm) {
        println!("  [REGISTER-FORM] {} -> {}", form.url, form.action);
        self.registration_forms.lock().await.push(form);
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn is_static(url: &str) -> bool {
    let exts = [".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map", ".webp"];
    let url_lower = url.to_lowercase();
    exts.iter().any(|ext| url_lower.contains(ext))
}

fn should_capture_body(mime_type: &str) -> bool {
    let mime_lower = mime_type.to_lowercase();
    mime_lower.contains("json") || mime_lower.contains("xml") || mime_lower.contains("text/html")
        || mime_lower.contains("text/plain") || mime_lower.contains("javascript")
        || mime_lower.contains("graphql")
}

fn is_jwt(token: &str) -> bool {
    token.split('.').count() == 3 && token.len() > 50
}

fn redact(value: &str) -> String {
    if value.len() <= 10 { "[REDACTED]".to_string() }
    else { format!("{}...{}", &value[..4], &value[value.len()-4..]) }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() } else { format!("{}...", &s[..max.saturating_sub(3)]) }
}

fn parse_cookies(cookie_header: Option<&String>) -> Vec<Cookie> {
    cookie_header.map(|h| {
        h.split(';')
            .filter_map(|c| {
                let mut parts = c.trim().splitn(2, '=');
                Some(Cookie {
                    name: parts.next()?.to_string(),
                    value: parts.next().unwrap_or("").to_string(),
                    domain: None, path: None, expires: None,
                    http_only: false, secure: false, same_site: None,
                })
            })
            .collect()
    }).unwrap_or_default()
}

fn parse_set_cookie(value: &str) -> Cookie {
    let parts: Vec<&str> = value.split(';').collect();
    let mut cookie = Cookie {
        name: String::new(), value: String::new(),
        domain: None, path: None, expires: None,
        http_only: false, secure: false, same_site: None,
    };

    if let Some(first) = parts.first() {
        let mut kv = first.splitn(2, '=');
        cookie.name = kv.next().unwrap_or("").trim().to_string();
        cookie.value = kv.next().unwrap_or("").trim().to_string();
    }

    for part in parts.iter().skip(1) {
        let part_lower = part.to_lowercase();
        let part_trimmed = part.trim();

        if part_lower.contains("httponly") {
            cookie.http_only = true;
        } else if part_lower.trim() == "secure" {
            cookie.secure = true;
        } else if part_lower.contains("domain=") {
            cookie.domain = Some(part_trimmed.split('=').nth(1).unwrap_or("").to_string());
        } else if part_lower.contains("path=") {
            cookie.path = Some(part_trimmed.split('=').nth(1).unwrap_or("").to_string());
        } else if part_lower.contains("expires=") {
            cookie.expires = Some(part_trimmed.split('=').nth(1).unwrap_or("").to_string());
        } else if part_lower.contains("samesite=") {
            cookie.same_site = Some(part_trimmed.split('=').nth(1).unwrap_or("").to_string());
        }
    }
    cookie
}

// ============================================================================
// JavaScript
// ============================================================================

const RECON_JS: &str = r#"
(function() {
    window.__recon = {
        analyzeForms: function() {
            return Array.from(document.forms).map(f => {
                const fields = Array.from(f.elements).filter(e => e.name || e.id).map(e => ({
                    name: e.name || '', type: e.type || 'text', id: e.id || null,
                    placeholder: e.placeholder || null, required: e.required || false,
                    pattern: e.pattern || null, autocomplete: e.autocomplete || null,
                    value: e.type === 'hidden' ? e.value : null
                }));
                const hasPassword = fields.some(f => f.type === 'password');
                const hasUsername = fields.some(f => f.name.toLowerCase().includes('user') || f.autocomplete === 'username');
                const hasEmail = fields.some(f => f.type === 'email' || f.name.toLowerCase().includes('email'));
                const csrfField = fields.find(f => f.name.toLowerCase().includes('csrf') || f.name.toLowerCase().includes('token') || f.name === '_token');
                return {
                    url: window.location.href, action: f.action || window.location.href,
                    method: (f.method || 'GET').toUpperCase(), fields: fields,
                    hasPassword, hasUsername, hasEmail, hasCsrf: !!csrfField,
                    csrfField: csrfField ? csrfField.name : null,
                    isLoginForm: hasPassword && (hasUsername || hasEmail) && fields.length < 10,
                    isRegisterForm: hasPassword && hasEmail && fields.length >= 3
                };
            });
        },
        findLoginForms: function() { return this.analyzeForms().filter(f => f.isLoginForm); },
        findRegisterForms: function() { return this.analyzeForms().filter(f => f.isRegisterForm); },
        detectAntibot: function() {
            const scripts = Array.from(document.querySelectorAll('script[src]'));
            const patterns = ['captcha', 'recaptcha', 'hcaptcha', 'turnstile', 'datadome', 'perimeterx', 'fingerprint'];
            return scripts.map(s => s.src).filter(src => patterns.some(p => src.toLowerCase().includes(p)));
        },
        getStorage: function() {
            const result = { localStorage: {}, sessionStorage: {} };
            try {
                for (let i = 0; i < localStorage.length; i++) {
                    const key = localStorage.key(i);
                    result.localStorage[key] = localStorage.getItem(key).substring(0, 100);
                }
                for (let i = 0; i < sessionStorage.length; i++) {
                    const key = sessionStorage.key(i);
                    result.sessionStorage[key] = sessionStorage.getItem(key).substring(0, 100);
                }
            } catch(e) {}
            return result;
        },
        findAuthPatterns: function() {
            const html = document.documentElement.innerHTML.toLowerCase();
            const patterns = [];
            if (html.includes('csrf') || html.includes('_token')) patterns.push('CSRF');
            if (html.includes('jwt')) patterns.push('JWT');
            if (html.includes('oauth')) patterns.push('OAuth');
            if (html.includes('2fa') || html.includes('mfa')) patterns.push('MFA');
            return patterns;
        }
    };
    console.log('[RECON] v3 loaded');
})();
"#;

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_max_level(tracing::Level::WARN).init();

    let args: Vec<String> = std::env::args().collect();
    let target = args.get(1).map(|s| s.as_str()).unwrap_or("https://example.com");
    let export_format = args.get(2).map(|s| s.as_str()).unwrap_or("all");

    println!("\n{}", "═".repeat(70));
    println!(" WEB RECON TOOL v3 - Bug Bounty Edition");
    println!(" Target: {}", target);
    println!("{}", "═".repeat(70));
    println!();

    let engine = Arc::new(ReconEngine::new());

    println!("[*] Launching browser...");
    let config = BrowserConfig::builder()
        .with_head()
        .no_sandbox()
        .arg("--disable-blink-features=AutomationControlled")
        .window_size(1920, 1080)
        .build()?;

    let (browser, mut handler) = Browser::launch(config).await?;
    let handle = tokio::spawn(async move { while handler.next().await.is_some() {} });

    let page = browser.new_page("about:blank").await?;
    page.enable_stealth_mode().await?;

    // Event listeners
    let mut req_events = page.event_listener::<EventRequestWillBeSent>().await?;
    let mut resp_events = page.event_listener::<EventResponseReceived>().await?;
    let mut ws_created = page.event_listener::<EventWebSocketCreated>().await?;
    let mut ws_sent = page.event_listener::<EventWebSocketFrameSent>().await?;
    let mut ws_recv = page.event_listener::<EventWebSocketFrameReceived>().await?;
    let mut ws_closed = page.event_listener::<EventWebSocketClosed>().await?;

    // Spawn handlers
    let engine_req = Arc::clone(&engine);
    let req_handle = tokio::spawn(async move {
        while let Some(event) = req_events.next().await {
            engine_req.capture_request(&event).await;
        }
    });

    let engine_resp = Arc::clone(&engine);
    let resp_handle = tokio::spawn(async move {
        while let Some(event) = resp_events.next().await {
            engine_resp.capture_response(&event).await;
        }
    });

    let engine_ws1 = Arc::clone(&engine);
    tokio::spawn(async move { while let Some(e) = ws_created.next().await { engine_ws1.handle_websocket_created(&e).await; } });

    let engine_ws2 = Arc::clone(&engine);
    tokio::spawn(async move { while let Some(e) = ws_sent.next().await { engine_ws2.handle_websocket_frame_sent(&e).await; } });

    let engine_ws3 = Arc::clone(&engine);
    tokio::spawn(async move { while let Some(e) = ws_recv.next().await { engine_ws3.handle_websocket_frame_received(&e).await; } });

    let engine_ws4 = Arc::clone(&engine);
    tokio::spawn(async move { while let Some(e) = ws_closed.next().await { engine_ws4.handle_websocket_closed(&e).await; } });

    // Inject JS
    page.evaluate_on_new_document(RECON_JS).await?;

    // Navigate
    println!("[*] Navigating to target...\n");
    page.goto(target).await?;
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    // Scroll
    println!("[*] Scrolling page...");
    page.evaluate("window.scrollTo(0, document.body.scrollHeight/2)").await?;
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    page.evaluate("window.scrollTo(0, document.body.scrollHeight)").await?;
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Fetch bodies
    println!("\n[*] Fetching request/response bodies...");
    engine.fetch_pending_bodies(&page).await;

    // Client analysis
    println!("\n[*] Client-side analysis...");
    let login_forms: Vec<serde_json::Value> = page.evaluate("window.__recon.findLoginForms()").await?.into_value().unwrap_or_default();
    for form_json in &login_forms {
        if let Ok(form) = serde_json::from_value::<LoginForm>(form_json.clone()) {
            engine.add_login_form(form).await;
        }
    }

    let reg_forms: Vec<serde_json::Value> = page.evaluate("window.__recon.findRegisterForms()").await?.into_value().unwrap_or_default();
    for form_json in &reg_forms {
        if let Ok(form) = serde_json::from_value::<RegistrationForm>(form_json.clone()) {
            engine.add_registration_form(form).await;
        }
    }

    let antibot: Vec<String> = page.evaluate("window.__recon.detectAntibot()").await?.into_value().unwrap_or_default();
    if !antibot.is_empty() {
        println!("  [ANTIBOT] Client scripts: {:?}", antibot);
    }

    let storage: serde_json::Value = page.evaluate("window.__recon.getStorage()").await?.into_value().unwrap_or_default();
    println!("  [STORAGE] localStorage: {:?}", storage.get("localStorage").and_then(|v| v.as_object()).map(|o| o.keys().collect::<Vec<_>>()));

    // Report
    println!("\n{}", "═".repeat(70));
    println!(" RECON REPORT");
    println!("{}", "═".repeat(70));

    let report = engine.generate_report(target).await;

    println!("\nTotal Requests: {}", report.total_requests);
    println!("API Endpoints: {}", report.api_endpoints.len());
    println!("WebSocket Connections: {}", report.websocket_connections.len());
    println!("Tokens Captured: {}", report.captured_tokens.len());
    println!("Auth Flows: {}", report.auth_flows.len());
    println!("Requests with Bodies: {}", report.captured_requests.iter().filter(|r| r.body.is_some()).count());
    println!("Responses with Bodies: {}", report.captured_responses.iter().filter(|r| r.body.is_some()).count());

    println!("\n--- API Endpoints ({}) ---", report.api_endpoints.len());
    for api in &report.api_endpoints { println!("  {} {} {}", api.method, api.api_type, truncate(&api.url, 50)); }

    println!("\n--- WebSocket ({}) ---", report.websocket_connections.len());
    for ws in &report.websocket_connections { println!("  {} - {} messages", truncate(&ws.url, 40), ws.messages.len()); }

    println!("\n--- Captured Tokens ({}) ---", report.captured_tokens.len());
    for token in &report.captured_tokens { println!("  [{}] {} @ {}", token.token_type, token.name, token.location); }

    println!("\n--- Auth Flows ({}) ---", report.auth_flows.len());
    for flow in &report.auth_flows { println!("  {} - {} steps", flow.flow_type, flow.steps.len()); }

    println!("\n--- Security ({}) ---", report.security_findings.len());
    for f in &report.security_findings { println!("  [!] {}", f.finding_type); }

    println!("\n--- Missing Headers ---");
    for h in &report.missing_headers { println!("  [!] {}", h); }

    // Save
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let json_file = format!("recon_{}.json", timestamp);
    std::fs::write(&json_file, serde_json::to_string_pretty(&report)?)?;
    println!("\n[*] Report: {}", json_file);

    if export_format == "curl" || export_format == "all" {
        let curl_file = format!("recon_{}_curl.sh", timestamp);
        std::fs::write(&curl_file, format!("#!/bin/bash\n\n{}", report.curl_commands.join("\n\n")))?;
        println!("[*] Curl: {}", curl_file);
    }

    if export_format == "python" || export_format == "all" {
        let py_file = format!("recon_{}_requests.py", timestamp);
        std::fs::write(&py_file, report.python_requests.join("\n\n"))?;
        println!("[*] Python: {}", py_file);
    }

    if export_format == "raw" || export_format == "all" {
        let raw_file = format!("recon_{}_raw.txt", timestamp);
        std::fs::write(&raw_file, report.raw_http.join("\n\n---\n\n"))?;
        println!("[*] Raw HTTP: {}", raw_file);
    }

    println!("\n{}", "═".repeat(70));
    println!(" Complete - {} requests, {} with bodies", report.total_requests,
        report.captured_requests.iter().filter(|r| r.body.is_some()).count());
    println!("{}", "═".repeat(70));

    drop(req_handle);
    drop(resp_handle);
    drop(handle);

    Ok(())
}
