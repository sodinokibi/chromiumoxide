//! # Web Recon Tool - Bug Bounty Edition v2
//!
//! Advanced security research tool for capturing traffic and generating raw requests.
//! Features: API discovery, auth detection, login flow testing, multi-format export.
//!
//! ## Usage
//! ```bash
//! cargo run --example recon -- https://target.com [--export curl|python|raw|all]
//! ```

use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::cdp::browser_protocol::network::{
    EventRequestWillBeSent, EventResponseReceived,
};
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
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: Option<String>,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestResponsePair {
    pub request: RawRequest,
    pub response: Option<RawResponse>,
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
    pub flow_type: String, // login, register, oauth, mfa
    pub steps: Vec<AuthFlowStep>,
    pub tokens_captured: Vec<CapturedToken>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthFlowStep {
    pub step_number: usize,
    pub url: String,
    pub action: String,
    pub tokens_received: Vec<String>,
    pub tokens_sent: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedToken {
    pub token_type: String, // csrf, session, jwt, oauth
    pub name: String,
    pub value_preview: String,
    pub location: String, // header, cookie, body, url
    pub first_seen_url: String,
}

// ============================================================================
// API and Security Structures
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiEndpoint {
    url: String,
    method: String,
    api_type: String,
    has_auth: bool,
    request_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthFinding {
    auth_type: String,
    location: String,
    key_name: String,
    sample: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiBotFinding {
    service: String,
    indicator: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    finding_type: String,
    details: String,
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
    pub operation_type: String, // query, mutation, subscription
    pub operation_name: Option<String>,
    pub variables: Option<serde_json::Value>,
    pub request_id: String,
}

// ============================================================================
// Recon Engine
// ============================================================================

struct ReconEngine {
    // Raw capture
    requests: Mutex<HashMap<String, RawRequest>>,
    responses: Mutex<Vec<RawResponse>>,

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
            responses: Mutex::new(Vec::new()),
            seen_urls: Mutex::new(HashSet::new()),
            apis: Mutex::new(Vec::new()),
            graphql_ops: Mutex::new(Vec::new()),
            auth_findings: Mutex::new(Vec::new()),
            captured_tokens: Mutex::new(Vec::new()),
            login_forms: Mutex::new(Vec::new()),
            registration_forms: Mutex::new(Vec::new()),
            antibot_findings: Mutex::new(Vec::new()),
            security_findings: Mutex::new(Vec::new()),
            interesting_urls: Mutex::new(Vec::new()),
            request_count: Mutex::new(0),
            checked_headers: Mutex::new(false),
            header_findings: Mutex::new(Vec::new()),
        }
    }

    // ========================================================================
    // Request Capture & Analysis
    // ========================================================================

    async fn capture_request(&self, event: &EventRequestWillBeSent) {
        *self.request_count.lock().await += 1;

        let url = &event.request.url;
        let method = &event.request.method;
        let request_id = event.request_id.inner().to_string();

        // Parse headers
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

        // Parse cookies from header
        let cookies = parse_cookies(headers.get("Cookie").or(headers.get("cookie")));

        // Get content type
        let content_type = headers.get("Content-Type")
            .or(headers.get("content-type"))
            .cloned();

        // Get body if available (from has_post_data flag - actual body needs Network.getRequestPostData)
        let has_body = event.request.has_post_data.unwrap_or(false);

        // Create raw request
        let raw_request = RawRequest {
            id: request_id.clone(),
            url: url.clone(),
            method: method.clone(),
            headers: headers.clone(),
            cookies,
            body: if has_body { Some("[POST_DATA]".to_string()) } else { None },
            content_type: content_type.clone(),
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            initiator: event.initiator.url.clone(),
            resource_type: event.r#type.as_ref().map(|t| format!("{:?}", t)).unwrap_or_default(),
        };

        // Store request
        self.requests.lock().await.insert(request_id.clone(), raw_request);

        // Skip static for analysis (but keep in raw capture)
        if is_static(url) {
            return;
        }

        // Analyze for APIs
        self.detect_api(url, method, &headers, Some(&request_id)).await;

        // Check for GraphQL
        self.detect_graphql(url, &headers, event.request.has_post_data.unwrap_or(false), &request_id).await;

        // Detect auth tokens
        self.capture_auth_tokens(url, &headers, "request").await;

        // Check interesting
        self.check_interesting(url).await;

        // Anti-bot in URL
        self.detect_antibot_url(url).await;

        // Sensitive data
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

        // Create raw response
        let raw_response = RawResponse {
            request_id: request_id.clone(),
            url: url.clone(),
            status,
            status_text: event.response.status_text.clone(),
            headers: headers.clone(),
            mime_type: event.response.mime_type.clone(),
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };

        self.responses.lock().await.push(raw_response);

        // Security headers check
        if !*self.checked_headers.lock().await {
            self.check_security_headers(&headers).await;
            *self.checked_headers.lock().await = true;
        }

        // Capture tokens from response
        self.capture_auth_tokens(url, &headers, "response").await;

        // Capture Set-Cookie tokens
        self.capture_set_cookie_tokens(url, &headers).await;

        // Anti-bot detection
        self.detect_antibot_response(&headers).await;

        // Status code analysis
        if status == 401 || status == 403 {
            println!("  [AUTH-REQUIRED] {} {} {}", status, event.response.status_text, truncate(url, 60));
        } else if status >= 500 {
            println!("  [SERVER-ERROR] {} {} - Potential info leak", status, truncate(url, 60));
            self.security_findings.lock().await.push(SecurityFinding {
                finding_type: "Server Error".to_string(),
                details: format!("{} at {}", status, truncate(url, 100)),
            });
        }

        // CORS check
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
    // Token Capture
    // ========================================================================

    async fn capture_auth_tokens(&self, url: &str, headers: &HashMap<String, String>, context: &str) {
        let mut tokens = self.captured_tokens.lock().await;
        let mut findings = self.auth_findings.lock().await;

        // Authorization header
        if let Some(auth) = headers.get("Authorization").or(headers.get("authorization")) {
            let (token_type, auth_type_str) = if auth.starts_with("Bearer ") {
                let token = &auth[7..];
                if is_jwt(token) {
                    ("jwt", "JWT")
                } else {
                    ("bearer", "Bearer Token")
                }
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
                    location: "header".to_string(),
                    first_seen_url: url.to_string(),
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
            "X-Client-ID", "x-client-id", "X-Client-Secret", "x-client-secret",
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
                        location: "header".to_string(),
                        first_seen_url: url.to_string(),
                    });

                    if !findings.iter().any(|f| f.key_name.to_lowercase() == key_lower) {
                        findings.push(AuthFinding {
                            auth_type: "API Key".to_string(),
                            location: "header".to_string(),
                            key_name: key.to_string(),
                            sample: redact(value),
                        });
                    }
                }
            }
        }

        // CSRF tokens
        let csrf_headers = ["X-CSRF-Token", "x-csrf-token", "X-XSRF-Token", "x-xsrf-token"];
        for key in &csrf_headers {
            if let Some(value) = headers.get(*key) {
                if !tokens.iter().any(|t| t.token_type == "csrf") {
                    println!("  [TOKEN] CSRF token captured");
                    tokens.push(CapturedToken {
                        token_type: "csrf".to_string(),
                        name: key.to_string(),
                        value_preview: redact(value),
                        location: "header".to_string(),
                        first_seen_url: url.to_string(),
                    });

                    if !findings.iter().any(|f| f.auth_type == "CSRF Token") {
                        findings.push(AuthFinding {
                            auth_type: "CSRF Token".to_string(),
                            location: "header".to_string(),
                            key_name: key.to_string(),
                            sample: "[PRESENT]".to_string(),
                        });
                    }
                }
            }
        }
    }

    async fn capture_set_cookie_tokens(&self, url: &str, headers: &HashMap<String, String>) {
        let mut tokens = self.captured_tokens.lock().await;
        let mut findings = self.auth_findings.lock().await;

        // Check Set-Cookie headers
        for (key, value) in headers.iter() {
            if key.to_lowercase() == "set-cookie" {
                let cookie_name = value.split('=').next().unwrap_or("").trim();
                let session_patterns = ["session", "sess", "sid", "token", "auth", "jwt", "csrf", "xsrf"];

                for pattern in &session_patterns {
                    if cookie_name.to_lowercase().contains(pattern) {
                        if !tokens.iter().any(|t| t.name.to_lowercase() == cookie_name.to_lowercase()) {
                            let token_type = if cookie_name.to_lowercase().contains("csrf") || cookie_name.to_lowercase().contains("xsrf") {
                                "csrf"
                            } else if cookie_name.to_lowercase().contains("jwt") {
                                "jwt"
                            } else {
                                "session"
                            };

                            println!("  [TOKEN] Cookie set: {} ({})", cookie_name, token_type);
                            tokens.push(CapturedToken {
                                token_type: token_type.to_string(),
                                name: cookie_name.to_string(),
                                value_preview: "[SET-COOKIE]".to_string(),
                                location: "cookie".to_string(),
                                first_seen_url: url.to_string(),
                            });

                            if !findings.iter().any(|f| f.key_name.to_lowercase() == cookie_name.to_lowercase()) {
                                findings.push(AuthFinding {
                                    auth_type: "Session Cookie".to_string(),
                                    location: "cookie".to_string(),
                                    key_name: cookie_name.to_string(),
                                    sample: "[SET-COOKIE]".to_string(),
                                });
                            }
                        }
                        break;
                    }
                }
            }
        }
    }

    // ========================================================================
    // API Detection
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

            // Internal API check
            let internal_patterns = ["/internal", "/private", "/admin", "/_", "/debug", "/config", "/hidden"];
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
            // We'd need to get the actual body to parse the operation
            // For now, just record that we found a GraphQL endpoint
            self.graphql_ops.lock().await.push(GraphQLOperation {
                url: url.to_string(),
                operation_type: "unknown".to_string(),
                operation_name: None,
                variables: None,
                request_id: request_id.to_string(),
            });
        }
    }

    // ========================================================================
    // Existing Detection Methods
    // ========================================================================

    async fn detect_antibot_url(&self, url: &str) {
        let url_lower = url.to_lowercase();
        let mut findings = self.antibot_findings.lock().await;

        let checks = [
            ("recaptcha", "Google reCAPTCHA"),
            ("hcaptcha", "hCaptcha"),
            ("turnstile", "Cloudflare Turnstile"),
            ("datadome", "DataDome"),
            ("perimeterx", "PerimeterX"),
            ("px-cdn", "PerimeterX CDN"),
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

        // Cloudflare
        let has_cf = headers.contains_key("CF-Ray") || headers.contains_key("cf-ray")
            || headers.get("Server").or(headers.get("server")).map(|s| s.to_lowercase().contains("cloudflare")).unwrap_or(false);

        if has_cf && !findings.iter().any(|f| f.service == "Cloudflare") {
            println!("  [ANTIBOT] Cloudflare detected");
            findings.push(AntiBotFinding {
                service: "Cloudflare".to_string(),
                indicator: "CF-Ray/Server header".to_string(),
            });
        }

        // Akamai
        if headers.contains_key("X-Akamai-Transformed") || headers.contains_key("x-akamai-transformed") {
            if !findings.iter().any(|f| f.service == "Akamai") {
                println!("  [ANTIBOT] Akamai detected");
                findings.push(AntiBotFinding {
                    service: "Akamai".to_string(),
                    indicator: "Akamai headers".to_string(),
                });
            }
        }

        // DataDome
        if headers.contains_key("X-DataDome") || headers.contains_key("x-datadome") {
            if !findings.iter().any(|f| f.service == "DataDome") {
                println!("  [ANTIBOT] DataDome detected");
                findings.push(AntiBotFinding {
                    service: "DataDome".to_string(),
                    indicator: "X-DataDome header".to_string(),
                });
            }
        }
    }

    async fn check_interesting(&self, url: &str) {
        let url_lower = url.to_lowercase();
        let patterns = [
            "/admin", "/api/internal", "/api/private", "/debug", "/config",
            "/swagger", "/openapi", "/graphql", "/graphiql", "/.env",
            "/backup", "/dump", "/export", "/download", "/upload",
            "/login", "/signin", "/auth", "/oauth", "/token",
            "/user", "/account", "/profile", "/settings", "/register",
            "/signup", "/password", "/reset", "/forgot", "/mfa", "/2fa",
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
        let sensitive_params = ["api_key", "apikey", "key=", "secret", "password", "token=", "auth=", "credential"];

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
            ("referrer-policy", "Referrer-Policy"),
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
            if is_static(&req.url) {
                continue;
            }

            let mut cmd = format!("curl -X {} '{}'", req.method, req.url);

            for (key, value) in &req.headers {
                // Skip some headers that curl handles
                let key_lower = key.to_lowercase();
                if key_lower == "host" || key_lower == "content-length" || key_lower == "connection" {
                    continue;
                }
                cmd.push_str(&format!(" \\\n  -H '{}: {}'", key, value.replace("'", "\\'")));
            }

            if let Some(body) = &req.body {
                if body != "[POST_DATA]" {
                    cmd.push_str(&format!(" \\\n  -d '{}'", body.replace("'", "\\'")));
                } else {
                    cmd.push_str(" \\\n  -d '[REQUEST_BODY]'");
                }
            }

            commands.push(cmd);
        }

        commands
    }

    async fn generate_python_requests(&self) -> Vec<String> {
        let requests = self.requests.lock().await;
        let mut scripts = Vec::new();

        for (_, req) in requests.iter() {
            if is_static(&req.url) {
                continue;
            }

            let mut script = String::from("import requests\n\n");

            // Headers
            script.push_str("headers = {\n");
            for (key, value) in &req.headers {
                let key_lower = key.to_lowercase();
                if key_lower == "host" || key_lower == "content-length" {
                    continue;
                }
                script.push_str(&format!("    '{}': '{}',\n", key, value.replace("'", "\\'")));
            }
            script.push_str("}\n\n");

            // Request
            let method_lower = req.method.to_lowercase();
            if req.body.is_some() {
                script.push_str(&format!(
                    "response = requests.{}(\n    '{}',\n    headers=headers,\n    data='[REQUEST_BODY]'\n)\n",
                    method_lower, req.url
                ));
            } else {
                script.push_str(&format!(
                    "response = requests.{}('{}', headers=headers)\n",
                    method_lower, req.url
                ));
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
            if is_static(&req.url) {
                continue;
            }

            let url_parsed = url::Url::parse(&req.url).ok();
            let path = url_parsed.as_ref().map(|u| {
                let p = u.path();
                if let Some(q) = u.query() {
                    format!("{}?{}", p, q)
                } else {
                    p.to_string()
                }
            }).unwrap_or("/".to_string());

            let host = url_parsed.as_ref().and_then(|u| u.host_str()).unwrap_or("unknown");

            let mut raw = format!("{} {} HTTP/1.1\r\n", req.method, path);
            raw.push_str(&format!("Host: {}\r\n", host));

            for (key, value) in &req.headers {
                let key_lower = key.to_lowercase();
                if key_lower == "host" {
                    continue;
                }
                raw.push_str(&format!("{}: {}\r\n", key, value));
            }

            raw.push_str("\r\n");

            if let Some(body) = &req.body {
                raw.push_str(body);
            }

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

        // Build request-response pairs
        let mut pairs = Vec::new();
        for (id, req) in requests.iter() {
            let resp = responses.iter().find(|r| r.request_id == *id).cloned();
            pairs.push(RequestResponsePair {
                request: req.clone(),
                response: resp,
            });
        }

        ReconReport {
            target: target.to_string(),
            scan_time: chrono::Utc::now().to_rfc3339(),
            total_requests: *self.request_count.lock().await,
            captured_requests: requests.values().cloned().collect(),
            captured_responses: responses.clone(),
            request_response_pairs: pairs,
            login_forms: self.login_forms.lock().await.clone(),
            registration_forms: self.registration_forms.lock().await.clone(),
            auth_flows: Vec::new(), // TODO: implement flow tracking
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

    // ========================================================================
    // Login Form Analysis (called from JS)
    // ========================================================================

    async fn add_login_form(&self, form: LoginForm) {
        println!("  [LOGIN-FORM] Found: {} -> {}", form.url, form.action);
        if form.has_csrf {
            println!("    -> CSRF field: {:?}", form.csrf_field);
        }
        println!("    -> Fields: {:?}", form.fields.iter().map(|f| &f.name).collect::<Vec<_>>());
        self.login_forms.lock().await.push(form);
    }

    async fn add_registration_form(&self, form: RegistrationForm) {
        println!("  [REGISTER-FORM] Found: {} -> {}", form.url, form.action);
        println!("    -> Fields: {:?}", form.fields.iter().map(|f| &f.name).collect::<Vec<_>>());
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

fn is_jwt(token: &str) -> bool {
    token.split('.').count() == 3 && token.len() > 50
}

fn redact(value: &str) -> String {
    if value.len() <= 10 {
        "[REDACTED]".to_string()
    } else {
        format!("{}...{}", &value[..4], &value[value.len()-4..])
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() } else { format!("{}...", &s[..max-3]) }
}

fn parse_cookies(cookie_header: Option<&String>) -> Vec<Cookie> {
    cookie_header.map(|h| {
        h.split(';')
            .filter_map(|c| {
                let mut parts = c.trim().splitn(2, '=');
                Some(Cookie {
                    name: parts.next()?.to_string(),
                    value: parts.next().unwrap_or("").to_string(),
                    domain: None,
                    path: None,
                })
            })
            .collect()
    }).unwrap_or_default()
}

// ============================================================================
// Enhanced JavaScript for Form Discovery
// ============================================================================

const RECON_JS: &str = r#"
(function() {
    window.__recon = {
        // Detect all forms with detailed field analysis
        analyzeForms: function() {
            return Array.from(document.forms).map(f => {
                const fields = Array.from(f.elements).filter(e => e.name || e.id).map(e => ({
                    name: e.name || '',
                    type: e.type || 'text',
                    id: e.id || null,
                    placeholder: e.placeholder || null,
                    required: e.required || false,
                    pattern: e.pattern || null,
                    autocomplete: e.autocomplete || null,
                    value: e.type === 'hidden' ? e.value : null
                }));

                const hasPassword = fields.some(f => f.type === 'password');
                const hasUsername = fields.some(f =>
                    f.name.toLowerCase().includes('user') ||
                    f.name.toLowerCase().includes('login') ||
                    f.autocomplete === 'username'
                );
                const hasEmail = fields.some(f =>
                    f.type === 'email' ||
                    f.name.toLowerCase().includes('email') ||
                    f.autocomplete === 'email'
                );
                const csrfField = fields.find(f =>
                    f.name.toLowerCase().includes('csrf') ||
                    f.name.toLowerCase().includes('token') ||
                    f.name === '_token'
                );

                return {
                    url: window.location.href,
                    action: f.action || window.location.href,
                    method: (f.method || 'GET').toUpperCase(),
                    fields: fields,
                    hasPassword: hasPassword,
                    hasUsername: hasUsername,
                    hasEmail: hasEmail,
                    hasCsrf: !!csrfField,
                    csrfField: csrfField ? csrfField.name : null,
                    csrfValue: csrfField ? csrfField.value : null,
                    isLoginForm: hasPassword && (hasUsername || hasEmail) && fields.length < 10,
                    isRegisterForm: hasPassword && hasEmail && fields.length >= 3
                };
            });
        },

        // Find login forms specifically
        findLoginForms: function() {
            return this.analyzeForms().filter(f => f.isLoginForm);
        },

        // Find registration forms
        findRegisterForms: function() {
            return this.analyzeForms().filter(f => f.isRegisterForm);
        },

        // Detect antibot scripts
        detectAntibot: function() {
            const scripts = Array.from(document.querySelectorAll('script[src]'));
            const patterns = ['captcha', 'recaptcha', 'hcaptcha', 'turnstile', 'datadome', 'perimeterx', 'kasada', 'fingerprint', 'botd'];
            return scripts.map(s => s.src).filter(src => patterns.some(p => src.toLowerCase().includes(p)));
        },

        // Get all storage
        getStorage: function() {
            const result = { localStorage: {}, sessionStorage: {} };
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                result.localStorage[key] = localStorage.getItem(key).substring(0, 100);
            }
            for (let i = 0; i < sessionStorage.length; i++) {
                const key = sessionStorage.key(i);
                result.sessionStorage[key] = sessionStorage.getItem(key).substring(0, 100);
            }
            return result;
        },

        // Find auth patterns in page
        findAuthPatterns: function() {
            const html = document.documentElement.innerHTML.toLowerCase();
            const patterns = [];
            if (html.includes('csrf') || html.includes('_token')) patterns.push('CSRF token');
            if (html.includes('jwt')) patterns.push('JWT reference');
            if (html.includes('oauth')) patterns.push('OAuth');
            if (html.includes('bearer')) patterns.push('Bearer token');
            if (html.includes('two-factor') || html.includes('2fa') || html.includes('mfa')) patterns.push('MFA/2FA');
            if (html.includes('password') && html.includes('confirm')) patterns.push('Password confirmation');
            return patterns;
        },

        // Intercept form submissions
        interceptForms: function() {
            document.querySelectorAll('form').forEach(form => {
                form.addEventListener('submit', function(e) {
                    const data = new FormData(form);
                    const params = {};
                    for (let [key, value] of data.entries()) {
                        params[key] = value;
                    }
                    console.log('[RECON-FORM-SUBMIT]', form.action, params);
                });
            });
        }
    };

    // Auto-intercept
    window.__recon.interceptForms();
    console.log('[RECON] Enhanced instrumentation loaded');
})();
"#;

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .init();

    let args: Vec<String> = std::env::args().collect();
    let target = args.get(1).map(|s| s.as_str()).unwrap_or("https://example.com");
    let export_format = args.get(2).map(|s| s.as_str()).unwrap_or("all");

    println!();
    println!("{}", "═".repeat(70));
    println!(" WEB RECON TOOL v2 - Bug Bounty Edition");
    println!(" Target: {}", target);
    println!(" Export: {}", export_format);
    println!("{}", "═".repeat(70));
    println!();

    let engine = Arc::new(ReconEngine::new());
    let engine_req = Arc::clone(&engine);
    let engine_resp = Arc::clone(&engine);

    // Launch browser
    println!("[*] Launching browser with stealth mode...");
    let config = BrowserConfig::builder()
        .with_head()
        .no_sandbox()
        .arg("--disable-blink-features=AutomationControlled")
        .window_size(1920, 1080)
        .build()?;

    let (browser, mut handler) = Browser::launch(config).await?;
    let handle = tokio::spawn(async move { while let Some(_) = handler.next().await {} });

    let page = browser.new_page("about:blank").await?;
    page.enable_stealth_mode().await?;

    // Event listeners
    let mut req_events = page.event_listener::<EventRequestWillBeSent>().await?;
    let mut resp_events = page.event_listener::<EventResponseReceived>().await?;

    let req_handle = tokio::spawn(async move {
        while let Some(event) = req_events.next().await {
            engine_req.capture_request(&event).await;
        }
    });

    let resp_handle = tokio::spawn(async move {
        while let Some(event) = resp_events.next().await {
            engine_resp.capture_response(&event).await;
        }
    });

    // Inject JS
    page.evaluate_on_new_document(RECON_JS).await?;

    // Navigate
    println!("[*] Navigating to target...\n");
    page.goto(target).await?;
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    // Scroll
    println!("[*] Triggering lazy-loaded content...");
    page.evaluate("window.scrollTo(0, document.body.scrollHeight/2)").await?;
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    page.evaluate("window.scrollTo(0, document.body.scrollHeight)").await?;
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Client-side analysis
    println!("\n[*] Analyzing forms and auth patterns...");

    // Login forms
    let login_forms: Vec<serde_json::Value> = page.evaluate("window.__recon.findLoginForms()").await?.into_value().unwrap_or_default();
    for form_json in &login_forms {
        if let Ok(form) = serde_json::from_value::<LoginForm>(form_json.clone()) {
            engine.add_login_form(form).await;
        }
    }

    // Registration forms
    let reg_forms: Vec<serde_json::Value> = page.evaluate("window.__recon.findRegisterForms()").await?.into_value().unwrap_or_default();
    for form_json in &reg_forms {
        if let Ok(form) = serde_json::from_value::<RegistrationForm>(form_json.clone()) {
            engine.add_registration_form(form).await;
        }
    }

    // Antibot scripts
    let antibot: Vec<String> = page.evaluate("window.__recon.detectAntibot()").await?.into_value().unwrap_or_default();
    if !antibot.is_empty() {
        println!("  [ANTIBOT] Client scripts:");
        for s in &antibot { println!("    - {}", truncate(s, 60)); }
    }

    // Storage
    let storage: serde_json::Value = page.evaluate("window.__recon.getStorage()").await?.into_value().unwrap_or_default();
    println!("  [STORAGE] localStorage: {:?}", storage.get("localStorage").and_then(|v| v.as_object()).map(|o| o.keys().collect::<Vec<_>>()));
    println!("  [STORAGE] sessionStorage: {:?}", storage.get("sessionStorage").and_then(|v| v.as_object()).map(|o| o.keys().collect::<Vec<_>>()));

    // Auth patterns
    let auth_patterns: Vec<String> = page.evaluate("window.__recon.findAuthPatterns()").await?.into_value().unwrap_or_default();
    if !auth_patterns.is_empty() {
        println!("  [AUTH-PATTERNS] Found: {:?}", auth_patterns);
    }

    // Generate report
    println!("\n{}", "═".repeat(70));
    println!(" RECON REPORT");
    println!("{}", "═".repeat(70));

    let report = engine.generate_report(target).await;

    println!("\nTotal Requests: {}", report.total_requests);
    println!("API Endpoints: {}", report.api_endpoints.len());
    println!("Tokens Captured: {}", report.captured_tokens.len());
    println!("Login Forms: {}", report.login_forms.len());
    println!("Registration Forms: {}", report.registration_forms.len());

    // Print APIs
    println!("\n--- API Endpoints ({}) ---", report.api_endpoints.len());
    for api in &report.api_endpoints {
        println!("  {} {} {}", api.method, api.api_type, truncate(&api.url, 60));
    }

    // Print tokens
    println!("\n--- Captured Tokens ({}) ---", report.captured_tokens.len());
    for token in &report.captured_tokens {
        println!("  [{}] {} @ {} = {}", token.token_type, token.name, token.location, token.value_preview);
    }

    // Print login forms
    println!("\n--- Login Forms ({}) ---", report.login_forms.len());
    for form in &report.login_forms {
        println!("  {} -> {}", form.url, form.action);
        println!("    CSRF: {} | Fields: {:?}", form.has_csrf, form.fields.iter().map(|f| &f.name).collect::<Vec<_>>());
    }

    // Security
    println!("\n--- Security Issues ({}) ---", report.security_findings.len());
    for f in &report.security_findings { println!("  [!] {} - {}", f.finding_type, f.details); }

    println!("\n--- Missing Headers ---");
    for h in &report.missing_headers { println!("  [!] {}", h); }

    // Save report
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");

    // Main JSON report
    let report_json = serde_json::to_string_pretty(&report)?;
    let json_file = format!("recon_{}.json", timestamp);
    std::fs::write(&json_file, &report_json)?;
    println!("\n[*] Report saved: {}", json_file);

    // Export curl commands
    if export_format == "curl" || export_format == "all" {
        let curl_file = format!("recon_{}_curl.sh", timestamp);
        let curl_content = report.curl_commands.join("\n\n# ---\n\n");
        std::fs::write(&curl_file, format!("#!/bin/bash\n# Generated by recon.rs\n\n{}", curl_content))?;
        println!("[*] Curl commands: {}", curl_file);
    }

    // Export Python
    if export_format == "python" || export_format == "all" {
        let py_file = format!("recon_{}_requests.py", timestamp);
        let py_content = report.python_requests.join("\n# ---\n\n");
        std::fs::write(&py_file, format!("# Generated by recon.rs\n\n{}", py_content))?;
        println!("[*] Python requests: {}", py_file);
    }

    // Export raw HTTP
    if export_format == "raw" || export_format == "all" {
        let raw_file = format!("recon_{}_raw.txt", timestamp);
        let raw_content = report.raw_http.join("\n\n---\n\n");
        std::fs::write(&raw_file, &raw_content)?;
        println!("[*] Raw HTTP: {}", raw_file);
    }

    println!("\n{}", "═".repeat(70));
    println!(" Scan Complete - {} requests captured", report.total_requests);
    println!("{}", "═".repeat(70));

    drop(req_handle);
    drop(resp_handle);
    drop(handle);

    Ok(())
}
