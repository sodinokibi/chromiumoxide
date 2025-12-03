//! # Web Recon Tool - Bug Bounty Edition v5
//!
//! Advanced security research tool with request interception, cookie dumping,
//! XHR replay, secret scanning, and automatic security issue detection.
//!
//! ## TIER 1 Features:
//! - Request interception via Fetch domain (modify/block requests)
//! - Full cookie jar dump via Network.getCookies
//! - XHR replay via Network.replayXHR
//! - Secret scanning via Network.searchInResponseBody
//! - Auto security issues via Audits.issueAdded
//!
//! ## TIER 2 Features:
//! - Raw cookies via Network.requestWillBeSentExtraInfo
//! - Blocked cookies/HSTS via Network.responseReceivedExtraInfo
//! - SSE streams via Network.eventSourceMessageReceived
//! - Direct storage dump via DOMStorage.getDOMStorageItems
//! - SSL/TLS state via Security.visibleSecurityStateChanged
//!
//! ## TIER 3 Features (NEW):
//! - IndexedDB enumeration via IndexedDB.requestDatabaseNames/requestData
//! - CacheStorage inspection via CacheStorage.requestCacheNames/requestEntries
//! - Console log capture via Runtime.consoleAPICalled
//! - WebTransport session tracking via Network.webTransport* events
//!
//! ## Usage
//! ```bash
//! cargo run --example recon -- https://target.com [--intercept] [--export curl|python|raw|all]
//! ```

use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::cdp::browser_protocol::network::{
    EventRequestWillBeSent, EventResponseReceived,
    EventWebSocketCreated, EventWebSocketFrameSent, EventWebSocketFrameReceived,
    EventWebSocketClosed, GetRequestPostDataParams, GetResponseBodyParams,
    GetCookiesParams, ReplayXhrParams, SearchInResponseBodyParams,
    RequestId,
    // TIER 2
    EventRequestWillBeSentExtraInfo, EventResponseReceivedExtraInfo,
    EventEventSourceMessageReceived,
    // TIER 3: WebTransport
    EventWebTransportCreated, EventWebTransportConnectionEstablished, EventWebTransportClosed,
};
use chromiumoxide::cdp::browser_protocol::fetch::{
    EnableParams as FetchEnableParams, EventRequestPaused,
    ContinueRequestParams, FailRequestParams, RequestPattern,
};
use chromiumoxide::cdp::browser_protocol::audits::{
    EnableParams as AuditsEnableParams, EventIssueAdded,
};
// TIER 2: DOMStorage and Security
use chromiumoxide::cdp::browser_protocol::dom_storage::{
    EnableParams as DomStorageEnableParams,
    GetDomStorageItemsParams, StorageId,
    EventDomStorageItemAdded, EventDomStorageItemUpdated,
};
use chromiumoxide::cdp::browser_protocol::security::{
    EnableParams as SecurityEnableParams,
    EventVisibleSecurityStateChanged,
};
// TIER 3: IndexedDB, CacheStorage, Console/Log
use chromiumoxide::cdp::browser_protocol::indexed_db::{
    EnableParams as IndexedDbEnableParams,
    RequestDatabaseNamesParams, RequestDatabaseParams, RequestDataParams,
};
use chromiumoxide::cdp::browser_protocol::cache_storage::{
    RequestCacheNamesParams, RequestEntriesParams,
};
use chromiumoxide::cdp::browser_protocol::log::{
    EnableParams as LogEnableParams, EventEntryAdded,
};
use chromiumoxide::cdp::js_protocol::runtime::{
    EnableParams as RuntimeEnableParams, EventConsoleApiCalled,
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
    pub is_xhr: bool,
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
    pub secrets_found: Vec<SecretMatch>,
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
    pub priority: Option<String>,
    pub source_scheme: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestResponsePair {
    pub request: RawRequest,
    pub response: Option<RawResponse>,
}

// ============================================================================
// TIER 1: New Structures
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptedRequest {
    pub request_id: String,
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub resource_type: String,
    pub action_taken: String, // "continued", "modified", "blocked"
    pub modifications: Option<RequestModification>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestModification {
    pub url_changed: Option<String>,
    pub method_changed: Option<String>,
    pub headers_added: Vec<String>,
    pub headers_removed: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMatch {
    pub pattern_name: String,
    pub matched_value: String,
    pub line_number: Option<i64>,
    pub context: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityIssue {
    pub issue_code: String,
    pub severity: String,
    pub description: String,
    pub affected_url: Option<String>,
    pub details: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieJar {
    pub cookies: Vec<Cookie>,
    pub captured_at: u64,
    pub total_count: usize,
    pub secure_count: usize,
    pub http_only_count: usize,
    pub session_cookies: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XhrReplayResult {
    pub original_request_id: String,
    pub replayed: bool,
    pub error: Option<String>,
    pub timestamp: u64,
}

// ============================================================================
// TIER 2: New Structures
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssociatedCookieInfo {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub blocked: bool,
    pub blocked_reasons: Vec<String>,
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedCookieInfo {
    pub name: String,
    pub value: Option<String>,
    pub blocked_reasons: Vec<String>,
    pub request_id: String,
    pub cookie_line: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SSEMessage {
    pub request_id: String,
    pub event_name: String,
    pub event_id: String,
    pub data: String,
    pub timestamp: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageItem {
    pub storage_type: String, // "localStorage" or "sessionStorage"
    pub origin: String,
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityState {
    pub security_state: String,
    pub certificate_security_state: Option<CertificateInfo>,
    pub safety_tip: Option<String>,
    pub secure_origin: bool,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub protocol: Option<String>,
    pub key_exchange: Option<String>,
    pub cipher: Option<String>,
    pub certificate_has_weak_signature: bool,
    pub certificate_has_sha1_signature: bool,
    pub modern_ssl: bool,
    pub obsolete_ssl_protocol: bool,
    pub obsolete_ssl_key_exchange: bool,
    pub obsolete_ssl_cipher: bool,
    pub subject_name: Option<String>,
    pub issuer: Option<String>,
    pub valid_from: Option<f64>,
    pub valid_to: Option<f64>,
}

// ============================================================================
// TIER 3: IndexedDB, CacheStorage, Console, WebTransport Structures
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedDbDatabase {
    pub origin: String,
    pub name: String,
    pub version: f64,
    pub object_stores: Vec<IndexedDbObjectStore>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedDbObjectStore {
    pub name: String,
    pub key_path: String,
    pub auto_increment: bool,
    pub indexes: Vec<String>,
    pub entries: Vec<IndexedDbEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedDbEntry {
    pub key: String,
    pub value: String, // JSON stringified
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStorageCache {
    pub security_origin: String,
    pub cache_name: String,
    pub cache_id: String,
    pub entries: Vec<CacheStorageEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStorageEntry {
    pub request_url: String,
    pub request_method: String,
    pub response_status: i64,
    pub response_type: String,
    pub response_time: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleMessage {
    pub level: String,        // log, warn, error, info, debug
    pub source: String,       // javascript, network, security, etc.
    pub text: String,
    pub url: Option<String>,
    pub line_number: Option<i64>,
    pub timestamp: f64,
    pub args: Vec<String>,    // Stringified arguments
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogMessage {
    pub level: String,
    pub source: String,
    pub text: String,
    pub url: Option<String>,
    pub line_number: Option<i64>,
    pub category: Option<String>,
    pub network_request_id: Option<String>,
    pub timestamp: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebTransportSession {
    pub transport_id: String,
    pub url: String,
    pub initiator_origin: Option<String>,
    pub created_at: u64,
    pub established_at: Option<u64>,
    pub closed_at: Option<u64>,
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
    pub direction: String,
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
    pub full_value: Option<String>,
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
pub struct GraphQLOperation {
    pub url: String,
    pub operation_type: String,
    pub operation_name: Option<String>,
    pub query: Option<String>,
    pub variables: Option<serde_json::Value>,
    pub request_id: String,
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

    // TIER 1: New data
    pub intercepted_requests: Vec<InterceptedRequest>,
    pub cookie_jar: Option<CookieJar>,
    pub xhr_replays: Vec<XhrReplayResult>,
    pub secrets_found: Vec<SecretMatch>,
    pub security_issues: Vec<SecurityIssue>,

    // TIER 2: Enhanced data
    pub associated_cookies: Vec<AssociatedCookieInfo>,
    pub blocked_cookies: Vec<BlockedCookieInfo>,
    pub sse_messages: Vec<SSEMessage>,
    pub storage_items: Vec<StorageItem>,
    pub security_state: Option<SecurityState>,

    // TIER 3: Deep inspection data
    pub indexed_databases: Vec<IndexedDbDatabase>,
    pub cache_storage: Vec<CacheStorageCache>,
    pub console_messages: Vec<ConsoleMessage>,
    pub log_messages: Vec<LogMessage>,
    pub webtransport_sessions: Vec<WebTransportSession>,

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
    pub missing_headers: Vec<String>,

    // Interesting
    pub interesting_urls: Vec<String>,

    // Export commands
    pub curl_commands: Vec<String>,
    pub python_requests: Vec<String>,
    pub raw_http: Vec<String>,
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
// Secret Patterns for Scanning
// ============================================================================

const SECRET_PATTERNS: &[(&str, &str)] = &[
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
    ("AWS Secret Key", r#"(?i)aws(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]"#),
    ("GitHub Token", r"ghp_[0-9a-zA-Z]{36}"),
    ("GitHub OAuth", r"gho_[0-9a-zA-Z]{36}"),
    ("Slack Token", r"xox[baprs]-[0-9a-zA-Z]{10,48}"),
    ("Slack Webhook", r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"),
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}"),
    ("Stripe Key", r"sk_live_[0-9a-zA-Z]{24}"),
    ("Stripe Publishable", r"pk_live_[0-9a-zA-Z]{24}"),
    ("Private Key", r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    ("JWT Token", r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"),
    ("Bearer Token", r"[Bb]earer\s+[a-zA-Z0-9_\-\.]+"),
    ("Basic Auth", r"[Bb]asic\s+[a-zA-Z0-9+/=]{20,}"),
    ("API Key Generic", r#"(?i)(api[_-]?key|apikey)['"]?\s*[:=]\s*['"]?[a-zA-Z0-9_\-]{16,}"#),
    ("Password Field", r#"(?i)(password|passwd|pwd)['"]?\s*[:=]\s*['"][^'"]{4,}['"]"#),
    ("Secret Generic", r#"(?i)(secret|token)['"]?\s*[:=]\s*['"][a-zA-Z0-9_\-]{16,}['"]"#),
    ("Firebase URL", r"https://[a-z0-9-]+\.firebaseio\.com"),
    ("Twilio Key", r"SK[a-f0-9]{32}"),
    ("SendGrid Key", r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}"),
    ("Mailgun Key", r"key-[0-9a-zA-Z]{32}"),
];

// ============================================================================
// Recon Engine
// ============================================================================

#[allow(dead_code)]
struct ReconEngine {
    // Raw capture
    requests: Mutex<HashMap<String, RawRequest>>,
    responses: Mutex<HashMap<String, RawResponse>>,

    // Pending body fetches
    pending_request_bodies: Mutex<Vec<PendingRequest>>,
    pending_response_bodies: Mutex<Vec<PendingResponse>>,

    // TIER 1: New captures
    intercepted_requests: Mutex<Vec<InterceptedRequest>>,
    security_issues: Mutex<Vec<SecurityIssue>>,
    secrets_found: Mutex<Vec<SecretMatch>>,
    xhr_requests: Mutex<Vec<String>>, // Request IDs of XHR requests
    xhr_replays: Mutex<Vec<XhrReplayResult>>,
    intercept_mode: bool,

    // TIER 2: Enhanced captures
    associated_cookies: Mutex<Vec<AssociatedCookieInfo>>,
    blocked_cookies: Mutex<Vec<BlockedCookieInfo>>,
    sse_messages: Mutex<Vec<SSEMessage>>,
    storage_items: Mutex<Vec<StorageItem>>,
    security_state: Mutex<Option<SecurityState>>,

    // TIER 3: Deep inspection
    indexed_databases: Mutex<Vec<IndexedDbDatabase>>,
    cache_storage: Mutex<Vec<CacheStorageCache>>,
    console_messages: Mutex<Vec<ConsoleMessage>>,
    log_messages: Mutex<Vec<LogMessage>>,
    webtransport_sessions: Mutex<HashMap<String, WebTransportSession>>,

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
    interesting_urls: Mutex<Vec<String>>,

    // Headers
    request_count: Mutex<usize>,
    checked_headers: Mutex<bool>,
    header_findings: Mutex<Vec<String>>,
}

impl ReconEngine {
    fn new(intercept_mode: bool) -> Self {
        Self {
            requests: Mutex::new(HashMap::new()),
            responses: Mutex::new(HashMap::new()),
            pending_request_bodies: Mutex::new(Vec::new()),
            pending_response_bodies: Mutex::new(Vec::new()),
            intercepted_requests: Mutex::new(Vec::new()),
            security_issues: Mutex::new(Vec::new()),
            secrets_found: Mutex::new(Vec::new()),
            xhr_requests: Mutex::new(Vec::new()),
            xhr_replays: Mutex::new(Vec::new()),
            intercept_mode,
            // TIER 2
            associated_cookies: Mutex::new(Vec::new()),
            blocked_cookies: Mutex::new(Vec::new()),
            sse_messages: Mutex::new(Vec::new()),
            storage_items: Mutex::new(Vec::new()),
            security_state: Mutex::new(None),
            // TIER 3
            indexed_databases: Mutex::new(Vec::new()),
            cache_storage: Mutex::new(Vec::new()),
            console_messages: Mutex::new(Vec::new()),
            log_messages: Mutex::new(Vec::new()),
            webtransport_sessions: Mutex::new(HashMap::new()),
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
            interesting_urls: Mutex::new(Vec::new()),
            request_count: Mutex::new(0),
            checked_headers: Mutex::new(false),
            header_findings: Mutex::new(Vec::new()),
        }
    }

    // ========================================================================
    // TIER 1: Request Interception (Fetch Domain)
    // ========================================================================

    async fn handle_intercepted_request(&self, event: &EventRequestPaused) -> InterceptedRequest {
        let request_id = event.request_id.inner().to_string();
        let url = event.request.url.clone();
        let method = event.request.method.clone();
        let resource_type = format!("{:?}", event.resource_type);

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

        println!("  [INTERCEPT] {} {} {}", method, truncate(&url, 50), resource_type);

        // Analyze for blocking decision
        let should_block = self.should_block_request(&url, &headers).await;

        let action = if should_block {
            "blocked".to_string()
        } else {
            "continued".to_string()
        };

        let intercepted = InterceptedRequest {
            request_id: request_id.clone(),
            url: url.clone(),
            method,
            headers,
            resource_type,
            action_taken: action.clone(),
            modifications: None,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };

        self.intercepted_requests.lock().await.push(intercepted.clone());
        intercepted
    }

    async fn should_block_request(&self, url: &str, _headers: &HashMap<String, String>) -> bool {
        let url_lower = url.to_lowercase();

        // Block known tracking/analytics
        let block_patterns = [
            "google-analytics.com",
            "googletagmanager.com",
            "facebook.com/tr",
            "doubleclick.net",
            "adsense",
            "adserver",
            "tracking",
            "analytics",
            "telemetry",
        ];

        for pattern in &block_patterns {
            if url_lower.contains(pattern) {
                println!("    -> BLOCKED: matches '{}'", pattern);
                return true;
            }
        }
        false
    }

    // ========================================================================
    // TIER 1: Cookie Jar Dump
    // ========================================================================

    async fn dump_cookie_jar(&self, page: &Page) -> Option<CookieJar> {
        println!("[*] Dumping full cookie jar...");

        let params = GetCookiesParams::default();
        match page.execute(params).await {
            Ok(result) => {
                let cookies: Vec<Cookie> = result.cookies.iter().map(|c| {
                    Cookie {
                        name: c.name.clone(),
                        value: c.value.clone(),
                        domain: Some(c.domain.clone()),
                        path: Some(c.path.clone()),
                        expires: if c.expires < 0.0 { None } else { Some(format!("{}", c.expires)) },
                        http_only: c.http_only,
                        secure: c.secure,
                        same_site: c.same_site.as_ref().map(|s| format!("{:?}", s)),
                        priority: Some(format!("{:?}", c.priority)),
                        source_scheme: Some(format!("{:?}", c.source_scheme)),
                    }
                }).collect();

                let secure_count = cookies.iter().filter(|c| c.secure).count();
                let http_only_count = cookies.iter().filter(|c| c.http_only).count();
                let session_cookies = result.cookies.iter().filter(|c| c.session).count();

                println!("  [COOKIES] Total: {}, Secure: {}, HttpOnly: {}, Session: {}",
                    cookies.len(), secure_count, http_only_count, session_cookies);

                // Print interesting cookies
                for cookie in &cookies {
                    let name_lower = cookie.name.to_lowercase();
                    if name_lower.contains("session") || name_lower.contains("token") ||
                       name_lower.contains("auth") || name_lower.contains("jwt") ||
                       name_lower.contains("csrf") {
                        println!("    -> {} = {}... (Secure:{}, HttpOnly:{})",
                            cookie.name,
                            truncate(&cookie.value, 20),
                            cookie.secure,
                            cookie.http_only);
                    }
                }

                Some(CookieJar {
                    total_count: cookies.len(),
                    secure_count,
                    http_only_count,
                    session_cookies,
                    cookies,
                    captured_at: chrono::Utc::now().timestamp_millis() as u64,
                })
            }
            Err(e) => {
                println!("  [ERROR] Failed to dump cookies: {}", e);
                None
            }
        }
    }

    // ========================================================================
    // TIER 1: XHR Replay
    // ========================================================================

    async fn replay_xhr_requests(&self, page: &Page) {
        let xhr_ids = self.xhr_requests.lock().await.clone();

        if xhr_ids.is_empty() {
            println!("[*] No XHR requests to replay");
            return;
        }

        println!("[*] Replaying {} XHR requests...", xhr_ids.len());

        for request_id in xhr_ids.iter().take(5) { // Limit to 5 replays
            let params = ReplayXhrParams::new(RequestId::from(request_id.clone()));

            let result = match page.execute(params).await {
                Ok(_) => {
                    println!("  [REPLAY] {} - Success", request_id);
                    XhrReplayResult {
                        original_request_id: request_id.clone(),
                        replayed: true,
                        error: None,
                        timestamp: chrono::Utc::now().timestamp_millis() as u64,
                    }
                }
                Err(e) => {
                    println!("  [REPLAY] {} - Failed: {}", request_id, e);
                    XhrReplayResult {
                        original_request_id: request_id.clone(),
                        replayed: false,
                        error: Some(e.to_string()),
                        timestamp: chrono::Utc::now().timestamp_millis() as u64,
                    }
                }
            };

            self.xhr_replays.lock().await.push(result);
        }
    }

    // ========================================================================
    // TIER 1: Secret Scanning in Response Bodies
    // ========================================================================

    async fn scan_response_for_secrets(&self, page: &Page, request_id: &str, url: &str) -> Vec<SecretMatch> {
        let mut found_secrets = Vec::new();

        // Use CDP searchInResponseBody for each pattern
        for (pattern_name, pattern) in SECRET_PATTERNS {
            let mut params = SearchInResponseBodyParams::new(
                RequestId::from(request_id.to_string()),
                pattern.to_string()
            );
            params.is_regex = Some(true);

            if let Ok(response) = page.execute(params).await {
                for search_match in &response.result.result {
                    let secret = SecretMatch {
                        pattern_name: pattern_name.to_string(),
                        matched_value: truncate(&search_match.line_content, 100),
                        line_number: Some(search_match.line_number as i64),
                        context: Some(search_match.line_content.clone()),
                    };

                    println!("  [SECRET!] {} found in {} (line {})",
                        pattern_name, truncate(url, 40), search_match.line_number as i64);

                    found_secrets.push(secret);
                }
            }
        }

        if !found_secrets.is_empty() {
            self.secrets_found.lock().await.extend(found_secrets.clone());
        }

        found_secrets
    }

    // ========================================================================
    // TIER 1: Security Issue Handler (Audits Domain)
    // ========================================================================

    async fn handle_security_issue(&self, event: &EventIssueAdded) {
        let code = format!("{:?}", event.issue.code);
        let details = format!("{:?}", event.issue.details);

        let severity = match &event.issue.code {
            c if format!("{:?}", c).contains("Cookie") => "Medium",
            c if format!("{:?}", c).contains("MixedContent") => "High",
            c if format!("{:?}", c).contains("Cors") => "Medium",
            c if format!("{:?}", c).contains("Csp") => "High",
            c if format!("{:?}", c).contains("Deprecation") => "Low",
            _ => "Info",
        };

        // Extract affected URL if available
        let affected_url = if details.contains("url") {
            // Try to extract URL from details
            details.split("url").nth(1)
                .and_then(|s| s.split('"').nth(1))
                .map(|s| s.to_string())
        } else {
            None
        };

        let description = match &code {
            c if c.contains("SameSiteCookie") => "Cookie without SameSite attribute",
            c if c.contains("MixedContent") => "Mixed content (HTTP resource on HTTPS page)",
            c if c.contains("BlockedByResponse") => "Request blocked by response headers (CORS/COEP)",
            c if c.contains("Cors") => "CORS policy violation",
            c if c.contains("ContentSecurityPolicy") => "Content Security Policy violation",
            c if c.contains("Deprecation") => "Deprecated API usage",
            _ => "Security issue detected",
        };

        println!("  [SECURITY-ISSUE] [{}] {} - {}", severity, code, description);

        let issue = SecurityIssue {
            issue_code: code,
            severity: severity.to_string(),
            description: description.to_string(),
            affected_url,
            details,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };

        self.security_issues.lock().await.push(issue);
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

        // Check if XHR
        let is_xhr = event.r#type.as_ref()
            .map(|t| format!("{:?}", t).contains("XHR"))
            .unwrap_or(false);

        if is_xhr {
            self.xhr_requests.lock().await.push(request_id.clone());
        }

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
            body: None,
            content_type: content_type.clone(),
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            initiator: event.initiator.url.clone(),
            resource_type: event.r#type.as_ref().map(|t| format!("{:?}", t)).unwrap_or_default(),
            is_xhr,
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
            secrets_found: Vec::new(),
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
            self.security_issues.lock().await.push(SecurityIssue {
                issue_code: "ServerError".to_string(),
                severity: "Medium".to_string(),
                description: format!("Server error {} at endpoint", status),
                affected_url: Some(url.clone()),
                details: format!("Status: {} {}", status, event.response.status_text),
                timestamp: chrono::Utc::now().timestamp_millis() as u64,
            });
        }

        if let Some(cors) = headers.get("Access-Control-Allow-Origin").or(headers.get("access-control-allow-origin")) {
            if cors == "*" {
                println!("  [CORS] Wildcard CORS: {}", truncate(url, 60));
                self.security_issues.lock().await.push(SecurityIssue {
                    issue_code: "WildcardCORS".to_string(),
                    severity: "Medium".to_string(),
                    description: "Wildcard CORS allows any origin".to_string(),
                    affected_url: Some(url.clone()),
                    details: "Access-Control-Allow-Origin: *".to_string(),
                    timestamp: chrono::Utc::now().timestamp_millis() as u64,
                });
            }
        }
    }

    // ========================================================================
    // Body Fetching (with secret scanning)
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
                        if req.url.to_lowercase().contains("graphql") {
                            self.parse_graphql_body(&body, &pending.request_id).await;
                        }
                        println!("  [BODY] Request {} - {} bytes", truncate(&req.url, 40), body.len());
                        req.body = Some(body);
                    }
                }
            }
        }

        // Fetch response bodies with secret scanning
        let pending_resps = {
            let mut pending = self.pending_response_bodies.lock().await;
            std::mem::take(&mut *pending)
        };

        for pending in pending_resps {
            // Scan for secrets first (uses CDP search which is more efficient)
            let secrets = self.scan_response_for_secrets(page, &pending.request_id, &pending.url).await;

            if let Ok((body, _base64)) = self.fetch_response_body(page, &pending.request_id).await {
                let mut responses = self.responses.lock().await;
                if let Some(resp) = responses.get_mut(&pending.request_id) {
                    if !body.is_empty() {
                        let size = body.len();
                        let stored_body = if size > 50000 {
                            format!("{}... [TRUNCATED - {} bytes total]", &body[..50000], size)
                        } else {
                            body
                        };
                        println!("  [BODY] Response {} - {} bytes", truncate(&pending.url, 40), size);
                        resp.body = Some(stored_body);
                        resp.body_size = Some(size);
                        resp.secrets_found = secrets;
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
                if q.trim().starts_with("mutation") { "mutation" }
                else if q.trim().starts_with("subscription") { "subscription" }
                else { "query" }
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
    // TIER 2: Raw Cookie Capture (requestWillBeSentExtraInfo)
    // ========================================================================

    async fn handle_request_extra_info(&self, event: &EventRequestWillBeSentExtraInfo) {
        let request_id = event.request_id.inner().to_string();

        for assoc_cookie in &event.associated_cookies {
            let blocked = !assoc_cookie.blocked_reasons.is_empty();
            let blocked_reasons: Vec<String> = assoc_cookie.blocked_reasons
                .iter()
                .map(|r| format!("{:?}", r))
                .collect();

            if blocked {
                println!("  [COOKIE-BLOCKED] {} - {:?}", assoc_cookie.cookie.name, blocked_reasons);
            }

            let info = AssociatedCookieInfo {
                name: assoc_cookie.cookie.name.clone(),
                value: assoc_cookie.cookie.value.clone(),
                domain: assoc_cookie.cookie.domain.clone(),
                path: assoc_cookie.cookie.path.clone(),
                blocked,
                blocked_reasons,
                request_id: request_id.clone(),
            };

            self.associated_cookies.lock().await.push(info);
        }
    }

    // ========================================================================
    // TIER 2: Blocked Cookie / Response Extra Info
    // ========================================================================

    async fn handle_response_extra_info(&self, event: &EventResponseReceivedExtraInfo) {
        let request_id = event.request_id.inner().to_string();

        for blocked in &event.blocked_cookies {
            let blocked_reasons: Vec<String> = blocked.blocked_reasons
                .iter()
                .map(|r| format!("{:?}", r))
                .collect();

            // Try to get cookie name from the cookie or the cookie line
            let (name, value, cookie_line) = if let Some(ref cookie) = blocked.cookie {
                (cookie.name.clone(), Some(cookie.value.clone()), None)
            } else {
                // Parse from cookie line
                let line = blocked.cookie_line.clone();
                let name = line.split('=').next()
                    .map(String::from)
                    .unwrap_or_else(|| "unknown".to_string());
                (name, None, Some(line))
            };

            println!("  [SET-COOKIE-BLOCKED] {} - {:?}", name, blocked_reasons);

            let info = BlockedCookieInfo {
                name,
                value,
                blocked_reasons,
                request_id: request_id.clone(),
                cookie_line,
            };

            self.blocked_cookies.lock().await.push(info);
        }
    }

    // ========================================================================
    // TIER 2: Server-Sent Events (SSE)
    // ========================================================================

    async fn handle_sse_message(&self, event: &EventEventSourceMessageReceived) {
        let request_id = event.request_id.inner().to_string();

        println!("  [SSE] {} event='{}' id='{}' data='{}'",
            request_id,
            event.event_name,
            event.event_id,
            truncate(&event.data, 50));

        let msg = SSEMessage {
            request_id,
            event_name: event.event_name.clone(),
            event_id: event.event_id.clone(),
            data: event.data.clone(),
            timestamp: *event.timestamp.inner(),
        };

        self.sse_messages.lock().await.push(msg);
    }

    // ========================================================================
    // TIER 2: DOMStorage Direct Dump
    // ========================================================================

    async fn dump_dom_storage(&self, page: &Page, origin: &str) {
        println!("[*] Dumping DOM storage for {}...", origin);

        // localStorage
        let local_storage_id = StorageId {
            storage_key: None,
            security_origin: Some(origin.to_string()),
            is_local_storage: true,
        };

        if let Ok(response) = page.execute(GetDomStorageItemsParams::new(local_storage_id)).await {
            for entry in &response.entries {
                let items = entry.inner();
                if items.len() >= 2 {
                    let key = &items[0];
                    let value = &items[1];
                    println!("  [localStorage] {} = {}", key, truncate(value, 50));

                    self.storage_items.lock().await.push(StorageItem {
                        storage_type: "localStorage".to_string(),
                        origin: origin.to_string(),
                        key: key.clone(),
                        value: value.clone(),
                    });
                }
            }
        }

        // sessionStorage
        let session_storage_id = StorageId {
            storage_key: None,
            security_origin: Some(origin.to_string()),
            is_local_storage: false,
        };

        if let Ok(response) = page.execute(GetDomStorageItemsParams::new(session_storage_id)).await {
            for entry in &response.entries {
                let items = entry.inner();
                if items.len() >= 2 {
                    let key = &items[0];
                    let value = &items[1];
                    println!("  [sessionStorage] {} = {}", key, truncate(value, 50));

                    self.storage_items.lock().await.push(StorageItem {
                        storage_type: "sessionStorage".to_string(),
                        origin: origin.to_string(),
                        key: key.clone(),
                        value: value.clone(),
                    });
                }
            }
        }
    }

    async fn handle_storage_item_added(&self, event: &EventDomStorageItemAdded) {
        let storage_type = if event.storage_id.is_local_storage { "localStorage" } else { "sessionStorage" };
        let origin = event.storage_id.security_origin.clone().unwrap_or_default();

        println!("  [STORAGE-ADD] [{}] {} = {}", storage_type, event.key, truncate(&event.new_value, 50));

        self.storage_items.lock().await.push(StorageItem {
            storage_type: storage_type.to_string(),
            origin,
            key: event.key.clone(),
            value: event.new_value.clone(),
        });
    }

    async fn handle_storage_item_updated(&self, event: &EventDomStorageItemUpdated) {
        let storage_type = if event.storage_id.is_local_storage { "localStorage" } else { "sessionStorage" };

        println!("  [STORAGE-UPDATE] [{}] {} = {} -> {}",
            storage_type, event.key, truncate(&event.old_value, 20), truncate(&event.new_value, 30));

        // Update existing or add new
        let origin = event.storage_id.security_origin.clone().unwrap_or_default();
        let mut items = self.storage_items.lock().await;
        if let Some(item) = items.iter_mut().find(|i| i.key == event.key && i.storage_type == storage_type) {
            item.value = event.new_value.clone();
        } else {
            items.push(StorageItem {
                storage_type: storage_type.to_string(),
                origin,
                key: event.key.clone(),
                value: event.new_value.clone(),
            });
        }
    }

    // ========================================================================
    // TIER 2: Security State
    // ========================================================================

    async fn handle_security_state_changed(&self, event: &EventVisibleSecurityStateChanged) {
        let state = &event.visible_security_state;
        let security_state_str = format!("{:?}", state.security_state);

        println!("  [SECURITY-STATE] {}", security_state_str);

        let cert_info = state.certificate_security_state.as_ref().map(|cert| {
            CertificateInfo {
                protocol: Some(cert.protocol.clone()),
                key_exchange: Some(cert.key_exchange.clone()),
                cipher: Some(cert.cipher.clone()),
                certificate_has_weak_signature: cert.certificate_has_weak_signature,
                certificate_has_sha1_signature: cert.certificate_has_sha1_signature,
                modern_ssl: cert.modern_ssl,
                obsolete_ssl_protocol: cert.obsolete_ssl_protocol,
                obsolete_ssl_key_exchange: cert.obsolete_ssl_key_exchange,
                obsolete_ssl_cipher: cert.obsolete_ssl_cipher,
                subject_name: Some(cert.subject_name.clone()),
                issuer: Some(cert.issuer.clone()),
                valid_from: Some(*cert.valid_from.inner()),
                valid_to: Some(*cert.valid_to.inner()),
            }
        });

        if let Some(ref cert) = cert_info {
            if cert.obsolete_ssl_protocol || cert.obsolete_ssl_cipher || cert.obsolete_ssl_key_exchange {
                println!("    [!] Obsolete SSL detected!");
                self.security_issues.lock().await.push(SecurityIssue {
                    issue_code: "ObsoleteSSL".to_string(),
                    severity: "High".to_string(),
                    description: "Obsolete SSL/TLS configuration detected".to_string(),
                    affected_url: None,
                    details: format!("Protocol: {:?}, Cipher: {:?}, KeyExchange: {:?}",
                        cert.protocol, cert.cipher, cert.key_exchange),
                    timestamp: chrono::Utc::now().timestamp_millis() as u64,
                });
            }
            if cert.certificate_has_weak_signature || cert.certificate_has_sha1_signature {
                println!("    [!] Weak certificate signature!");
                self.security_issues.lock().await.push(SecurityIssue {
                    issue_code: "WeakCertificate".to_string(),
                    severity: "Medium".to_string(),
                    description: "Certificate has weak or SHA1 signature".to_string(),
                    affected_url: None,
                    details: format!("Subject: {:?}, Issuer: {:?}", cert.subject_name, cert.issuer),
                    timestamp: chrono::Utc::now().timestamp_millis() as u64,
                });
            }
            if let (Some(subj), Some(proto)) = (&cert.subject_name, &cert.protocol) {
                println!("    Certificate: {} via {}", subj, proto);
            }
        }

        let safety_tip = state.safety_tip_info.as_ref().map(|tip| format!("{:?}", tip.safety_tip_status));

        let sec_state = SecurityState {
            security_state: security_state_str,
            certificate_security_state: cert_info,
            safety_tip,
            secure_origin: state.security_state_issue_ids.is_empty(),
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };

        *self.security_state.lock().await = Some(sec_state);
    }

    // ========================================================================
    // TIER 3: IndexedDB Enumeration
    // ========================================================================

    async fn dump_indexed_db(&self, page: &Page, origin: &str) {
        println!("[*] Dumping IndexedDB for {}...", origin);

        // First, get list of database names
        let params = RequestDatabaseNamesParams::builder()
            .security_origin(origin)
            .build();

        if let Ok(response) = page.execute(params).await {
            for db_name in &response.database_names {
                println!("  [IndexedDB] Found database: {}", db_name);

                // Get database details
                let db_params = RequestDatabaseParams::builder()
                    .security_origin(origin)
                    .database_name(db_name.clone())
                    .build();

                if let Ok(db_params) = db_params {
                if let Ok(db_response) = page.execute(db_params).await {
                    let db_info = &db_response.database_with_object_stores;
                    let mut object_stores = Vec::new();

                    for store in &db_info.object_stores {
                        println!("    [ObjectStore] {} (keyPath: {:?}, autoIncrement: {})",
                            store.name, store.key_path, store.auto_increment);

                        let indexes: Vec<String> = store.indexes.iter()
                            .map(|idx| idx.name.clone())
                            .collect();

                        // Try to get some data from the object store
                        let mut entries = Vec::new();
                        let data_params = RequestDataParams::builder()
                            .security_origin(origin)
                            .database_name(db_name.clone())
                            .object_store_name(store.name.clone())
                            .index_name("")
                            .skip_count(0)
                            .page_size(100) // Limit to first 100 entries
                            .build();

                        if let Ok(data_params) = data_params {
                            if let Ok(data_response) = page.execute(data_params).await {
                                for data_entry in &data_response.object_store_data_entries {
                                    let key = format!("{:?}", data_entry.key);
                                    let value = format!("{:?}", data_entry.value);
                                    println!("      [Entry] key={} value={}",
                                        truncate(&key, 30), truncate(&value, 50));
                                    entries.push(IndexedDbEntry {
                                        key,
                                        value,
                                    });
                                }
                            }
                        }

                        let key_path_str = format!("{:?}", store.key_path);
                        object_stores.push(IndexedDbObjectStore {
                            name: store.name.clone(),
                            key_path: key_path_str,
                            auto_increment: store.auto_increment,
                            indexes,
                            entries,
                        });
                    }

                    self.indexed_databases.lock().await.push(IndexedDbDatabase {
                        origin: origin.to_string(),
                        name: db_info.name.clone(),
                        version: db_info.version,
                        object_stores,
                    });
                }
                } // Close if let Ok(db_params)
            }
        }
    }

    // ========================================================================
    // TIER 3: CacheStorage Inspection
    // ========================================================================

    async fn dump_cache_storage(&self, page: &Page, origin: &str) {
        println!("[*] Dumping CacheStorage for {}...", origin);

        let params = RequestCacheNamesParams::builder()
            .security_origin(origin)
            .build();

        if let Ok(response) = page.execute(params).await {
            for cache in &response.caches {
                println!("  [CacheStorage] Found cache: {}", cache.cache_name);

                let entries_params = RequestEntriesParams::builder()
                    .cache_id(cache.cache_id.clone())
                    .skip_count(0)
                    .page_size(100)
                    .build();

                if let Ok(entries_params) = entries_params {
                    let mut entries = Vec::new();

                    if let Ok(entries_response) = page.execute(entries_params).await {
                        for entry in &entries_response.cache_data_entries {
                            println!("    [Cached] {} {} -> {} {:?}",
                                entry.request_method,
                                truncate(&entry.request_url, 50),
                                entry.response_status,
                                entry.response_type);

                            entries.push(CacheStorageEntry {
                                request_url: entry.request_url.clone(),
                                request_method: entry.request_method.clone(),
                                response_status: entry.response_status,
                                response_type: format!("{:?}", entry.response_type),
                                response_time: entry.response_time,
                            });
                        }
                    }

                    self.cache_storage.lock().await.push(CacheStorageCache {
                        security_origin: origin.to_string(),
                        cache_name: cache.cache_name.clone(),
                        cache_id: cache.cache_id.inner().clone(),
                        entries,
                    });
                }
            }
        }
    }

    // ========================================================================
    // TIER 3: Console Message Capture
    // ========================================================================

    async fn handle_console_api_called(&self, event: &EventConsoleApiCalled) {
        let level = format!("{:?}", event.r#type);
        let timestamp = *event.timestamp.inner();

        // Convert args to strings
        let args: Vec<String> = event.args.iter()
            .map(|arg| {
                arg.description.clone()
                    .or_else(|| arg.value.as_ref().map(|v| v.to_string()))
                    .unwrap_or_else(|| format!("{:?}", arg.r#type))
            })
            .collect();

        let text = args.join(" ");

        // Extract URL/line from stack trace if available
        let (url, line_number) = event.stack_trace.as_ref()
            .and_then(|st| st.call_frames.first())
            .map(|frame| (Some(frame.url.clone()), Some(frame.line_number as i64)))
            .unwrap_or((None, None));

        println!("  [CONSOLE:{}] {}", level, truncate(&text, 80));

        self.console_messages.lock().await.push(ConsoleMessage {
            level,
            source: "console".to_string(),
            text,
            url,
            line_number,
            timestamp,
            args,
        });
    }

    // ========================================================================
    // TIER 3: Log Entry Capture
    // ========================================================================

    async fn handle_log_entry(&self, event: &EventEntryAdded) {
        let entry = &event.entry;
        let level = format!("{:?}", entry.level);
        let source = format!("{:?}", entry.source);
        let timestamp = *entry.timestamp.inner();

        println!("  [LOG:{}:{}] {}", source, level, truncate(&entry.text, 80));

        self.log_messages.lock().await.push(LogMessage {
            level,
            source,
            text: entry.text.clone(),
            url: entry.url.clone(),
            line_number: entry.line_number,
            category: entry.category.as_ref().map(|c| format!("{:?}", c)),
            network_request_id: entry.network_request_id.as_ref().map(|id| id.inner().clone()),
            timestamp,
        });
    }

    // ========================================================================
    // TIER 3: WebTransport Session Tracking
    // ========================================================================

    async fn handle_webtransport_created(&self, event: &EventWebTransportCreated) {
        let transport_id = event.transport_id.inner().to_string();
        let url = event.url.clone();

        println!("  [WEBTRANSPORT:CREATED] {} -> {}", transport_id, truncate(&url, 60));

        let session = WebTransportSession {
            transport_id: transport_id.clone(),
            url,
            initiator_origin: event.initiator.as_ref().and_then(|i| i.url.clone()),
            created_at: chrono::Utc::now().timestamp_millis() as u64,
            established_at: None,
            closed_at: None,
        };

        self.webtransport_sessions.lock().await.insert(transport_id, session);
    }

    async fn handle_webtransport_established(&self, event: &EventWebTransportConnectionEstablished) {
        let transport_id = event.transport_id.inner().to_string();
        println!("  [WEBTRANSPORT:ESTABLISHED] {}", transport_id);

        if let Some(session) = self.webtransport_sessions.lock().await.get_mut(&transport_id) {
            session.established_at = Some(chrono::Utc::now().timestamp_millis() as u64);
        }
    }

    async fn handle_webtransport_closed(&self, event: &EventWebTransportClosed) {
        let transport_id = event.transport_id.inner().to_string();
        println!("  [WEBTRANSPORT:CLOSED] {}", transport_id);

        if let Some(session) = self.webtransport_sessions.lock().await.get_mut(&transport_id) {
            session.closed_at = Some(chrono::Utc::now().timestamp_millis() as u64);
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

        if !is_auth_endpoint { return; }

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
        if current_flow.is_none() { return; }

        let flow = current_flow.as_mut().unwrap();

        let tokens_received: Vec<String> = {
            let mut tokens = Vec::new();
            for (key, value) in headers.iter() {
                if key.to_lowercase() == "set-cookie" {
                    let cookie_name = value.split('=').next().unwrap_or("");
                    if cookie_name.to_lowercase().contains("session") || cookie_name.to_lowercase().contains("token") {
                        tokens.push(format!("cookie:{}", cookie_name));
                    }
                }
            }
            if headers.contains_key("Authorization") || headers.contains_key("authorization") {
                tokens.push("header:authorization".to_string());
            }
            tokens
        };

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

        if (status == 200 || status == 302) && !tokens_received.is_empty() {
            flow.completed_at = Some(chrono::Utc::now().timestamp_millis() as u64);
            let captured = self.captured_tokens.lock().await;
            flow.tokens_captured = captured.clone();
            let completed_flow = flow.clone();
            drop(current_flow);
            self.auth_flows.lock().await.push(completed_flow);
            *self.current_auth_flow.lock().await = None;
            println!("  [AUTH-FLOW] Completed - {} steps",
                self.auth_flows.lock().await.last().map(|f| f.steps.len()).unwrap_or(0));
        }
    }

    // ========================================================================
    // Token Capture
    // ========================================================================

    async fn capture_auth_tokens(&self, url: &str, headers: &HashMap<String, String>, context: &str, request_id: Option<&str>) {
        let mut tokens = self.captured_tokens.lock().await;
        let mut findings = self.auth_findings.lock().await;
        let timestamp = chrono::Utc::now().timestamp_millis() as u64;

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

        let api_key_headers = ["X-API-Key", "x-api-key", "Api-Key", "api-key", "X-Auth-Token", "x-auth-token"];
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

        let csrf_headers = ["X-CSRF-Token", "x-csrf-token", "X-XSRF-Token", "x-xsrf-token"];
        for key in &csrf_headers {
            if let Some(value) = headers.get(*key) {
                if !tokens.iter().any(|t| t.token_type == "csrf" && t.name.to_lowercase() == key.to_lowercase()) {
                    println!("  [TOKEN] CSRF token captured: {}", key);
                    tokens.push(CapturedToken {
                        token_type: "csrf".to_string(),
                        name: key.to_string(),
                        value_preview: redact(value),
                        full_value: Some(value.clone()),
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
                            let token_type = if name_lower.contains("csrf") || name_lower.contains("xsrf") { "csrf" }
                            else if name_lower.contains("jwt") || is_jwt(&cookie.value) { "jwt" }
                            else { "session" };

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
                                sample: format!("HttpOnly:{} Secure:{} SameSite:{:?}", cookie.http_only, cookie.secure, cookie.same_site),
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

        let api_type = if url_lower.contains("graphql") || url_lower.contains("/gql") { "GraphQL" }
        else if url_lower.starts_with("wss://") || url_lower.starts_with("ws://") { "WebSocket" }
        else if url_lower.contains("/api/") || url_lower.contains("/v1/") || url_lower.contains("/v2/") || url_lower.contains("/v3/") { "REST" }
        else if headers.get("Content-Type").or(headers.get("content-type")).map(|ct| ct.contains("json")).unwrap_or(false) { "JSON" }
        else { return; };

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
        if !url.to_lowercase().contains("graphql") && !url.to_lowercase().contains("/gql") { return; }
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
            ("recaptcha", "Google reCAPTCHA"), ("hcaptcha", "hCaptcha"), ("turnstile", "Cloudflare Turnstile"),
            ("datadome", "DataDome"), ("perimeterx", "PerimeterX"), ("kasada", "Kasada"), ("fingerprintjs", "FingerprintJS"),
        ];
        for (pattern, service) in &checks {
            if url_lower.contains(pattern) && !findings.iter().any(|f| f.service == *service) {
                println!("  [ANTIBOT] {} detected", service);
                findings.push(AntiBotFinding { service: service.to_string(), indicator: format!("URL contains '{}'", pattern) });
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
                self.security_issues.lock().await.push(SecurityIssue {
                    issue_code: "SecretInURL".to_string(),
                    severity: "High".to_string(),
                    description: format!("Sensitive parameter '{}' found in URL", param),
                    affected_url: Some(url.to_string()),
                    details: format!("Parameter '{}' should not be in URL", param),
                    timestamp: chrono::Utc::now().timestamp_millis() as u64,
                });
                break;
            }
        }
    }

    async fn check_security_headers(&self, headers: &HashMap<String, String>) {
        let mut missing = self.header_findings.lock().await;
        let headers_lower: HashMap<String, String> = headers.iter().map(|(k, v)| (k.to_lowercase(), v.clone())).collect();
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

    async fn generate_report(&self, target: &str, cookie_jar: Option<CookieJar>) -> ReconReport {
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
            intercepted_requests: self.intercepted_requests.lock().await.clone(),
            cookie_jar,
            xhr_replays: self.xhr_replays.lock().await.clone(),
            secrets_found: self.secrets_found.lock().await.clone(),
            security_issues: self.security_issues.lock().await.clone(),
            // TIER 2
            associated_cookies: self.associated_cookies.lock().await.clone(),
            blocked_cookies: self.blocked_cookies.lock().await.clone(),
            sse_messages: self.sse_messages.lock().await.clone(),
            storage_items: self.storage_items.lock().await.clone(),
            security_state: self.security_state.lock().await.clone(),
            // TIER 3
            indexed_databases: self.indexed_databases.lock().await.clone(),
            cache_storage: self.cache_storage.lock().await.clone(),
            console_messages: self.console_messages.lock().await.clone(),
            log_messages: self.log_messages.lock().await.clone(),
            webtransport_sessions: self.webtransport_sessions.lock().await.values().cloned().collect(),
            websocket_connections: websockets.values().cloned().collect(),
            login_forms: self.login_forms.lock().await.clone(),
            registration_forms: self.registration_forms.lock().await.clone(),
            auth_flows: self.auth_flows.lock().await.clone(),
            captured_tokens: self.captured_tokens.lock().await.clone(),
            api_endpoints: self.apis.lock().await.clone(),
            graphql_operations: self.graphql_ops.lock().await.clone(),
            auth_findings: self.auth_findings.lock().await.clone(),
            antibot_findings: self.antibot_findings.lock().await.clone(),
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
        || mime_lower.contains("text/plain") || mime_lower.contains("javascript") || mime_lower.contains("graphql")
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
        h.split(';').filter_map(|c| {
            let mut parts = c.trim().splitn(2, '=');
            Some(Cookie {
                name: parts.next()?.to_string(),
                value: parts.next().unwrap_or("").to_string(),
                domain: None, path: None, expires: None,
                http_only: false, secure: false, same_site: None,
                priority: None, source_scheme: None,
            })
        }).collect()
    }).unwrap_or_default()
}

fn parse_set_cookie(value: &str) -> Cookie {
    let parts: Vec<&str> = value.split(';').collect();
    let mut cookie = Cookie {
        name: String::new(), value: String::new(),
        domain: None, path: None, expires: None,
        http_only: false, secure: false, same_site: None,
        priority: None, source_scheme: None,
    };
    if let Some(first) = parts.first() {
        let mut kv = first.splitn(2, '=');
        cookie.name = kv.next().unwrap_or("").trim().to_string();
        cookie.value = kv.next().unwrap_or("").trim().to_string();
    }
    for part in parts.iter().skip(1) {
        let part_lower = part.to_lowercase();
        let part_trimmed = part.trim();
        if part_lower.contains("httponly") { cookie.http_only = true; }
        else if part_lower.trim() == "secure" { cookie.secure = true; }
        else if part_lower.contains("domain=") { cookie.domain = Some(part_trimmed.split('=').nth(1).unwrap_or("").to_string()); }
        else if part_lower.contains("path=") { cookie.path = Some(part_trimmed.split('=').nth(1).unwrap_or("").to_string()); }
        else if part_lower.contains("expires=") { cookie.expires = Some(part_trimmed.split('=').nth(1).unwrap_or("").to_string()); }
        else if part_lower.contains("samesite=") { cookie.same_site = Some(part_trimmed.split('=').nth(1).unwrap_or("").to_string()); }
    }
    cookie
}

// ============================================================================
// JavaScript for Client-Side Analysis
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
        }
    };
    console.log('[RECON] v4 loaded - TIER 1 features enabled');
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
    let intercept_mode = args.iter().any(|a| a == "--intercept");
    let export_format = args.iter().find(|a| a.starts_with("--export"))
        .and_then(|_| args.iter().skip_while(|a| *a != "--export").nth(1))
        .map(|s| s.as_str())
        .unwrap_or("all");

    println!("\n{}", "═".repeat(70));
    println!(" WEB RECON TOOL v4 - TIER 1 + TIER 2 Features");
    println!(" Target: {}", target);
    println!(" Intercept Mode: {}", intercept_mode);
    println!("{}", "═".repeat(70));
    println!();

    let engine = Arc::new(ReconEngine::new(intercept_mode));

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

    // Enable Audits domain for security issues
    println!("[*] Enabling Audits domain...");
    page.execute(AuditsEnableParams::default()).await?;

    // TIER 2: Enable DOMStorage domain
    println!("[*] Enabling DOMStorage domain...");
    page.execute(DomStorageEnableParams::default()).await?;

    // TIER 2: Enable Security domain
    println!("[*] Enabling Security domain...");
    page.execute(SecurityEnableParams::default()).await?;

    // TIER 3: Enable IndexedDB domain
    println!("[*] Enabling IndexedDB domain...");
    page.execute(IndexedDbEnableParams::default()).await?;

    // TIER 3: Enable Log domain
    println!("[*] Enabling Log domain...");
    page.execute(LogEnableParams::default()).await?;

    // TIER 3: Enable Runtime domain (for console)
    println!("[*] Enabling Runtime domain...");
    page.execute(RuntimeEnableParams::default()).await?;

    // Enable Fetch domain for interception if requested
    if intercept_mode {
        println!("[*] Enabling Fetch domain for interception...");
        let fetch_params = FetchEnableParams::builder()
            .pattern(RequestPattern::builder().url_pattern("*").build())
            .build();
        page.execute(fetch_params).await?;
    }

    // Event listeners
    let mut req_events = page.event_listener::<EventRequestWillBeSent>().await?;
    let mut resp_events = page.event_listener::<EventResponseReceived>().await?;
    let mut ws_created = page.event_listener::<EventWebSocketCreated>().await?;
    let mut ws_sent = page.event_listener::<EventWebSocketFrameSent>().await?;
    let mut ws_recv = page.event_listener::<EventWebSocketFrameReceived>().await?;
    let mut ws_closed = page.event_listener::<EventWebSocketClosed>().await?;
    let mut audit_events = page.event_listener::<EventIssueAdded>().await?;

    // Spawn request handler
    let engine_req = Arc::clone(&engine);
    let req_handle = tokio::spawn(async move {
        while let Some(event) = req_events.next().await {
            engine_req.capture_request(&event).await;
        }
    });

    // Spawn response handler
    let engine_resp = Arc::clone(&engine);
    let resp_handle = tokio::spawn(async move {
        while let Some(event) = resp_events.next().await {
            engine_resp.capture_response(&event).await;
        }
    });

    // Spawn WebSocket handlers
    let engine_ws1 = Arc::clone(&engine);
    tokio::spawn(async move { while let Some(e) = ws_created.next().await { engine_ws1.handle_websocket_created(&e).await; } });
    let engine_ws2 = Arc::clone(&engine);
    tokio::spawn(async move { while let Some(e) = ws_sent.next().await { engine_ws2.handle_websocket_frame_sent(&e).await; } });
    let engine_ws3 = Arc::clone(&engine);
    tokio::spawn(async move { while let Some(e) = ws_recv.next().await { engine_ws3.handle_websocket_frame_received(&e).await; } });
    let engine_ws4 = Arc::clone(&engine);
    tokio::spawn(async move { while let Some(e) = ws_closed.next().await { engine_ws4.handle_websocket_closed(&e).await; } });

    // Spawn audit handler (TIER 1)
    let engine_audit = Arc::clone(&engine);
    tokio::spawn(async move {
        while let Some(event) = audit_events.next().await {
            engine_audit.handle_security_issue(&event).await;
        }
    });

    // TIER 2: Request/Response Extra Info handlers
    let mut req_extra_events = page.event_listener::<EventRequestWillBeSentExtraInfo>().await?;
    let mut resp_extra_events = page.event_listener::<EventResponseReceivedExtraInfo>().await?;
    let mut sse_events = page.event_listener::<EventEventSourceMessageReceived>().await?;
    let mut storage_added_events = page.event_listener::<EventDomStorageItemAdded>().await?;
    let mut storage_updated_events = page.event_listener::<EventDomStorageItemUpdated>().await?;
    let mut security_events = page.event_listener::<EventVisibleSecurityStateChanged>().await?;

    // TIER 2: Request Extra Info (raw cookies)
    let engine_req_extra = Arc::clone(&engine);
    tokio::spawn(async move {
        while let Some(event) = req_extra_events.next().await {
            engine_req_extra.handle_request_extra_info(&event).await;
        }
    });

    // TIER 2: Response Extra Info (blocked cookies)
    let engine_resp_extra = Arc::clone(&engine);
    tokio::spawn(async move {
        while let Some(event) = resp_extra_events.next().await {
            engine_resp_extra.handle_response_extra_info(&event).await;
        }
    });

    // TIER 2: SSE handler
    let engine_sse = Arc::clone(&engine);
    tokio::spawn(async move {
        while let Some(event) = sse_events.next().await {
            engine_sse.handle_sse_message(&event).await;
        }
    });

    // TIER 2: Storage handlers
    let engine_storage1 = Arc::clone(&engine);
    tokio::spawn(async move {
        while let Some(event) = storage_added_events.next().await {
            engine_storage1.handle_storage_item_added(&event).await;
        }
    });
    let engine_storage2 = Arc::clone(&engine);
    tokio::spawn(async move {
        while let Some(event) = storage_updated_events.next().await {
            engine_storage2.handle_storage_item_updated(&event).await;
        }
    });

    // TIER 2: Security state handler
    let engine_security = Arc::clone(&engine);
    tokio::spawn(async move {
        while let Some(event) = security_events.next().await {
            engine_security.handle_security_state_changed(&event).await;
        }
    });

    // TIER 3: Console API handler
    let mut console_events = page.event_listener::<EventConsoleApiCalled>().await?;
    let engine_console = Arc::clone(&engine);
    tokio::spawn(async move {
        while let Some(event) = console_events.next().await {
            engine_console.handle_console_api_called(&event).await;
        }
    });

    // TIER 3: Log entry handler
    let mut log_events = page.event_listener::<EventEntryAdded>().await?;
    let engine_log = Arc::clone(&engine);
    tokio::spawn(async move {
        while let Some(event) = log_events.next().await {
            engine_log.handle_log_entry(&event).await;
        }
    });

    // TIER 3: WebTransport handlers
    let mut wt_created_events = page.event_listener::<EventWebTransportCreated>().await?;
    let mut wt_established_events = page.event_listener::<EventWebTransportConnectionEstablished>().await?;
    let mut wt_closed_events = page.event_listener::<EventWebTransportClosed>().await?;

    let engine_wt1 = Arc::clone(&engine);
    tokio::spawn(async move {
        while let Some(event) = wt_created_events.next().await {
            engine_wt1.handle_webtransport_created(&event).await;
        }
    });
    let engine_wt2 = Arc::clone(&engine);
    tokio::spawn(async move {
        while let Some(event) = wt_established_events.next().await {
            engine_wt2.handle_webtransport_established(&event).await;
        }
    });
    let engine_wt3 = Arc::clone(&engine);
    tokio::spawn(async move {
        while let Some(event) = wt_closed_events.next().await {
            engine_wt3.handle_webtransport_closed(&event).await;
        }
    });

    // Intercept handler (TIER 1)
    if intercept_mode {
        let mut intercept_events = page.event_listener::<EventRequestPaused>().await?;
        let engine_intercept = Arc::clone(&engine);
        let page_clone = page.clone();
        tokio::spawn(async move {
            while let Some(event) = intercept_events.next().await {
                let intercepted = engine_intercept.handle_intercepted_request(&event).await;

                // Continue or block based on analysis
                if intercepted.action_taken == "blocked" {
                    let fail_params = FailRequestParams::new(
                        event.request_id.clone(),
                        chromiumoxide::cdp::browser_protocol::network::ErrorReason::BlockedByClient
                    );
                    let _ = page_clone.execute(fail_params).await;
                } else {
                    let continue_params = ContinueRequestParams::new(event.request_id.clone());
                    let _ = page_clone.execute(continue_params).await;
                }
            }
        });
    }

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

    // TIER 1: Dump cookie jar
    let cookie_jar = engine.dump_cookie_jar(&page).await;

    // TIER 2: Dump DOM storage directly via CDP
    let origin = url::Url::parse(target).ok().map(|u| u.origin().ascii_serialization()).unwrap_or_default();
    if !origin.is_empty() {
        engine.dump_dom_storage(&page, &origin).await;

        // TIER 3: Dump IndexedDB
        engine.dump_indexed_db(&page, &origin).await;

        // TIER 3: Dump CacheStorage
        engine.dump_cache_storage(&page, &origin).await;
    }

    // Fetch bodies with secret scanning
    println!("\n[*] Fetching request/response bodies (with secret scanning)...");
    engine.fetch_pending_bodies(&page).await;

    // TIER 1: Replay XHR requests
    engine.replay_xhr_requests(&page).await;

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
    println!(" RECON REPORT v5 - TIER 1 + TIER 2 + TIER 3");
    println!("{}", "═".repeat(70));

    let report = engine.generate_report(target, cookie_jar).await;

    println!("\n--- Summary ---");
    println!("Total Requests: {}", report.total_requests);
    println!("API Endpoints: {}", report.api_endpoints.len());
    println!("WebSocket Connections: {}", report.websocket_connections.len());
    println!("Tokens Captured: {}", report.captured_tokens.len());
    println!("Requests with Bodies: {}", report.captured_requests.iter().filter(|r| r.body.is_some()).count());
    println!("Responses with Bodies: {}", report.captured_responses.iter().filter(|r| r.body.is_some()).count());

    println!("\n--- TIER 1: New Features ---");
    println!("Intercepted Requests: {}", report.intercepted_requests.len());
    if let Some(jar) = &report.cookie_jar {
        println!("Cookies Dumped: {} (Secure:{}, HttpOnly:{}, Session:{})",
            jar.total_count, jar.secure_count, jar.http_only_count, jar.session_cookies);
    }
    println!("XHR Replays: {}", report.xhr_replays.len());
    println!("Secrets Found: {}", report.secrets_found.len());
    println!("Security Issues: {}", report.security_issues.len());

    println!("\n--- TIER 2: Enhanced Features ---");
    println!("Associated Cookies (sent): {}", report.associated_cookies.len());
    let blocked_sent = report.associated_cookies.iter().filter(|c| c.blocked).count();
    println!("Blocked Cookies (sending): {}", blocked_sent);
    println!("Blocked Cookies (set-cookie): {}", report.blocked_cookies.len());
    println!("SSE Messages: {}", report.sse_messages.len());
    println!("Storage Items: {}", report.storage_items.len());
    if let Some(ref sec_state) = report.security_state {
        println!("Security State: {} (Secure Origin: {})", sec_state.security_state, sec_state.secure_origin);
        if let Some(ref cert) = sec_state.certificate_security_state {
            if let Some(ref proto) = cert.protocol {
                println!("  TLS Protocol: {}", proto);
            }
            println!("  Modern SSL: {}, Obsolete: {}", cert.modern_ssl,
                cert.obsolete_ssl_protocol || cert.obsolete_ssl_cipher);
        }
    }

    println!("\n--- TIER 3: Deep Inspection ---");
    println!("IndexedDB Databases: {}", report.indexed_databases.len());
    let total_object_stores: usize = report.indexed_databases.iter().map(|db| db.object_stores.len()).sum();
    println!("IndexedDB Object Stores: {}", total_object_stores);
    println!("CacheStorage Caches: {}", report.cache_storage.len());
    let total_cached_entries: usize = report.cache_storage.iter().map(|c| c.entries.len()).sum();
    println!("Cached Entries: {}", total_cached_entries);
    println!("Console Messages: {}", report.console_messages.len());
    let console_errors = report.console_messages.iter().filter(|m| m.level.to_lowercase().contains("error")).count();
    if console_errors > 0 {
        println!("  Console Errors: {}", console_errors);
    }
    println!("Log Messages: {}", report.log_messages.len());
    println!("WebTransport Sessions: {}", report.webtransport_sessions.len());

    if !report.indexed_databases.is_empty() {
        println!("\n--- INDEXEDDB DATABASES ---");
        for db in &report.indexed_databases {
            println!("  [DB] {} v{} ({} stores)", db.name, db.version, db.object_stores.len());
            for store in &db.object_stores {
                println!("    [Store] {} ({} entries, autoInc: {})",
                    store.name, store.entries.len(), store.auto_increment);
            }
        }
    }

    if !report.cache_storage.is_empty() {
        println!("\n--- CACHE STORAGE ---");
        for cache in &report.cache_storage {
            println!("  [Cache] {} ({} entries)", cache.cache_name, cache.entries.len());
            for entry in cache.entries.iter().take(5) {
                println!("    {} {} -> {}", entry.request_method, truncate(&entry.request_url, 40), entry.response_status);
            }
        }
    }

    if !report.console_messages.is_empty() {
        println!("\n--- CONSOLE MESSAGES (first 10) ---");
        for msg in report.console_messages.iter().take(10) {
            println!("  [{}] {}", msg.level, truncate(&msg.text, 60));
        }
    }

    if !report.blocked_cookies.is_empty() {
        println!("\n--- BLOCKED SET-COOKIES ---");
        for cookie in report.blocked_cookies.iter().take(10) {
            println!("  [!] {} - {:?}", cookie.name, cookie.blocked_reasons);
        }
    }

    if !report.storage_items.is_empty() {
        println!("\n--- STORAGE ITEMS ---");
        for item in report.storage_items.iter().take(10) {
            println!("  [{}] {} = {}", item.storage_type, item.key, truncate(&item.value, 40));
        }
    }

    if !report.secrets_found.is_empty() {
        println!("\n--- SECRETS FOUND ---");
        for secret in &report.secrets_found {
            println!("  [!] {} - {}", secret.pattern_name, truncate(&secret.matched_value, 50));
        }
    }

    if !report.security_issues.is_empty() {
        println!("\n--- SECURITY ISSUES ---");
        for issue in &report.security_issues {
            println!("  [{}] {} - {}", issue.severity, issue.issue_code, issue.description);
        }
    }

    println!("\n--- API Endpoints ({}) ---", report.api_endpoints.len());
    for api in &report.api_endpoints { println!("  {} {} {}", api.method, api.api_type, truncate(&api.url, 50)); }

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
    println!(" Complete - TIER 1 + TIER 2 Features Active");
    println!(" {} requests | {} secrets | {} issues | {} storage items",
        report.total_requests, report.secrets_found.len(), report.security_issues.len(), report.storage_items.len());
    println!("{}", "═".repeat(70));

    drop(req_handle);
    drop(resp_handle);
    drop(handle);

    Ok(())
}
