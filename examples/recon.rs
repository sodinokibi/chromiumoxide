//! # Web Recon Tool - Bug Bounty Edition
//!
//! A lightweight security research tool built on chromiumoxide.
//! Captures traffic, discovers APIs, detects auth mechanisms, and identifies anti-bot measures.
//!
//! ## Usage
//! ```bash
//! cargo run --example recon -- https://target.com
//! ```

use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::cdp::browser_protocol::network::{
    EventRequestWillBeSent, EventResponseReceived,
};
use futures::StreamExt;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;

// ============================================================================
// Data Structures
// ============================================================================

#[derive(Debug, Clone, Serialize)]
struct ApiEndpoint {
    url: String,
    method: String,
    api_type: String,
    has_auth: bool,
}

#[derive(Debug, Clone, Serialize)]
struct AuthFinding {
    auth_type: String,
    location: String,
    key_name: String,
    sample: String,
}

#[derive(Debug, Clone, Serialize)]
struct AntiBotFinding {
    service: String,
    indicator: String,
}

#[derive(Debug, Clone, Serialize)]
struct SecurityFinding {
    finding_type: String,
    details: String,
}

#[derive(Debug, Default, Serialize)]
struct ReconResults {
    target: String,
    total_requests: usize,
    apis: Vec<ApiEndpoint>,
    auth_findings: Vec<AuthFinding>,
    antibot_findings: Vec<AntiBotFinding>,
    security_findings: Vec<SecurityFinding>,
    interesting_urls: Vec<String>,
    missing_headers: Vec<String>,
}

// ============================================================================
// Recon Engine
// ============================================================================

struct ReconEngine {
    seen_urls: Mutex<HashSet<String>>,
    apis: Mutex<Vec<ApiEndpoint>>,
    auth_findings: Mutex<Vec<AuthFinding>>,
    antibot_findings: Mutex<Vec<AntiBotFinding>>,
    security_findings: Mutex<Vec<SecurityFinding>>,
    interesting_urls: Mutex<Vec<String>>,
    request_count: Mutex<usize>,
    checked_headers: Mutex<bool>,
    header_findings: Mutex<Vec<String>>,
}

impl ReconEngine {
    fn new() -> Self {
        Self {
            seen_urls: Mutex::new(HashSet::new()),
            apis: Mutex::new(Vec::new()),
            auth_findings: Mutex::new(Vec::new()),
            antibot_findings: Mutex::new(Vec::new()),
            security_findings: Mutex::new(Vec::new()),
            interesting_urls: Mutex::new(Vec::new()),
            request_count: Mutex::new(0),
            checked_headers: Mutex::new(false),
            header_findings: Mutex::new(Vec::new()),
        }
    }

    async fn analyze_request(&self, event: &EventRequestWillBeSent) {
        *self.request_count.lock().await += 1;

        let url = &event.request.url;
        let method = &event.request.method;
        let headers: HashMap<String, String> = event
            .request
            .headers
            .inner()
            .as_object()
            .map(|obj| {
                obj.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.to_lowercase(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();

        // Skip static resources
        if is_static(url) {
            return;
        }

        // Check for API endpoints
        self.detect_api(url, method, &headers).await;

        // Check for auth mechanisms (note: post_data not directly available on Request, use has_post_data)
        self.detect_auth(url, &headers, None).await;

        // Check for interesting endpoints
        self.check_interesting(url).await;

        // Check for anti-bot indicators in URL
        self.detect_antibot_url(url).await;

        // Check for sensitive data in URL
        self.check_sensitive_url(url).await;
    }

    async fn analyze_response(&self, event: &EventResponseReceived) {
        let url = &event.response.url;
        let status = event.response.status;
        let headers: HashMap<String, String> = event
            .response
            .headers
            .inner()
            .as_object()
            .map(|obj| {
                obj.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.to_lowercase(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();

        // Check security headers (only once per main document)
        if !*self.checked_headers.lock().await {
            self.check_security_headers(&headers).await;
            *self.checked_headers.lock().await = true;
        }

        // Detect anti-bot services
        self.detect_antibot_response(url, &headers).await;

        // Check for interesting status codes
        if status == 401 || status == 403 {
            println!("  [AUTH-REQUIRED] {} {} {}", status, event.response.status_text, truncate(url, 60));
        } else if status >= 500 {
            println!("  [SERVER-ERROR] {} {} - Potential info leak", status, truncate(url, 60));
            self.security_findings.lock().await.push(SecurityFinding {
                finding_type: "Server Error".to_string(),
                details: format!("{} at {}", status, truncate(url, 100)),
            });
        }

        // Check CORS
        if let Some(cors) = headers.get("access-control-allow-origin") {
            if cors == "*" {
                println!("  [CORS] Wildcard CORS: {}", truncate(url, 60));
                self.security_findings.lock().await.push(SecurityFinding {
                    finding_type: "Wildcard CORS".to_string(),
                    details: format!("Access-Control-Allow-Origin: * at {}", truncate(url, 80)),
                });
            }
        }
    }

    async fn detect_api(&self, url: &str, method: &str, headers: &HashMap<String, String>) {
        let url_lower = url.to_lowercase();

        let api_type = if url_lower.contains("graphql") || url_lower.contains("/gql") {
            "GraphQL"
        } else if url_lower.starts_with("wss://") || url_lower.starts_with("ws://") {
            "WebSocket"
        } else if url_lower.contains("/api/") || url_lower.contains("/v1/") || url_lower.contains("/v2/") || url_lower.contains("/v3/") {
            "REST"
        } else if headers.get("content-type").map(|ct| ct.contains("json")).unwrap_or(false) {
            "JSON"
        } else {
            return; // Not an API
        };

        let has_auth = headers.contains_key("authorization")
            || headers.contains_key("x-api-key")
            || headers.contains_key("x-auth-token");

        let mut seen = self.seen_urls.lock().await;
        if !seen.contains(url) {
            seen.insert(url.to_string());
            drop(seen);

            println!("  [API] {} {} {}", api_type, method, truncate(url, 60));

            self.apis.lock().await.push(ApiEndpoint {
                url: url.to_string(),
                method: method.to_string(),
                api_type: api_type.to_string(),
                has_auth,
            });

            // Check for internal API patterns
            let internal_patterns = ["/internal", "/private", "/admin", "/_", "/debug", "/config"];
            for pattern in &internal_patterns {
                if url_lower.contains(pattern) {
                    println!("    -> INTERNAL API DETECTED: contains '{}'", pattern);
                }
            }
        }
    }

    async fn detect_auth(&self, _url: &str, headers: &HashMap<String, String>, body: Option<&str>) {
        let mut findings = self.auth_findings.lock().await;

        // Check Authorization header
        if let Some(auth) = headers.get("authorization") {
            let auth_type = if auth.starts_with("Bearer ") {
                if is_jwt(&auth[7..]) { "JWT" } else { "Bearer Token" }
            } else if auth.starts_with("Basic ") {
                "Basic Auth"
            } else {
                "Custom Auth"
            };

            if !findings.iter().any(|f| f.auth_type == auth_type && f.location == "header") {
                println!("  [AUTH] {} in Authorization header", auth_type);
                findings.push(AuthFinding {
                    auth_type: auth_type.to_string(),
                    location: "header".to_string(),
                    key_name: "Authorization".to_string(),
                    sample: redact(auth),
                });
            }
        }

        // Check API key headers
        let api_key_headers = ["x-api-key", "api-key", "x-auth-token", "x-access-token", "x-client-id"];
        for key in &api_key_headers {
            if let Some(value) = headers.get(*key) {
                if !findings.iter().any(|f| f.key_name == *key) {
                    println!("  [AUTH] API Key in header: {}", key);
                    findings.push(AuthFinding {
                        auth_type: "API Key".to_string(),
                        location: "header".to_string(),
                        key_name: key.to_string(),
                        sample: redact(value),
                    });
                }
            }
        }

        // Check CSRF token
        if headers.get("x-csrf-token").is_some() || headers.get("x-xsrf-token").is_some() {
            if !findings.iter().any(|f| f.auth_type == "CSRF Token") {
                println!("  [AUTH] CSRF protection detected");
                findings.push(AuthFinding {
                    auth_type: "CSRF Token".to_string(),
                    location: "header".to_string(),
                    key_name: "X-CSRF-Token".to_string(),
                    sample: "[PRESENT]".to_string(),
                });
            }
        }

        // Check cookies for session tokens
        if let Some(cookie) = headers.get("cookie") {
            let session_patterns = ["session", "sess", "token", "auth", "jwt", "sid"];
            for part in cookie.split(';') {
                let name = part.split('=').next().unwrap_or("").trim().to_lowercase();
                for pattern in &session_patterns {
                    if name.contains(pattern) {
                        if !findings.iter().any(|f| f.key_name.to_lowercase() == name) {
                            println!("  [AUTH] Session cookie: {}", name);
                            findings.push(AuthFinding {
                                auth_type: "Session Cookie".to_string(),
                                location: "cookie".to_string(),
                                key_name: name.clone(),
                                sample: "[REDACTED]".to_string(),
                            });
                        }
                        break;
                    }
                }
            }
        }

        // Check body for OAuth tokens
        if let Some(body) = body {
            if (body.contains("access_token") || body.contains("refresh_token"))
                && !findings.iter().any(|f| f.auth_type == "OAuth2") {
                println!("  [AUTH] OAuth2 tokens in request body");
                findings.push(AuthFinding {
                    auth_type: "OAuth2".to_string(),
                    location: "body".to_string(),
                    key_name: "access_token/refresh_token".to_string(),
                    sample: "[REDACTED]".to_string(),
                });
            }
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
            ("px-cdn", "PerimeterX CDN"),
            ("kasada", "Kasada"),
            ("fingerprintjs", "FingerprintJS"),
            ("challenge", "Challenge Page"),
        ];

        for (pattern, service) in &checks {
            if url_lower.contains(pattern) && !findings.iter().any(|f| f.service == *service) {
                println!("  [ANTIBOT] {} detected: {}", service, truncate(url, 50));
                findings.push(AntiBotFinding {
                    service: service.to_string(),
                    indicator: format!("URL contains '{}'", pattern),
                });
            }
        }
    }

    async fn detect_antibot_response(&self, _url: &str, headers: &HashMap<String, String>) {
        let mut findings = self.antibot_findings.lock().await;

        // Cloudflare
        if (headers.contains_key("cf-ray") || headers.get("server").map(|s| s.contains("cloudflare")).unwrap_or(false))
            && !findings.iter().any(|f| f.service == "Cloudflare") {
            println!("  [ANTIBOT] Cloudflare detected");
            findings.push(AntiBotFinding {
                service: "Cloudflare".to_string(),
                indicator: "CF-Ray header or server header".to_string(),
            });
        }

        // Akamai
        if headers.contains_key("x-akamai-transformed") || headers.contains_key("akamai-grn") {
            if !findings.iter().any(|f| f.service == "Akamai") {
                println!("  [ANTIBOT] Akamai detected");
                findings.push(AntiBotFinding {
                    service: "Akamai".to_string(),
                    indicator: "Akamai headers".to_string(),
                });
            }
        }

        // DataDome
        if headers.contains_key("x-datadome") {
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
            "/user", "/account", "/profile", "/settings",
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
        let sensitive_params = ["api_key", "apikey", "key=", "secret", "password", "token=", "auth="];

        for param in &sensitive_params {
            if url_lower.contains(param) {
                println!("  [SENSITIVE] Potential secret in URL: {} - {}", param, truncate(url, 50));
                self.security_findings.lock().await.push(SecurityFinding {
                    finding_type: "Secret in URL".to_string(),
                    details: format!("Parameter '{}' found in URL", param),
                });
                break;
            }
        }
    }

    async fn check_security_headers(&self, headers: &HashMap<String, String>) {
        let mut missing = self.header_findings.lock().await;

        let required_headers = [
            ("content-security-policy", "Content-Security-Policy"),
            ("strict-transport-security", "Strict-Transport-Security (HSTS)"),
            ("x-frame-options", "X-Frame-Options"),
            ("x-content-type-options", "X-Content-Type-Options"),
            ("referrer-policy", "Referrer-Policy"),
        ];

        for (header, name) in &required_headers {
            if !headers.contains_key(*header) {
                missing.push(name.to_string());
            }
        }
    }

    async fn generate_results(&self, target: &str) -> ReconResults {
        ReconResults {
            target: target.to_string(),
            total_requests: *self.request_count.lock().await,
            apis: self.apis.lock().await.clone(),
            auth_findings: self.auth_findings.lock().await.clone(),
            antibot_findings: self.antibot_findings.lock().await.clone(),
            security_findings: self.security_findings.lock().await.clone(),
            interesting_urls: self.interesting_urls.lock().await.clone(),
            missing_headers: self.header_findings.lock().await.clone(),
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn is_static(url: &str) -> bool {
    let extensions = [".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map"];
    let url_lower = url.to_lowercase();
    extensions.iter().any(|ext| url_lower.contains(ext))
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
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max-3])
    }
}

// ============================================================================
// JavaScript for Client-Side Detection
// ============================================================================

const RECON_JS: &str = r#"
(function() {
    window.__recon = {
        // Detect antibot scripts
        detectAntibot: function() {
            const scripts = Array.from(document.querySelectorAll('script[src]'));
            const patterns = ['captcha', 'recaptcha', 'hcaptcha', 'turnstile', 'datadome', 'perimeterx', 'kasada', 'fingerprint'];
            return scripts.map(s => s.src).filter(src => patterns.some(p => src.toLowerCase().includes(p)));
        },

        // Get storage keys
        getStorageKeys: function() {
            return {
                local: Object.keys(localStorage),
                session: Object.keys(sessionStorage)
            };
        },

        // Get all forms
        getForms: function() {
            return Array.from(document.forms).map(f => ({
                action: f.action,
                method: f.method,
                fields: Array.from(f.elements).filter(e => e.name).map(e => ({ name: e.name, type: e.type }))
            }));
        },

        // Check for common auth patterns in page
        findAuthPatterns: function() {
            const html = document.documentElement.innerHTML;
            const patterns = [];
            if (html.includes('csrf') || html.includes('_token')) patterns.push('CSRF token in page');
            if (html.includes('jwt') || html.includes('Bearer')) patterns.push('JWT references');
            if (html.includes('oauth') || html.includes('OAuth')) patterns.push('OAuth flow');
            return patterns;
        }
    };
    console.log('[RECON] Client instrumentation loaded');
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

    println!();
    println!("{}","=".repeat(70));
    println!(" WEB RECON TOOL - Bug Bounty Edition");
    println!(" Target: {}", target);
    println!("{}","=".repeat(70));
    println!();

    // Initialize engine
    let engine = Arc::new(ReconEngine::new());
    let engine_req = Arc::clone(&engine);
    let engine_resp = Arc::clone(&engine);

    // Launch browser with stealth mode
    println!("[*] Launching browser...");
    let config = BrowserConfig::builder()
        .with_head()  // Remove for headless
        .no_sandbox()
        .arg("--disable-blink-features=AutomationControlled")
        .window_size(1920, 1080)
        .build()?;

    let (browser, mut handler) = Browser::launch(config).await?;

    // Spawn handler
    let handle = tokio::spawn(async move {
        while let Some(_) = handler.next().await {}
    });

    // Create page
    let page = browser.new_page("about:blank").await?;
    page.enable_stealth_mode().await?;

    // Subscribe to events
    let mut req_events = page.event_listener::<EventRequestWillBeSent>().await?;
    let mut resp_events = page.event_listener::<EventResponseReceived>().await?;

    // Spawn analyzers
    let req_handle = tokio::spawn(async move {
        while let Some(event) = req_events.next().await {
            engine_req.analyze_request(&event).await;
        }
    });

    let resp_handle = tokio::spawn(async move {
        while let Some(event) = resp_events.next().await {
            engine_resp.analyze_response(&event).await;
        }
    });

    // Inject client-side recon
    page.evaluate_on_new_document(RECON_JS).await?;

    // Navigate
    println!("[*] Navigating to target...");
    println!();
    page.goto(target).await?;

    // Wait for initial load
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    // Scroll to trigger lazy loading
    println!("[*] Scrolling to trigger lazy-loaded content...");
    page.evaluate("window.scrollTo(0, document.body.scrollHeight / 2)").await?;
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    page.evaluate("window.scrollTo(0, document.body.scrollHeight)").await?;
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Client-side analysis
    println!();
    println!("[*] Running client-side analysis...");

    // Detect antibot scripts
    let antibot: Vec<String> = page.evaluate("window.__recon.detectAntibot()").await?.into_value().unwrap_or_default();
    if !antibot.is_empty() {
        println!("  [ANTIBOT] Scripts found:");
        for script in &antibot {
            println!("    - {}", truncate(script, 70));
        }
    }

    // Get storage
    let storage: serde_json::Value = page.evaluate("window.__recon.getStorageKeys()").await?.into_value().unwrap_or_default();
    println!("  [STORAGE] localStorage keys: {:?}", storage.get("local"));
    println!("  [STORAGE] sessionStorage keys: {:?}", storage.get("session"));

    // Get forms
    let forms: Vec<serde_json::Value> = page.evaluate("window.__recon.getForms()").await?.into_value().unwrap_or_default();
    if !forms.is_empty() {
        println!("  [FORMS] Found {} form(s):", forms.len());
        for form in &forms {
            println!("    - {} {}",
                form.get("method").and_then(|v| v.as_str()).unwrap_or("GET"),
                form.get("action").and_then(|v| v.as_str()).unwrap_or("N/A")
            );
        }
    }

    // Auth patterns
    let auth_patterns: Vec<String> = page.evaluate("window.__recon.findAuthPatterns()").await?.into_value().unwrap_or_default();
    if !auth_patterns.is_empty() {
        println!("  [AUTH-PATTERNS] Found in page:");
        for pattern in &auth_patterns {
            println!("    - {}", pattern);
        }
    }

    // Generate report
    println!();
    println!("{}","=".repeat(70));
    println!(" RECON REPORT");
    println!("{}","=".repeat(70));

    let results = engine.generate_results(target).await;

    println!();
    println!("Total Requests Analyzed: {}", results.total_requests);

    println!();
    println!("--- API Endpoints ({}) ---", results.apis.len());
    for api in &results.apis {
        println!("  [{}] {} {} {}",
            api.api_type,
            api.method,
            truncate(&api.url, 60),
            if api.has_auth { "(AUTH)" } else { "" }
        );
    }

    println!();
    println!("--- Authentication Mechanisms ({}) ---", results.auth_findings.len());
    for auth in &results.auth_findings {
        println!("  [{}] {} in {} = {}", auth.auth_type, auth.key_name, auth.location, auth.sample);
    }

    println!();
    println!("--- Anti-Bot Protections ({}) ---", results.antibot_findings.len());
    for ab in &results.antibot_findings {
        println!("  [{}] {}", ab.service, ab.indicator);
    }

    println!();
    println!("--- Security Findings ({}) ---", results.security_findings.len());
    for finding in &results.security_findings {
        println!("  [{}] {}", finding.finding_type, finding.details);
    }

    println!();
    println!("--- Missing Security Headers ---");
    for header in &results.missing_headers {
        println!("  [!] {}", header);
    }

    println!();
    println!("--- Interesting URLs ({}) ---", results.interesting_urls.len());
    for url in &results.interesting_urls {
        println!("  - {}", truncate(url, 70));
    }

    // Save JSON report
    let report_json = serde_json::to_string_pretty(&results)?;
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let filename = format!("recon_{}.json", timestamp);
    std::fs::write(&filename, &report_json)?;

    println!();
    println!("[*] Report saved to: {}", filename);
    println!();
    println!("{}","=".repeat(70));
    println!(" Scan Complete");
    println!("{}","=".repeat(70));

    // Cleanup
    drop(req_handle);
    drop(resp_handle);
    drop(handle);

    Ok(())
}
