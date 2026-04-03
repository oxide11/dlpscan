//! Webhook notification system for DLP scan findings.
//!
//! Sends HTTP POST notifications to registered URLs when sensitive data is detected.
//! Supports retry with exponential backoff, fire-and-forget delivery in background threads.

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use crate::guard::ScanResult;

/// Maximum number of concurrent notify dispatch threads across all notifiers.
const MAX_NOTIFY_THREADS: usize = 16;

/// Global counter for active notify dispatch threads.
static ACTIVE_NOTIFY_THREADS: AtomicUsize = AtomicUsize::new(0);

// ---------------------------------------------------------------------------
// URL safety & sanitisation helpers
// ---------------------------------------------------------------------------

/// Parse a URL into (scheme, userinfo, host, port, path).
/// Returns `Err` if the URL is malformed or has an unsupported scheme.
fn parse_url(url: &str) -> Result<(&str, Option<&str>, &str, u16, &str), String> {
    let (scheme, rest) = if let Some(r) = url.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = url.strip_prefix("http://") {
        ("http", r)
    } else {
        return Err(format!("Unsupported URL scheme (must be http:// or https://): {}", sanitize_url(url)));
    };

    // Split off userinfo (user:pass@host)
    let (userinfo, after_userinfo) = if let Some(at) = rest.find('@') {
        // Make sure '@' appears before the first '/'
        let slash = rest.find('/').unwrap_or(rest.len());
        if at < slash {
            (Some(&rest[..at]), &rest[at + 1..])
        } else {
            (None, rest)
        }
    } else {
        (None, rest)
    };

    let (host_port, path) = after_userinfo
        .find('/')
        .map(|i| (&after_userinfo[..i], &after_userinfo[i..]))
        .unwrap_or((after_userinfo, "/"));

    let default_port: u16 = if scheme == "https" { 443 } else { 80 };
    let (host, port) = if host_port.starts_with('[') {
        // IPv6 bracket notation: [::1]:port or [::ffff:127.0.0.1]
        if let Some(bracket_end) = host_port.find(']') {
            let ipv6_host = &host_port[..bracket_end + 1];
            let after_bracket = &host_port[bracket_end + 1..];
            let port = if let Some(colon_port) = after_bracket.strip_prefix(':') {
                colon_port.parse::<u16>().unwrap_or(default_port)
            } else {
                default_port
            };
            (ipv6_host, port)
        } else {
            (host_port, default_port)
        }
    } else if let Some(i) = host_port.rfind(':') {
        // IPv4 or hostname with port — use rfind to handle edge cases
        let potential_port = &host_port[i + 1..];
        if let Ok(p) = potential_port.parse::<u16>() {
            (&host_port[..i], p)
        } else {
            (host_port, default_port)
        }
    } else {
        (host_port, default_port)
    };

    Ok((scheme, userinfo, host, port, path))
}

/// Strip credentials (userinfo) from a URL before logging.
pub fn sanitize_url(url: &str) -> String {
    // Find scheme
    let scheme_end = url.find("://").map(|i| i + 3).unwrap_or(0);
    let rest = &url[scheme_end..];
    // Check for userinfo
    if let Some(at) = rest.find('@') {
        let slash = rest.find('/').unwrap_or(rest.len());
        if at < slash {
            // Strip userinfo
            return format!("{}***@{}", &url[..scheme_end], &rest[at + 1..]);
        }
    }
    url.to_string()
}

/// Check whether a URL is safe to connect to (SSRF protection).
///
/// Rejects:
/// - URLs without http:// or https:// scheme
/// - `localhost` hostname
/// - Private/internal IP ranges: 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12,
///   192.168.0.0/16, 169.254.0.0/16, ::1, fd00::/8
pub fn is_safe_url(url: &str) -> bool {
    let (_scheme, _userinfo, host, _port, _path) = match parse_url(url) {
        Ok(parts) => parts,
        Err(_) => return false,
    };

    let host_lower = host.to_lowercase();

    // Reject localhost
    if host_lower == "localhost" {
        return false;
    }

    // Reject IPv6 loopback and private
    let trimmed = host_lower.trim_start_matches('[').trim_end_matches(']');
    if trimmed == "::1" || trimmed.starts_with("fd") {
        return false;
    }

    // Try parsing as IPv4
    if let Ok(ip) = trimmed.parse::<std::net::Ipv4Addr>() {
        if is_private_ipv4(&ip) {
            return false;
        }
    }

    // Try parsing as IPv6
    if let Ok(ip) = trimmed.parse::<std::net::Ipv6Addr>() {
        if ip.is_loopback() {
            return false;
        }
        let segs = ip.segments();
        // fd00::/8 (unique local)
        if (segs[0] >> 8) == 0xfd {
            return false;
        }
        // fe80::/10 (link-local)
        if (segs[0] & 0xffc0) == 0xfe80 {
            return false;
        }
        // Check IPv4-mapped IPv6 (::ffff:x.x.x.x) to prevent SSRF bypass
        if segs[0] == 0 && segs[1] == 0 && segs[2] == 0
            && segs[3] == 0 && segs[4] == 0 && segs[5] == 0xffff
        {
            let ipv4 = std::net::Ipv4Addr::new(
                (segs[6] >> 8) as u8, segs[6] as u8,
                (segs[7] >> 8) as u8, segs[7] as u8,
            );
            if is_private_ipv4(&ipv4) {
                return false;
            }
        }
    }

    true
}

/// Check if an IPv4 address is private/internal.
fn is_private_ipv4(ip: &std::net::Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 0           // 0.0.0.0/8 (includes 0.0.0.0)
    || o[0] == 127      // 127.0.0.0/8 (loopback)
    || o[0] == 10       // 10.0.0.0/8
    || (o[0] == 172 && (o[1] >= 16 && o[1] <= 31))  // 172.16.0.0/12
    || (o[0] == 192 && o[1] == 168)                  // 192.168.0.0/16
    || (o[0] == 169 && o[1] == 254)                  // 169.254.0.0/16 (link-local)
}

// ---------------------------------------------------------------------------
// Payload types
// ---------------------------------------------------------------------------

/// Webhook notification payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookPayload {
    pub event_type: String,
    pub timestamp: String,
    pub finding_count: usize,
    pub categories: Vec<String>,
    pub source: Option<String>,
    pub details: Vec<FindingDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingDetail {
    pub category: String,
    pub sub_category: String,
    pub confidence: f64,
    pub redacted_match: String,
}

/// Build a webhook payload from a ScanResult.
pub fn build_payload(result: &ScanResult, source: Option<&str>) -> WebhookPayload {
    WebhookPayload {
        event_type: "dlpscan.finding".to_string(),
        timestamp: iso8601_now(),
        finding_count: result.finding_count(),
        categories: result.categories_found.iter().cloned().collect(),
        source: source.map(|s| s.to_string()),
        details: result
            .findings
            .iter()
            .map(|m| FindingDetail {
                category: m.category.clone(),
                sub_category: m.sub_category.clone(),
                confidence: m.confidence,
                redacted_match: m.redacted_text(),
            })
            .collect(),
    }
}

// ---------------------------------------------------------------------------
// WebhookNotifier
// ---------------------------------------------------------------------------

/// Webhook notifier that sends findings to registered URLs.
pub struct WebhookNotifier {
    urls: Mutex<Vec<String>>,
    retries: usize,
    timeout_secs: u64,
    backoff_base: f64,
    max_concurrent: usize,
}

impl WebhookNotifier {
    pub fn new(urls: Vec<String>) -> Self {
        Self {
            urls: Mutex::new(urls),
            retries: 2,
            timeout_secs: 10,
            backoff_base: 1.0,
            max_concurrent: 8,
        }
    }

    pub fn with_retries(mut self, retries: usize) -> Self {
        self.retries = retries;
        self
    }

    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    pub fn with_backoff(mut self, base: f64) -> Self {
        self.backoff_base = base;
        self
    }

    pub fn with_max_concurrent(mut self, max: usize) -> Self {
        self.max_concurrent = max;
        self
    }

    /// Add a URL to the notification list.
    /// Returns `Err` if the URL fails SSRF safety checks.
    pub fn add_url(&self, url: &str) -> Result<(), String> {
        if !is_safe_url(url) {
            return Err(format!(
                "Refusing to add unsafe/internal URL: {}",
                sanitize_url(url)
            ));
        }
        let mut urls = self.urls.lock().unwrap_or_else(|e| e.into_inner());
        urls.push(url.to_string());
        Ok(())
    }

    /// Remove a URL from the notification list.
    pub fn remove_url(&self, url: &str) {
        let mut urls = self.urls.lock().unwrap_or_else(|e| e.into_inner());
        urls.retain(|u| u != url);
    }

    /// Send notification for scan result.
    /// Spawns a single background thread that delivers to all URLs sequentially,
    /// bounded by `max_concurrent`.
    /// No-op if the result is clean (no findings).
    pub fn notify(&self, result: &ScanResult, source: Option<&str>) {
        if result.is_clean {
            return;
        }

        let payload = build_payload(result, source);
        let urls = self.urls.lock().map(|u| u.clone()).unwrap_or_default();
        let retries = self.retries;
        let timeout = self.timeout_secs;
        let backoff = self.backoff_base;
        let max_concurrent = self.max_concurrent;

        // Check global thread bound before spawning
        if ACTIVE_NOTIFY_THREADS.load(Ordering::SeqCst) >= MAX_NOTIFY_THREADS {
            tracing::warn!("Webhook notification thread limit reached, dropping notification");
            return;
        }
        ACTIVE_NOTIFY_THREADS.fetch_add(1, Ordering::SeqCst);

        // Spawn a single thread that processes URLs in bounded batches
        std::thread::spawn(move || {
            struct ThreadGuard;
            impl Drop for ThreadGuard {
                fn drop(&mut self) {
                    ACTIVE_NOTIFY_THREADS.fetch_sub(1, Ordering::SeqCst);
                }
            }
            let _guard = ThreadGuard;

            let active = Arc::new(AtomicUsize::new(0));
            let mut handles = Vec::new();

            for url in urls {
                // Wait until we are below the concurrency limit
                while active.load(Ordering::SeqCst) >= max_concurrent {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }

                active.fetch_add(1, Ordering::SeqCst);
                let payload = payload.clone();
                let active = Arc::clone(&active);
                let handle = std::thread::spawn(move || {
                    deliver(&url, &payload, retries, timeout, backoff);
                    active.fetch_sub(1, Ordering::SeqCst);
                });
                handles.push(handle);
            }

            for handle in handles {
                let _ = handle.join();
            }
        });
    }
}

/// Deliver payload to URL with retry and exponential backoff.
fn deliver(
    url: &str,
    payload: &WebhookPayload,
    retries: usize,
    timeout_secs: u64,
    backoff_base: f64,
) {
    let safe_url = sanitize_url(url);
    let body = match serde_json::to_vec(payload) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(url = %safe_url, %e, "Failed to serialize webhook payload");
            return;
        }
    };

    for attempt in 0..=retries {
        if attempt > 0 {
            let wait_secs = backoff_base * (2.0_f64).powi(attempt as i32 - 1);
            std::thread::sleep(std::time::Duration::from_secs_f64(wait_secs));
        }

        match http_post(url, &body, timeout_secs) {
            Ok(status) if (200..300).contains(&status) => return,
            Ok(status) => {
                tracing::warn!(url = %safe_url, status, attempt, "Webhook delivery got non-2xx");
            }
            Err(e) => {
                tracing::warn!(url = %safe_url, %e, attempt, "Webhook delivery error");
            }
        }
    }

    tracing::error!(url = %safe_url, retries, "Webhook delivery exhausted all retries");
}

/// HTTP POST supporting both `http://` and `https://` URLs.
///
/// For `http://` URLs, uses a raw `TcpStream`.
/// For `https://` URLs, uses rustls when the `tls` feature is enabled.
fn http_post(url: &str, body: &[u8], timeout_secs: u64) -> Result<u16, String> {
    use std::io::{Read, Write};

    let (scheme, _userinfo, host, port, path) = parse_url(url)?;

    let addr = format!("{host}:{port}");
    let timeout = std::time::Duration::from_secs(timeout_secs);
    let tcp_stream = std::net::TcpStream::connect_timeout(
        &addr.parse().map_err(|e: std::net::AddrParseError| e.to_string())?,
        timeout,
    )
    .map_err(|e| e.to_string())?;
    if let Err(e) = tcp_stream.set_read_timeout(Some(timeout)) {
        tracing::warn!(error = %e, "Failed to set read timeout on webhook socket");
    }

    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );

    if scheme == "https" {
        #[cfg(feature = "tls")]
        {
            let root_store = rustls::RootCertStore::from_iter(
                webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
            );
            let tls_config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            let server_name = host.to_string().try_into()
                .map_err(|e: rustls::pki_types::InvalidDnsNameError| e.to_string())?;
            let mut conn = rustls::ClientConnection::new(
                std::sync::Arc::new(tls_config),
                server_name,
            ).map_err(|e| e.to_string())?;
            let mut tls = rustls::Stream::new(&mut conn, &mut &tcp_stream);
            tls.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
            tls.write_all(body).map_err(|e| e.to_string())?;
            let mut response = vec![0u8; 512];
            let n = tls.read(&mut response).map_err(|e| e.to_string())?;
            let resp = String::from_utf8_lossy(&response[..n]);
            return resp.lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .and_then(|s| s.parse::<u16>().ok())
                .ok_or_else(|| "Could not parse HTTP status".to_string());
        }
        #[cfg(not(feature = "tls"))]
        return Err(format!(
            "HTTPS URLs require the `tls` or `async-support` feature. \
             Cannot connect to {} without TLS support.",
            sanitize_url(url)
        ));
    }

    let mut stream = tcp_stream;
    stream.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    stream.write_all(body).map_err(|e| e.to_string())?;

    let mut response = vec![0u8; 512];
    let n = stream.read(&mut response).map_err(|e| e.to_string())?;
    let resp = String::from_utf8_lossy(&response[..n]);

    resp.lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| "Could not parse HTTP status".to_string())
}

// ---------------------------------------------------------------------------
// Global registry
// ---------------------------------------------------------------------------

static NOTIFIERS: Lazy<Mutex<Vec<Arc<WebhookNotifier>>>> =
    Lazy::new(|| Mutex::new(Vec::new()));

/// Register a notifier in the global registry.
pub fn register_notifier(notifier: Arc<WebhookNotifier>) {
    if let Ok(mut list) = NOTIFIERS.lock() {
        list.push(notifier);
    }
}

/// Unregister a notifier from the global registry.
pub fn unregister_notifier(notifier: &Arc<WebhookNotifier>) {
    if let Ok(mut list) = NOTIFIERS.lock() {
        list.retain(|n| !Arc::ptr_eq(n, notifier));
    }
}

/// Notify all registered notifiers about scan findings.
pub fn notify_findings(result: &ScanResult, source: Option<&str>) {
    if let Ok(list) = NOTIFIERS.lock() {
        for notifier in list.iter() {
            notifier.notify(result, source);
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn iso8601_now() -> String {
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (s, m, h, day, mon, year) = epoch_to_parts(secs);
    format!("{year:04}-{mon:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

fn epoch_to_parts(epoch: u64) -> (u64, u64, u64, u64, u64, u64) {
    let s = epoch % 60;
    let m = (epoch / 60) % 60;
    let h = (epoch / 3600) % 24;
    let mut days = epoch / 86400;
    let mut year = 1970u64;
    loop {
        let yd = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) { 366 } else { 365 };
        if days < yd { break; }
        days -= yd;
        year += 1;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let mdays = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut mon = 0u64;
    for md in mdays {
        if days < md { break; }
        days -= md;
        mon += 1;
    }
    (s, m, h, days + 1, mon + 1, year)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_build_payload_clean() {
        let result = ScanResult {
            text: "hello".to_string(),
            is_clean: true,
            findings: vec![],
            redacted_text: None,
            categories_found: HashSet::new(),
            scan_truncated: false,
        };
        let payload = build_payload(&result, Some("test"));
        assert_eq!(payload.finding_count, 0);
        assert_eq!(payload.source, Some("test".to_string()));
    }

    #[test]
    fn test_notifier_url_management() {
        let notifier = WebhookNotifier::new(vec!["http://a.com".to_string()]);
        notifier.add_url("http://b.com").unwrap();
        assert_eq!(notifier.urls.lock().unwrap().len(), 2);
        notifier.remove_url("http://a.com");
        assert_eq!(notifier.urls.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_add_url_rejects_internal() {
        let notifier = WebhookNotifier::new(vec![]);
        assert!(notifier.add_url("http://127.0.0.1/hook").is_err());
        assert!(notifier.add_url("http://localhost/hook").is_err());
        assert!(notifier.add_url("http://10.0.0.1/hook").is_err());
        assert!(notifier.add_url("http://192.168.1.1/hook").is_err());
        assert!(notifier.add_url("http://172.16.0.1/hook").is_err());
        assert!(notifier.add_url("http://169.254.1.1/hook").is_err());
        assert!(notifier.add_url("ftp://example.com/hook").is_err());
    }

    #[test]
    fn test_is_safe_url_accepts_public() {
        assert!(is_safe_url("http://example.com/hook"));
        assert!(is_safe_url("https://hooks.slack.com/services/T00/B00/xxx"));
    }

    #[test]
    fn test_is_safe_url_blocks_zero_address() {
        assert!(!is_safe_url("http://0.0.0.0/hook"));
        assert!(!is_safe_url("http://0.0.0.1/hook"));
    }

    #[test]
    fn test_is_safe_url_blocks_ipv4_mapped_ipv6() {
        // ::ffff:127.0.0.1 — IPv4-mapped loopback
        assert!(!is_safe_url("http://[::ffff:127.0.0.1]/hook"));
        // ::ffff:10.0.0.1 — IPv4-mapped private
        assert!(!is_safe_url("http://[::ffff:10.0.0.1]/hook"));
        // ::ffff:192.168.1.1 — IPv4-mapped private
        assert!(!is_safe_url("http://[::ffff:192.168.1.1]/hook"));
    }

    #[test]
    fn test_sanitize_url_strips_credentials() {
        assert_eq!(
            sanitize_url("http://user:pass@example.com/hook"),
            "http://***@example.com/hook"
        );
        assert_eq!(
            sanitize_url("https://example.com/hook"),
            "https://example.com/hook"
        );
    }

    #[test]
    fn test_parse_url_both_schemes() {
        let (scheme, _, host, port, path) = parse_url("http://example.com/test").unwrap();
        assert_eq!(scheme, "http");
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/test");

        let (scheme, _, host, port, _) = parse_url("https://secure.example.com:8443/api").unwrap();
        assert_eq!(scheme, "https");
        assert_eq!(host, "secure.example.com");
        assert_eq!(port, 8443);
    }

    #[test]
    fn test_epoch_to_parts() {
        let (s, m, h, d, mon, y) = epoch_to_parts(0);
        assert_eq!((y, mon, d, h, m, s), (1970, 1, 1, 0, 0, 0));
    }
}
