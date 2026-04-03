//! Webhook notification system for DLP scan findings.
//!
//! Sends HTTP POST notifications to registered URLs when sensitive data is detected.
//! Supports retry with exponential backoff, fire-and-forget delivery in background threads.

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use crate::guard::ScanResult;

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
}

impl WebhookNotifier {
    pub fn new(urls: Vec<String>) -> Self {
        Self {
            urls: Mutex::new(urls),
            retries: 2,
            timeout_secs: 10,
            backoff_base: 1.0,
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

    /// Add a URL to the notification list.
    pub fn add_url(&self, url: &str) {
        if let Ok(mut urls) = self.urls.lock() {
            urls.push(url.to_string());
        }
    }

    /// Remove a URL from the notification list.
    pub fn remove_url(&self, url: &str) {
        if let Ok(mut urls) = self.urls.lock() {
            urls.retain(|u| u != url);
        }
    }

    /// Send notification for scan result. Spawns background threads for delivery.
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

        for url in urls {
            let payload = payload.clone();
            std::thread::spawn(move || {
                deliver(&url, &payload, retries, timeout, backoff);
            });
        }
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
    let body = match serde_json::to_vec(payload) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(url, %e, "Failed to serialize webhook payload");
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
                tracing::warn!(url, status, attempt, "Webhook delivery got non-2xx");
            }
            Err(e) => {
                tracing::warn!(url, %e, attempt, "Webhook delivery error");
            }
        }
    }

    tracing::error!(url, retries, "Webhook delivery exhausted all retries");
}

/// Simple HTTP POST using TcpStream.
fn http_post(url: &str, body: &[u8], timeout_secs: u64) -> Result<u16, String> {
    use std::io::{Read, Write};

    let url_body = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("Only http:// URLs supported (got {url})"))?;

    let (host_port, path) = url_body
        .find('/')
        .map(|i| (&url_body[..i], &url_body[i..]))
        .unwrap_or((url_body, "/"));

    let (host, port) = if let Some(i) = host_port.find(':') {
        (
            &host_port[..i],
            host_port[i + 1..].parse::<u16>().unwrap_or(80),
        )
    } else {
        (host_port, 80u16)
    };

    let addr = format!("{host}:{port}");
    let timeout = std::time::Duration::from_secs(timeout_secs);
    let mut stream = std::net::TcpStream::connect_timeout(
        &addr.parse().map_err(|e: std::net::AddrParseError| e.to_string())?,
        timeout,
    )
    .map_err(|e| e.to_string())?;
    stream.set_read_timeout(Some(timeout)).ok();

    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
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
        notifier.add_url("http://b.com");
        assert_eq!(notifier.urls.lock().unwrap().len(), 2);
        notifier.remove_url("http://a.com");
        assert_eq!(notifier.urls.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_epoch_to_parts() {
        let (s, m, h, d, mon, y) = epoch_to_parts(0);
        assert_eq!((y, mon, d, h, m, s), (1970, 1, 1, 0, 0, 0));
    }
}
