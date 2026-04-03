//! Streaming scanner for processing data in chunks.

use std::sync::Mutex;

use crate::models::Match;
use crate::scanner::{self, ScanConfig};

/// Stream scanner that processes text in buffered chunks.
pub struct StreamScanner {
    buffer: Mutex<String>,
    buffer_size: usize,
    overlap: usize,
    config: ScanConfig,
}

impl StreamScanner {
    /// Create a new stream scanner.
    pub fn new(buffer_size: usize, overlap: usize) -> Self {
        let buffer_size = buffer_size.min(100 * 1024 * 1024); // Cap at 100MB
        let buffer_size = buffer_size.max(1024); // At least 1KB
        let overlap = overlap.min(buffer_size / 2); // Overlap can't exceed half buffer
        Self {
            buffer: Mutex::new(String::with_capacity(buffer_size + overlap)),
            buffer_size,
            overlap,
            config: ScanConfig::default(),
        }
    }

    /// Create with custom scan config.
    pub fn with_config(mut self, config: ScanConfig) -> Self {
        self.config = config;
        self
    }

    /// Feed a chunk of text. Returns matches if the buffer is full.
    pub fn feed(&self, chunk: &str) -> Vec<Match> {
        // Take the text out of the lock quickly to minimize lock hold time
        let text = {
            let mut buf = self.buffer.lock().unwrap_or_else(|e| e.into_inner());
            buf.push_str(chunk);

            if buf.len() >= self.buffer_size {
                // Take the full buffer, replace with overlap tail
                let text = std::mem::take(&mut *buf);
                if text.len() > self.overlap {
                    let mut split_at = text.len() - self.overlap;
                    while split_at > 0 && !text.is_char_boundary(split_at) {
                        split_at -= 1;
                    }
                    *buf = text[split_at..].to_string();
                }
                Some(text)
            } else {
                None
            }
        };
        // Lock is released — scan outside the critical section
        match text {
            Some(text) => match scanner::scan_text_with_config(&text, &self.config) {
                Ok(output) => output.matches,
                Err(e) => {
                    tracing::error!(error = %e, "Streaming scan failed on buffer flush");
                    vec![]
                }
            },
            None => vec![],
        }
    }

    /// Flush remaining buffer and return any matches.
    pub fn flush(&self) -> Vec<Match> {
        let mut buf = self.buffer.lock().unwrap_or_else(|e| e.into_inner());
        if buf.is_empty() {
            return vec![];
        }

        let text = std::mem::take(&mut *buf);
        match scanner::scan_text_with_config(&text, &self.config) {
            Ok(output) => output.matches,
            Err(e) => {
                tracing::error!(error = %e, "Streaming scan failed on final flush");
                vec![]
            }
        }
    }

    /// Reset the scanner state.
    pub fn reset(&self) {
        let mut buf = self.buffer.lock().unwrap_or_else(|e| e.into_inner());
        buf.clear();
    }
}

impl Default for StreamScanner {
    fn default() -> Self {
        Self::new(4096, 256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_creates_scanner() {
        let s = StreamScanner::default();
        assert_eq!(s.buffer_size, 4096);
        assert_eq!(s.overlap, 256);
    }

    #[test]
    fn test_buffer_size_clamped() {
        // Too small
        let s = StreamScanner::new(100, 10);
        assert_eq!(s.buffer_size, 1024);
        // Too large
        let s = StreamScanner::new(200 * 1024 * 1024, 100);
        assert_eq!(s.buffer_size, 100 * 1024 * 1024);
    }

    #[test]
    fn test_overlap_clamped_to_half_buffer() {
        let s = StreamScanner::new(2048, 2048);
        assert_eq!(s.overlap, 1024); // half of 2048
    }

    #[test]
    fn test_feed_below_buffer_returns_empty() {
        let s = StreamScanner::new(4096, 256);
        let matches = s.feed("Hello world");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_flush_empty_returns_empty() {
        let s = StreamScanner::default();
        assert!(s.flush().is_empty());
    }

    #[test]
    fn test_feed_and_flush_detects_email() {
        let s = StreamScanner::new(1024, 128);
        // Feed text below threshold
        let _ = s.feed("Contact us at test@example.com for details.");
        // Flush should find the email
        let matches = s.flush();
        assert!(matches.iter().any(|m| m.sub_category == "Email Address"));
    }

    #[test]
    fn test_feed_triggers_scan_at_buffer_size() {
        let s = StreamScanner::new(1024, 128);
        // Feed enough data to exceed buffer_size
        let chunk = "SSN: 123-45-6789 ".repeat(100);
        let matches = s.feed(&chunk);
        // Should have triggered a scan and found SSNs
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_reset_clears_buffer() {
        let s = StreamScanner::default();
        s.feed("some text");
        s.reset();
        assert!(s.flush().is_empty());
    }

    #[test]
    fn test_with_config() {
        let config = ScanConfig {
            min_confidence: 0.8,
            ..Default::default()
        };
        let s = StreamScanner::default().with_config(config);
        assert_eq!(s.config.min_confidence, 0.8);
    }

    #[test]
    fn test_multibyte_overlap_safety() {
        // Feed multi-byte UTF-8 text to ensure overlap slicing doesn't panic
        let s = StreamScanner::new(1024, 256);
        let chunk = "日本語テスト ".repeat(200); // ~1200 bytes of 3-byte chars
        let _ = s.feed(&chunk);
        let _ = s.flush(); // Should not panic
    }
}
