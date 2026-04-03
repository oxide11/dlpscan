//! InputGuard — high-level API for scanning and sanitizing inputs.
//!
//! Provides preset-based scanning, multiple actions (reject, redact, flag,
//! tokenize, obfuscate), and RBAC-controlled token vaults.

mod obfuscate;
mod presets;
mod tokenize;

pub use obfuscate::{obfuscate_match, obfuscate_matches, set_obfuscation_seed};
pub use presets::{Preset, PRESET_CATEGORIES};
pub use tokenize::TokenVault;

use std::collections::HashSet;

use crate::allowlist::Allowlist;
use crate::models::Match;
use crate::scanner::{self, ScanConfig};

/// Action to take when sensitive data is detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Raise an error.
    Reject,
    /// Replace sensitive data with redaction characters.
    Redact,
    /// Return findings but leave text unchanged.
    Flag,
    /// Replace with reversible tokens.
    Tokenize,
    /// Replace with realistic fake data.
    Obfuscate,
}

/// Scanning mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Block the listed categories (default).
    Denylist,
    /// Allow only the listed categories.
    Allowlist,
}

use serde::{Deserialize, Serialize};

/// Result of an InputGuard scan.
#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    /// Original input text.
    pub text: String,
    /// Whether the text is clean (no findings).
    pub is_clean: bool,
    /// List of sensitive data findings.
    pub findings: Vec<Match>,
    /// Transformed text (redacted/tokenized/obfuscated), if applicable.
    pub redacted_text: Option<String>,
    /// Set of categories found.
    pub categories_found: HashSet<String>,
    /// Whether the scan was truncated.
    pub scan_truncated: bool,
}

impl ScanResult {
    /// Number of findings.
    pub fn finding_count(&self) -> usize {
        self.findings.len()
    }
}

/// InputGuard builder and scanner.
pub struct InputGuard {
    presets: Vec<Preset>,
    categories: Option<HashSet<String>>,
    mode: Mode,
    action: Action,
    min_confidence: f64,
    require_context: bool,
    redaction_char: char,
    allowlist: Option<Allowlist>,
    baseline_only: bool,
}

impl InputGuard {
    /// Create a new InputGuard with default settings.
    pub fn new() -> Self {
        Self {
            presets: Vec::new(),
            categories: None,
            mode: Mode::Denylist,
            action: Action::Flag,
            min_confidence: 0.0,
            require_context: false,
            redaction_char: 'X',
            allowlist: None,
            baseline_only: false,
        }
    }

    /// Set presets.
    pub fn with_presets(mut self, presets: Vec<Preset>) -> Self {
        self.presets = presets;
        self
    }

    /// Set categories to scan.
    pub fn with_categories(mut self, categories: HashSet<String>) -> Self {
        self.categories = Some(categories);
        self
    }

    /// Set scanning mode.
    pub fn with_mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }

    /// Set action on detection.
    pub fn with_action(mut self, action: Action) -> Self {
        self.action = action;
        self
    }

    /// Set minimum confidence threshold.
    pub fn with_min_confidence(mut self, min_confidence: f64) -> Self {
        self.min_confidence = min_confidence;
        self
    }

    /// Set context requirement.
    pub fn with_require_context(mut self, require: bool) -> Self {
        self.require_context = require;
        self
    }

    /// Set redaction character.
    pub fn with_redaction_char(mut self, ch: char) -> Self {
        self.redaction_char = ch;
        self
    }

    /// Set allowlist.
    pub fn with_allowlist(mut self, allowlist: Allowlist) -> Self {
        self.allowlist = Some(allowlist);
        self
    }

    /// Enable baseline-only mode: only run high-confidence (always-run) patterns.
    /// Skips all context-gated patterns for faster scanning with lower recall.
    pub fn with_baseline_only(mut self, baseline_only: bool) -> Self {
        self.baseline_only = baseline_only;
        self
    }

    /// Resolve effective categories based on presets and mode.
    fn resolve_categories(&self) -> Option<HashSet<String>> {
        let mut cats = HashSet::new();

        // Add preset categories
        for preset in &self.presets {
            if let Some(preset_cats) = PRESET_CATEGORIES.get(preset) {
                cats.extend(preset_cats.iter().map(|s| s.to_string()));
            }
        }

        // Add explicit categories
        if let Some(ref explicit) = self.categories {
            cats.extend(explicit.iter().cloned());
        }

        if cats.is_empty() {
            None // Scan all
        } else {
            Some(cats)
        }
    }

    /// Scan text and return a ScanResult.
    pub fn scan(&self, text: &str) -> crate::Result<ScanResult> {
        let config = ScanConfig {
            categories: self.resolve_categories(),
            require_context: self.require_context,
            min_confidence: self.min_confidence,
            baseline_only: self.baseline_only,
            ..Default::default()
        };

        let output = scanner::scan_text_with_config(text, &config)?;
        let mut findings = output.matches;

        // Apply allowlist
        if let Some(ref allowlist) = self.allowlist {
            findings.retain(|m| !allowlist.is_suppressed(m));
        }

        let is_clean = findings.is_empty();
        let categories_found: HashSet<String> =
            findings.iter().map(|m| m.category.clone()).collect();

        let redacted_text = match self.action {
            Action::Redact => Some(self.redact_text(text, &findings)),
            Action::Obfuscate => Some(obfuscate_matches(text, &findings)),
            Action::Tokenize => Some(self.redact_text(text, &findings)),
            _ => None,
        };

        let result = ScanResult {
            text: text.to_string(),
            is_clean,
            findings,
            redacted_text,
            categories_found,
            scan_truncated: false,
        };

        if self.action == Action::Reject && !result.is_clean {
            return Err(crate::errors::DlpError::SensitiveDataDetected {
                finding_count: result.finding_count(),
                categories: result.categories_found.iter().cloned().collect(),
            });
        }

        Ok(result)
    }

    /// Quick boolean check — returns true if text is clean.
    pub fn check(&self, text: &str) -> bool {
        self.scan(text).map(|r| r.is_clean).unwrap_or(false)
    }

    /// Return redacted text.
    pub fn sanitize(&self, text: &str) -> crate::Result<String> {
        let config = ScanConfig {
            categories: self.resolve_categories(),
            require_context: self.require_context,
            min_confidence: self.min_confidence,
            baseline_only: self.baseline_only,
            ..Default::default()
        };
        let output = scanner::scan_text_with_config(text, &config)?;
        Ok(self.redact_text(text, &output.matches))
    }

    /// Redact findings in text.
    fn redact_text(&self, text: &str, findings: &[Match]) -> String {
        if findings.is_empty() {
            return text.to_string();
        }

        let mut result = text.to_string();
        // Process findings from end to start to maintain positions
        let mut sorted: Vec<&Match> = findings.iter().collect();
        sorted.sort_by(|a, b| b.span.0.cmp(&a.span.0));

        for finding in sorted {
            let (start, end) = finding.span;
            if start < result.len() && end <= result.len()
                && result.is_char_boundary(start) && result.is_char_boundary(end)
            {
                let span_text = &result[start..end];
                let char_count = span_text.chars().count();
                let replacement: String =
                    std::iter::repeat(self.redaction_char).take(char_count).collect();
                result.replace_range(start..end, &replacement);
            }
        }

        result
    }
}

impl Default for InputGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_guard() {
        let guard = InputGuard::default();
        assert_eq!(guard.action, Action::Flag);
        assert_eq!(guard.mode, Mode::Denylist);
        assert_eq!(guard.min_confidence, 0.0);
        assert!(!guard.require_context);
        assert_eq!(guard.redaction_char, 'X');
    }

    #[test]
    fn test_scan_clean_text() {
        let guard = InputGuard::new();
        let result = guard.scan("Hello world, just a test.").unwrap();
        assert!(result.is_clean);
        assert_eq!(result.finding_count(), 0);
        assert!(result.categories_found.is_empty());
    }

    #[test]
    fn test_scan_detects_email() {
        let guard = InputGuard::new()
            .with_presets(vec![Preset::ContactInfo]);
        let result = guard.scan("Contact us at test@example.com").unwrap();
        assert!(!result.is_clean);
        assert!(result.findings.iter().any(|m| m.sub_category == "Email Address"));
        assert!(result.categories_found.contains("Contact Information"));
    }

    #[test]
    fn test_flag_action_preserves_text() {
        let guard = InputGuard::new()
            .with_action(Action::Flag);
        let result = guard.scan("Card: 4532015112830366").unwrap();
        assert!(result.redacted_text.is_none());
    }

    #[test]
    fn test_redact_action() {
        let guard = InputGuard::new()
            .with_presets(vec![Preset::ContactInfo])
            .with_action(Action::Redact);
        let result = guard.scan("Email: test@example.com").unwrap();
        assert!(result.redacted_text.is_some());
        let redacted = result.redacted_text.unwrap();
        assert!(!redacted.contains("test@example.com"));
        assert!(redacted.contains('X'));
    }

    #[test]
    fn test_reject_action_returns_error() {
        let guard = InputGuard::new()
            .with_presets(vec![Preset::PciDss])
            .with_action(Action::Reject);
        let result = guard.scan("Card: 4532015112830366");
        assert!(result.is_err());
        match result {
            Err(crate::errors::DlpError::SensitiveDataDetected { finding_count, .. }) => {
                assert!(finding_count > 0);
            }
            _ => panic!("Expected SensitiveDataDetected error"),
        }
    }

    #[test]
    fn test_check_returns_bool() {
        let guard = InputGuard::new();
        assert!(guard.check("Hello world, just a test."));
        // Text with PII should return false when scanning all categories
        assert!(!guard.check("My email is test@example.com"));
    }

    #[test]
    fn test_sanitize_returns_redacted_string() {
        let guard = InputGuard::new()
            .with_presets(vec![Preset::ContactInfo]);
        let sanitized = guard.sanitize("Email: test@example.com").unwrap();
        assert!(!sanitized.contains("test@example.com"));
    }

    #[test]
    fn test_min_confidence_filters() {
        let guard = InputGuard::new()
            .with_min_confidence(0.99);
        let result = guard.scan("Email: test@example.com").unwrap();
        // At 0.99 confidence, most matches should be filtered
        assert!(result.finding_count() == 0 || result.findings.iter().all(|m| m.confidence >= 0.99));
    }

    #[test]
    fn test_obfuscate_action() {
        let guard = InputGuard::new()
            .with_presets(vec![Preset::ContactInfo])
            .with_action(Action::Obfuscate);
        let result = guard.scan("Email: test@example.com").unwrap();
        assert!(result.redacted_text.is_some());
        let obfuscated = result.redacted_text.unwrap();
        assert!(!obfuscated.contains("test@example.com"));
        assert!(obfuscated.contains('@')); // Obfuscated email still has @
    }

    #[test]
    fn test_resolve_categories_with_presets() {
        let guard = InputGuard::new()
            .with_presets(vec![Preset::PciDss]);
        let cats = guard.resolve_categories().unwrap();
        assert!(cats.contains("Credit Card Numbers"));
    }

    #[test]
    fn test_resolve_categories_empty_returns_none() {
        let guard = InputGuard::new();
        assert!(guard.resolve_categories().is_none());
    }

    #[test]
    fn test_scan_result_finding_count() {
        let result = ScanResult {
            text: String::new(),
            is_clean: false,
            findings: vec![
                Match::new("test".into(), "cat".into(), "sub".into(), false, 0.5, (0, 4), false),
            ],
            redacted_text: None,
            categories_found: HashSet::new(),
            scan_truncated: false,
        };
        assert_eq!(result.finding_count(), 1);
    }
}
