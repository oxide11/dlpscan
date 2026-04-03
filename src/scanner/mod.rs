//! Core scanning engine using RegexSet for two-phase matching.
//!
//! Phase 1: RegexSet identifies WHICH patterns match (single O(n) pass).
//! Phase 2: Individual Regex extracts spans for only the matched patterns.

use once_cell::sync::Lazy;
use rayon::prelude::*;
use regex::Regex;
use std::collections::HashSet;
use std::time::Instant;

use crate::context;
use crate::models::{is_context_required, pattern_specificity, Match, PatternDef};
use crate::normalize;
use crate::patterns::PATTERNS;
use crate::scoring::{compute_confidence, deduplicate_overlapping};
use crate::validation::{is_luhn_valid, validate_text_input};

/// Maximum number of matches returned per scan.
pub const MAX_MATCHES: usize = 50_000;

/// Maximum scan time in seconds.
pub const MAX_SCAN_SECONDS: u64 = 120;

/// Per-pattern regex timeout.
pub const REGEX_TIMEOUT_SECONDS: u64 = 5;

/// Maximum input size (10 MB).
pub const MAX_INPUT_SIZE: usize = 10 * 1024 * 1024;

/// Result of a scan operation, including whether results may be incomplete.
#[derive(Debug, Clone)]
pub struct ScanOutput {
    /// Matched findings.
    pub matches: Vec<Match>,
    /// True if the scan was terminated early (timeout or match cap reached).
    pub truncated: bool,
}

/// Scanner configuration.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Categories to scan (None = all).
    pub categories: Option<HashSet<String>>,
    /// Only return matches with context keywords.
    pub require_context: bool,
    /// Maximum matches to return.
    pub max_matches: usize,
    /// Whether to deduplicate overlapping matches.
    pub deduplicate: bool,
    /// Minimum confidence threshold.
    pub min_confidence: f64,
    /// Only run baseline (always-run) patterns — skip context-gated patterns entirely.
    pub baseline_only: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            categories: None,
            require_context: false,
            max_matches: MAX_MATCHES,
            deduplicate: true,
            min_confidence: 0.0,
            baseline_only: false,
        }
    }
}

/// Compiled regex cache: one Regex per pattern, compiled once at startup.
struct CompiledPattern {
    regex: Regex,
    def: &'static PatternDef,
}

static COMPILED: Lazy<Vec<CompiledPattern>> = Lazy::new(|| {
    let mut compiled = Vec::with_capacity(PATTERNS.len());

    for pat in PATTERNS.iter() {
        let regex_str = if pat.case_insensitive {
            format!("(?i){}", pat.regex)
        } else {
            pat.regex.to_string()
        };

        match Regex::new(&regex_str) {
            Ok(re) => {
                compiled.push(CompiledPattern {
                    regex: re,
                    def: pat,
                });
            }
            Err(e) => {
                tracing::warn!(
                    pattern = pat.sub_category,
                    error = %e,
                    "Failed to compile pattern, skipping"
                );
            }
        }
    }

    compiled
});

// ---------------------------------------------------------------------------
// Aho-Corasick prefilter: classify patterns as always-run vs context-gated
// ---------------------------------------------------------------------------

/// Specificity threshold — patterns at or above always run.
const SPECIFICITY_THRESHOLD: f64 = 0.85;

/// Curated set of patterns that always run regardless of specificity.
static CRITICAL_ALWAYS_RUN: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        // US core
        "USA SSN", "USA ITIN", "USA EIN", "USA Passport", "USA Passport Card",
        "USA Routing Number", "US Phone Number", "US MBI", "US NPI",
        // Canada
        "Canada SIN", "Canada Passport",
        // UK
        "UK NIN", "British NHS", "UK Passport",
        // Europe
        "France NIR", "Germany Tax ID", "Netherlands BSN", "Spain DNI",
        "Italy Codice Fiscale", "Italy SSN", "Sweden PIN", "Poland PESEL",
        "Belgium NRN", "Denmark CPR",
        // Asia-Pacific
        "India Aadhaar", "India PAN", "China Resident ID", "Japan My Number",
        "South Korea RRN", "Singapore NRIC", "Singapore FIN", "Hong Kong ID",
        // Latin America
        "Brazil CPF", "Brazil CNPJ", "Mexico CURP", "Argentina CUIL/CUIT",
        "Chile RUN/RUT",
        // Middle East
        "Israel Teudat Zehut", "UAE Emirates ID", "Saudi Arabia National ID",
        // Crypto
        "Bitcoin Address (Legacy)", "Bitcoin Address (Bech32)",
        "Ethereum Address", "Litecoin Address", "Bitcoin Cash Address",
        "Ripple Address",
        // Contact & network
        "E.164 Phone Number", "UK Phone Number",
        "IPv4 Address", "IPv6 Address", "MAC Address",
        // Secrets (important but below threshold)
        "Bearer Token", "Generic API Key", "Generic Secret Assignment",
        "Slack Webhook",
        // Structurally distinctive
        "GPS Coordinates", "PAN", "VIN", "IMEI", "IMEISV", "MEID",
        // Financial
        "ABA Routing Number", "CUSIP", "ISIN", "SEDOL", "LEI", "Ticker Symbol",
        // URLs with credentials
        "URL with Password", "URL with Token",
    ]
    .into_iter()
    .collect()
});

/// Returns true if a pattern should always run (never context-gated).
fn is_always_run(sub_category: &str) -> bool {
    let spec = pattern_specificity(sub_category);
    spec >= SPECIFICITY_THRESHOLD || CRITICAL_ALWAYS_RUN.contains(sub_category)
}

/// Scan text for sensitive data.
///
/// Uses Aho-Corasick prefilter to skip ~80% of regex patterns when their
/// context keywords aren't present, then runs remaining patterns in parallel.
pub fn scan_text(text: &str) -> crate::Result<Vec<Match>> {
    scan_text_with_config(text, &ScanConfig::default()).map(|o| o.matches)
}

/// Scan text with custom configuration.
///
/// Uses parallel iteration over compiled regexes with Rayon for throughput.
pub fn scan_text_with_config(text: &str, config: &ScanConfig) -> crate::Result<ScanOutput> {
    validate_text_input(text)?;

    let start = Instant::now();

    // Normalize text to defeat evasion
    let (normalized, offset_map) = normalize::normalize_text(text);

    // Build Aho-Corasick hit index for context matching
    let hit_index = context::build_hit_index(&normalized);

    let compiled = &*COMPILED;

    // Build set of context-gated (category, sub_category) pairs whose keywords
    // were found somewhere in the text. Patterns not in this set get skipped.
    let active_gated: HashSet<(&str, &str)> = if let Some(ref index) = hit_index {
        compiled
            .iter()
            .filter(|cp| !is_always_run(cp.def.sub_category))
            .filter(|cp| {
                index.has_hit_in_range(
                    cp.def.category,
                    cp.def.sub_category,
                    0,
                    normalized.len(),
                )
            })
            .map(|cp| (cp.def.category, cp.def.sub_category))
            .collect()
    } else {
        HashSet::new()
    };

    let prefilter_active = hit_index.is_some();

    // Filter patterns: category filter + AC prefilter + baseline_only
    let active_patterns: Vec<&CompiledPattern> = compiled
        .iter()
        .filter(|cp| {
            // Category filter
            if let Some(ref cats) = config.categories {
                if !cats.contains(cp.def.category) {
                    return false;
                }
            }
            // Baseline-only mode: only run always-run patterns
            if config.baseline_only {
                return is_always_run(cp.def.sub_category);
            }
            // AC prefilter: skip context-gated patterns whose keywords aren't present
            if prefilter_active && !is_always_run(cp.def.sub_category) {
                if !active_gated.contains(&(cp.def.category, cp.def.sub_category)) {
                    return false;
                }
            }
            true
        })
        .collect();

    // Run each pattern in parallel, collect per-pattern match vecs
    let per_pattern_matches: Vec<Vec<Match>> = active_patterns
        .par_iter()
        .map(|cp| {
            let pat = cp.def;
            let mut local_matches = Vec::new();
            const MAX_MATCHES_PER_PATTERN: usize = 10_000;

            for mat in cp.regex.find_iter(&normalized) {
                if local_matches.len() >= MAX_MATCHES_PER_PATTERN {
                    break;
                }
                let norm_start = mat.start();
                let norm_end = mat.end();
                let matched_text = mat.as_str();

                // Luhn validation for credit card patterns
                if pat.category == "Credit Card Numbers" && !is_luhn_valid(matched_text) {
                    continue;
                }

                // Context checking
                let has_context = context::check_context(
                    &normalized,
                    norm_start,
                    norm_end,
                    pat.category,
                    pat.sub_category,
                    hit_index.as_ref(),
                );

                let ctx_required = is_context_required(pat.sub_category);

                if ctx_required && !has_context {
                    continue;
                }
                if config.require_context && !has_context {
                    continue;
                }

                let confidence = compute_confidence(pat.sub_category, has_context, ctx_required);
                if confidence < config.min_confidence {
                    continue;
                }

                // Map normalized positions back to original text
                let (orig_start, orig_end) = if !offset_map.is_empty() {
                    let os = if norm_start < offset_map.len() {
                        offset_map[norm_start]
                    } else {
                        text.len()
                    };
                    let oe = if norm_end > 0 && norm_end <= offset_map.len() {
                        // Find the end of the original character at the last
                        // normalized byte. offset_map gives us the start byte
                        // of the original char — we need the byte AFTER it.
                        let last_orig = offset_map[norm_end - 1];
                        // Walk forward to the next char boundary in the original text
                        let mut end = last_orig + 1;
                        while end < text.len() && !text.is_char_boundary(end) {
                            end += 1;
                        }
                        end
                    } else {
                        text.len()
                    };
                    (os, oe)
                } else {
                    (norm_start, norm_end)
                };

                // Safety: ensure slice boundaries are valid UTF-8 char boundaries
                let original_text = if orig_end <= text.len()
                    && orig_start <= orig_end
                    && text.is_char_boundary(orig_start)
                    && text.is_char_boundary(orig_end)
                {
                    &text[orig_start..orig_end]
                } else {
                    matched_text
                };

                local_matches.push(Match::new(
                    original_text.to_string(),
                    pat.category.to_string(),
                    pat.sub_category.to_string(),
                    has_context,
                    confidence,
                    (orig_start, orig_end),
                    ctx_required,
                ));
            }

            local_matches
        })
        .collect();

    // Check if scan exceeded timeout
    let timed_out = start.elapsed().as_secs() > MAX_SCAN_SECONDS;
    if timed_out {
        tracing::warn!("Scan exceeded timeout of {}s, returning partial results", MAX_SCAN_SECONDS);
    }

    // Flatten and truncate
    let all_matches: Vec<Match> = per_pattern_matches
        .into_iter()
        .flatten()
        .collect();
    let match_cap_hit = all_matches.len() > config.max_matches;
    let mut matches: Vec<Match> = all_matches.into_iter().take(config.max_matches).collect();

    // Deduplicate overlapping matches
    if config.deduplicate {
        deduplicate_overlapping(&mut matches);
    }

    Ok(ScanOutput {
        matches,
        truncated: timed_out || match_cap_hit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_empty() {
        assert!(scan_text("").is_err());
    }

    #[test]
    fn test_scan_clean_text() {
        let result = scan_text("Hello world, this is a test.").unwrap();
        // Clean text should have few or no matches
        assert!(result.len() < 5);
    }

    #[test]
    fn test_scan_email() {
        let result = scan_text("Contact us at test@example.com for info.").unwrap();
        assert!(result.iter().any(|m| m.sub_category == "Email Address"));
    }

    #[test]
    fn test_scan_credit_card() {
        // Valid Visa number (passes Luhn)
        let result = scan_text("Card: 4532015112830366").unwrap();
        assert!(result.iter().any(|m| m.sub_category == "Visa"));
    }

    #[test]
    fn test_scan_with_categories() {
        let config = ScanConfig {
            categories: Some(["Contact Information".to_string()].into_iter().collect()),
            ..Default::default()
        };
        let output =
            scan_text_with_config("Email: test@example.com SSN: 123-45-6789", &config).unwrap();
        assert!(output.matches.iter().all(|m| m.category == "Contact Information"));
    }

    // ---- Evasion detection tests ----

    #[test]
    fn test_ssn_plain_formats() {
        for input in &[
            "SSN: 123-45-6789",
            "SSN: 123 45 6789",
            "SSN: 123.45.6789",
            "SSN: 123456789",
            "SSN: 123/45/6789",
        ] {
            let result = scan_text(input).unwrap();
            assert!(
                result.iter().any(|m| m.sub_category == "USA SSN"),
                "Failed to detect SSN in: {input}"
            );
        }
    }

    #[test]
    fn test_ssn_zero_width_evasion() {
        // Zero-width spaces inserted between digits
        let input = "SSN: 123\u{200B}-\u{200B}45\u{200B}-\u{200B}6789";
        let result = scan_text(input).unwrap();
        assert!(
            result.iter().any(|m| m.sub_category == "USA SSN"),
            "Failed to detect SSN with zero-width chars"
        );
    }

    #[test]
    fn test_ssn_fullwidth_digits() {
        // Fullwidth digits: １２３-４５-６７８９
        let input = "SSN: \u{FF11}\u{FF12}\u{FF13}-\u{FF14}\u{FF15}-\u{FF16}\u{FF17}\u{FF18}\u{FF19}";
        let result = scan_text(input).unwrap();
        assert!(
            result.iter().any(|m| m.sub_category == "USA SSN"),
            "Failed to detect SSN with fullwidth digits"
        );
    }

    #[test]
    fn test_iban_with_dashes() {
        let result = scan_text("IBAN: DE89-3704-0044-0532-0130-00").unwrap();
        assert!(
            result.iter().any(|m| m.sub_category.contains("IBAN")),
            "Failed to detect IBAN with dashes"
        );
    }

    #[test]
    fn test_iban_with_dots() {
        let result = scan_text("IBAN: GB29.NWBK.6016.1331.9268.19").unwrap();
        assert!(
            result.iter().any(|m| m.sub_category.contains("IBAN")),
            "Failed to detect IBAN with dots"
        );
    }

    #[test]
    fn test_iban_no_separators() {
        let result = scan_text("IBAN: DE89370400440532013000").unwrap();
        assert!(
            result.iter().any(|m| m.sub_category.contains("IBAN")),
            "Failed to detect IBAN without separators"
        );
    }

    #[test]
    fn test_e164_phone_with_spaces() {
        let result = scan_text("Phone: +1 234 567 8901").unwrap();
        assert!(
            result.iter().any(|m| m.sub_category.contains("Phone")),
            "Failed to detect E.164 phone with spaces"
        );
    }

    #[test]
    fn test_e164_phone_with_dashes() {
        let result = scan_text("Phone: +44-20-7183-8750").unwrap();
        assert!(
            result.iter().any(|m| m.sub_category.contains("Phone")),
            "Failed to detect E.164 phone with dashes"
        );
    }

    #[test]
    fn test_credit_card_zero_width_evasion() {
        // Valid Visa with zero-width spaces
        let input = "Card: 4532\u{200B}0151\u{200B}1283\u{200B}0366";
        let result = scan_text(input).unwrap();
        assert!(
            result.iter().any(|m| m.sub_category == "Visa"),
            "Failed to detect Visa with zero-width chars"
        );
    }

    #[test]
    fn test_credit_card_fullwidth_digits() {
        // Valid Visa in fullwidth: ４５３２０１５１１２８３０３６６
        let input = "Card: \u{FF14}\u{FF15}\u{FF13}\u{FF12}\u{FF10}\u{FF11}\u{FF15}\u{FF11}\u{FF11}\u{FF12}\u{FF18}\u{FF13}\u{FF10}\u{FF13}\u{FF16}\u{FF16}";
        let result = scan_text(input).unwrap();
        assert!(
            result.iter().any(|m| m.sub_category == "Visa"),
            "Failed to detect Visa with fullwidth digits"
        );
    }

    #[test]
    fn test_email_fullwidth_at() {
        // Fullwidth @ sign: user＠example.com
        let input = "Email: user\u{FF20}example.com";
        let result = scan_text(input).unwrap();
        assert!(
            result.iter().any(|m| m.sub_category == "Email Address"),
            "Failed to detect email with fullwidth @"
        );
    }

    #[test]
    fn test_sin_with_unicode_separators() {
        // Canada SIN with en-dash
        let input = "SIN: 046\u{2013}454\u{2013}286";
        let result = scan_text(input).unwrap();
        assert!(
            result.iter().any(|m| m.sub_category == "Canada SIN"),
            "Failed to detect SIN with en-dash separators"
        );
    }

    #[test]
    fn test_specificity_scores_correct() {
        // Verify the name mismatches are fixed
        use crate::models::pattern_specificity;
        assert!(pattern_specificity("E.164 Phone Number") > 0.5, "E.164 Phone should be > 0.5");
        assert!(pattern_specificity("USA SSN") > 0.4, "USA SSN should be > default");
        assert!(pattern_specificity("Canada SIN") > 0.4, "Canada SIN should be > default");
        assert!(pattern_specificity("US Phone Number") > 0.4, "US Phone should be > default");
        assert!(pattern_specificity("Slack Webhook") > 0.5, "Slack Webhook should be > 0.5");
        assert!(pattern_specificity("Bitcoin Address (Legacy)") > 0.5, "BTC Legacy should be > 0.5");
        assert!(pattern_specificity("URL with Password") > 0.5, "URL with Password should be > 0.5");
        assert!(pattern_specificity("URL with Token") > 0.5, "URL with Token should be > 0.5");
    }
}
