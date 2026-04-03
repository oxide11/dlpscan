//! Unicode normalization to defeat evasion attacks.
//!
//! Handles zero-width character stripping, whitespace normalization,
//! homoglyph substitution, and leet-speak decoding.

use once_cell::sync::Lazy;
use std::collections::HashMap;
use unicode_normalization::UnicodeNormalization;

/// Zero-width and invisible Unicode characters.
pub static ZERO_WIDTH_CHARS: Lazy<Vec<char>> = Lazy::new(|| {
    vec![
        '\u{200B}', '\u{200C}', '\u{200D}', '\u{200E}', '\u{200F}',
        '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}',
        '\u{2060}', '\u{2061}', '\u{2062}', '\u{2063}', '\u{2064}',
        '\u{FEFF}', '\u{00AD}', '\u{034F}', '\u{061C}',
        '\u{180E}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
        '\u{FE00}', '\u{FE01}', '\u{FE02}', '\u{FE03}', '\u{FE04}',
        '\u{FE05}', '\u{FE06}', '\u{FE07}', '\u{FE08}', '\u{FE09}',
        '\u{FE0A}', '\u{FE0B}', '\u{FE0C}', '\u{FE0D}', '\u{FE0E}',
        '\u{FE0F}',
    ]
});

/// Exotic Unicode whitespace characters.
pub static UNICODE_SPACES: Lazy<Vec<char>> = Lazy::new(|| {
    vec![
        '\u{00A0}', '\u{1680}', '\u{2000}', '\u{2001}', '\u{2002}',
        '\u{2003}', '\u{2004}', '\u{2005}', '\u{2006}', '\u{2007}',
        '\u{2008}', '\u{2009}', '\u{200A}', '\u{202F}', '\u{205F}',
        '\u{3000}',
    ]
});

/// Leet-speak substitution map.
static LEET_MAP: Lazy<HashMap<char, char>> = Lazy::new(|| {
    let pairs = [
        ('@', 'a'), ('4', 'a'), ('8', 'b'), ('(', 'c'),
        ('3', 'e'), ('6', 'g'), ('#', 'h'), ('!', 'i'),
        ('1', 'l'), ('0', 'o'), ('5', 's'), ('7', 't'),
        ('+', 't'), ('2', 'z'),
    ];
    pairs.iter().copied().collect()
});

/// Homoglyph substitution map (Cyrillic, Greek, etc. → ASCII).
static HOMOGLYPH_MAP: Lazy<HashMap<char, char>> = Lazy::new(|| {
    let pairs = [
        // Cyrillic
        ('\u{0410}', 'A'), ('\u{0412}', 'B'), ('\u{0421}', 'C'),
        ('\u{0415}', 'E'), ('\u{041D}', 'H'), ('\u{041A}', 'K'),
        ('\u{041C}', 'M'), ('\u{041E}', 'O'), ('\u{0420}', 'P'),
        ('\u{0422}', 'T'), ('\u{0425}', 'X'),
        ('\u{0430}', 'a'), ('\u{0435}', 'e'), ('\u{043E}', 'o'),
        ('\u{0440}', 'p'), ('\u{0441}', 'c'), ('\u{0443}', 'y'),
        ('\u{0445}', 'x'),
        // Greek
        ('\u{0391}', 'A'), ('\u{0392}', 'B'), ('\u{0395}', 'E'),
        ('\u{0397}', 'H'), ('\u{0399}', 'I'), ('\u{039A}', 'K'),
        ('\u{039C}', 'M'), ('\u{039D}', 'N'), ('\u{039F}', 'O'),
        ('\u{03A1}', 'P'), ('\u{03A4}', 'T'), ('\u{03A5}', 'Y'),
        ('\u{03A7}', 'X'), ('\u{0396}', 'Z'),
        ('\u{03B1}', 'a'), ('\u{03BF}', 'o'),
        // Digit homoglyphs
        ('\u{FF10}', '0'), ('\u{FF11}', '1'), ('\u{FF12}', '2'),
        ('\u{FF13}', '3'), ('\u{FF14}', '4'), ('\u{FF15}', '5'),
        ('\u{FF16}', '6'), ('\u{FF17}', '7'), ('\u{FF18}', '8'),
        ('\u{FF19}', '9'),
    ];
    pairs.iter().copied().collect()
});

/// Strip zero-width characters from text.
/// Returns (cleaned_text, offset_map) where offset_map[i] = original position of char i.
pub fn strip_zero_width(text: &str) -> (String, Vec<usize>) {
    // Fast path: check if any zero-width chars exist
    let has_zw = text.chars().any(|c| ZERO_WIDTH_CHARS.contains(&c));
    if !has_zw {
        // Return empty offset_map to signal "no mapping needed" (identity)
        return (text.to_string(), Vec::new());
    }

    let mut result = String::with_capacity(text.len());
    let mut offset_map = Vec::with_capacity(text.len());

    for (byte_idx, ch) in text.char_indices() {
        if !ZERO_WIDTH_CHARS.contains(&ch) {
            let start = result.len();
            result.push(ch);
            // Map each byte of the output char to the original byte index
            for i in 0..ch.len_utf8() {
                offset_map.push(byte_idx + i);
            }
            let _ = start; // suppress unused warning
        }
    }

    (result, offset_map)
}

/// Replace exotic Unicode whitespace with ASCII space.
pub fn normalize_whitespace(text: &str) -> String {
    text.chars()
        .map(|c| if UNICODE_SPACES.contains(&c) { ' ' } else { c })
        .collect()
}

/// Replace homoglyph characters with ASCII equivalents (NFKC + explicit map).
pub fn normalize_homoglyphs(text: &str) -> String {
    let nfkc: String = text.nfkc().collect();
    nfkc.chars()
        .map(|c| *HOMOGLYPH_MAP.get(&c).unwrap_or(&c))
        .collect()
}

/// Convert leet-speak back to letters.
pub fn normalize_leet(text: &str) -> String {
    text.chars()
        .map(|c| *LEET_MAP.get(&c).unwrap_or(&c))
        .collect()
}

/// Check if text is pure ASCII (fast path to skip expensive Unicode normalization).
fn is_ascii_only(text: &str) -> bool {
    text.as_bytes().iter().all(|&b| b < 128)
}

/// Full normalization pipeline: zero-width strip → whitespace → homoglyphs.
/// Returns (normalized_text, offset_map).
///
/// Fast path: if text is pure ASCII, skip NFKC and homoglyph replacement.
pub fn normalize_text(text: &str) -> (String, Vec<usize>) {
    if is_ascii_only(text) {
        // Pure ASCII — no zero-width chars, no exotic spaces, no homoglyphs
        return (text.to_string(), Vec::new());
    }
    let (stripped, offset_map) = strip_zero_width(text);
    let ws_normalized = normalize_whitespace(&stripped);
    let homoglyph_normalized = normalize_homoglyphs(&ws_normalized);
    (homoglyph_normalized, offset_map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_zero_width_no_change() {
        let (result, _) = strip_zero_width("hello world");
        assert_eq!(result, "hello world");
    }

    #[test]
    fn test_strip_zero_width_removes_chars() {
        let input = "he\u{200B}llo";
        let (result, offsets) = strip_zero_width(input);
        assert_eq!(result, "hello");
        assert!(!offsets.is_empty());
    }

    #[test]
    fn test_normalize_whitespace() {
        let input = "hello\u{00A0}world";
        assert_eq!(normalize_whitespace(input), "hello world");
    }

    #[test]
    fn test_normalize_leet() {
        assert_eq!(normalize_leet("h3ll0"), "hello");
    }

    #[test]
    fn test_normalize_homoglyphs() {
        // Cyrillic 'а' (U+0430) → ASCII 'a'
        let input = "\u{0430}bc";
        let result = normalize_homoglyphs(input);
        assert_eq!(result, "abc");
    }
}
