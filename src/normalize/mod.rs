//! Unicode normalization to defeat evasion attacks.
//!
//! Handles zero-width character stripping, combining mark removal,
//! whitespace normalization, NFKC normalization, and confusable/homoglyph
//! substitution using a 1,500+ entry map derived from Unicode NFKC/NFKD data.

mod confusables;

use once_cell::sync::Lazy;
use std::collections::HashMap;
use unicode_general_category::{get_general_category, GeneralCategory};
use unicode_normalization::UnicodeNormalization;

/// Returns true if a character is invisible/zero-width and should be stripped.
///
/// Uses Unicode General_Category for future-proof detection rather than a
/// hand-maintained whitelist. Catches all Format (Cf) characters plus
/// variation selectors (Mn category, FE00-FE0F range).
#[inline]
fn is_invisible(c: char) -> bool {
    match get_general_category(c) {
        // Format characters: ZWSP, ZWNJ, ZWJ, bidi controls, BOM, soft hyphen, etc.
        GeneralCategory::Format => true,
        // Variation selectors are Nonspacing Marks, but act as invisible modifiers
        GeneralCategory::NonspacingMark => {
            matches!(c, '\u{FE00}'..='\u{FE0F}' | '\u{E0100}'..='\u{E01EF}')
        }
        _ => false,
    }
}

/// Returns true if a character is an exotic Unicode whitespace (General_Category = Zs)
/// that should be normalized to ASCII space. Excludes regular ASCII space (U+0020).
#[inline]
fn is_unicode_space(c: char) -> bool {
    c != ' ' && get_general_category(c) == GeneralCategory::SpaceSeparator
}

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

/// Comprehensive confusable/homoglyph substitution map (1,500+ entries).
///
/// Built from the auto-generated `confusables::CONFUSABLES` table (derived from
/// Unicode NFKC/NFKD decomposition data) plus hand-curated additions for
/// characters that Unicode decomposition doesn't cover (Cyrillic/Greek
/// lookalikes, IPA variants, small capitals).
///
/// Applied AFTER NFKC normalization to catch anything NFKC doesn't handle.
static HOMOGLYPH_MAP: Lazy<HashMap<char, char>> = Lazy::new(|| {
    // Start with the auto-generated confusables (1,573 entries from Unicode data)
    let mut map: HashMap<char, char> = confusables::CONFUSABLES.iter().copied().collect();

    // Hand-curated additions: characters that NFKC/NFKD don't decompose to ASCII
    // but are visually confusable. These override any conflicting auto-generated
    // entries where we have a better manual mapping.
    let manual_overrides = [
        // ---- Cyrillic uppercase ----
        ('\u{0410}', 'A'), ('\u{0412}', 'B'), ('\u{0421}', 'C'),
        ('\u{0415}', 'E'), ('\u{041D}', 'H'), ('\u{0406}', 'I'),
        ('\u{0408}', 'J'), ('\u{041A}', 'K'), ('\u{041C}', 'M'),
        ('\u{041E}', 'O'), ('\u{0420}', 'P'), ('\u{0405}', 'S'),
        ('\u{0422}', 'T'), ('\u{0425}', 'X'), ('\u{0417}', 'Z'),
        // ---- Cyrillic lowercase ----
        ('\u{0430}', 'a'), ('\u{0435}', 'e'), ('\u{0456}', 'i'),
        ('\u{0458}', 'j'), ('\u{043E}', 'o'), ('\u{0440}', 'p'),
        ('\u{0441}', 'c'), ('\u{0443}', 'y'), ('\u{0445}', 'x'),
        ('\u{0455}', 's'),
        // ---- Greek uppercase ----
        ('\u{0391}', 'A'), ('\u{0392}', 'B'), ('\u{0393}', 'G'),
        ('\u{0395}', 'E'), ('\u{0397}', 'H'), ('\u{0399}', 'I'),
        ('\u{039A}', 'K'), ('\u{039C}', 'M'), ('\u{039D}', 'N'),
        ('\u{039F}', 'O'), ('\u{03A1}', 'P'), ('\u{03A4}', 'T'),
        ('\u{03A5}', 'Y'), ('\u{03A7}', 'X'), ('\u{0396}', 'Z'),
        // ---- Greek lowercase ----
        ('\u{03B1}', 'a'), ('\u{03BF}', 'o'), ('\u{03B9}', 'i'),
        ('\u{03BA}', 'k'), ('\u{03BD}', 'v'), ('\u{03C1}', 'p'),
        ('\u{03C5}', 'u'), ('\u{03C7}', 'x'),
        // ---- Fullwidth digits (backup — NFKC should handle these) ----
        ('\u{FF10}', '0'), ('\u{FF11}', '1'), ('\u{FF12}', '2'),
        ('\u{FF13}', '3'), ('\u{FF14}', '4'), ('\u{FF15}', '5'),
        ('\u{FF16}', '6'), ('\u{FF17}', '7'), ('\u{FF18}', '8'),
        ('\u{FF19}', '9'),
        // ---- Fullwidth ASCII A-Z (backup — NFKC should handle) ----
        ('\u{FF21}', 'A'), ('\u{FF22}', 'B'), ('\u{FF23}', 'C'),
        ('\u{FF24}', 'D'), ('\u{FF25}', 'E'), ('\u{FF26}', 'F'),
        ('\u{FF27}', 'G'), ('\u{FF28}', 'H'), ('\u{FF29}', 'I'),
        ('\u{FF2A}', 'J'), ('\u{FF2B}', 'K'), ('\u{FF2C}', 'L'),
        ('\u{FF2D}', 'M'), ('\u{FF2E}', 'N'), ('\u{FF2F}', 'O'),
        ('\u{FF30}', 'P'), ('\u{FF31}', 'Q'), ('\u{FF32}', 'R'),
        ('\u{FF33}', 'S'), ('\u{FF34}', 'T'), ('\u{FF35}', 'U'),
        ('\u{FF36}', 'V'), ('\u{FF37}', 'W'), ('\u{FF38}', 'X'),
        ('\u{FF39}', 'Y'), ('\u{FF3A}', 'Z'),
        // ---- Fullwidth ASCII a-z (backup — NFKC should handle) ----
        ('\u{FF41}', 'a'), ('\u{FF42}', 'b'), ('\u{FF43}', 'c'),
        ('\u{FF44}', 'd'), ('\u{FF45}', 'e'), ('\u{FF46}', 'f'),
        ('\u{FF47}', 'g'), ('\u{FF48}', 'h'), ('\u{FF49}', 'i'),
        ('\u{FF4A}', 'j'), ('\u{FF4B}', 'k'), ('\u{FF4C}', 'l'),
        ('\u{FF4D}', 'm'), ('\u{FF4E}', 'n'), ('\u{FF4F}', 'o'),
        ('\u{FF50}', 'p'), ('\u{FF51}', 'q'), ('\u{FF52}', 'r'),
        ('\u{FF53}', 's'), ('\u{FF54}', 't'), ('\u{FF55}', 'u'),
        ('\u{FF56}', 'v'), ('\u{FF57}', 'w'), ('\u{FF58}', 'x'),
        ('\u{FF59}', 'y'), ('\u{FF5A}', 'z'),
        // ---- Fullwidth punctuation ----
        ('\u{FF0D}', '-'), ('\u{FF0E}', '.'), ('\u{FF20}', '@'),
        ('\u{FF3F}', '_'), ('\u{FF0A}', '*'),
        // ---- Superscript digits ----
        ('\u{2070}', '0'), ('\u{00B9}', '1'), ('\u{00B2}', '2'),
        ('\u{00B3}', '3'), ('\u{2074}', '4'), ('\u{2075}', '5'),
        ('\u{2076}', '6'), ('\u{2077}', '7'), ('\u{2078}', '8'),
        ('\u{2079}', '9'),
        // ---- Subscript digits ----
        ('\u{2080}', '0'), ('\u{2081}', '1'), ('\u{2082}', '2'),
        ('\u{2083}', '3'), ('\u{2084}', '4'), ('\u{2085}', '5'),
        ('\u{2086}', '6'), ('\u{2087}', '7'), ('\u{2088}', '8'),
        ('\u{2089}', '9'),
        // ---- Enclosed/circled digits (U+2460-2473, U+24EA, U+2776-277F) ----
        ('\u{2460}', '1'), ('\u{2461}', '2'), ('\u{2462}', '3'),
        ('\u{2463}', '4'), ('\u{2464}', '5'), ('\u{2465}', '6'),
        ('\u{2466}', '7'), ('\u{2467}', '8'), ('\u{2468}', '9'),
        ('\u{24EA}', '0'), // circled 0
        // Parenthesized digits
        ('\u{2474}', '1'), ('\u{2475}', '2'), ('\u{2476}', '3'),
        ('\u{2477}', '4'), ('\u{2478}', '5'), ('\u{2479}', '6'),
        ('\u{247A}', '7'), ('\u{247B}', '8'), ('\u{247C}', '9'),
        // Negative circled digits (dingbats)
        ('\u{2776}', '1'), ('\u{2777}', '2'), ('\u{2778}', '3'),
        ('\u{2779}', '4'), ('\u{277A}', '5'), ('\u{277B}', '6'),
        ('\u{277C}', '7'), ('\u{277D}', '8'), ('\u{277E}', '9'),
        ('\u{277F}', '0'),
        // ---- Enclosed/circled letters (U+24B6-24E9) ----
        ('\u{24B6}', 'A'), ('\u{24B7}', 'B'), ('\u{24B8}', 'C'),
        ('\u{24B9}', 'D'), ('\u{24BA}', 'E'), ('\u{24BB}', 'F'),
        ('\u{24BC}', 'G'), ('\u{24BD}', 'H'), ('\u{24BE}', 'I'),
        ('\u{24BF}', 'J'), ('\u{24C0}', 'K'), ('\u{24C1}', 'L'),
        ('\u{24C2}', 'M'), ('\u{24C3}', 'N'), ('\u{24C4}', 'O'),
        ('\u{24C5}', 'P'), ('\u{24C6}', 'Q'), ('\u{24C7}', 'R'),
        ('\u{24C8}', 'S'), ('\u{24C9}', 'T'), ('\u{24CA}', 'U'),
        ('\u{24CB}', 'V'), ('\u{24CC}', 'W'), ('\u{24CD}', 'X'),
        ('\u{24CE}', 'Y'), ('\u{24CF}', 'Z'),
        ('\u{24D0}', 'a'), ('\u{24D1}', 'b'), ('\u{24D2}', 'c'),
        ('\u{24D3}', 'd'), ('\u{24D4}', 'e'), ('\u{24D5}', 'f'),
        ('\u{24D6}', 'g'), ('\u{24D7}', 'h'), ('\u{24D8}', 'i'),
        ('\u{24D9}', 'j'), ('\u{24DA}', 'k'), ('\u{24DB}', 'l'),
        ('\u{24DC}', 'm'), ('\u{24DD}', 'n'), ('\u{24DE}', 'o'),
        ('\u{24DF}', 'p'), ('\u{24E0}', 'q'), ('\u{24E1}', 'r'),
        ('\u{24E2}', 's'), ('\u{24E3}', 't'), ('\u{24E4}', 'u'),
        ('\u{24E5}', 'v'), ('\u{24E6}', 'w'), ('\u{24E7}', 'x'),
        ('\u{24E8}', 'y'), ('\u{24E9}', 'z'),
        // ---- Roman numerals (U+2160-217F) ----
        ('\u{2160}', 'I'), ('\u{2161}', 'I'), ('\u{2162}', 'I'),
        ('\u{2163}', 'I'), ('\u{2164}', 'V'), ('\u{2165}', 'V'),
        ('\u{2166}', 'V'), ('\u{2167}', 'V'), ('\u{2168}', 'I'),
        ('\u{2169}', 'X'), ('\u{216A}', 'X'), ('\u{216B}', 'X'),
        ('\u{216C}', 'L'), ('\u{216D}', 'C'), ('\u{216E}', 'D'),
        ('\u{216F}', 'M'),
        ('\u{2170}', 'i'), ('\u{2171}', 'i'), ('\u{2172}', 'i'),
        ('\u{2173}', 'i'), ('\u{2174}', 'v'), ('\u{2175}', 'v'),
        ('\u{2176}', 'v'), ('\u{2177}', 'v'), ('\u{2178}', 'i'),
        ('\u{2179}', 'x'), ('\u{217A}', 'x'), ('\u{217B}', 'x'),
        ('\u{217C}', 'l'), ('\u{217D}', 'c'), ('\u{217E}', 'd'),
        ('\u{217F}', 'm'),
        // ---- Mathematical bold digits (U+1D7CE-1D7D7) ----
        ('\u{1D7CE}', '0'), ('\u{1D7CF}', '1'), ('\u{1D7D0}', '2'),
        ('\u{1D7D1}', '3'), ('\u{1D7D2}', '4'), ('\u{1D7D3}', '5'),
        ('\u{1D7D4}', '6'), ('\u{1D7D5}', '7'), ('\u{1D7D6}', '8'),
        ('\u{1D7D7}', '9'),
        // ---- Mathematical double-struck digits (U+1D7D8-1D7E1) ----
        ('\u{1D7D8}', '0'), ('\u{1D7D9}', '1'), ('\u{1D7DA}', '2'),
        ('\u{1D7DB}', '3'), ('\u{1D7DC}', '4'), ('\u{1D7DD}', '5'),
        ('\u{1D7DE}', '6'), ('\u{1D7DF}', '7'), ('\u{1D7E0}', '8'),
        ('\u{1D7E1}', '9'),
        // ---- Mathematical sans-serif digits (U+1D7E2-1D7EB) ----
        ('\u{1D7E2}', '0'), ('\u{1D7E3}', '1'), ('\u{1D7E4}', '2'),
        ('\u{1D7E5}', '3'), ('\u{1D7E6}', '4'), ('\u{1D7E7}', '5'),
        ('\u{1D7E8}', '6'), ('\u{1D7E9}', '7'), ('\u{1D7EA}', '8'),
        ('\u{1D7EB}', '9'),
        // ---- Mathematical sans-serif bold digits (U+1D7EC-1D7F5) ----
        ('\u{1D7EC}', '0'), ('\u{1D7ED}', '1'), ('\u{1D7EE}', '2'),
        ('\u{1D7EF}', '3'), ('\u{1D7F0}', '4'), ('\u{1D7F1}', '5'),
        ('\u{1D7F2}', '6'), ('\u{1D7F3}', '7'), ('\u{1D7F4}', '8'),
        ('\u{1D7F5}', '9'),
        // ---- Mathematical monospace digits (U+1D7F6-1D7FF) ----
        ('\u{1D7F6}', '0'), ('\u{1D7F7}', '1'), ('\u{1D7F8}', '2'),
        ('\u{1D7F9}', '3'), ('\u{1D7FA}', '4'), ('\u{1D7FB}', '5'),
        ('\u{1D7FC}', '6'), ('\u{1D7FD}', '7'), ('\u{1D7FE}', '8'),
        ('\u{1D7FF}', '9'),
        // ---- Mathematical bold uppercase (U+1D400-1D419) ----
        ('\u{1D400}', 'A'), ('\u{1D401}', 'B'), ('\u{1D402}', 'C'),
        ('\u{1D403}', 'D'), ('\u{1D404}', 'E'), ('\u{1D405}', 'F'),
        ('\u{1D406}', 'G'), ('\u{1D407}', 'H'), ('\u{1D408}', 'I'),
        ('\u{1D409}', 'J'), ('\u{1D40A}', 'K'), ('\u{1D40B}', 'L'),
        ('\u{1D40C}', 'M'), ('\u{1D40D}', 'N'), ('\u{1D40E}', 'O'),
        ('\u{1D40F}', 'P'), ('\u{1D410}', 'Q'), ('\u{1D411}', 'R'),
        ('\u{1D412}', 'S'), ('\u{1D413}', 'T'), ('\u{1D414}', 'U'),
        ('\u{1D415}', 'V'), ('\u{1D416}', 'W'), ('\u{1D417}', 'X'),
        ('\u{1D418}', 'Y'), ('\u{1D419}', 'Z'),
        // ---- Mathematical bold lowercase (U+1D41A-1D433) ----
        ('\u{1D41A}', 'a'), ('\u{1D41B}', 'b'), ('\u{1D41C}', 'c'),
        ('\u{1D41D}', 'd'), ('\u{1D41E}', 'e'), ('\u{1D41F}', 'f'),
        ('\u{1D420}', 'g'), ('\u{1D421}', 'h'), ('\u{1D422}', 'i'),
        ('\u{1D423}', 'j'), ('\u{1D424}', 'k'), ('\u{1D425}', 'l'),
        ('\u{1D426}', 'm'), ('\u{1D427}', 'n'), ('\u{1D428}', 'o'),
        ('\u{1D429}', 'p'), ('\u{1D42A}', 'q'), ('\u{1D42B}', 'r'),
        ('\u{1D42C}', 's'), ('\u{1D42D}', 't'), ('\u{1D42E}', 'u'),
        ('\u{1D42F}', 'v'), ('\u{1D430}', 'w'), ('\u{1D431}', 'x'),
        ('\u{1D432}', 'y'), ('\u{1D433}', 'z'),
        // ---- Mathematical italic uppercase (U+1D434-1D44D) ----
        ('\u{1D434}', 'A'), ('\u{1D435}', 'B'), ('\u{1D436}', 'C'),
        ('\u{1D437}', 'D'), ('\u{1D438}', 'E'), ('\u{1D439}', 'F'),
        ('\u{1D43A}', 'G'), ('\u{1D43B}', 'H'), ('\u{1D43C}', 'I'),
        ('\u{1D43D}', 'J'), ('\u{1D43E}', 'K'), ('\u{1D43F}', 'L'),
        ('\u{1D440}', 'M'), ('\u{1D441}', 'N'), ('\u{1D442}', 'O'),
        ('\u{1D443}', 'P'), ('\u{1D444}', 'Q'), ('\u{1D445}', 'R'),
        ('\u{1D446}', 'S'), ('\u{1D447}', 'T'), ('\u{1D448}', 'U'),
        ('\u{1D449}', 'V'), ('\u{1D44A}', 'W'), ('\u{1D44B}', 'X'),
        ('\u{1D44C}', 'Y'), ('\u{1D44D}', 'Z'),
        // ---- Mathematical italic lowercase (U+1D44E-1D467) ----
        ('\u{1D44E}', 'a'), ('\u{1D44F}', 'b'), ('\u{1D450}', 'c'),
        ('\u{1D451}', 'd'), ('\u{1D452}', 'e'), ('\u{1D453}', 'f'),
        ('\u{1D454}', 'g'), // U+1D455 is unassigned (h is at U+210E)
        ('\u{1D456}', 'i'), ('\u{1D457}', 'j'), ('\u{1D458}', 'k'),
        ('\u{1D459}', 'l'), ('\u{1D45A}', 'm'), ('\u{1D45B}', 'n'),
        ('\u{1D45C}', 'o'), ('\u{1D45D}', 'p'), ('\u{1D45E}', 'q'),
        ('\u{1D45F}', 'r'), ('\u{1D460}', 's'), ('\u{1D461}', 't'),
        ('\u{1D462}', 'u'), ('\u{1D463}', 'v'), ('\u{1D464}', 'w'),
        ('\u{1D465}', 'x'), ('\u{1D466}', 'y'), ('\u{1D467}', 'z'),
        // ---- Mathematical script uppercase (U+1D49C-1D4B5) ----
        ('\u{1D49C}', 'A'), // B at U+212C, C at U+1D49E...
        ('\u{1D49E}', 'C'), ('\u{1D49F}', 'D'),
        ('\u{1D4A2}', 'G'),
        ('\u{1D4A5}', 'J'), ('\u{1D4A6}', 'K'),
        ('\u{1D4A9}', 'N'), ('\u{1D4AA}', 'O'), ('\u{1D4AB}', 'P'),
        ('\u{1D4AC}', 'Q'), ('\u{1D4AE}', 'S'), ('\u{1D4AF}', 'T'),
        ('\u{1D4B0}', 'U'), ('\u{1D4B1}', 'V'), ('\u{1D4B2}', 'W'),
        ('\u{1D4B3}', 'X'), ('\u{1D4B4}', 'Y'), ('\u{1D4B5}', 'Z'),
        // ---- Mathematical script lowercase (U+1D4B6-1D4CF) ----
        ('\u{1D4B6}', 'a'), ('\u{1D4B7}', 'b'), ('\u{1D4B8}', 'c'),
        ('\u{1D4B9}', 'd'), ('\u{1D4BB}', 'f'),
        ('\u{1D4BD}', 'h'), ('\u{1D4BE}', 'i'), ('\u{1D4BF}', 'j'),
        ('\u{1D4C0}', 'k'), ('\u{1D4C1}', 'l'), ('\u{1D4C2}', 'm'),
        ('\u{1D4C3}', 'n'), ('\u{1D4C5}', 'p'), ('\u{1D4C6}', 'q'),
        ('\u{1D4C7}', 'r'), ('\u{1D4C8}', 's'), ('\u{1D4C9}', 't'),
        ('\u{1D4CA}', 'u'), ('\u{1D4CB}', 'v'), ('\u{1D4CC}', 'w'),
        ('\u{1D4CD}', 'x'), ('\u{1D4CE}', 'y'), ('\u{1D4CF}', 'z'),
        // ---- Mathematical fraktur uppercase (selected) ----
        ('\u{1D504}', 'A'), ('\u{1D505}', 'B'),
        ('\u{1D507}', 'D'), ('\u{1D508}', 'E'), ('\u{1D509}', 'F'),
        ('\u{1D50A}', 'G'), ('\u{1D50D}', 'J'), ('\u{1D50E}', 'K'),
        ('\u{1D50F}', 'L'), ('\u{1D510}', 'M'), ('\u{1D511}', 'N'),
        ('\u{1D512}', 'O'), ('\u{1D513}', 'P'), ('\u{1D514}', 'Q'),
        ('\u{1D516}', 'S'), ('\u{1D517}', 'T'), ('\u{1D518}', 'U'),
        ('\u{1D519}', 'V'), ('\u{1D51A}', 'W'), ('\u{1D51B}', 'X'),
        ('\u{1D51C}', 'Y'),
        // ---- Mathematical fraktur lowercase ----
        ('\u{1D51E}', 'a'), ('\u{1D51F}', 'b'), ('\u{1D520}', 'c'),
        ('\u{1D521}', 'd'), ('\u{1D522}', 'e'), ('\u{1D523}', 'f'),
        ('\u{1D524}', 'g'), ('\u{1D525}', 'h'), ('\u{1D526}', 'i'),
        ('\u{1D527}', 'j'), ('\u{1D528}', 'k'), ('\u{1D529}', 'l'),
        ('\u{1D52A}', 'm'), ('\u{1D52B}', 'n'), ('\u{1D52C}', 'o'),
        ('\u{1D52D}', 'p'), ('\u{1D52E}', 'q'), ('\u{1D52F}', 'r'),
        ('\u{1D530}', 's'), ('\u{1D531}', 't'), ('\u{1D532}', 'u'),
        ('\u{1D533}', 'v'), ('\u{1D534}', 'w'), ('\u{1D535}', 'x'),
        ('\u{1D536}', 'y'), ('\u{1D537}', 'z'),
        // ---- IPA / Latin Extended lookalikes (U+0250-02AF) ----
        ('\u{0131}', 'i'), // dotless i
        ('\u{0237}', 'j'), // dotless j
        ('\u{0251}', 'a'), // ɑ open back unrounded
        ('\u{0252}', 'a'), // ɒ open back rounded (turned a)
        ('\u{0253}', 'b'), // ɓ implosive b
        ('\u{0255}', 'c'), // ɕ alveolo-palatal
        ('\u{0256}', 'd'), // ɖ retroflex d
        ('\u{0257}', 'd'), // ɗ implosive d
        ('\u{025B}', 'e'), // ɛ open-mid front
        ('\u{025C}', 'e'), // ɜ open-mid central
        ('\u{0260}', 'g'), // ɠ implosive g
        ('\u{0261}', 'g'), // ɡ voiced velar plosive
        ('\u{0262}', 'G'), // ɢ small capital G
        ('\u{0265}', 'h'), // ɥ turned h
        ('\u{0266}', 'h'), // ɦ hooktop h
        ('\u{0268}', 'i'), // ɨ barred i
        ('\u{026A}', 'i'), // ɪ near-close front
        ('\u{026B}', 'l'), // ɫ dark l
        ('\u{026C}', 'l'), // ɬ lateral fricative
        ('\u{026D}', 'l'), // ɭ retroflex l
        ('\u{026F}', 'm'), // ɯ turned m
        ('\u{0270}', 'm'), // ɰ turned m with long leg
        ('\u{0271}', 'm'), // ɱ labiodental nasal
        ('\u{0272}', 'n'), // ɲ palatal nasal
        ('\u{0273}', 'n'), // ɳ retroflex nasal
        ('\u{0274}', 'N'), // ɴ small capital N
        ('\u{0275}', 'o'), // ɵ barred o
        ('\u{0278}', 'p'), // ɸ (phi-like, but IPA for voiceless bilabial)
        ('\u{0279}', 'r'), // ɹ turned r
        ('\u{027A}', 'r'), // ɺ turned r with long leg
        ('\u{027B}', 'r'), // ɻ turned r with hook
        ('\u{027C}', 'r'), // ɼ r with long leg
        ('\u{027D}', 'r'), // ɽ retroflex flap
        ('\u{027E}', 'r'), // ɾ alveolar flap
        ('\u{027F}', 'r'), // ɿ reversed r with fishhook
        ('\u{0280}', 'R'), // ʀ uvular trill
        ('\u{0282}', 's'), // ʂ retroflex s
        ('\u{0284}', 'j'), // ʄ dotless j with stroke and hook
        ('\u{0285}', 's'), // ʅ squat reversed esh (looks like s)
        ('\u{0288}', 't'), // ʈ retroflex t
        ('\u{028B}', 'v'), // ʋ labiodental approximant
        ('\u{028C}', 'v'), // ʌ turned v
        ('\u{028D}', 'w'), // ʍ turned w
        ('\u{028F}', 'Y'), // ʏ small capital Y
        ('\u{0290}', 'z'), // ʐ retroflex z
        ('\u{0291}', 'z'), // ʑ curly-tail z
        ('\u{0297}', 'c'), // ʗ stretched c (click)
        ('\u{0299}', 'B'), // ʙ bilabial trill
        ('\u{029B}', 'G'), // ʛ small capital G with hook
        ('\u{029C}', 'H'), // ʜ small capital H
        ('\u{029D}', 'j'), // ʝ curly-tail j
        ('\u{029F}', 'L'), // ʟ small capital L
        ('\u{02A0}', 'q'), // ʠ q with hook
        // ---- Small capitals (U+1D00-1D2F) ----
        ('\u{1D00}', 'A'), ('\u{1D03}', 'B'), ('\u{1D04}', 'C'),
        ('\u{1D05}', 'D'), ('\u{1D07}', 'E'), ('\u{1D08}', 'e'),
        ('\u{1D09}', 'i'), ('\u{1D0A}', 'J'), ('\u{1D0B}', 'K'),
        ('\u{1D0C}', 'L'), ('\u{1D0D}', 'M'), ('\u{1D0F}', 'O'),
        ('\u{1D18}', 'P'), ('\u{1D19}', 'R'), ('\u{1D1A}', 'R'),
        ('\u{1D1B}', 'T'), ('\u{1D1C}', 'U'), ('\u{1D1D}', 'u'),
        ('\u{1D20}', 'V'), ('\u{1D21}', 'W'), ('\u{1D22}', 'Z'),
        // ---- Letterlike symbols ----
        ('\u{210E}', 'h'), // Planck constant (italic h)
        ('\u{2110}', 'I'), // script I
        ('\u{2112}', 'L'), // script L
        ('\u{211B}', 'R'), // script R
        ('\u{212C}', 'B'), // script B
        ('\u{2130}', 'E'), // script E
        ('\u{2131}', 'F'), // script F
        ('\u{2133}', 'M'), // script M
    ];
    for (src, dst) in manual_overrides {
        map.insert(src, dst);
    }
    map
});

/// Strip invisible/zero-width characters from text.
/// Returns (cleaned_text, offset_map) where offset_map[i] = original position of char i.
pub fn strip_zero_width(text: &str) -> (String, Vec<usize>) {
    // Fast path: check if any invisible chars exist
    let has_invisible = text.chars().any(|c| is_invisible(c));
    if !has_invisible {
        return (text.to_string(), Vec::new());
    }

    let mut result = String::with_capacity(text.len());
    let mut offset_map = Vec::with_capacity(text.len());

    for (byte_idx, ch) in text.char_indices() {
        if !is_invisible(ch) {
            result.push(ch);
            for i in 0..ch.len_utf8() {
                offset_map.push(byte_idx + i);
            }
        }
    }

    (result, offset_map)
}

/// Replace exotic Unicode whitespace with ASCII space.
pub fn normalize_whitespace(text: &str) -> String {
    text.chars()
        .map(|c| if is_unicode_space(c) { ' ' } else { c })
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

/// Returns true if a character is a combining diacritical mark that should be
/// stripped during normalization. Covers the main combining ranges used in
/// evasion attacks (e.g., `1̃2̃3̃` to break `\d{3}` matching).
#[inline]
fn is_combining_mark(c: char) -> bool {
    matches!(c,
        '\u{0300}'..='\u{036F}'  // Combining Diacritical Marks
        | '\u{0483}'..='\u{0489}' // Combining Cyrillic
        | '\u{1AB0}'..='\u{1AFF}' // Combining Diacritical Marks Extended
        | '\u{1DC0}'..='\u{1DFF}' // Combining Diacritical Marks Supplement
        | '\u{20D0}'..='\u{20FF}' // Combining Diacritical Marks for Symbols
        | '\u{FE20}'..='\u{FE2F}' // Combining Half Marks
    )
}

/// Full normalization pipeline with accurate byte-level offset tracking.
///
/// Pipeline: zero-width strip → combining mark strip → whitespace normalize
///         → NFKC → homoglyph map.
/// The returned offset_map maps each byte index in the normalized output back
/// to the corresponding byte index in the original input. Empty offset_map
/// means identity mapping (text was pure ASCII, nothing changed).
pub fn normalize_text(text: &str) -> (String, Vec<usize>) {
    if is_ascii_only(text) {
        return (text.to_string(), Vec::new());
    }

    // Stage 1: Strip zero-width characters AND combining diacritical marks,
    // building initial offset map. offset[output_byte] = original_byte.
    // Combining marks (U+0300-036F etc.) are stripped because attackers insert
    // them between digits to break regex continuity (e.g., 1̃2̃3̃ vs 123).
    let mut current = String::with_capacity(text.len());
    let mut offsets: Vec<usize> = Vec::with_capacity(text.len());

    for (byte_idx, ch) in text.char_indices() {
        if !is_invisible(ch) && !is_combining_mark(ch) {
            current.push(ch);
            for i in 0..ch.len_utf8() {
                offsets.push(byte_idx + i);
            }
        }
    }

    // Stage 2: Normalize exotic whitespace (char-by-char, may change byte widths).
    let (current, offsets) = remap_char_transform(&current, &offsets, |c| {
        if is_unicode_space(c) { ' ' } else { c }
    });

    // Stage 3: NFKC normalization (handles fullwidth digits/letters, ligatures, etc.).
    // NFKC can change string length — one input char may produce multiple output chars
    // or vice versa. We track at char granularity: each output char inherits the
    // original byte offset of the input char that produced it.
    let (current, offsets) = remap_nfkc(&current, &offsets);

    // Stage 4: Homoglyph map (Cyrillic/Greek/mathematical/enclosed → ASCII).
    // Always 1:1 char replacement, but replacement char may have different UTF-8
    // byte width.
    let (current, offsets) = remap_char_transform(&current, &offsets, |c| {
        *HOMOGLYPH_MAP.get(&c).unwrap_or(&c)
    });

    // If nothing changed, return empty offsets (identity)
    if current == text {
        return (current, Vec::new());
    }

    (current, offsets)
}

/// Apply a 1-char → 1-char transform while maintaining byte-level offset map.
/// The transform function maps each input char to exactly one output char.
fn remap_char_transform(
    input: &str,
    input_offsets: &[usize],
    transform: impl Fn(char) -> char,
) -> (String, Vec<usize>) {
    let mut output = String::with_capacity(input.len());
    let mut output_offsets = Vec::with_capacity(input.len());

    for (byte_idx, ch) in input.char_indices() {
        let replacement = transform(ch);
        output.push(replacement);

        // The original offset for this input char's first byte
        let orig_start = if byte_idx < input_offsets.len() {
            input_offsets[byte_idx]
        } else {
            byte_idx
        };

        // Map each byte of the output char to the original offset
        for _ in 0..replacement.len_utf8() {
            output_offsets.push(orig_start);
        }
    }

    (output, output_offsets)
}

/// Apply NFKC normalization while maintaining byte-level offset map.
/// NFKC can expand or contract characters (e.g., fullwidth '０' → '0',
/// ligature 'ﬁ' → 'fi'). Each output char inherits the original byte offset
/// of the input char that produced it.
fn remap_nfkc(input: &str, input_offsets: &[usize]) -> (String, Vec<usize>) {
    let mut output = String::with_capacity(input.len());
    let mut output_offsets = Vec::with_capacity(input.len());

    for (byte_idx, ch) in input.char_indices() {
        // The original offset for this input char
        let orig_offset = if byte_idx < input_offsets.len() {
            input_offsets[byte_idx]
        } else {
            byte_idx
        };

        // NFKC decompose this single character
        let nfkc_chars: String = std::iter::once(ch).nfkc().collect();
        for nfkc_ch in nfkc_chars.chars() {
            output.push(nfkc_ch);
            for _ in 0..nfkc_ch.len_utf8() {
                output_offsets.push(orig_offset);
            }
        }
    }

    (output, output_offsets)
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

    #[test]
    fn test_fullwidth_digits_normalized() {
        // Fullwidth digits ０１２３ should normalize to 0123
        let input = "\u{FF10}\u{FF11}\u{FF12}\u{FF13}";
        let (result, offsets) = normalize_text(input);
        assert_eq!(result, "0123");
        assert!(!offsets.is_empty());
        // Verify offset map points back to original positions
        assert_eq!(offsets[0], 0); // '0' maps to byte 0 of original ０
    }

    #[test]
    fn test_fullwidth_letters_normalized() {
        // Fullwidth Ａ Ｂ Ｃ should normalize to ABC
        let input = "\u{FF21}\u{FF22}\u{FF23}";
        let (result, _) = normalize_text(input);
        assert_eq!(result, "ABC");
    }

    #[test]
    fn test_cyrillic_homoglyphs_normalized() {
        // Cyrillic а е о should normalize to a e o
        let input = "\u{0430}\u{0435}\u{043E}";
        let (result, _) = normalize_text(input);
        assert_eq!(result, "aeo");
    }

    #[test]
    fn test_mixed_unicode_evasion() {
        // SSN with fullwidth digits: １２３-４５-６７８９
        let input = "\u{FF11}\u{FF12}\u{FF13}-\u{FF14}\u{FF15}-\u{FF16}\u{FF17}\u{FF18}\u{FF19}";
        let (result, offsets) = normalize_text(input);
        assert_eq!(result, "123-45-6789");
        assert!(!offsets.is_empty());
    }

    #[test]
    fn test_offset_map_accuracy_multibyte() {
        // Zero-width char followed by fullwidth digit
        let input = "\u{200B}\u{FF10}"; // ZW + fullwidth 0
        let (result, offsets) = normalize_text(input);
        assert_eq!(result, "0");
        // The '0' should map back to byte offset of ０ in original (byte 3, after 3-byte ZW)
        assert_eq!(offsets[0], 3);
    }

    #[test]
    fn test_normalize_text_ascii_fast_path() {
        let (result, offsets) = normalize_text("hello world");
        assert_eq!(result, "hello world");
        assert!(offsets.is_empty()); // Empty = identity mapping
    }

    // ---- Combining diacritical marks stripping ----

    #[test]
    fn test_combining_marks_stripped() {
        // SSN with combining tildes: 1̃2̃3̃-4̃5̃-6̃7̃8̃9̃
        let input = "1\u{0303}2\u{0303}3\u{0303}-4\u{0303}5\u{0303}-6\u{0303}7\u{0303}8\u{0303}9\u{0303}";
        let (result, _) = normalize_text(input);
        assert_eq!(result, "123-45-6789");
    }

    #[test]
    fn test_combining_grave_accent_stripped() {
        // Digits with combining grave accents
        let input = "4\u{0300}5\u{0300}3\u{0300}2";
        let (result, _) = normalize_text(input);
        assert_eq!(result, "4532");
    }

    #[test]
    fn test_combining_marks_cyrillic_range() {
        // Cyrillic combining marks (U+0483-0489)
        let input = "test\u{0483}123";
        let (result, _) = normalize_text(input);
        assert_eq!(result, "test123");
    }

    // ---- Enclosed alphanumerics ----

    #[test]
    fn test_circled_digits_normalized() {
        // ①②③④⑤ → 12345
        let input = "\u{2460}\u{2461}\u{2462}\u{2463}\u{2464}";
        let (result, _) = normalize_text(input);
        assert_eq!(result, "12345");
    }

    #[test]
    fn test_circled_letters_normalized() {
        // Ⓐ Ⓑ Ⓒ → A B C
        let input = "\u{24B6}\u{24B7}\u{24B8}";
        let (result, _) = normalize_text(input);
        assert_eq!(result, "ABC");
    }

    #[test]
    fn test_negative_circled_digits_normalized() {
        // Dingbat negative circled digits
        let input = "\u{2776}\u{2777}\u{2778}";
        let (result, _) = normalize_text(input);
        assert_eq!(result, "123");
    }

    // ---- Roman numerals ----

    #[test]
    fn test_roman_numerals_normalized() {
        // Ⅰ → I, Ⅴ → V, Ⅹ → X
        let input = "\u{2160}\u{2164}\u{2169}";
        let (result, _) = normalize_text(input);
        assert_eq!(result, "IVX");
    }

    // ---- Mathematical symbols ----

    #[test]
    fn test_math_bold_digits_normalized() {
        // Mathematical bold digits 𝟎𝟏𝟐𝟑 → 0123
        let input = "\u{1D7CE}\u{1D7CF}\u{1D7D0}\u{1D7D1}";
        let (result, _) = normalize_text(input);
        assert_eq!(result, "0123");
    }

    #[test]
    fn test_math_bold_letters_normalized() {
        // Mathematical bold A B C → A B C
        let input = "\u{1D400}\u{1D401}\u{1D402}";
        let (result, _) = normalize_text(input);
        assert_eq!(result, "ABC");
    }

    #[test]
    fn test_math_italic_letters_normalized() {
        // Mathematical italic a b c → a b c
        let input = "\u{1D44E}\u{1D44F}\u{1D450}";
        let (result, _) = normalize_text(input);
        assert_eq!(result, "abc");
    }

    #[test]
    fn test_math_fraktur_letters_normalized() {
        // Mathematical fraktur A B → A B
        let input = "\u{1D504}\u{1D505}";
        let (result, _) = normalize_text(input);
        assert_eq!(result, "AB");
    }

    #[test]
    fn test_math_monospace_digits_normalized() {
        // Mathematical monospace 𝟶𝟷𝟸𝟹 → 0123
        let input = "\u{1D7F6}\u{1D7F7}\u{1D7F8}\u{1D7F9}";
        let (result, _) = normalize_text(input);
        assert_eq!(result, "0123");
    }

    // ---- IPA lookalikes ----

    #[test]
    fn test_ipa_lookalikes_normalized() {
        // ɑ → a, ɡ → g, ɪ → i
        let input = "\u{0251}\u{0261}\u{026A}";
        let (result, _) = normalize_text(input);
        assert_eq!(result, "agi");
    }

    // ---- Letterlike symbols ----

    #[test]
    fn test_letterlike_symbols_normalized() {
        // ℎ (Planck) → h, ℬ (script B) → B
        let input = "\u{210E}\u{212C}";
        let (result, _) = normalize_text(input);
        assert_eq!(result, "hB");
    }

    // ---- Combined evasion scenarios ----

    #[test]
    fn test_ssn_combining_marks_plus_fullwidth() {
        // SSN: fullwidth digits with combining marks
        let input = "\u{FF11}\u{0303}\u{FF12}\u{0303}\u{FF13}\u{0303}";
        let (result, _) = normalize_text(input);
        assert_eq!(result, "123");
    }

    #[test]
    fn test_credit_card_math_bold_digits() {
        // Credit card number in mathematical bold: 𝟒𝟓𝟑𝟐𝟎𝟏𝟓𝟏𝟏𝟐𝟖𝟑𝟎𝟑𝟔𝟔
        let input = "\u{1D7D2}\u{1D7D3}\u{1D7D1}\u{1D7D0}\u{1D7CE}\u{1D7CF}\u{1D7D3}\u{1D7CF}\u{1D7CF}\u{1D7D0}\u{1D7D6}\u{1D7D1}\u{1D7CE}\u{1D7D1}\u{1D7D4}\u{1D7D4}";
        let (result, _) = normalize_text(input);
        assert_eq!(result, "4532015112830366");
    }
}
