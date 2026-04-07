# Evasion Defenses

Technical reference for dlpscan's built-in defenses against adversarial evasion
techniques. Each defense maps to one or more attack vectors cataloged in
[evasion_techniques.md](evasion_techniques.md).

---

## Defense Architecture

dlpscan applies a **normalization-before-scanning** pipeline. All text passes
through five preprocessing stages before regex patterns are evaluated:

```
Original Text
     │
     ▼
┌──────────────────────────┐
│ 1. Invisible Character   │  Remove all Unicode Format (Cf) characters:
│    Stripping              │  ZWSP, ZWNJ, ZWJ, BOM, soft hyphen, bidi
│    + Combining Mark Strip │  overrides, variation selectors, Unicode Tags.
│                           │  Also strips 6 combining diacritical mark
│    → offset_map built     │  ranges (U+0300-036F, U+0483-0489, etc.)
└──────────┬────────────────┘
           │
           ▼
┌──────────────────────────┐
│ 2. Whitespace Normalize  │  Convert all Unicode Space Separator (Zs)
│    normalize_whitespace() │  characters to ASCII space
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐
│ 3. NFKC Decomposition    │  Standard Unicode compatibility decomposition
│    unicode-normalization  │  handles fullwidth, ligatures, compatibility
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐
│ 4. Confusable/Homoglyph  │  1,650+ character mappings:
│    Mapping                │  - 1,573 auto-generated from NFKC/NFKD
│    normalize_homoglyphs() │  - 80+ manual overrides (Cyrillic, Greek,
│                           │    IPA, small caps, letterlike symbols)
└──────────┬───────────────┘
           │
           ▼
    Normalized Text  ──→  Regex Scanning  ──→  Offset Map  ──→  Original Spans
```

The **offset map** created in stage 1 tracks the original position of every
surviving character, allowing match spans to be mapped back to the original text
for accurate redaction, tokenization, and obfuscation.

### Character Classification

dlpscan uses the `unicode-general-category` crate for standards-compliant
character classification:

- **Invisible characters**: `GeneralCategory::Format` (Cf) — covers all zero-width,
  bidi, and format control characters without maintaining a manual whitelist
- **Unicode spaces**: `GeneralCategory::SpaceSeparator` (Zs) — covers all Unicode
  space characters including ideographic, thin, hair, em, en, figure, etc.
- **Variation selectors**: Explicitly matched within `NonspacingMark` category
  (`U+FE00`–`U+FE0F`, `U+E0100`–`U+E01EF`)

---

## 1. Invisible Character Stripping

**Module:** `src/normalize/mod.rs` — `is_invisible()`

**Attack:** Insert invisible Unicode characters between digits/letters to break
regex continuity (e.g., `4\u{200b}5\u{200b}3\u{200b}2...` for a Visa number).

**Defense:** Removes **all** characters classified as Unicode Format (Cf) plus
variation selectors before scanning. This is category-based, not a manual
whitelist, so it automatically covers:

| Group | Characters | Coverage |
|-------|-----------|-------|
| Core invisible | ZWSP, ZWNJ, ZWJ, Word Joiner, invisible operators | Automatic (Cf) |
| Marks | LRM, RLM, Arabic Letter Mark, Mongolian Vowel Separator | Automatic (Cf) |
| Format | BOM, Soft Hyphen, Combining Grapheme Joiner | Automatic (Cf) |
| Annotation | Interlinear anchors/separators | Automatic (Cf) |
| Bidi overrides | LRE, RLE, PDF, LRO, RLO (`U+202A`–`U+202E`) | Automatic (Cf) |
| Bidi isolates | LRI, RLI, FSI, PDI (`U+2066`–`U+2069`) | Automatic (Cf) |
| Variation selectors | VS1–VS16 (`U+FE00`–`U+FE0F`) | Explicit match |
| Unicode Tags | Language tag block (`U+E0001`–`U+E007F`) | Automatic (Cf) |

### Combining Diacritical Mark Stripping

Additionally, combining diacritical marks are stripped to defeat accent-based
evasion (e.g., `S̈S̈N̈: 1̈2̈3̈-4̈5̈-6̈7̈8̈9̈`). Six Unicode ranges are covered:

| Range | Name |
|-------|------|
| `U+0300`–`U+036F` | Combining Diacritical Marks |
| `U+0483`–`U+0489` | Combining Cyrillic |
| `U+1AB0`–`U+1AFF` | Combining Diacritical Marks Extended |
| `U+1DC0`–`U+1DFF` | Combining Diacritical Marks Supplement |
| `U+20D0`–`U+20FF` | Combining Diacritical Marks for Symbols |
| `U+FE20`–`U+FE2F` | Combining Half Marks |

**Offset mapping:** Each surviving character's original index is recorded in a
vector. Position `i` in the cleaned text maps to `offset_map[i]` in the original.
Multi-byte character boundaries are handled correctly.

---

## 2. RTL/Bidi Override Stripping

**Module:** `src/normalize/mod.rs` — `is_invisible()`

**Attack:** Insert directional override characters (`U+202E` RLO, `U+2066` LRI,
etc.) to visually reorder digits while the logical byte order in memory differs.

**Defense:** All 9 directional formatting characters are automatically classified
as `GeneralCategory::Format` and stripped:

| Code Point | Name | Purpose |
|-----------|------|---------|
| `U+202A` | Left-to-Right Embedding | Nest LTR text |
| `U+202B` | Right-to-Left Embedding | Nest RTL text |
| `U+202C` | Pop Directional Formatting | End nesting |
| `U+202D` | Left-to-Right Override | Force LTR |
| `U+202E` | Right-to-Left Override | Force RTL |
| `U+2066` | Left-to-Right Isolate | Isolate LTR |
| `U+2067` | Right-to-Left Isolate | Isolate RTL |
| `U+2068` | First Strong Isolate | Auto-detect direction |
| `U+2069` | Pop Directional Isolate | End isolate |

---

## 3. Unicode Whitespace Normalization

**Module:** `src/normalize/mod.rs` — `is_unicode_space()`

**Attack:** Use exotic Unicode space characters as delimiters in sensitive data.

**Defense:** Converts all characters classified as Unicode `SpaceSeparator` (Zs)
to ASCII space before scanning. This automatically covers:

| Code Point | Name |
|-----------|------|
| `U+00A0` | No-Break Space |
| `U+1680` | Ogham Space Mark |
| `U+2000` | En Quad |
| `U+2001` | Em Quad |
| `U+2002` | En Space |
| `U+2003` | Em Space |
| `U+2004` | Three-Per-Em Space |
| `U+2005` | Four-Per-Em Space |
| `U+2006` | Six-Per-Em Space |
| `U+2007` | Figure Space |
| `U+2008` | Punctuation Space |
| `U+2009` | Thin Space |
| `U+200A` | Hair Space |
| `U+202F` | Narrow No-Break Space |
| `U+205F` | Medium Mathematical Space |
| `U+3000` | Ideographic Space |

---

## 4. Confusable / Homoglyph Normalization

**Module:** `src/normalize/mod.rs` — `normalize_homoglyphs()`,
`src/normalize/confusables.rs`

**Attack:** Replace ASCII digits or letters with visually identical Unicode
characters from other scripts (Cyrillic `а` for Latin `a`, fullwidth `４` for
`4`, Greek `Ο` for Latin `O`).

**Defense:** Two-pass normalization with 1,650+ character mappings:

### Pass 1: NFKC Decomposition

Handles fullwidth digits/letters, ligatures (`ﬁ` → `fi`), circled characters,
and other compatibility forms.

### Pass 2: Confusable Map (1,650+ entries)

| Source | Characters | Count |
|--------|-----------|-------|
| Auto-generated (NFKC/NFKD) | Accented letters, mathematical symbols, enclosed forms, compatibility chars | 1,573 |
| Cyrillic → Latin | А/а, В/в, С/с, Е/е, Н/н, І/і, К/к, М/м, О/о, Р/р, Ѕ/ѕ, Т/т, Х/х, У/у, Ј, Ґ, З, Є | 30+ |
| Greek → Latin | Α/α, Β/β, Ε/ε, Η/η, Ι/ι, Κ/κ, Μ/μ, Ν/ν, Ο/ο, Ρ/ρ, Τ/τ, Χ/χ, Υ/υ, Ζ/ζ, ϲ, ϒ | 30+ |
| IPA Extensions | 50+ characters (U+0251–U+02A0) | 50+ |
| Small Capitals | ᴀ→A through ᴢ→Z | 22 |
| Letterlike Symbols | ℃→C, ℉→F, Ω→O, ℓ→l, etc. | 10+ |
| Fullwidth symbols | ：→:, ！→!, ＠→@, ＃→#, etc. | 20+ |
| Circled/enclosed | ①→1, ⓪→0, Ⅰ→I, etc. | 30+ |

### Example

```rust
use dlpscan::normalize::normalize_text;

// Fullwidth Visa number
let text = "\u{FF14}\u{FF15}\u{FF13}\u{FF12}015112830366";
let (normalized, offsets) = normalize_text(text);
// normalized = "4532015112830366"

// Cyrillic email evasion
let text = "us\u{0435}r@t\u{0435}st.com";  // Cyrillic е
let (normalized, _) = normalize_text(text);
// normalized = "user@test.com"

// Combined evasion: zero-width + combining marks + fullwidth
let text = "S\u{0308}\u{200B}S\u{0308}N: \u{FF11}23-45-6789";
let (normalized, _) = normalize_text(text);
// normalized = "SSN: 123-45-6789"
```

---

## 5. Regex Safety (ReDoS Protection)

**Module:** `src/scanner/mod.rs`

**Attack:** Craft input that triggers catastrophic backtracking in regex patterns.

**Defense:** Rust's `regex` crate guarantees **linear-time matching** by design —
it uses a finite automaton approach that prevents catastrophic backtracking entirely.
Additionally, defense-in-depth timeouts are configured:

| Constant | Default | Description |
|----------|---------|-------------|
| `REGEX_TIMEOUT_SECONDS` | 5 | Per-pattern regex timeout |
| `MAX_SCAN_SECONDS` | 120 | Global scan timeout |
| `MAX_MATCHES` | 50,000 | Maximum matches per scan |
| `MAX_INPUT_SIZE` | 10 MB | Maximum input size |

---

## 6. Scan Completeness Indicator

**Module:** `src/scanner/mod.rs` — `ScanOutput`

**Attack:** Flood a document with 50,000+ pattern matches so the scanner hits
`MAX_MATCHES` and silently stops.

**Defense:** `ScanOutput` exposes truncation status:

```rust
pub struct ScanOutput {
    pub matches: Vec<Match>,
    pub truncated: bool,  // True if scan was terminated early
}
```

---

## 7. Context-Gated Pattern Prefilter

**Module:** `src/scanner/mod.rs`, `src/context/mod.rs`

**Attack:** Submit text with many low-specificity pattern matches to waste
scanning resources.

**Defense:** Aho-Corasick keyword prefilter gates 452 low-specificity patterns:

- Patterns with specificity ≥ 0.85 or in `CRITICAL_ALWAYS_RUN` run unconditionally
- Patterns below 0.85 only run if their context keywords are found in the text
- Single O(n) Aho-Corasick pass identifies which keyword groups are present
- 2,718 keywords across 560 groups provide comprehensive context coverage

---

## 8. Chained/Polymorphic Evasion

**Attack:** Layer multiple evasion techniques simultaneously — e.g., fullwidth
digits + zero-width spaces + combining marks + RTL overrides.

**Defense:** The 5-stage normalization pipeline handles chained attacks because
each stage operates on the output of the previous:

1. Invisible char + combining mark stripping removes ZWSP, bidi, diacritics
2. Whitespace normalization converts exotic spaces to ASCII
3. NFKC decomposes compatibility forms
4. Confusable mapping converts remaining lookalikes to ASCII

A string like `\u{202e}\u{FF14}\u{200b}\u{FF15}\u{0308}\u{200b}\u{FF13}...`
(RTL override + fullwidth digits + zero-width + combining marks) is normalized
to `453...` after all stages complete.

---

## Defense Coverage Summary

| Evasion Technique | Defense | Status |
|-------------------|---------|--------|
| Zero-width char insertion | `is_invisible()` (Cf category) | **Defended** |
| Combining mark injection | `is_combining_mark()` (6 ranges) | **Defended** |
| RTL/Bidi manipulation | Automatic (Cf category) | **Defended** |
| Variation selectors | Explicit match in `is_invisible()` | **Defended** |
| Unicode Tags steganography | Automatic (Cf category) | **Defended** |
| Delimiter variation | `is_unicode_space()` (Zs category) | **Defended** |
| Homoglyph substitution | 1,650+ confusable mappings | **Defended** |
| Fullwidth/compatibility forms | NFKC decomposition | **Defended** |
| Case-variant evasion | 152 patterns now case-insensitive | **Defended** |
| Separator-variant evasion | IBAN/E.164 patterns accept `-./\s` | **Defended** |
| ReDoS / timeout bypass | Linear-time regex + timeouts | **Defended** |
| Max matches truncation | `ScanOutput.truncated` | **Exposed** |
| Polymorphic encoding chains | Sequential 5-stage pipeline | **Defended** |
| Low-specificity flooding | Context-gated prefilter | **Defended** |

---

## Remaining Gaps

These evasion vectors are identified but not yet fully defended:

1. **Multilingual context keywords** — Keyword lists are primarily English. No
   translations or non-English synonyms.

2. **Leet-speak normalization** — A `normalize_leet()` function exists but is
   intentionally NOT enabled globally because it converts digits to letters
   (4→a, 0→o), which is catastrophic for digit-based patterns (SSN, CC, phone).
   Leet-speak normalization would need to be pattern-category-aware.

3. **Per-pattern OCR confidence** — Global threshold may be too aggressive for
   some patterns and too lenient for others.

See the [Priority Remediation Roadmap](evasion_techniques.md#priority-remediation-roadmap)
in evasion_techniques.md for the full backlog.
