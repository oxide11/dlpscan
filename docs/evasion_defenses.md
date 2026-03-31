# Evasion Defenses

Technical reference for dlpscan's built-in defenses against adversarial evasion
techniques. Each defense maps to one or more attack vectors cataloged in
[evasion_techniques.md](evasion_techniques.md).

---

## Defense Architecture

dlpscan applies a **normalization-before-scanning** pipeline. All text passes
through three preprocessing stages before regex patterns are evaluated:

```
Original Text
     │
     ▼
┌──────────────────────────┐
│ 1. Zero-Width Stripping  │  Remove invisible characters (ZWSP, ZWNJ, ZWJ,
│    strip_zero_width()    │  BOM, soft hyphen, bidi overrides, variation
│                          │  selectors, Unicode Tags)
│    → offset_map built    │
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐
│ 2. Whitespace Normalize  │  Convert 14 exotic Unicode spaces (ideographic,
│    normalize_whitespace() │  thin, hair, em, en, etc.) to ASCII space
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐
│ 3. Homoglyph Normalize   │  NFKC decomposition + explicit mapping of 80+
│    normalize_homoglyphs() │  Cyrillic/Greek/fullwidth/symbol confusables
└──────────┬───────────────┘
           │
           ▼
    Normalized Text  ──→  Regex Scanning  ──→  Offset Map  ──→  Original Spans
```

The **offset map** created in step 1 tracks the original position of every
surviving character, allowing match spans to be mapped back to the original text
for accurate redaction, tokenization, and obfuscation.

---

## 1. Zero-Width Character Stripping

**Module:** `dlpscan/unicode_normalize.py` — `strip_zero_width()`

**Attack:** Insert invisible Unicode characters between digits/letters to break
regex continuity (e.g., `4\u200b5\u200b3\u200b2...` for a Visa number).

**Defense:** Removes **all** characters in the `ZERO_WIDTH_CHARS` set before
scanning. The current set contains **160+ characters** across these groups:

| Group | Characters | Count |
|-------|-----------|-------|
| Core invisible | ZWSP, ZWNJ, ZWJ, Word Joiner, invisible operators | 10 |
| Marks | LRM, RLM, Arabic Letter Mark, Mongolian Vowel Separator | 4 |
| Format | BOM, Soft Hyphen, Combining Grapheme Joiner | 3 |
| Annotation | Interlinear anchors/separators | 3 |
| Bidi overrides | LRE, RLE, PDF, LRO, RLO (`U+202A`–`U+202E`) | 5 |
| Bidi isolates | LRI, RLI, FSI, PDI (`U+2066`–`U+2069`) | 4 |
| Variation selectors | VS1–VS16 (`U+FE00`–`U+FE0F`) | 16 |
| Unicode Tags | Language tag block (`U+E0001`–`U+E007F`) | 127 |

**Offset mapping:** Each surviving character's original index is recorded in a
list. Position `i` in the cleaned text maps to `offset_map[i]` in the original.
This ensures redaction targets the correct bytes even when hundreds of invisible
characters were injected.

### Usage

```python
from dlpscan.unicode_normalize import strip_zero_width

text = "4\u200b5\u200b3\u200b2\u200b0151\u200b1283\u200b0366"
cleaned, offsets = strip_zero_width(text)
# cleaned = "4532015112830366"
# offsets = [0, 2, 4, 6, 8, 9, 10, 11, 13, 14, 15, 16, 18, 19, 20, 21]
```

---

## 2. RTL/Bidi Override Stripping

**Module:** `dlpscan/unicode_normalize.py` — `ZERO_WIDTH_CHARS`

**Attack:** Insert directional override characters (`U+202E` RLO, `U+2066` LRI,
etc.) to visually reorder digits while the logical byte order in memory differs,
causing regex patterns to scan reversed or rearranged text.

**Defense:** All 9 directional formatting characters are included in the
zero-width strip set:

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

Combined with `U+200E` (LRM) and `U+200F` (RLM) already in the set, **all 11
Unicode directional formatting characters** are stripped before scanning.

---

## 3. Variation Selector Stripping

**Module:** `dlpscan/unicode_normalize.py` — `ZERO_WIDTH_CHARS`

**Attack:** Insert variation selectors (`U+FE00`–`U+FE0F`) between characters.
These invisible characters select glyph variants and break regex continuity
without changing visual appearance.

**Defense:** All 16 variation selectors (VS1–VS16) are included in the
zero-width strip set and removed before scanning.

---

## 4. Unicode Tags Block Stripping

**Module:** `dlpscan/unicode_normalize.py` — `ZERO_WIDTH_CHARS`

**Attack:** Embed data steganographically using Unicode Tag characters
(`U+E0001`–`U+E007F`). These invisible characters from the Supplementary
Special-purpose Plane can encode full ASCII text invisibly within document
content.

**Defense:** The entire Unicode Tags range (127 characters) is included in the
zero-width strip set and removed before scanning.

---

## 5. Unicode Whitespace Normalization

**Module:** `dlpscan/unicode_normalize.py` — `normalize_whitespace()`

**Attack:** Use exotic Unicode space characters as delimiters in sensitive data.
Standard delimiter patterns (`_S`) match common separators but not ideographic
space (`U+3000`), thin space (`U+2009`), or other rare whitespace characters.

**Defense:** Converts 14 exotic Unicode whitespace characters to ASCII space
before scanning:

| Code Point | Name |
|-----------|------|
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

This is a 1:1 character replacement (no length change), so the offset map
remains valid across this stage.

### Usage

```python
from dlpscan.unicode_normalize import normalize_whitespace

text = "4532\u30000151\u30001283\u30000366"  # Ideographic spaces
normalized = normalize_whitespace(text)
# "4532 0151 1283 0366"  — now matches standard delimiter patterns
```

---

## 6. Homoglyph / Confusable Normalization

**Module:** `dlpscan/unicode_normalize.py` — `normalize_homoglyphs()`

**Attack:** Replace ASCII digits or letters with visually identical Unicode
characters from other scripts (Cyrillic `а` for Latin `a`, fullwidth `４` for
`4`, Greek `Ο` for Latin `O`).

**Defense:** Two-pass normalization:

1. **NFKC decomposition** — Handles fullwidth digits/letters, ligatures (`ﬁ` →
   `fi`), circled characters, and other compatibility forms.

2. **Explicit homoglyph map** — 80+ entries covering characters NFKC doesn't
   normalize:
   - **Cyrillic → Latin**: А/а, В/в, С/с, Е/е, Н/н, І/і, К/к, М/м, О/о, Р/р,
     Ѕ/ѕ, Т/т, Х/х, У/у
   - **Greek → Latin**: Α/α, Β/β, Ε/ε, Η/η, Ι/ι, Κ/κ, Μ/μ, Ν/ν, Ο/ο, Ρ/ρ,
     Τ/τ, Χ/χ, Υ/υ, Ζ/ζ
   - **Fullwidth Latin**: Ａ–Ｚ, ａ–ｚ (52 entries)
   - **Digit confusables**: Fullwidth ０–９, subscript ₀–₉, superscript ⁰–⁹
   - **Symbol lookalikes**: 10 dash/hyphen variants, fullwidth `.`, `@`, `/`

### Usage

```python
from dlpscan.unicode_normalize import normalize_homoglyphs

# Fullwidth Visa number
text = "\uff14\uff15\uff13\uff12\uff10\uff11\uff15\uff11\uff11\uff12\uff18\uff13\uff10\uff13\uff16\uff16"
normalized = normalize_homoglyphs(text)
# "4532015112830366"

# Cyrillic email evasion
text = "us\u0435r@t\u0435st.com"  # Cyrillic е
normalized = normalize_homoglyphs(text)
# "user@test.com"
```

---

## 7. Cross-Platform Regex Timeout

**Module:** `dlpscan/scanner.py` — `_ThreadTimeout`, `_can_use_sigalrm()`

**Attack:** Craft input that triggers catastrophic backtracking (ReDoS) in regex
patterns. On non-Unix platforms or in worker threads, the SIGALRM-based timeout
doesn't work, allowing unbounded CPU consumption.

**Defense:** Dual-layer timeout system:

| Layer | Mechanism | Scope | Precision |
|-------|-----------|-------|-----------|
| **SIGALRM** | Unix signal handler | Main thread, Unix only | Interrupts mid-regex |
| **_ThreadTimeout** | `threading.Timer` | All platforms, all threads | Checked between patterns |

The `_ThreadTimeout` class starts a daemon timer that sets an `expired` flag
after the configured duration. The scan loop checks this flag between every
pattern category and sub-category iteration. While it cannot interrupt a single
blocking regex mid-execution, it prevents runaway scans from consuming unbounded
time across multiple patterns.

**Configuration:**

| Constant | Default | Description |
|----------|---------|-------------|
| `REGEX_TIMEOUT_SECONDS` | 5 | Per-pattern SIGALRM timeout (Unix main thread) |
| `MAX_SCAN_SECONDS` | 120 | Global scan timeout (both layers) |

### How it works

```python
# In enhanced_scan_text():
if _can_use_sigalrm():
    # Unix main thread: hard interrupt via SIGALRM
    signal.signal(signal.SIGALRM, _timeout_handler)
    signal.alarm(MAX_SCAN_SECONDS)
else:
    # Fallback: threading.Timer sets flag checked in scan loop
    _thread_timeout = _ThreadTimeout(MAX_SCAN_SECONDS)
    _thread_timeout.start()

# Between each pattern:
if _thread_timeout and _thread_timeout.expired:
    scan_timed_out = True
    break
```

---

## 8. Scan Completeness Indicator

**Module:** `dlpscan/guard/core.py` — `ScanResult`

**Attack:** Flood a document with 50,000+ pattern matches so the scanner hits
`MAX_MATCHES` and silently stops. Real sensitive data after the limit is
unscanned.

**Defense:** `ScanResult` now exposes truncation status to API consumers:

| Field | Type | Description |
|-------|------|-------------|
| `scan_truncated` | `bool` | `True` if scan was cut short by match limits or timeout |
| `scan_complete` | `bool` (property) | `True` if scan ran to full completion |

These fields are also included in `ScanResult.to_dict()` for JSON serialization.

### Usage

```python
from dlpscan import InputGuard, Preset, Action

guard = InputGuard(presets=[Preset.PCI_DSS], action=Action.FLAG)
result = guard.scan(text)

if result.scan_truncated:
    logger.warning("Scan incomplete — %d findings found before truncation",
                   result.finding_count)

# JSON output includes the field:
result.to_dict()
# {'is_clean': False, 'scan_truncated': True, 'finding_count': 50000, ...}
```

---

## 9. InputGuard Transform Pipeline

**Module:** `dlpscan/guard/core.py`, `dlpscan/guard/transforms.py`

**Attack:** Zero-width characters survive into match text, causing format
mismatches in redaction, tokenization, and obfuscation outputs.

**Defense:** All InputGuard transform actions clean match text before processing:

- **REDACT** (`core.py:_redact_matches`): Calls `strip_zero_width()` on each
  match span before passing to `redact_sensitive_info()`.
- **TOKENIZE** (`transforms.py:tokenize_matches`): Stores the cleaned value
  (not the raw text with invisible characters) in the token vault.
- **OBFUSCATE** (`transforms.py`): All 7 obfuscation generators
  (`_obfuscate_credit_card`, `_obfuscate_phone`, `_obfuscate_ssn`, etc.) use
  `_clean_match_text()` to strip zero-width characters before generating format-
  preserving fake data.

This ensures output text never contains invisible characters from evasion
attempts.

---

## 10. Chained/Polymorphic Evasion

**Attack:** Layer multiple evasion techniques simultaneously — e.g., fullwidth
digits + zero-width spaces + RTL overrides.

**Defense:** The normalization pipeline handles chained attacks because it
applies transformations in sequence:

1. Zero-width stripping removes ZWSP, bidi overrides, variation selectors
2. Whitespace normalization converts exotic spaces to ASCII
3. NFKC + homoglyph mapping converts fullwidth/Cyrillic/Greek to ASCII

Each stage operates on the output of the previous stage, so layered evasion
techniques are peeled away one layer at a time. A string like
`\u202e\uff14\u200b\uff15\u200b\uff13\u200b\uff12...` (RTL override +
fullwidth digits + zero-width spaces) is normalized to `4532...` after all
three stages complete.

---

## Defense Coverage Summary

| Evasion Technique | Defense | Status |
|-------------------|---------|--------|
| Zero-width char insertion | `strip_zero_width()` | **Defended** |
| RTL/Bidi manipulation | Bidi chars in strip set | **Defended** |
| Variation selectors | VS1–VS16 in strip set | **Defended** |
| Unicode Tags steganography | Tags block in strip set | **Defended** |
| Delimiter variation | `normalize_whitespace()` | **Defended** |
| Homoglyph substitution | `normalize_homoglyphs()` | **Defended** (80+ mappings) |
| Word boundary bypass | Post-normalization `\b` | **Defended** |
| ReDoS / timeout bypass | SIGALRM + `_ThreadTimeout` | **Defended** |
| Max matches truncation | `ScanResult.scan_truncated` | **Exposed** |
| Polymorphic encoding chains | Sequential pipeline | **Defended** |
| Transform output pollution | `_clean_match_text()` | **Defended** |
| Context keyword homoglyphs | Normalized before context search | **Defended** |
| OCR confidence manipulation | — | Weak |
| Context keyword evasion | — | Weak |
| Unsupported file formats | — | Weak |
| Allowlist value mutation | — | Weak |

---

## Remaining Gaps

These evasion vectors are identified but not yet fully defended:

1. **Expand homoglyph coverage** — Current map has ~80 entries vs Unicode
   Consortium's confusables.txt (6,000+). Armenian, Georgian, Cherokee, and
   mathematical alphanumeric symbols are not mapped.

2. **Context keyword evasion** — Keyword lists are static and primarily English.
   No fuzzy matching or multilingual synonym expansion.

3. **File format coverage** — RTF, ODS, Pages, and other formats lack
   extractors. Sensitive data in unsupported formats is silently skipped.

4. **OCR confidence hardening** — `MIN_OCR_CONFIDENCE = 30` is low. No
   per-pattern OCR confidence thresholds.

5. **Allowlist pattern matching** — Allowlist uses exact string matching only.
   No wildcard or prefix-based allowlisting.

See the [Priority Remediation Roadmap](evasion_techniques.md#priority-remediation-roadmap)
in evasion_techniques.md for the full backlog.
