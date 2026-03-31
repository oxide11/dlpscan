# Advanced DLP Techniques

Technical reference for dlpscan's advanced detection modules: Aho-Corasick
context matching, Exact Data Match (EDM), and Locality-Sensitive Hashing (LSH).

**Version:** 1.7.0

---

## Table of Contents

1. [Aho-Corasick Context Matching](#aho-corasick-context-matching)
2. [Exact Data Match (EDM)](#exact-data-match-edm)
3. [Locality-Sensitive Hashing (LSH)](#locality-sensitive-hashing-lsh)
4. [Benchmark Results](#benchmark-results)
5. [Architecture Overview](#architecture-overview)

---

## Aho-Corasick Context Matching

### What It Does

Replaces the default regex-based context keyword matching with a single-pass
trie-based automaton that matches all 2,500+ context keywords simultaneously
in O(n) time.

### The Problem It Solves

dlpscan's context matching verifies that sensitive data patterns (e.g., credit
card numbers) appear near relevant keywords (e.g., "credit card", "payment",
"visa"). The default regex backend compiles 560 separate alternation patterns:

```
\b(visa|credit card|card number|card no|pan)\b
```

Each pattern match in the text triggers a context check, which searches for
keywords in the surrounding window. With 560 patterns and potentially thousands
of matches, this creates O(M x K) context checks per scan.

### How Aho-Corasick Works

1. **Build Phase**: All 2,500+ keywords are inserted into a trie (prefix tree).
   Failure links are computed using BFS — these let the automaton "fall back"
   to the longest matching suffix when a character doesn't match, similar to
   how KMP works for single patterns.

2. **Search Phase**: The text is scanned character-by-character. The automaton
   follows trie edges, falling back via failure links as needed. Every time a
   keyword is completed, it's emitted with its position. This is a single O(n)
   pass that finds ALL keywords simultaneously.

3. **Index Phase**: Keyword hits are organized into a `ContextHitIndex` — a
   sorted position list per (category, sub_category) pair. Proximity queries
   use binary search for O(log n) per lookup.

```
Text: "credit card number 4111111111111111 expires 12/28"

Trie traversal: c→r→e→d→i→t→ →c→a→r→d  → EMIT "credit card" at pos 0
                                  n→u→m→b→e→r → EMIT "card number" at pos 12
                                  e→x→p→i→r→e→s → EMIT "expires" at pos 35

Hit Index: {
  ('Credit Card Numbers', 'Visa'): [0, 12, 35]  ← sorted positions
}

Query: has_hit_in_range('Visa', match_start-50, match_end+50)
       → binary search → O(log 3)
```

### Configuration

Three ways to enable:

```python
# 1. Programmatic (per-guard)
from dlpscan import InputGuard, Preset
guard = InputGuard(presets=[Preset.PCI_DSS], context_backend="ahocorasick")

# 2. Programmatic (global)
from dlpscan import set_context_backend
set_context_backend("ahocorasick")

# 3. Environment variable
# DLPSCAN_CONTEXT_BACKEND=ahocorasick

# 4. Config file (pyproject.toml)
# [tool.dlpscan]
# context_backend = "ahocorasick"

# 5. Config file (.dlpscanrc)
# {"context_backend": "ahocorasick"}
```

To switch back: `set_context_backend("regex")`

### C Extension vs Pure Python

The module uses **pyahocorasick** (C extension) when available:

```bash
pip install dlpscan[ahocorasick]   # or: pip install pyahocorasick
```

If not installed, a pure-Python fallback automaton is used. The C extension
is significantly faster for large keyword sets.

### Fuzzy Matching Integration

Aho-Corasick performs **exact** keyword matching. It does NOT replace fuzzy
Levenshtein matching. When the Aho-Corasick backend is active:

1. First: O(1) lookup in the Aho-Corasick hit index (exact match)
2. If no exact match: fall through to Levenshtein fuzzy matching (edit distance ≤ 2)

This means typo detection ("credti card" → "credit card") still works.

### Thread Safety

The automaton is built once and is read-only during scanning. Multiple threads
can share the same matcher. The automaton is rebuilt automatically when custom
patterns are registered/unregistered.

### API Reference

```python
# Module: dlpscan.ahocorasick

class AhoCorasickMatcher:
    def build(context_keywords=None, custom_context=None) -> None
    def search(text: str) -> ContextHitIndex
    def has_context_near(hit_index, match_start, match_end,
                         category, sub_category, distance=50) -> bool
    @property
    def is_built(self) -> bool
    @property
    def keyword_count(self) -> int

class ContextHitIndex:
    def has_hit_in_range(category, sub_category, range_start, range_end) -> bool
    @property
    def empty(self) -> bool

# Singleton access
get_matcher() -> AhoCorasickMatcher
rebuild_matcher(custom_context=None) -> None

# Scanner integration
set_context_backend(backend: str) -> None   # "regex" or "ahocorasick"
get_context_backend() -> str
```

---

## Exact Data Match (EDM)

### What It Does

Detects specific known sensitive values (e.g., a list of 50,000 employee SSNs)
with **zero false positives** using salted cryptographic hashes. Unlike pattern
matching which finds anything that *looks like* an SSN, EDM only matches values
you've explicitly registered.

### The Problem It Solves

Pattern matching with `\d{3}-\d{2}-\d{4}` catches SSN-like patterns but also
matches phone numbers, ZIP codes, and other numeric sequences. EDM eliminates
this ambiguity entirely: if the hash matches, the exact value was present.

### How It Works

1. **Registration**: Each known sensitive value is normalized (lowercase, strip
   separators) and hashed with HMAC-SHA256 using a per-deployment salt:
   ```
   H(salt, normalize("123-45-6789")) → "a1b2c3d4..."
   ```
   Only the hash is stored — the original value is never kept.

2. **Scanning**: Text is tokenized into candidate values using configurable
   tokenizers (numeric sequences, emails, word n-grams). Each candidate is
   normalized, hashed, and checked against the hash set.

3. **Privacy**: The hash set is safe to distribute (e.g., to scanning nodes)
   because recovering original values from HMAC-SHA256 hashes is
   computationally infeasible. The salt must be kept secret.

```
Registration:
  "123-45-6789" → normalize → "123456789" → HMAC-SHA256(salt, "123456789") → "a1b2..."
  "987-65-4321" → normalize → "987654321" → HMAC-SHA256(salt, "987654321") → "f3e4..."

  Hash set: {"a1b2...", "f3e4..."}

Scanning:
  Text: "Employee SSN is 123-45-6789 on file."
  Tokenizer: extracts "123-45-6789" at span (16, 27)
  Normalize: "123456789"
  Hash: HMAC-SHA256(salt, "123456789") → "a1b2..."
  Lookup: "a1b2..." in hash_set → MATCH (confidence: 1.0)
```

### Usage

```python
from dlpscan import ExactDataMatcher

# Create matcher with auto-generated salt
matcher = ExactDataMatcher()

# Or with explicit salt (for reproducibility / persistence)
matcher = ExactDataMatcher(salt=b'my-secret-deployment-salt-32bytes')

# Register known sensitive values
matcher.register_values("employee_ssn", [
    "123-45-6789",
    "987-65-4321",
    "555-12-3456",
])

matcher.register_values("customer_cc", [
    "4111-1111-1111-1111",
    "5500-0000-0000-0004",
])

# Scan text
hits = matcher.scan("Employee SSN is 123-45-6789 on file.")
for hit in hits:
    print(f"EDM match: category={hit.category}, span={hit.span}, "
          f"confidence={hit.confidence}")

# Quick check
matcher.check_value("123-45-6789", category="employee_ssn")  # True
matcher.check_value("000-00-0000", category="employee_ssn")  # False

# Persistence
matcher.save("edm_hashes.json")
loaded = ExactDataMatcher.load("edm_hashes.json")
```

### Tokenizers

Tokenizers extract candidate values from text for hashing:

| Tokenizer | What It Extracts | Use Case |
|-----------|-----------------|----------|
| `numeric` | Digit sequences with separators (`\d[\d\-. ]{3,18}\d`) | SSNs, credit cards, phone numbers |
| `email` | Email addresses | Email addresses |
| `word_1gram` | Single words (2+ chars) | Names, keywords |
| `word_2gram` | Two-word phrases | Full names |
| `word_3gram` | Three-word phrases | Addresses |

```python
# Custom tokenizer configuration
matcher = ExactDataMatcher(tokenizers=['numeric', 'email', 'word_2gram'])

# Register custom tokenizer
import re
def my_tokenizer(text):
    return [(m.group(), m.span()) for m in re.finditer(r'PRJ-\d{6}', text)]

matcher.register_tokenizer('project_code', my_tokenizer)
```

### Value Normalization

Before hashing, values are normalized to handle formatting variations:

```
"123-45-6789"      → "123456789"     (separators stripped)
"4111 1111 1111 1111" → "4111111111111111" (spaces stripped)
"John.Doe@EXAMPLE.com" → "johndoeexamplecom" (lowercased, dots stripped)
```

This ensures that `411-1111-1111-1111`, `4111 1111 1111 1111`, and
`4111111111111111` all produce the same hash.

### Persistence Format

```json
{
  "version": 1,
  "salt": "base64-encoded-salt==",
  "tokenizers": ["numeric", "email"],
  "categories": {
    "employee_ssn": ["a1b2c3d4...", "f3e4d5c6..."],
    "customer_cc": ["7890abcd...", "ef012345..."]
  }
}
```

### API Reference

```python
# Module: dlpscan.edm

class ExactDataMatcher:
    def __init__(salt=None, tokenizers=None, normalize=None)
    def register_values(category: str, values: Iterable[str]) -> int
    def register_tokenizer(name: str, func: Callable) -> None
    def scan(text: str, categories=None) -> List[EDMMatch]
    def check_value(value: str, category=None) -> bool
    def save(path: str) -> None
    @classmethod
    def load(path: str) -> ExactDataMatcher
    def clear(category=None) -> None
    @property
    def categories(self) -> List[str]
    @property
    def total_hashes(self) -> int

class EDMMatch:
    value_hash: str       # Truncated HMAC-SHA256 hash
    category: str         # Category of the matched value
    span: Tuple[int, int] # Position in text
    matched_text: str     # The raw text that matched
    confidence: float     # Always 1.0 for EDM matches
    def to_dict() -> dict
```

---

## Locality-Sensitive Hashing (LSH)

### What It Does

Detects documents that are **similar** to known sensitive documents, even after
editing, reformatting, cropping, or partial paraphrasing. Unlike pattern
matching (which finds specific data types), LSH operates at the document level.

### The Problem It Solves

A confidential contract might be leaked by copying it, changing a few words,
and reformatting it. Standard hashing (SHA-256) would produce a completely
different hash for even a single character change. Pattern matching wouldn't
catch it because the document doesn't necessarily contain patterns like SSNs.

### How It Works

1. **Shingling**: Break documents into overlapping word 3-grams (shingles):
   ```
   "the quick brown fox jumps"
   → {"the quick brown", "quick brown fox", "brown fox jumps"}
   ```

2. **MinHash**: Generate a compact signature (128 hash values) that approximates
   the Jaccard similarity of shingle sets. Documents with similar content
   produce similar signatures.
   ```
   Jaccard(A, B) = |A ∩ B| / |A ∪ B|

   Document A: 1000 shingles
   Document B: 950 shingles (edited copy)
   Overlap: 800 shingles
   Jaccard ≈ 800/1150 ≈ 0.70

   MinHash signature (128 values) estimates this Jaccard in O(1).
   ```

3. **LSH Banding**: Split the 128-hash signature into 16 bands of 8 rows.
   Documents that share ANY band hash are candidate near-duplicates. This
   gives sub-linear query time — you don't compare against every document.

4. **Verification**: For each candidate, compute the exact estimated Jaccard
   from the full 128-hash signatures. Only report matches above the threshold.

```
Registration:
  "This is a confidential contract about project Alpha..."
  → 500 shingles → MinHash signature [h1, h2, ..., h128]
  → 16 band hashes → inserted into 16 hash tables

Query:
  "This is a confidential contract about project Alpha with minor edits..."
  → 480 shingles → MinHash signature [h1', h2', ..., h128']
  → 16 band hashes → check against 16 hash tables
  → Candidate: "contract_v1" (shares 12 of 16 bands)
  → Verify: Jaccard ≈ 0.85 ≥ threshold (0.80)
  → MATCH: SimilarityMatch(doc_id="contract_v1", similarity=0.85)
```

### Usage

```python
from dlpscan import DocumentVault

# Create vault with 80% similarity threshold
vault = DocumentVault(threshold=0.8)

# Register known sensitive documents
vault.register("contract_v1", contract_text, sensitivity="confidential")
vault.register("employee_handbook", handbook_text, sensitivity="internal")
vault.register("source_code_auth", auth_module_text, sensitivity="proprietary")

# Query incoming text for similarity
matches = vault.query(suspicious_email_text)
for m in matches:
    print(f"Similar to {m.doc_id}: {m.similarity:.0%} "
          f"(sensitivity: {m.sensitivity})")

# Quick boolean check
if vault.contains_similar(outgoing_email):
    block_and_alert()

# Persistence
vault.save("sensitive_docs_vault.json")
vault = DocumentVault.load("sensitive_docs_vault.json")
```

### Tuning Parameters

| Parameter | Default | Effect |
|-----------|---------|--------|
| `num_hashes` | 128 | More hashes = more accurate similarity estimate |
| `bands` | 16 | More bands = catches lower-similarity matches |
| `threshold` | 0.8 | Minimum Jaccard similarity to report as match |
| `shingle_size` | 3 | Words per shingle. Smaller = more sensitive to edits |

**Threshold tuning guide:**

| Threshold | Use Case |
|-----------|----------|
| 0.9+ | Near-exact copies (reformatting only) |
| 0.8 | Default — catches moderate edits |
| 0.6-0.7 | Catches significant paraphrasing |
| 0.5 | Aggressive — may produce false positives |
| <0.5 | Not recommended (too many false positives) |

**Memory usage:** ~1 KB per registered document (128 x 8-byte hashes + metadata).
10,000 documents ≈ 10 MB.

### API Reference

```python
# Module: dlpscan.lsh

class DocumentVault:
    def __init__(num_hashes=128, bands=16, threshold=0.8, shingle_size=3)
    def register(doc_id: str, text: str, sensitivity="sensitive",
                 metadata=None) -> None
    def unregister(doc_id: str) -> bool
    def query(text: str, threshold=None) -> List[SimilarityMatch]
    def contains_similar(text: str, threshold=None) -> bool
    def save(path: str) -> None
    @classmethod
    def load(path: str) -> DocumentVault
    def clear() -> None
    @property
    def document_count(self) -> int
    @property
    def threshold(self) -> float

class SimilarityMatch:
    doc_id: str           # ID of the matching document
    similarity: float     # Estimated Jaccard similarity (0.0-1.0)
    sensitivity: str      # Sensitivity label
    doc_metadata: dict    # Custom metadata
    def to_dict() -> dict
```

---

## Benchmark Results

Benchmarks comparing the Regex and Aho-Corasick context matching backends.
Run on Python 3.11 with `pyahocorasick` 2.3.0 (C extension).

### Throughput

| Text Size | Backend | Avg (ms) | Ops/sec | MB/s |
|-----------|---------|----------|---------|------|
| 1 KB (normal density) | regex | 6.7 | 149 | 0.15 |
| 1 KB (normal density) | ahocorasick | 6.6 | 151 | 0.15 |
| 10 KB (normal density) | regex | 71.9 | 13.9 | 0.14 |
| 10 KB (normal density) | ahocorasick | 72.6 | 13.8 | 0.13 |
| 100 KB (normal density) | regex | 974 | 1.0 | 0.10 |
| 100 KB (normal density) | ahocorasick | 966 | 1.0 | 0.10 |
| 1 MB (normal density) | regex | 10,134 | 0.1 | 0.10 |
| 1 MB (normal density) | ahocorasick | 10,142 | 0.1 | 0.10 |
| 10 KB (high density) | regex | 256 | 3.9 | 0.04 |
| 10 KB (high density) | ahocorasick | 248 | 4.0 | 0.04 |
| 100 KB (high density) | regex | 3,460 | 0.3 | 0.03 |
| 100 KB (high density) | ahocorasick | 3,324 | 0.3 | 0.03 |

### Key Observations

1. **Throughput parity**: Both backends are within 1-4% of each other on all
   text sizes. The 560 regex `finditer()` calls dominate scan time, not context
   matching.

2. **Dense text advantage**: Aho-Corasick shows a consistent 3-4% advantage on
   high-density texts (many matches). This is because the single-pass hit index
   is shared across all pattern matches, while the regex backend runs a separate
   context search per match.

3. **Accuracy**: Both backends produce identical matches on most texts. Minor
   differences in overlap deduplication occur on large texts where Aho-Corasick
   finds additional context hits (it performs a more comprehensive single-pass
   search vs. the regex backend's per-match windowed search).

4. **Scaling projection**: The Aho-Corasick advantage grows with:
   - More context keywords (currently 2,531 — at 10,000+ the gap widens)
   - Higher match density (more context checks per scan)
   - Batch processing (automaton built once, reused across scans)

### When to Use Each

| Scenario | Recommended Backend |
|----------|-------------------|
| Default / simple use | `regex` (zero dependencies) |
| Small texts (<10 KB) | Either (equivalent performance) |
| Large documents (>100 KB) | `ahocorasick` (slight advantage) |
| High match density | `ahocorasick` (3-4% faster) |
| Batch file processing | `ahocorasick` (amortized build cost) |
| Custom keyword sets (>5,000) | `ahocorasick` (single pass scales better) |
| No external dependencies | `regex` (stdlib only) |
| Maximum compatibility | `regex` (no C extension needed) |

### Running Benchmarks

```bash
# Full comparison suite
python tests/bench_context_backends.py

# Machine-readable JSON output
python tests/bench_context_backends.py --json

# General performance benchmarks
python tests/benchmarks.py
```

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Input Text                                    │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────────────┐                                            │
│  │ Unicode Normalize    │  Stage 1: Strip zero-width chars          │
│  │ (unicode_normalize)  │  Stage 2: Normalize whitespace            │
│  │                      │  Stage 3: Map homoglyphs to ASCII         │
│  └─────────┬───────────┘                                            │
│            │                                                         │
│  ┌─────────▼───────────┐                                            │
│  │ Pattern Matching     │  560 compiled regex patterns               │
│  │ (scanner.py)         │  126 categories, finditer() per pattern   │
│  └─────────┬───────────┘                                            │
│            │                                                         │
│  ┌─────────▼───────────────────────────────────────────────┐        │
│  │ Context Matching (configurable backend)                  │        │
│  │                                                          │        │
│  │  ┌─────────────────────┐  ┌──────────────────────────┐  │        │
│  │  │ REGEX (default)      │  │ AHO-CORASICK (opt-in)   │  │        │
│  │  │                      │  │                          │  │        │
│  │  │ 560 compiled         │  │ Single O(n) trie pass   │  │        │
│  │  │ alternation patterns │  │ ContextHitIndex with     │  │        │
│  │  │ Per-match regex      │  │ binary search lookups    │  │        │
│  │  │ search in window     │  │                          │  │        │
│  │  └──────────┬───────────┘  └────────────┬─────────────┘  │        │
│  │             │                           │                │        │
│  │             └─────────┬─────────────────┘                │        │
│  │                       │                                  │        │
│  │             ┌─────────▼───────────┐                      │        │
│  │             │ Fuzzy Levenshtein    │  Edit distance ≤ 2  │        │
│  │             │ (fallback for both)  │  Keywords ≥ 5 chars │        │
│  │             └─────────────────────┘                      │        │
│  └──────────────────────────────────────────────────────────┘        │
│            │                                                         │
│  ┌─────────▼───────────┐                                            │
│  │ Confidence Scoring   │  Base specificity + context boost         │
│  │ Deduplication        │  Overlap removal, highest confidence wins │
│  │ Plugin Validators    │  Custom match validation                  │
│  └─────────┬───────────┘                                            │
│            │                                                         │
│  ┌─────────▼───────────┐                                            │
│  │ Match Output         │  List[Match] with spans, confidence       │
│  └─────────────────────┘                                            │
│                                                                      │
│  ── Parallel / Independent Modules ──                               │
│                                                                      │
│  ┌─────────────────────┐  ┌─────────────────────┐                   │
│  │ EDM (edm.py)         │  │ LSH (lsh.py)         │                  │
│  │                      │  │                      │                  │
│  │ Salted HMAC-SHA256   │  │ MinHash signatures   │                  │
│  │ Known-value matching │  │ Document similarity   │                  │
│  │ Zero false positives │  │ LSH band indexing     │                  │
│  │ Tokenizer pipeline   │  │ Jaccard estimation    │                  │
│  └──────────────────────┘  └──────────────────────┘                  │
└──────────────────────────────────────────────────────────────────────┘
```

**EDM and LSH are independent modules** — they don't replace or modify the
core pattern matching pipeline. They provide complementary detection capabilities:

- **Pattern matching**: "Find anything that looks like a credit card"
- **EDM**: "Find these exact 50,000 known credit card numbers"
- **LSH**: "Find documents similar to this confidential contract"

Use them together for defense in depth.
