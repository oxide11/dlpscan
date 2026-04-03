# Changelog

All notable changes to dlpscan will be documented in this file.

## [2.1.0] - 2026-04-03

### Enterprise Readiness

#### Prometheus Metrics
- 9 metrics wired into scan operations via `MetricsCollector` callback:
  `dlpscan_scans_total`, `dlpscan_scan_errors_total`, `dlpscan_findings_total`,
  `dlpscan_bytes_scanned_total`, `dlpscan_scan_duration_seconds` (histogram),
  `dlpscan_files_scanned_total`, `dlpscan_patterns_timed_out_total`,
  `dlpscan_scans_truncated_total`, `dlpscan_scans_in_flight` (gauge)
- `GET /metrics` endpoint returns Prometheus text exposition format
- `enable_prometheus()` auto-called on API server startup
- `prometheus_text_output()` for custom integrations

#### TLS/HTTPS Support
- **API server**: `DLPSCAN_TLS_CERT` and `DLPSCAN_TLS_KEY` environment variables
  enable HTTPS via `tokio-rustls` with PEM cert/key loading
- **Webhooks**: `http_post()` supports `https://` URLs via `rustls` +
  `webpki-roots` for sync TLS connections
- **SIEM adapters**: Same `rustls` TLS support for Splunk HEC, Elasticsearch,
  Datadog HTTPS endpoints
- New `tls` feature flag (included in `async-support` and `full`)

#### Test Coverage
- 64 new tests across 6 previously untested modules:
  - `streaming/mod.rs` (10): buffer clamping, feed/flush, multibyte safety
  - `models.rs` (9): Match creation, redacted_text, pattern_specificity
  - `guard/mod.rs` (13): scan, flag/redact/reject/obfuscate actions, sanitize
  - `guard/tokenize.rs` (12): tokenize/detokenize roundtrip, determinism
  - `guard/presets.rs` (6): preset coverage, superset validation, serde
  - `pipeline/mod.rs` (14): file processing, directory scan, CSV/JSON export
- Total: **238 tests** (up from 174)

### Security Hardening

Comprehensive security audit and vulnerability remediation across the entire
Rust codebase. All critical, high, medium, and low findings resolved.

#### Critical & High Fixes
- **UTF-8 boundary safety** — All string slicing (`&text[start..end]`) across
  scanner, streaming, guard, compliance, batch, and models modules now validates
  `is_char_boundary()` before slicing. Eliminates 6 crash vectors on multi-byte
  input discovered by Evadex evasion testing
- **4-stage normalization with byte-level offset tracking** — Complete rewrite of
  `normalize_text()`. Each stage (zero-width strip, whitespace normalize, NFKC,
  homoglyph map) propagates `offset_map[output_byte] = original_byte` through
  character-width-changing transforms via `remap_char_transform()` and
  `remap_nfkc()`. Fixes 104 detection gaps for Unicode-encoded evasion attacks
- **Homoglyph map expansion** — 40 to 120+ entries: fullwidth ASCII A-Z/a-z
  (U+FF21-FF5A), fullwidth digits (U+FF10-FF19), fullwidth punctuation,
  subscript/superscript digits, Cyrillic/Greek lookalikes
- **SSRF protection** — `is_safe_url()` with `is_private_ipv4()` blocking
  0.0.0.0/8, 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16,
  169.254.0.0/16. IPv4-mapped IPv6 (`::ffff:x.x.x.x`) detection. IPv6 bracket
  notation in URL parsing
- **Constant-time API key verification** — SHA-256 hash comparison instead of
  string equality to prevent timing attacks
- **Archive bomb protection** — `MAX_EXTRACT_TOTAL_SIZE` (500MB),
  `MAX_EXTRACT_ENTRY_SIZE` (100MB), `MAX_EXTRACT_FILE_COUNT` (10,000) limits on
  ZIP/RAR/7z extraction
- **Path traversal prevention** — Pre-validate RAR entry names, canonicalize 7z
  paths post-extraction
- **API request body reading** — Full Content-Length loop with 30s timeout per
  chunk, preventing silent truncation of 1-10MB requests (was a DLP bypass)
- **Sensitive data in cache** — `ScanCache::put()` clears `result.text` before
  storing to avoid retaining plaintext PII
- **TOCTOU race fix** — Single lock acquisition in `run_validators` instead of
  check-then-act with two separate locks
- **HMAC token strength** — Truncation increased from 32-bit to 128-bit

#### Medium Fixes
- **Graceful shutdown** — `tokio::select!` with `ctrl_c()` signal handler, 30s
  connection drain before termination
- **JSON structured logging** — `DLPSCAN_LOG_FORMAT=json` environment variable
  enables JSON output via `tracing-subscriber`
- **Scan truncation indicator** — New `ScanOutput` struct with `truncated: bool`
  flag returned from `scan_text_with_config()`. Callers can now distinguish
  complete results from timeout/cap-limited partial results
- **Request correlation IDs** — `X-Request-ID` propagated to `tracing::info_span`
  so all log lines within a request share the same ID
- **Bounded webhook threads** — Global cap of 16 concurrent dispatch threads with
  RAII drop guard, preventing unbounded thread spawning under load
- **StreamScanner lock optimization** — `std::mem::take` extracts buffer then
  scans outside the mutex, eliminating clone-under-lock contention
- **Config validation** — `context_backend` validated with warning fallback to
  "regex"; `max_matches` capped at 500,000; `min_confidence` clamped to [0.0, 1.0]
  with NaN/Inf rejection
- **Structured error logging** — All `eprintln!` error paths in CLI replaced with
  `tracing::error!` / `tracing::warn!` for consistent structured output
- **Per-pattern match limit** — `MAX_MATCHES_PER_PATTERN = 10,000` prevents
  unbounded memory growth from pathological regex inputs
- **Bounded stdin reads** — 10MB cap with proper error handling
- **ApiConfig Debug redaction** — Custom `Debug` impl masks `api_key` as
  `[REDACTED]` to prevent accidental logging of secrets
- **Default bind address** — Changed from `0.0.0.0` to `127.0.0.1` in both
  `Default` and `from_env()` to prevent unintended network exposure

#### Low Fixes
- **Regex `.unwrap()` cleanup** — All hardcoded regex patterns in `edm.rs` use
  `.expect()` with descriptive messages
- **StderrAuditHandler** — Serialization failures now logged via
  `tracing::error!` instead of silently dropped
- **Webhook mutex recovery** — `add_url`/`remove_url` use
  `unwrap_or_else(|e| e.into_inner())` for poisoned-lock recovery
- **AhoCorasick build failure** — Logs warning instead of silently disabling
  context keyword detection
- **AuditEvent::new()** — Returns `Result` instead of panicking on invalid event
  type
- **File permissions** — EDM and LSH persistence files created with `0o600` mode
- **Glob recursion** — Allowlist glob matching capped at depth 1,000
- **Obfuscation seed warning** — `tracing::warn!` when deterministic seed is set

### Deployment & Operations
- **Dockerfile** — Rust 1.77 to 1.85, `--locked` builds, curl health check,
  removed silent error suppression
- **docker-compose.yml** — `restart: unless-stopped`, CPU/memory limits, log
  rotation
- **Helm chart** — `startupProbe`, `NetworkPolicy` source restrictions, secrets
  warning comment
- **CI** — Trivy container image scanning step added to GitHub Actions workflow

### Binary Format Support
- **CLI file scanning** — `process_file()` now tries `extractors::extract_text()`
  before `fs::read_to_string()`, enabling DOCX, XLSX, PDF, and other binary
  formats from the command line

### Tests
- 174 tests passing (up from 127), including:
  - 7 new normalization tests (fullwidth digits/letters, Cyrillic homoglyphs,
    mixed Unicode evasion, offset map accuracy)
  - 3 SSRF bypass tests (0.0.0.0, IPv4-mapped IPv6, bracket notation)
  - Stabilized flaky tests (`test_register_and_run_validator`,
    `test_deterministic_seed`)

## [2.0.0] - 2026-04-02

### Rust Port (`dlpscan-rs`)

Complete Rust port of the dlpscan library with full feature parity and 29-70x
faster throughput than the Python implementation. 15,000+ lines of Rust across
37 modules, 127 tests passing.

#### Core Scanning Engine
- **560 regex patterns** across 126 categories — identical to Python
- **Parallel regex matching** via Rayon `par_iter` over compiled patterns
- **Aho-Corasick prefilter** — single O(n) keyword pass gates 452 of 560
  patterns behind keyword presence checks, eliminating ~80% of regex work
- **ASCII fast-path normalization** — skips NFKC, homoglyph, and zero-width
  processing for pure ASCII input (vast majority of real text)
- **Aho-Corasick context matching** with 560+ keywords, HashMap O(1) lookup

#### InputGuard API
- Full `InputGuard` builder with presets (PCI-DSS, PII, Credentials,
  Healthcare, Contact Info), actions (Reject, Redact, Flag, Tokenize,
  Obfuscate), denylist/allowlist modes, confidence thresholds
- **Realistic fake data obfuscation** — Luhn-valid credit cards with correct
  brand prefixes, format-preserving emails, phones, SSNs, IBANs, IPv4, MACs
- **Reversible tokenization** with RBAC-controlled token vaults
- **Allowlist** suppression of known false positives

#### New Feature: `baseline_only` Scanning Mode
- `InputGuard::with_baseline_only(true)` restricts scanning to only the 108
  highest-confidence always-run patterns (SSNs, credit cards, national IDs,
  crypto addresses, secrets, tokens)
- Skips all 452 context-gated patterns regardless of keyword presence
- Best for high-throughput pipelines or latency-sensitive pre-screening
- `ScanConfig::baseline_only` available at the low-level scanner API

#### Data Processing
- **Batch scanning** (`batch.rs`) — parallel CSV, JSON/JSONL scanning with
  `BatchScanner`, progress callbacks, aggregated `BatchReport`
- **File pipeline** (`pipeline`) — concurrent file processing with format
  detection and size limits
- **Streaming scanner** (`streaming`) — chunk-buffered scanning for streams
- **Text extractors** (`extractors.rs`) — DOCX, XLSX, PPTX, RTF, EML, ZIP
  extraction with magic byte detection
- **LRU scan cache** (`cache.rs`) — thread-safe SHA-256-keyed cache with
  configurable TTL eviction

#### Advanced Detection
- **Exact Data Match** (`edm.rs`) — HMAC-SHA256 known-value detection with
  built-in tokenizers (numeric, email, word n-grams)
- **Locality-Sensitive Hashing** (`lsh.rs`) — MinHash + banded LSH for fuzzy
  document similarity with save/load persistence
- **Shannon entropy analysis** (`entropy.rs`) — format-specific thresholds,
  recursive ZIP archive extraction with zip-bomb protection

#### Enterprise
- **Policy engine** (`policy.rs`) — TOML-based policy rules with action routing
- **Compliance reporting** (`compliance.rs`) — PCI-DSS, HIPAA, SOC2, GDPR
  framework pass/fail reports in JSON, plain text, and HTML
- **Audit logging** (`audit.rs`) — pluggable handlers (file, stderr, callback)
  with builder pattern events and global singleton
- **SIEM integration** (`siem.rs`) — adapters for Splunk HEC, Elasticsearch,
  Syslog (UDP/TCP), Datadog, and generic webhooks
- **Webhook notifications** (`webhooks.rs`) — fire-and-forget delivery with
  retry and exponential backoff
- **HTTP API** (`api.rs`) — scan/batch/health endpoints with rate limiting and
  API key auth
- **Masking profiles** (`profiles.rs`) — 9 built-in profiles (PCI_PRODUCTION,
  HIPAA_STRICT, GDPR_COMPLIANCE, etc.) with JSON persistence
- **Plugin system** (`plugins.rs`) — per-sub_category validators and
  post-processor pipeline
- **Scan metrics** (`metrics.rs`) — duration/match/byte tracking with callbacks
- **Config loading** (`config.rs`) — pyproject.toml `[tool.dlpscan]` and
  `.dlpscanrc` JSON auto-discovery with directory walk

### Performance

Benchmarked on 1MB inputs with all presets enabled (Flag action):

| Scenario | Python v1.9 | Rust v2.0 | Speedup |
|---|---:|---:|---:|
| Clean text | 396 ms (2.5 MB/s) | 12 ms (83 MB/s) | **33x** |
| Mixed content | 960 ms (1.0 MB/s) | 33 ms (30 MB/s) | **29x** |
| Dense sensitive data | 2,197 ms (0.5 MB/s) | 31 ms (32 MB/s) | **70x** |

Full vs baseline-only mode on keyword-heavy text: 59 MB/s → 69 MB/s (1.2x).

See `dlpscan-rs/BENCHMARKS.md` for the complete optimization journey and
detailed latency tables.

### New Files

- `dlpscan-rs/` — Complete Rust crate (37 source files)
- `dlpscan-rs/BENCHMARKS.md` — Comprehensive benchmark results
- `dlpscan-rs/Cargo.toml` — Dependencies and feature flags
- `benchmark_py.py` — Python benchmark script for comparison

## [1.9.0] - 2026-04-01

### Performance

- **AC Keyword Pre-Filter**: 4-5x scan speedup via smart two-tier pattern
  execution. A single Aho-Corasick pass over the input text identifies which
  context keywords are present, then only runs regex patterns whose keywords
  were found. 108 critical patterns (SSN, credit cards, secrets, major national
  IDs, crypto addresses) always run unconditionally. 452 lower-priority patterns
  (driver's licenses, classification labels, regional IDs) are context-gated.
  Custom-registered patterns are never gated. Throughput improves from ~0.035
  MB/s to ~0.56 MB/s on all-category scans. Zero detection loss for critical
  data types verified via red-team testing.

- **Parallel File Scanning**: `scan_directory()` now accepts `max_workers`
  parameter for CPU-parallel scanning via `ProcessPoolExecutor`. With 4
  workers on 4 cores: 3.6x additional speedup. Combined with the pre-filter,
  directory scanning achieves ~2.1 MB/s (60x vs original 0.035 MB/s).

- **Process-Based Pipeline**: `Pipeline(use_processes=True)` uses
  `ProcessPoolExecutor` instead of `ThreadPoolExecutor`, bypassing the GIL
  for true CPU parallelism. 4.1x speedup on batch file processing with
  identical match results.

- **New module**: `dlpscan.scanner._prefilter` with `CRITICAL_ALWAYS_RUN`
  frozenset, `SPECIFICITY_THRESHOLD`, and `is_always_run()` helper.

## [1.8.0] - 2026-03-31

### New Features

- **L33tspeak Evasion Defense**: Third-pass context keyword detection that
  normalizes l33tspeak substitutions (`p@$$w0rd` → `password`, `cr3d1t` →
  `credit`) in context windows. Applied only to keyword proximity windows to
  avoid corrupting digit-based patterns. 18-character substitution map in
  `normalize_leet()`. Integrated into both regex and Aho-Corasick context paths.

- **Session Correlation in InputGuard**: `SessionCorrelator` can now be wired
  directly into `InputGuard` via `correlator` and `user_id` parameters.
  Per-scan user override with `scan(text, user_id=...)`. Correlation alerts
  returned in `ScanResult.correlation_alerts`. Enables drip exfiltration
  detection across multiple scans without manual wiring.

- **Observability & Availability Instrumentation**: New Prometheus metrics for
  operational monitoring:
  - `dlpscan_start_time_seconds` — Unix timestamp of service initialization
  - `dlpscan_uptime_seconds` — Seconds since initialization (updated on scrape)
  - `dlpscan_health_status` — Health gauge (1=healthy, 0=degraded)
  - `dlpscan_scans_in_flight` — Concurrent scan tracking
  - `dlpscan_bytes_scanned_total` — Total bytes processed
  - `dlpscan_patterns_timed_out_total` — Regex timeout counter
  - `get_health()` — Health-check dict for `/healthz` endpoints
  - `enable_auto_instrumentation()` — One-call bridge from `MetricsCollector`
    callback into Prometheus counters automatically
  - Health recovery: after 10 consecutive clean scans, degraded status
    automatically recovers to healthy

- **Prometheus Exporter `/healthz` Endpoint**: The built-in HTTP exporter now
  serves a `/healthz` JSON endpoint alongside `/metrics`, returning health
  status, uptime, scan/error totals, and in-flight count. Returns 503 when
  degraded.

- **Grafana Dashboard Template**: Sample dashboard JSON at
  `examples/grafana_dashboard.json` with 12 panels: health status, uptime,
  scan/finding/error totals, in-flight gauge, scan rate, finding rate, latency
  percentiles (p50/p90/p99), bytes throughput, pattern timeouts, and rate limit
  rejections.

### Architecture

- **Scanner Package Split**: Monolithic `scanner.py` (1,085 lines) decomposed
  into `scanner/` package with 8 submodules: `_config`, `_context`, `_core`,
  `_io`, `_redaction`, `_scoring`, `_timeout`, `_validation`. Full backward
  compatibility maintained via `__init__.py` re-exports and `__getattr__` for
  dynamic `CONTEXT_REQUIRED_PATTERNS` access.

### Tests

- 24 new integration tests covering l33tspeak normalization, session correlation
  in InputGuard, scanner package split backward compatibility, observability
  metrics & auto-instrumentation, and advanced modules (CountMinSketch,
  HyperLogLog, CuckooFilter, EntropyAnalyzer, PartialDocumentMatcher, EDM).
- Total: **627 tests** (540 unit + 87 integration).

### New Files

- `dlpscan/scanner/__init__.py` — Package re-exports
- `dlpscan/scanner/_config.py` — Pattern registry and context backend config
- `dlpscan/scanner/_context.py` — Context matching (exact, fuzzy, l33tspeak)
- `dlpscan/scanner/_core.py` — Core `enhanced_scan_text()` engine
- `dlpscan/scanner/_io.py` — File, stream, and directory scanning
- `dlpscan/scanner/_redaction.py` — Text redaction utilities
- `dlpscan/scanner/_scoring.py` — Confidence scoring and deduplication
- `dlpscan/scanner/_timeout.py` — SIGALRM and thread-based timeout handling
- `dlpscan/scanner/_validation.py` — Input validation and normalization
- `examples/grafana_dashboard.json` — Grafana operational dashboard

## [1.7.0] - 2026-03-31

### New Features

- **Aho-Corasick Context Matching** (`dlpscan.ahocorasick`): Optional trie-based
  multi-keyword matching engine that scans text in a single O(n) pass instead of
  running 560+ separate regex alternation patterns. Wraps the `pyahocorasick` C
  extension for native-speed trie traversal with a pure-Python fallback.
  Configurable via `DLPSCAN_CONTEXT_BACKEND=ahocorasick` env var,
  `context_backend` config key, or `InputGuard(context_backend="ahocorasick")`.
  Default remains `"regex"` for backward compatibility.

- **Exact Data Match** (`dlpscan.edm`): Zero false-positive detection of known
  sensitive values using salted HMAC-SHA256 hashes. Register known SSNs, credit
  cards, emails, etc. as hashes (never stored in plaintext). Configurable
  tokenizers (numeric, email, word n-grams) extract candidates from text.
  Supports save/load for hash set persistence.

- **Locality-Sensitive Hashing** (`dlpscan.lsh`): Fuzzy document similarity
  detection using MinHash signatures with LSH banding. Detects documents similar
  to known sensitive documents even after editing, reformatting, or cropping.
  Configurable threshold (default 80%), 128-hash signatures, sub-linear query
  time via band indexing. Thread-safe with save/load persistence.

- **Count-Min Sketch** (`dlpscan.countmin`): Probabilistic frequency estimation
  using a width×depth counter grid. Answers "how many times has X been seen?"
  using constant memory. Never undercounts; configurable accuracy via dimensions.

- **HyperLogLog** (`dlpscan.hyperloglog`): Cardinality estimation using ~1.5 KB
  of memory. Estimates unique item counts in streams with ±0.81% standard error
  at precision=14. Supports merge for distributed counting.

- **Cuckoo Filter** (`dlpscan.cuckoo`): Space-efficient probabilistic set with
  deletion support. 100K items in ~150 KB vs ~6.4 MB for a Python set. Uses
  cuckoo hashing with configurable fingerprint size (8/12/16/32 bits).

- **Session Correlator** (`dlpscan.session`): Stateful drip-exfiltration
  detection combining Count-Min Sketch (frequency) and HyperLogLog (cardinality)
  with per-user tracking across sliding time windows. Policy-based alerting when
  total or unique value thresholds are exceeded. Thread-safe.

- **Rabin-Karp Rolling Hash** (`dlpscan.rabin_karp`): Partial document matching
  via sliding window fingerprints. Pre-computes hashes for registered documents,
  scans incoming text in O(n) to detect copied fragments. Catches paragraph-level
  copying that LSH (whole-document) and pattern matching (structured data) miss.

- **Entropy Analysis & Recursive Unpacking** (`dlpscan.entropy`): Shannon
  entropy analyzer detecting encrypted/compressed payloads with format-specific
  thresholds. Recursive extractor unpacks nested ZIP/tar/gzip archives up to
  configurable depth with zip bomb protection.

## [1.6.0] - 2026-03-26

### New Features

- **Unicode Evasion Defense** (`dlpscan.unicode_normalize`): Three-stage text
  normalization pipeline that defeats adversarial evasion techniques before regex
  scanning:
  - **Zero-width stripping**: Removes 160+ invisible characters including ZWSP,
    ZWJ, ZWNJ, BOM, soft hyphen, RTL/Bidi overrides (`U+202A`–`U+202E`,
    `U+2066`–`U+2069`), variation selectors (`U+FE00`–`U+FE0F`), and Unicode
    Tags block (`U+E0001`–`U+E007F`). Builds offset map for accurate span
    mapping back to original text.
  - **Whitespace normalization**: Converts 14 exotic Unicode whitespace
    characters (ideographic space, thin space, hair space, etc.) to ASCII space,
    defeating delimiter variation attacks.
  - **Homoglyph normalization**: NFKC decomposition plus explicit mapping of 80+
    confusable characters (Cyrillic, Greek, fullwidth Latin, subscript/superscript
    digits, dash variants, symbol lookalikes) to ASCII equivalents.
  - Integrated into `enhanced_scan_text()`, `redact_sensitive_info_with_patterns()`,
    and all InputGuard transforms (REDACT, TOKENIZE, OBFUSCATE).

- **Cross-Platform Regex Timeout**: `_ThreadTimeout` class provides
  `threading.Timer`-based timeout fallback for non-Unix platforms and worker
  threads where SIGALRM is unavailable. Checks timeout flag between pattern
  iterations to prevent unbounded scan time.

- **Scan Completeness Indicator**: `ScanResult` now exposes `scan_truncated`
  (bool) and `scan_complete` (property) fields so API consumers can detect when
  scans were cut short by match limits or timeouts. Included in `to_dict()` JSON
  output.

- **Evasion Techniques Catalog** (`docs/evasion_techniques.md`): Comprehensive
  documentation of 17+ DLP evasion techniques across 8 categories with defense
  status matrix and priority remediation roadmap.

- **Evasion Defenses Guide** (`docs/evasion_defenses.md`): Technical reference
  for all 15 built-in defenses including architecture diagrams, character tables,
  usage examples, and coverage summary.

- **Expanded Homoglyph Coverage**: Homoglyph map expanded from ~80 to 200+
  entries. Added Armenian (13 letters), Cherokee (23 letters), small capitals
  (26 letters), circled/dingbat/parenthesized digits (28 entries), fullwidth
  symbols (20 entries), and additional Cyrillic/Greek/Latin variants.

- **Fuzzy Context Keyword Matching**: `scan_for_context()` now uses two-pass
  matching — exact regex (fast path) + Levenshtein fuzzy matching (edit
  distance ≤ 2) for keywords ≥ 5 characters. Multi-word keywords use n-gram
  matching. Catches typos like "credti card" → "credit card".

- **RTF Extractor**: Built-in RTF text extraction with control word parsing,
  Unicode/hex escape handling, and nested group support. No external dependencies.

- **Content-Type Detection**: `_detect_format_by_content()` reads file magic
  bytes (PDF, RTF, ZIP-based Office) as fallback when file extension is missing
  or misleading.

- **Wildcard Allowlist**: `Allowlist` text entries now support `fnmatch` glob
  syntax (`*`, `?`, `[seq]`). Enables prefix-based suppression like `4111*`
  alongside exact match.

- **OCR Confidence Hardening**: `MIN_OCR_CONFIDENCE` raised from 30 to 60,
  reducing false matches from degraded or adversarial images.

- **PHI/PII Baseline Doc Split**: PHI and PII baseline documentation split into
  separate pattern and keyword files (`phi-patterns.md`, `phi-keywords.md`,
  `pii-patterns.md`, `pii-keywords.md`) for easier reference.

- **Async API**: All scan endpoints now use `run_in_executor` to avoid blocking
  the event loop, enabling proper async concurrency under load.

- **Webhook Notifications** (`dlpscan.webhooks`): `WebhookNotifier` sends HTTP
  POST alerts when findings are detected. Non-blocking fire-and-forget delivery
  with configurable retry and timeout. Register global notifiers via
  `register_notifier()` and dispatch with `notify_findings()`.

- **Scan Result Caching** (`dlpscan.cache`): LRU + TTL cache with SHA-256 keying.
  Enable via `DLPSCAN_CACHE_ENABLED=1` environment variable. Thread-safe with
  hit/miss stats tracking.

- **Custom Pattern Management API**: New REST endpoints for runtime pattern
  management: `POST /v1/patterns`, `GET /v1/patterns`, `DELETE /v1/patterns/{name}`.

- **Docker Compose**: Production-ready `docker-compose.yml` with API and batch
  worker services, health checks, and environment configuration.

- **GitHub Actions Action**: Composite action at `.github/actions/dlpscan/` for
  CI/CD pipeline scanning with configurable path, format, and fail-on-findings.

- **YAML Scan Rulesets** (`dlpscan.rulesets`): Declarative YAML configuration
  for scan rules. Select patterns by baseline (PII, PCI, PHI, financial,
  secrets, confidential docs), preset, or individual category. Supports
  per-category overrides, custom inline regex patterns, and allowlists.
  Ships with 7 ready-to-use rulesets in `rulesets/`.

### Improvements

- **Drop Python 3.8**: Minimum version is now Python 3.9. Removed all
  `from __future__ import annotations` imports.

- **CI Enhancements**: Added mypy type checking, test coverage reporting with
  `coverage.xml` artifacts, and benchmark regression tracking with JSON output.

- **PyPI Publishing**: Workflow now triggers on GitHub releases for automated
  publishing via trusted publishing.

## [1.5.0] - 2026-03-26

### New Features

- **OCR Scanning** (`dlpscan.ocr`): Extract and scan text from images and scanned
  PDFs using Tesseract OCR. Supports PNG, JPEG, TIFF, BMP, and WebP formats.
  Image preprocessing (grayscale, thresholding, DPI normalization) for improved
  accuracy. Confidence scoring with low-quality warnings.
  `pip install dlpscan[ocr]` for image OCR, `pip install dlpscan[pdf-ocr]` for
  PDF OCR support.

- **PDF OCR Fallback**: The PDF extractor now automatically falls back to OCR for
  scanned pages that yield no extractable text. Mixed PDFs (typed + scanned pages)
  are handled efficiently with per-page hybrid extraction.

- **Image Extractors**: Image files (.png, .jpg, .jpeg, .tiff, .bmp, .webp) are now
  registered in the extractor registry. `extract_text()`, `Pipeline`, and
  `scan_directory()` all support image files natively when OCR is installed.

- **Directory Scanning for Images**: `scan_directory()` now processes image and
  document files via the extraction pipeline instead of skipping them as binary files.

### Security

- **Timing-safe API key comparison**: API key validation now uses `hmac.compare_digest()`
  to prevent timing side-channel attacks.
- **Request body size limits**: All API text fields capped at 1 MB to prevent memory
  exhaustion from oversized payloads.
- **Error message sanitization**: API 500 responses no longer leak internal exception
  details to clients.
- **PBKDF2 hardening**: Key derivation now uses random 16-byte salts (instead of a
  hardcoded default) and 600,000 iterations per OWASP guidance (up from 100,000).
- **File permission hardening**: Vault and audit log files are created with `0o600`
  permissions (owner read/write only).
- **Symlink attack prevention**: Vault and audit file paths are resolved and validated
  to reject symbolic links.
- **SQL injection prevention**: `scan_database()` now only allows `SELECT` queries.
  Results are fetched in bounded batches of 1,000 rows instead of unbounded `fetchall()`.
- **Metrics endpoint hardened**: Prometheus exporter binds to `127.0.0.1` instead of
  `0.0.0.0` to prevent unauthorized network access.
- **OCR config allowlist tightened**: Removed `--tessdata-dir`, `--user-words`, and
  `--user-patterns` from the Tesseract config allowlist to prevent path traversal.
- **ReDoS prevention**: HTML tag stripping regex now bounds match length to 1,000
  characters.
- **Token generation hardened**: `TokenVault` always uses HMAC with a random secret
  (via `secrets.token_bytes()`) to prevent token precomputation.
- **Rate limiter performance**: Replaced `list.pop(0)` O(n) with `deque.popleft()` O(1).
- **JSON recursion depth limit**: `_extract_json_strings()` now caps recursion at depth
  64 to prevent stack overflow from deeply nested payloads.

### Documentation

- Added OCR Scanning guide with installation, usage, and configuration examples.

## [1.4.0] - 2026-03-26

### New Features

- **REST API Server** (`dlpscan.api`): FastAPI-based HTTP server with scan, tokenize,
  detokenize, obfuscate, and batch scan endpoints. API key auth via `X-API-Key` header,
  request ID middleware, rate limiting, and in-memory vault management with TTL.
  `pip install dlpscan[api]` to install dependencies.

- **Policy-as-Code** (`dlpscan.policy`): Define scanning policies in YAML with per-category
  rules, audit configuration, and rate limiting. `PolicyEngine` creates guards from policies,
  applies rule overrides, and provides a convenience `scan()` method.
  `load_policies_from_dir()` for multi-policy setups.

- **Observability** (`dlpscan.observability`): Prometheus and OpenTelemetry metrics.
  Built-in DLP metrics (scans_total, findings_total, scan_duration_seconds, etc.).
  `PrometheusExporter` serves `/metrics` via stdlib HTTP server.
  Optional OpenTelemetry bridge via `setup_opentelemetry()`.

- **Batch Scanning** (`dlpscan.batch`): Scan CSV, JSON/JSONL, databases, and pandas
  DataFrames at scale. `BatchScanner` with parallel `ThreadPoolExecutor`, chunked
  processing, progress callbacks, and `BatchReport` aggregation.

- **Masking Profiles** (`dlpscan.profiles`): Named, reusable scan configurations.
  9 built-in profiles (PCI_PRODUCTION, HIPAA_STRICT, GDPR_COMPLIANCE, CI_PIPELINE, etc.).
  `ProfileRegistry` with JSON file save/load. `get_profile("pci-production").to_guard()`.

- **Documentation Site**: MkDocs Material site with getting started guide, user guide,
  enterprise feature docs, deployment guides, and API reference.

### New Files

- `dlpscan/api.py` — FastAPI REST server
- `dlpscan/policy.py` — YAML policy engine
- `dlpscan/observability.py` — Prometheus/OpenTelemetry metrics
- `dlpscan/batch.py` — Batch/database scanning
- `dlpscan/profiles.py` — Named masking profiles
- `mkdocs.yml` — Documentation site configuration
- `docs/` — Full documentation site (20+ pages)

### Changes

- Added `[api]` and `[observability]` optional dependency groups
- Added `mkdocs-material` to dev dependencies
- Version bumped to 1.4.0

---

## [1.3.0] - 2026-03-26

### Enterprise Features

- **Audit Logging** (`dlpscan.audit`): Structured audit trail for every DLP operation.
  `AuditEvent` dataclass with ISO 8601 timestamps. Pluggable handlers: `StderrAuditHandler`,
  `FileAuditHandler` (JSON-lines), `CallbackAuditHandler`, `NullAuditHandler`. Global logger
  via `set_audit_logger()` / `audit_event()`. Helper `event_from_scan()` for ScanResult integration.

- **Vault Persistence** (`dlpscan.guard.vault_backends`): Pluggable storage backends for
  TokenVault. `InMemoryBackend` (default), `FileBackend` (append-only JSON-lines with optional
  AES-256-GCM encryption), `EncryptedVault` (transparent encryption wrapper), `RedisBackend`
  (with optional TTL). All satisfy the `VaultBackend` protocol.

- **Rate Limiting** (`dlpscan.rate_limit`): Thread-safe token bucket `RateLimiter` with
  configurable max requests, time window, and payload size limits. `rate_limited()` decorator.
  Global default limiter via `set_default_limiter()`.

- **Environment Variable Configuration** (`dlpscan.env_config`): Configure dlpscan entirely
  via `DLPSCAN_*` environment variables. `configure_from_env()` one-call setup.
  `apply_env_to_guard_kwargs()` for InputGuard construction.

- **SIEM Integration** (`dlpscan.siem`): Ship scan events to security platforms. Adapters for
  Splunk HEC, Elasticsearch/OpenSearch, Syslog (RFC 5424), generic webhooks, and Datadog Logs.
  All thread-safe. Factory `create_siem_from_env()` reads `DLPSCAN_SIEM_*` env vars.

- **Role-Based Detokenization** (`dlpscan.guard.rbac`): `Role` enum (ADMIN, ANALYST, OPERATOR,
  VIEWER) with `Permission` enum. `RBACPolicy` for access control with per-user role overrides.
  `SecureTokenVault` wraps TokenVault with permission checks on detokenize/export/import/clear.

- **Compliance Reporting** (`dlpscan.compliance`): `ComplianceReporter` accumulates scan results
  and generates `ComplianceReport` with category breakdowns and framework compliance checks
  (PCI-DSS, HIPAA, SOC2, GDPR). Export to JSON, HTML, or plain text.

- **Custom Obfuscation Seeds**: `set_obfuscation_seed(seed)` enables deterministic, reproducible
  obfuscation output for testing and audit stability.

- **Pre-commit Hook Hardening**: `.dlpscanignore` file support, `--categories` filter,
  `--allowlist` file, `--format json` for CI, `--baseline` for known-finding suppression.

### New Files

- `dlpscan/audit.py` — Audit logging framework
- `dlpscan/guard/vault_backends.py` — Pluggable vault storage backends
- `dlpscan/rate_limit.py` — Token bucket rate limiter
- `dlpscan/env_config.py` — Environment variable configuration
- `dlpscan/siem.py` — SIEM integration adapters
- `dlpscan/guard/rbac.py` — Role-based access control
- `dlpscan/compliance.py` — Compliance reporting

### Tests

- Expanded from 288 to 335 unit tests.
- New test classes: `TestAuditLogging`, `TestRateLimiter`, `TestEnvConfig`, `TestSIEMAdapters`,
  `TestVaultBackends`, `TestRBAC`, `TestComplianceReporting`, `TestObfuscationSeeds`.

---

## [1.2.0] - 2026-03-26

### New Features

- **Tokenization** (`Action.TOKENIZE`): Replace sensitive data with reversible
  tokens (e.g., `4111111111111111` → `TOK_CC_b2a983d8`). A `TokenVault` stores
  the mapping for later recovery via `guard.detokenize()` or `vault.detokenize_text()`.
  Deterministic (HMAC-SHA256), thread-safe, with export/import support.
- **Obfuscation** (`Action.OBFUSCATE`): Replace sensitive data with realistic-looking
  fake data of the same type (credit cards with valid Luhn checksums, fake emails,
  format-preserving SSNs/phones/IBANs). Irreversible — ideal for test datasets.
- **Convenience methods**: `guard.tokenize(text)` returns `(tokenized_text, vault)`,
  `guard.obfuscate(text)` returns obfuscated text, `guard.detokenize(text)` reverses.
- **TokenVault**: Standalone class with `tokenize()`, `detokenize()`,
  `detokenize_text()`, `export_map()`, `import_map()`, `clear()`. Custom prefix
  and HMAC secret support.

### New Files

- `dlpscan/guard/transforms.py` — TokenVault, obfuscation generators, tokenize_matches, obfuscate_matches

### Tests

- Expanded from 257 to 288 unit tests.
- New test classes: `TestTokenVault`, `TestObfuscation`, `TestTokenizeAction`,
  `TestObfuscateAction`.

---

## [1.1.0] - 2026-03-26

### New Features

- **Custom pattern registration via InputGuard**: Define custom regex patterns
  directly in the `InputGuard` constructor via `custom_patterns={}`. Patterns
  are auto-compiled and registered, auto-cleaned on `close()` or context manager exit.
- **Per-category confidence tuning**: New `confidence_overrides` parameter on
  `InputGuard` allows setting different confidence thresholds per category
  (e.g., `{'Credit Card Numbers': 0.9, 'Contact Information': 0.5}`).
- **Streaming scanner** (`dlpscan.streaming.StreamScanner`): Stateful scanner for
  real-time text streams (chat, logs, tails). Buffer-based with configurable
  flush intervals and overlap for boundary match detection. Thread-safe.
- **Webhook scanner** (`dlpscan.streaming.WebhookScanner`): Scan HTTP webhook
  payloads (JSON, form data, plain text) and headers. Extracts nested JSON string
  values. Skips standard auth headers automatically.
- **Pipeline structured output**: New `results_to_json()`, `results_to_csv()`,
  and `results_to_sarif()` helper functions for exporting pipeline results.
- **Dockerfile**: Multi-stage production build with non-root user, all-formats
  support, and Docker Compose example.
- **CI/CD pipeline**: GitHub Actions workflows for testing (Python 3.9–3.13 matrix),
  PyPI publishing (trusted publisher OIDC), and Docker image builds (multi-arch).
- **Examples directory**: Integration examples for Flask, FastAPI, Django, and
  standalone usage with InputGuard.
- **Integration tests**: End-to-end tests covering the full pipeline, InputGuard,
  streaming scanner, and webhook scanner.
- **Performance benchmarks**: Configurable benchmarks for text scanning, file
  processing, pipeline throughput, and InputGuard latency.
- **PyPI publishing setup**: MANIFEST.in, version bump to 1.1.0, all packaging
  metadata complete.

### New Files

- `dlpscan/streaming.py` — StreamScanner, WebhookScanner
- `dlpscan/guard/core.py` — Added custom_patterns, confidence_overrides, close(), context manager
- `Dockerfile`, `.dockerignore`, `docker-compose.yml`
- `.github/workflows/ci.yml`, `publish.yml`, `docker.yml`
- `examples/basic_usage.py`, `flask_example.py`, `fastapi_example.py`, `django_example.py`
- `tests/test_integration.py`, `tests/benchmarks.py`
- `MANIFEST.in`

### Tests

- Expanded from 234 to 257 unit tests.
- New test classes: `TestInputGuardCustomPatterns`, `TestConfidenceOverrides`,
  `TestPipelineOutput`, `TestStreamScanner`, `TestWebhookScanner`.
- Added integration test suite (`tests/test_integration.py`).

---

## [1.0.0] - 2026-03-26

### Enterprise Features

- **Output redaction** (`--redact`): CLI flag redacts matched text in all output
  formats (text, JSON, CSV). Shows first/last 3 characters for matches >8 chars,
  otherwise `***`. Recommended for production use. SARIF output never includes
  matched text (safe by design).
- **Structured JSON logging**: `configure_logging(level, json_format=True)` emits
  JSON log lines compatible with ELK, Splunk, Datadog, and other log aggregation
  platforms. Includes scan duration, match count, file path, and exception info.
- **Metrics/observability**: Callback-based `ScanMetrics` system. Register a
  callback via `set_metrics_callback()` to receive duration, match count, bytes
  scanned, files scanned/skipped, and timeout stats after each scan. Wire into
  Prometheus, StatsD, or any monitoring backend.
- **Plugin system**: Register custom validators (`register_validator()`) that
  run after regex matching to accept/reject individual matches. Register
  post-processors (`register_post_processor()`) that transform the full match
  list after scanning. Fail-closed semantics: validator errors discard matches.
- **Async scanning**: `async_scan_text()`, `async_scan_file()`,
  `async_scan_directory()` for asyncio-based applications (FastAPI, aiohttp).
  Uses ThreadPoolExecutor for Python 3.8+ compatibility.

### Packaging & Deployment

- **Dockerfile**: Python 3.12-slim image with non-root user. Entrypoint is
  `dlpscan` CLI.
- **PyPI trusted publishing**: GitHub Actions workflow (`.github/workflows/publish.yml`)
  publishes to PyPI via OIDC on tag push. No API tokens needed.
- **MIT License**: Standalone `LICENSE` file added.
- **Version bump**: v1.0.0 — stable API with backward-compatible guarantees.

### Scanner Integration

- Metrics collection wired into `enhanced_scan_text()` — every scan automatically
  records duration, bytes scanned, match count, categories scanned, and timeout stats.
- Plugin validators run inline during scanning (before match is appended).
- Plugin post-processors run after deduplication on the full match list.

### New Exports

- `ScanMetrics`, `set_metrics_callback`, `MetricsCollector`
- `register_validator`, `unregister_validators`, `register_post_processor`,
  `unregister_post_processors`, `run_validators`, `run_post_processors`
- `configure_logging`
- `async_scan_text`, `async_scan_file`, `async_scan_directory`

### New Files

- `dlpscan/metrics.py` — Callback-based observability system
- `dlpscan/plugins.py` — Plugin validators and post-processors
- `dlpscan/logging_config.py` — Structured JSON logging
- `dlpscan/async_scanner.py` — Async scanning wrappers
- `Dockerfile` — Container image
- `.github/workflows/publish.yml` — PyPI publishing workflow
- `LICENSE` — MIT License

### Tests

- Expanded from 148 to 178+ tests.
- New test classes: `TestRedactedOutput`, `TestMetrics`, `TestPlugins`,
  `TestLoggingConfig`, `TestAsyncScanner`.

### Totals

- **560 patterns** across **126 categories** (unchanged).
- **178+ tests** (up from 148).

## [1.0.2] - 2026-03-26

### New Features

- **InputGuard**: Developer-facing module for scanning and sanitizing application
  inputs. Import into any Python app to protect against sensitive data ingestion.
- **Denylist/Allowlist modes**: DENYLIST blocks specified categories (default: all).
  ALLOWLIST permits only listed categories, blocking everything else detected.
- **Compliance presets**: Pre-configured category bundles for common use cases:
  - `Preset.PCI_DSS` — Credit card numbers, PANs, track data, card expiry
  - `Preset.SSN_SIN` — US SSN/ITIN, Canada SIN
  - `Preset.PII` — Personal identifiers, geolocation, device IDs, contact info
  - `Preset.PII_STRICT` — All PII + all 80+ regional ID/passport/DL categories
  - `Preset.CREDENTIALS` — API keys, tokens, secrets, webhooks
  - `Preset.FINANCIAL` — Banking, credit cards, securities, crypto, wire transfers
  - `Preset.HEALTHCARE` — Medical identifiers, insurance
  - `Preset.CONTACT_INFO` — Email, phone, IP, MAC
- **Actions**: `REJECT` (raise InputGuardError), `REDACT` (return sanitized text),
  `FLAG` (return findings without modifying input).
- **Decorator support**: `@guard.protect(param="user_input")` scans function
  arguments before execution. Supports targeted params or all string args.
- **Quick methods**: `guard.check(text)` returns bool, `guard.sanitize(text)`
  always returns redacted text regardless of configured action.
- **Detection callback**: `on_detect` callback invoked when sensitive data is found.
- **Thread-safe**: InputGuard instances are immutable after init, safe to share.

### New Files

- `dlpscan/guard/` — InputGuard subpackage:
  - `__init__.py` — Public exports (InputGuard, ScanResult, Preset, Action, Mode, InputGuardError, PRESET_CATEGORIES)
  - `core.py` — InputGuard class, ScanResult, InputGuardError
  - `enums.py` — Action and Mode enums
  - `presets.py` — Preset enum and PRESET_CATEGORIES mapping

### Tests

- Expanded from 199 to 234 tests.
- New test classes: `TestInputGuardBasic`, `TestInputGuardModes`,
  `TestInputGuardPresets`, `TestInputGuardFiltering`, `TestInputGuardDecorator`,
  `TestInputGuardScanResult`.

### Totals

- **560 patterns** across **126 categories** (unchanged).
- **234 tests** (up from 199).

## [1.0.1] - 2026-03-26

### New Features

- **File processing pipeline**: Queue-based concurrent pipeline that ingests files
  of any supported format, extracts text, runs DLP scanning, and returns structured
  results. Supports batch processing, directory scanning, async submission via
  futures, and per-file error isolation.
- **Text extraction from binary formats**: New `extractors` module extracts plain
  text from PDF, DOCX, XLSX, PPTX, EML, and MSG files. All extraction libraries
  are optional dependencies — clear error messages guide installation.
- **EML support**: Email files parsed via stdlib `email` module (no extra deps).
  Extracts headers (From, To, Subject) and body parts (text/plain and text/html).
- **MSG support**: Outlook `.msg` files via `extract-msg` library.
- **Legacy Office detection**: `.doc`, `.xls`, `.ppt` files raise clear errors
  with guidance on conversion options.
- **CLI auto-detection**: When a file with a binary format extension is passed to
  the CLI, it automatically routes through the pipeline extractor instead of the
  plain-text scanner. Directory scanning also uses the pipeline.
- **Custom extractor registration**: `register_extractor('.rtf', my_func)` to
  add support for additional formats.

### Pipeline API

- `Pipeline(max_workers, max_file_size, categories, min_confidence, allowlist, on_result)`
- `pipe.process_file(path)` — single file, synchronous
- `pipe.process_files([paths])` — batch, concurrent, ordered results
- `pipe.process_directory(dir_path)` — recursive directory scan
- `pipe.submit(path)` — returns `Future[PipelineResult]`
- `PipelineResult` — `.success`, `.matches`, `.match_count`, `.format_detected`,
  `.extraction_metadata`, `.duration_ms`, `.to_dict(redact=True)`

### New Optional Dependencies

```
pip install dlpscan[pdf]          # pdfplumber
pip install dlpscan[office]       # python-docx, openpyxl, python-pptx
pip install dlpscan[email]        # extract-msg
pip install dlpscan[all-formats]  # Everything
```

### New Files

- `dlpscan/extractors.py` — Text extraction registry and format handlers
- `dlpscan/pipeline.py` — Queue-based concurrent processing pipeline

### Tests

- Expanded from 170 to 199 tests.
- New test classes: `TestExtractors`, `TestPipeline`, `TestFileJob`.

### Totals

- **560 patterns** across **126 categories** (unchanged).
- **199 tests** (up from 170).

## [0.6.0] - 2026-03-26

### New Features

- **Configuration file support**: Loads settings from `pyproject.toml [tool.dlpscan]`
  or `.dlpscanrc` (JSON). Auto-discovers config files by walking up from the current
  directory. CLI arguments override config file settings.
- **Allowlist/ignore rules**: Suppress known false positives via:
  - `allowlist` — exact text values to skip
  - `ignore_patterns` — sub_category names to skip entirely
  - `ignore_paths` — file path globs to skip in directory scanning
  - Inline `# dlpscan:ignore` directive on source lines
- **SARIF output**: `--format sarif` produces SARIF 2.1.0 JSON, compatible with
  GitHub Code Scanning, Azure DevOps, and other security platforms.
- **Recursive directory scanning**: `dlpscan ./src/` scans all text files in a
  directory tree. Automatically skips binary files, `.git`, `node_modules`,
  `__pycache__`, and other common non-text directories.
- **GitHub Actions CI**: Workflow runs tests on Python 3.8–3.13 across Linux,
  macOS, and Windows. Includes ruff linting, mypy type checking, and coverage
  reporting via codecov.

### Packaging & Tooling

- **pyproject.toml**: Migrated from legacy `setup.py` to modern PEP 621
  packaging with `[project]` metadata, `[project.optional-dependencies]` for
  dev tools, and tool configurations for ruff, mypy, and coverage.
- **py.typed marker**: PEP 561 compliance — type checkers now recognize dlpscan
  as a typed package.
- **.pre-commit-config.yaml**: Development workflow hooks for ruff, mypy, and
  dlpscan itself.
- **`[dev]` extras**: `pip install dlpscan[dev]` installs ruff, mypy, coverage,
  and pre-commit.

### New Files

- `dlpscan/config.py` — Configuration file discovery and loading
- `dlpscan/allowlist.py` — Allowlist filtering and inline ignore support
- `dlpscan/py.typed` — PEP 561 marker
- `pyproject.toml` — Modern Python packaging
- `.github/workflows/ci.yml` — GitHub Actions CI pipeline
- `.pre-commit-config.yaml` — Pre-commit hooks

### Tests

- Expanded from 92 to 114 tests.
- New test classes: `TestDirectoryScanning`, `TestAllowlist`, `TestInlineIgnore`,
  `TestConfig`, `TestSARIFOutput`.

### Totals

- **560 patterns** across **126 categories** (unchanged).
- **114 tests** (up from 92).

## [0.5.0] - 2026-03-26

### New Features

- **Match dataclass**: `enhanced_scan_text()` now yields `Match` objects with
  `.text`, `.category`, `.sub_category`, `.has_context`, `.confidence`, `.span`,
  and `.context_required` attributes. Full backward compatibility preserved via
  `__iter__`/`__getitem__`/`__len__` — existing tuple unpacking still works.
- **Confidence scoring**: Each match gets a 0.0–1.0 confidence score based on
  pattern specificity and context keyword proximity. Context boosts score by +0.20.
- **Per-pattern context requirements**: 12 overly-broad patterns (e.g., Gender
  Marker, US Bank Account Number, Cardholder Name) are automatically filtered
  when no context keywords are nearby, regardless of the caller's `require_context`
  setting.
- **Overlap deduplication**: Overlapping matches on the same span are deduplicated,
  keeping the highest-confidence match. Controlled via `deduplicate=True` (default).
- **File scanning**: New `scan_file()` processes files in configurable chunks with
  overlap for boundary matches. Span offsets are relative to the full file.
- **Stream scanning**: New `scan_stream()` accepts any `TextIO` (StringIO, stdin).
- **Custom pattern registration**: `register_patterns()` / `unregister_patterns()`
  allow runtime injection of custom regex patterns, context keywords, and specificity
  scores.
- **CLI rewrite**: Full argparse CLI with `-f/--format` (text/json/csv),
  `--min-confidence`, `--categories`, `--require-context`, `--no-dedup`,
  `--max-matches`, file argument, and piped stdin support.
- **Pre-commit hook**: `dlpscan/hooks.py` scans staged git diffs for sensitive data.
  Supports `--min-confidence` and `--require-context` flags.
- **Performance benchmarks**: `benchmarks/bench.py` measures throughput, category
  filtering speedup, deduplication overhead, and stream scanning performance.

### New Files

- `dlpscan/models.py` — Match dataclass, PATTERN_SPECIFICITY, CONTEXT_REQUIRED_PATTERNS
- `dlpscan/hooks.py` — Pre-commit hook for git
- `benchmarks/bench.py` — Performance benchmark suite

### Tests

- Expanded from 68 to 92 tests.
- New test classes: `TestMatchDataclass`, `TestConfidenceScoring`,
  `TestContextRequired`, `TestOverlapDeduplication`, `TestFileScanming`,
  `TestCustomPatterns`.

### Totals

- **560 patterns** across **126 categories** (unchanged).
- **92 tests** (up from 68).

## [0.4.0] - 2026-03-25

### Breaking Changes

- **`enhanced_scan_text()` return tuple changed**: Now yields 4-element tuples
  `(matched_text, sub_category, has_context, category)` instead of 5-element
  tuples with a redundant `sub_category` at the end. Update any code that
  unpacks 5 elements (e.g., change `for text, sub, ctx, cat, _ in ...` to
  `for text, sub, ctx, cat in ...`).

### Scanner Hardening

- **Input validation on all public functions**: `redact_sensitive_info()` now
  properly rejects `None` and non-string inputs with `EmptyInputError`/`TypeError`
  (previously raised `AttributeError`). `scan_for_context()` validates text type,
  index bounds, and index ordering.
- **Fixed SIGALRM handler restoration order**: Signal handler is now restored
  before the alarm is cancelled, closing a race condition window.
- **Thread-safety guard**: SIGALRM timeout only activates in the main thread.
  Non-main threads fall back to unguarded matching automatically.
- **Global scan timeout**: New `MAX_SCAN_SECONDS` (default 120s) limits total
  scan time across all patterns, preventing worst-case 5s x 560 patterns.
- **Match count limit**: New `max_matches` parameter (default 50,000) on
  `enhanced_scan_text()` prevents memory exhaustion from dense inputs.
- **Logging for timeouts**: Pattern timeouts and scan truncations are logged
  via Python `logging` instead of silently swallowed.

### False Positive Reduction (27 patterns removed/tightened)

Removed or tightened patterns that matched bare digit sequences with no
structural constraints, causing excessive false positives in normal text:

- **Removed**: PIN (`\d{4,6}`), PVKI (`\d{1}`), PVV (`\d{4}`),
  Service Code (`\d{3}`), Dynamic CVV (`\d{3}`), CVV/CVC/CCV (`\d{3}`),
  Amex CID (`\d{4}`), BIN/IIN (`\d{6,8}`), Credit Score (`\d{3}`),
  Customer ID (`\d{6,12}`), Branch Code (`\d{4,6}`),
  Age Value, Australia/Germany Postcode (`\d{4}`/`\d{5}`),
  India PIN Code, US ZIP (plain 5-digit), MRN, Insurance Group Number,
  OTP Code, Social Media User ID, Student ID, Bar Number, GPA,
  IMSI, Android Device ID, Device Serial Number, CSRF Token, Refresh Token.
- **Tightened**: Ticker Symbol now requires `$` prefix (`$AAPL` not `AAPL`).
  Wire Reference/SEPA Reference require mixed letters+digits.
  ACH Trace Number requires valid routing prefix. CHIPS UID given structure.
  Loan Number/ULI require mixed alphanumeric. ICD-10 excludes ambiguous prefixes.
  US ZIP requires +4 suffix. Title Deed requires hyphen.

### Packaging

- **CLI entry point**: `pip install dlpscan` now creates a `dlpscan` console
  command via `entry_points` in `setup.py`.
- **New exports**: `MAX_MATCHES`, `MAX_SCAN_SECONDS`, `REGEX_TIMEOUT_SECONDS`
  available from `dlpscan` package.

### Tests

- Expanded from 37 to 68 tests.
- New test classes: `TestRegionalPatterns` (IBAN, SWIFT, UK NHS, Canada SIN,
  India Aadhaar, Brazil CPF), `TestSecrets` (GitHub tokens, JWT, Stripe),
  `TestFalsePositiveReduction` (plain text, ticker, short numbers),
  `TestDelimiterHandling` (slash, underscore, space, redaction preservation).
- Added validation tests for `scan_for_context()` (type errors, bounds errors).
- Added `max_matches` limit test, empty categories test, tuple length test.
- Removed orphaned test files (`test.py`, `test2.py`, `test5.py`).

### Totals

- **560 patterns** across **126 categories** (down from 587/127 — false-positive
  patterns removed).
- **68 tests** (up from 37).

## [0.3.0] - 2026-03-25

### Scanner Hardening & Refactoring

- **Fixed `redact_sensitive_info_with_patterns`**: Now uses `re.sub()` instead of
  `str.replace()`, preventing false redaction of identical substrings that appear
  in non-sensitive positions.
- **Input validation**: All public API functions now validate inputs — reject `None`,
  non-string types, empty strings, and oversized inputs (>10 MB) with clear exceptions.
- **ReDoS protection**: Regex matching is wrapped in a SIGALRM timeout guard (5s).
  Pathological inputs cause the pattern to be skipped instead of hanging the scanner.
- **`redaction_char` validation**: Must be exactly 1 character.
- **`is_luhn_valid` type check**: Rejects non-string input.

### New Scanner Features

- **Category filtering**: `enhanced_scan_text(text, categories={'Credit Card Numbers'})`
  to scan only specific pattern groups instead of all patterns.
- **Require-context mode**: `enhanced_scan_text(text, require_context=True)` to only
  return matches that have supporting context keywords nearby.

### Flexible Delimiter Handling

- **Standardized delimiter constant** (`_S`) across all 9 pattern files, accepting
  9 separator styles: dash, dot, space, forward slash, backslash, underscore, en dash
  (`\u2013`), em dash (`\u2014`), and non-breaking space (`\u00a0`).
- Catches sensitive data from PDF/Word copy-paste (unicode dashes), web copy-paste
  (non-breaking spaces), log files (underscores), and tax forms (slashes).
- `redact_sensitive_info()` preserves whichever delimiter was used in the original
  match (e.g., `123/45/6789` redacts to `XXX/XX/XXXX`).
- **`input.py` robustness**: Handles KeyboardInterrupt, EOFError, empty input, and
  scanner exceptions with proper exit codes and stderr output.

### Modular Architecture

- **Restructured patterns and context keywords** into a modular package layout:
  - `dlpscan/patterns/{generic,custom,regions}/` — organized module files
  - `dlpscan/context/{generic,custom,regions}/` — mirroring structure
  - `__init__.py` aggregation files merge all sub-modules into unified dicts
- Removed old monolithic `patterns.py` and `context_patterns.py` files.

### Credit Card Expansion

- **Credit Card Security Codes**: CVV/CVC/CCV (3-digit), Amex CID (4-digit).
- **Primary Account Numbers**: PAN, Masked/Truncated PAN, BIN/IIN.
- **Card Track Data**: Track 1 and Track 2 magnetic stripe data.
- **Card Expiration Dates**: MM/YY and MM/YYYY formats.

### Banking & Financial Expansion (9 new categories, 49 patterns)

- **Wire Transfer Data**: Fedwire IMAD, CHIPS UID, ACH trace/batch, SEPA references.
- **Check and MICR Data**: MICR magnetic ink lines, check numbers, cashier checks.
- **Securities Identifiers**: CUSIP, ISIN, SEDOL, FIGI, LEI, ticker symbols.
- **Loan and Mortgage Data**: Loan numbers, MERS MIN, Universal Loan Identifier, LTV.
- **Regulatory Identifiers**: SAR/CTR filings, AML case IDs, OFAC SDN, FinCEN reports.
- **Banking Authentication**: PIN, PIN block, HSM keys, encryption keys.
- **Customer Financial Data**: Account balances, income amounts, credit scores, DTI.
- **Internal Banking References**: Customer IDs, branch codes, teller IDs.
- **PCI Sensitive Data**: Dynamic CVV, PVKI, PVV, service codes, cardholder names.

### PII Expansion (13 new categories, 46 patterns)

- **Personal Identifiers**: Date of birth, age, gender markers.
- **Geolocation**: GPS coordinates (decimal and DMS), geohash.
- **Postal Codes**: US ZIP, UK, Canada, Australia, Germany, Japan, India, Brazil.
- **Device Identifiers**: IMEI, IMEISV, IMSI, MEID, ICCID, Android ID, IDFA/IDFV,
  serial numbers.
- **Medical Identifiers**: MRN, health plan ID, DEA, ICD-10, NDC codes.
- **Insurance Identifiers**: Policy, group, and claim numbers.
- **Authentication Tokens**: OTP, session ID, CSRF token, refresh token.
- **Social Media Identifiers**: Twitter handles, hashtags, user IDs.
- **Education Identifiers**: Student ID, .edu emails, GPA.
- **Legal Identifiers**: Federal case numbers, docket numbers, bar numbers.
- **Employment Identifiers**: Employee ID, work permit numbers.
- **Biometric Identifiers**: Biometric hashes, template IDs.
- **Property Identifiers**: Parcel/APN numbers, title deeds.

### Classification Labels & Regulatory Markers (6 new categories, 47 patterns)

- **Supervisory Information**: CSI, supervisory controlled/confidential, MRA/MRIA.
- **Privileged Information**: Attorney-client privilege, work product, litigation hold.
- **Data Classification Labels**: TOP SECRET, SECRET, FOUO, CUI, SBU, LES, NOFORN.
- **Corporate Classification**: Internal only, strictly confidential, do not distribute,
  need to know, eyes only, proprietary, trade secret, embargoed.
- **Financial Regulatory Labels**: MNPI, inside information, pre-decisional, market
  sensitive, information barrier, restricted list.
- **Privacy Classification**: PII, PHI, HIPAA, GDPR, PCI-DSS, FERPA, GLBA, CCPA/CPRA,
  SOX, NPI.

### Massive European Expansion (+115 patterns)

- Expanded from 12 to 34 European categories covering 32 countries.
- **New countries**: Austria, Belgium, Ireland, Denmark, Finland, Norway, Czech Republic,
  Hungary, Romania, Greece, Croatia, Bulgaria, Slovakia, Lithuania, Latvia, Estonia,
  Slovenia, Luxembourg, Malta, Cyprus, Iceland, Liechtenstein.
- Each country includes national ID, passport, driver's licence, and tax/social
  security number patterns where applicable.
- Added country-specific IBANs for Germany, France, and Netherlands.
- Added EU-wide VAT number pattern covering all member state prefixes.
- Improved existing UK patterns (added DL, fixed NHS format).

### Geographic Pattern Expansion

- **Asia-Pacific**: 66 patterns across 15 countries.
- **Latin America**: 34 patterns across 10 countries.
- **Middle East**: 21 patterns across 10 countries.
- **Africa**: 33 patterns across 10 countries.

### Documentation

- **README.md**: Complete rewrite with API reference, detection architecture,
  security features, usage examples, and pattern coverage summary.
- **PATTERNS.md**: Regenerated — complete inventory of all 587 patterns.
- **docs/ reference library**: Language-agnostic markdown files with raw regex
  patterns and context keywords, organized by category, for integration into
  any tool or language.

### Tests

- Expanded from 19 to 37 tests.
- New test classes: `TestRedactWithPatterns`, `TestScanForContext`.
- Coverage for: input validation (None, non-string, empty, oversized), category
  filtering, require-context mode, regex-sub vs string-replace, classification
  label detection, privileged info detection, Luhn type checking.

### Totals

- **587 patterns** across **127 categories** (up from 111 patterns / 12 categories in v0.2.0).
- All patterns have matching context keyword sets for proximity-based detection.

## [0.2.0] - 2026-03-25

### Bug Fixes

- **Fixed `enhanced_scan_text()` scanning wrong data**: The function was iterating
  over `compiled_context_patterns` (keyword text like "ssn", "visa") instead of
  `PATTERNS` (the actual sensitive data regexes). It now correctly scans text using
  `PATTERNS` and uses context keywords only for proximity verification.
- **Fixed `scan_for_context()` post-text window**: The post-match context window
  started at `start_index` instead of `end_index`, causing it to include the match
  itself in the context search. Now correctly uses the match's end position.
- **Removed debug `print()` statements** from `scan_for_context()` (4 occurrences).
- **Fixed `is_luhn_valid()` algorithm**: Rewrote with clearer double-and-subtract
  logic for improved readability and correctness.
- **Fixed UK NIN pattern**: Now uses HMRC-compliant letter restrictions (excluded
  D, F, I, Q, U, V prefix pairs; last character restricted to A-D).
- **Fixed Singapore NIRC pattern**: Added `M` prefix for newer-format cards.
- **Added Luhn validation to credit card scanning**: `enhanced_scan_text()` now
  automatically validates credit card matches via the Luhn algorithm, filtering
  out false positives.

### Refactoring

- Added type annotations to all public functions in `scanner.py`.
- `__init__.py` now exports the full public API (`enhanced_scan_text`,
  `redact_sensitive_info`, `redact_sensitive_info_with_patterns`, `is_luhn_valid`,
  `scan_for_context`, `PATTERNS`, `CONTEXT_KEYWORDS`, and all exception classes).
- Fixed `input.py` to use relative imports and properly consume the generator.
- Rewrote `tests/unit.py` to import from the package instead of defining local
  function copies. Added 19 tests covering redaction, Luhn validation, and
  `enhanced_scan_text` integration (email, AWS key, SSN context, Luhn rejection).
- Increased default context distance from 20 to 50 characters for more reliable
  proximity matching.
- Added `.gitignore` for `__pycache__/`, `*.pyc`, `*.egg-info/`, `dist/`, `build/`.

### New Pattern Categories (7 new)

- **Contact Information** (7 patterns): Email Address, US Phone Number, UK Phone
  Number, E.164 Phone Number, IPv4 Address, IPv6 Address, MAC Address.
- **API Keys and Secrets** (22 patterns): AWS Access Key, AWS Secret Key, Google
  API Key, GitHub Token (Classic), GitHub Token (Fine-Grained), GitHub OAuth Token,
  Stripe Secret Key, Stripe Publishable Key, Slack Bot Token, Slack User Token,
  Slack Webhook, Bearer Token, JWT Token, Private Key, Generic API Key, Generic
  Secret Assignment, Database Connection String, SendGrid API Key, Twilio API Key,
  Mailgun API Key, NPM Token, PyPI Token.
- **Cryptocurrency** (7 patterns): Bitcoin Address (Legacy), Bitcoin Address
  (Bech32), Ethereum Address, Litecoin Address, Bitcoin Cash Address, Monero
  Address, Ripple Address.
- **Vehicle Identification** (1 pattern): VIN.
- **Dates** (3 patterns): Date ISO, Date US, Date EU (context-gated for DOB
  detection).
- **URLs with Credentials** (2 patterns): URL with Password, URL with Token.

### Expanded Existing Categories

- **Personal Identification** (+19 patterns): USA ITIN, USA EIN, UK UTR, India
  Aadhaar, France NIR, Italy Codice Fiscale, Netherlands BSN, South Korea RRN,
  Japan My Number, Mexico CURP, Mexico RFC, South Africa ID, China Resident ID,
  Canada BN, Poland PESEL, Sweden PIN, Portugal NIF, Switzerland AHV, Turkey TC
  Kimlik.
- **Credit Card Numbers** (+3 patterns): JCB, Diners Club, UnionPay. Updated
  MasterCard to include 2-series (2221-2720) range.
- **Health Cards** (+3 patterns): US DEA Number, US NPI, US MBI (Medicare
  Beneficiary Identifier).
- **Passports** (+7 patterns): UK Passport, Germany Passport, France Passport,
  India Passport, China Passport, Australia Passport, Brazil Passport.
- **Bank Account Numbers** (+1 pattern): Canada Bank Code.

### Totals

- **111 patterns** across **12 categories** (up from ~30 patterns across 6 categories).
- **111 context keyword sets** with category-appropriate proximity distances.

## [0.1.0] - Initial Release

- Initial DLP scanner with regex-based pattern matching.
- Categories: Personal Identification, Credit Card Numbers, Driver Licenses,
  Health Cards, Passports, Bank Account Numbers.
- Context-aware scanning with proximity keyword detection.
- Redaction utilities and Luhn credit card validation.
