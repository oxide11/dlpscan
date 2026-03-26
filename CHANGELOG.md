# Changelog

All notable changes to dlpscan will be documented in this file.

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
