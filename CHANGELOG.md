# Changelog

All notable changes to dlpscan will be documented in this file.

## [0.3.0] - 2026-03-25

### Modular Architecture

- **Restructured patterns and context keywords** into a modular package layout:
  - `dlpscan/patterns/{generic,custom,regions}/` — 18 module files
  - `dlpscan/context/{generic,custom,regions}/` — mirroring structure
  - `__init__.py` aggregation files merge all sub-modules into unified dicts
- Removed old monolithic `patterns.py` and `context_patterns.py` files.

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

- **Asia-Pacific**: 66 patterns across 15 countries (Australia, Bangladesh, China/HK/TW,
  India, Indonesia, Japan, Malaysia, New Zealand, Pakistan, Philippines, Singapore,
  South Korea, Sri Lanka, Thailand, Vietnam).
- **Latin America**: 34 patterns across 10 countries (Argentina, Brazil, Chile, Colombia,
  Costa Rica, Ecuador, Paraguay, Peru, Uruguay, Venezuela).
- **Middle East**: 21 patterns across 10 countries (Bahrain, Iran, Iraq, Israel, Jordan,
  Kuwait, Lebanon, Qatar, Saudi Arabia, UAE).
- **Africa**: 33 patterns across 10 countries (Egypt, Ethiopia, Ghana, Kenya, Morocco,
  Nigeria, South Africa, Tanzania, Tunisia, Uganda).

### Totals

- **437 patterns** across **95 categories** (up from 111 patterns / 12 categories in v0.2.0).
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
