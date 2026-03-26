# dlpscan

A Python package for detecting and redacting sensitive information in text. Uses regex pattern matching with context-aware keyword proximity to minimize false positives.

**560 patterns** across **126 categories** covering credit cards, government IDs, passports, driver's licences, tax numbers, banking data, securities, authentication tokens, classification labels, and more — spanning 80+ countries.

## Installation

```bash
pip install dlpscan
```

After installation, the `dlpscan` CLI command is available:

```bash
dlpscan
```

## Quick Start

### Scan text for sensitive data

```python
from dlpscan import enhanced_scan_text

text = "My SSN is 123-45-6789 and credit card is 4532015112830366"

for match_text, sub_category, has_context, category in enhanced_scan_text(text):
    context = "WITH context" if has_context else "no context"
    print(f"[{category} > {sub_category}] '{match_text}' ({context})")
```

Output:
```
[North America - United States > USA SSN] '123-45-6789' (WITH context)
[Credit Card Numbers > Visa] '4532015112830366' (WITH context)
```

### Redact sensitive data

```python
from dlpscan import redact_sensitive_info, redact_sensitive_info_with_patterns

# Redact a single value
redact_sensitive_info("4532-0151-1283-0366")
# => 'XXXX-XXXX-XXXX-XXXX'

redact_sensitive_info("4532-0151-1283-0366", redaction_char='*')
# => '****-****-****-****'

# Redact all matches of a pattern in text
text = "Contact us at test@example.com or admin@example.com"
redact_sensitive_info_with_patterns(text, 'Contact Information', 'Email Address')
# => 'Contact us at XXXXXXXXXXXXXXXX or XXXXXXXXXXXXXXXXX'
```

### Scan specific categories only

```python
from dlpscan import enhanced_scan_text

text = "Card: 4532015112830366, SSN: 123-45-6789, email: test@example.com"

# Only scan for credit cards
results = list(enhanced_scan_text(text, categories={'Credit Card Numbers'}))
# Returns only the Visa match, skips SSN and email
```

### Require context keywords

```python
from dlpscan import enhanced_scan_text

# Only return matches that have supporting context keywords nearby
text = "The number 4532015112830366 appears in the document"
results = list(enhanced_scan_text(text, require_context=True))
# Fewer results — only matches with keywords like "credit card", "ssn" etc. nearby
```

### Validate credit cards

```python
from dlpscan import is_luhn_valid

is_luhn_valid("4532015112830366")  # True
is_luhn_valid("4532015112830365")  # False
is_luhn_valid("4532 0151 1283 0366")  # True (handles separators)
```

### Check context proximity

```python
from dlpscan import scan_for_context

text = "My credit card number is 4532015112830366"
scan_for_context(text, start_index=25, end_index=41,
                 category='Credit Card Numbers', sub_category='Visa')
# True — "credit card" keyword found within proximity distance
```

## How Detection Works

dlpscan uses a two-layer detection approach:

1. **Regex Pattern Matching** — Pre-compiled regex patterns scan the input text for potential sensitive data (credit card numbers, SSNs, IBANs, etc.).

2. **Context Keyword Proximity** — After a regex match is found, the scanner checks for contextual keywords (like "credit card", "ssn", "passport") within a configurable character distance before and after the match. This helps distinguish between a random 9-digit number and an actual SSN.

Each result includes a `has_context` flag indicating whether context keywords were found, allowing callers to make confidence-based decisions.

```
                    <-- distance -->              <-- distance -->
                    [  pre-text    ] [ match     ] [  post-text   ]
text: "My credit card number is    4532-0151-...  for payment"
                    ^^^^^^^^^^^^^^^^               ^^^^^^^^^^^^^^
                    keyword search                 keyword search
```

### Flexible Delimiter Handling

All multi-group patterns use a standard delimiter class that accepts 9 separator styles. This catches sensitive data regardless of formatting — including invisible characters from copy-paste:

| Delimiter | Example | Source |
|---|---|---|
| Dash `-` | `123-45-6789` | Standard formatting |
| Dot `.` | `123.45.6789` | European formats |
| Space | `123 45 6789` | Forms, spoken input |
| Slash `/` | `123/45/6789` | Tax forms, official docs |
| Backslash `\` | `123\45\6789` | Log files, Windows paths |
| Underscore `_` | `123_45_6789` | Database exports, CSVs |
| En dash `--` | `123--45--6789` | PDF/Word copy-paste |
| Em dash `---` | `123---45---6789` | PDF/Word copy-paste |
| Non-breaking space | `123 45 6789` | Web page copy-paste |
| No delimiter | `123456789` | Compact/stripped format |

Redaction preserves whichever delimiter was used:

```python
redact_sensitive_info("123/45/6789")   # => 'XXX/XX/XXXX'
redact_sensitive_info("123-45-6789")   # => 'XXX-XX-XXXX'
redact_sensitive_info("123_45_6789")   # => 'XXX_XX_XXXX'
```

### Credit Card Validation

Credit card matches are automatically validated using the **Luhn algorithm** before being returned. Invalid card numbers are silently filtered out.

### ReDoS Protection

All regex matching is wrapped in a timeout guard (`SIGALRM` on Unix, main thread only). If a pattern takes longer than 5 seconds on a given input, it is skipped. A global scan timeout of 120 seconds prevents unbounded total scan time. On Windows or in non-main threads, timeouts are unavailable and matching runs unguarded.

### Match Limits

`enhanced_scan_text` caps output at 50,000 matches by default (configurable via `max_matches`). This prevents memory exhaustion on dense or pathological inputs.

### Input Safety

- **Type validation**: All public functions reject `None`, non-string, and empty inputs with clear exceptions.
- **Size limits**: Inputs larger than 10 MB are rejected to prevent resource exhaustion.
- **Bounds checking**: `scan_for_context` validates all index parameters.
- **Safe redaction**: Uses `re.sub()` (not `str.replace()`) to only redact actual pattern matches.

### Thread Safety

The SIGALRM-based timeout only works in the main thread on Unix. When called from background threads, regex timeouts are automatically disabled. The scanner is safe to call from any thread, but ReDoS protection is only active in the main thread.

## API Reference

### `enhanced_scan_text(text, categories=None, require_context=False, max_matches=50000)`

Scan text for sensitive data.

| Parameter | Type | Description |
|---|---|---|
| `text` | `str` | Input text to scan |
| `categories` | `set[str]` or `None` | Category names to scan. `None` scans all. |
| `require_context` | `bool` | If `True`, only return matches with nearby keywords. |
| `max_matches` | `int` | Maximum matches to return (default 50,000). |

**Yields**: `(matched_text, sub_category, has_context, category)`

### `redact_sensitive_info(match, redaction_char='X')`

Redact a matched string, preserving delimiter characters (`-`, `.`, ` `, `/`, `\`, `_`, en dash, em dash, non-breaking space).

**Raises**: `EmptyInputError`, `TypeError`, `ShortInputError` (< 4 printable chars)

### `redact_sensitive_info_with_patterns(text, category, sub_category)`

Redact all occurrences of a specific pattern in text using regex substitution.

**Raises**: `SubCategoryNotFoundError`, `EmptyInputError`

### `is_luhn_valid(card_number)`

Validate a credit card number using the Luhn algorithm. Handles spaces and hyphens.

**Raises**: `InvalidCardNumberError`

### `scan_for_context(text, start_index, end_index, category, sub_category)`

Check for contextual keywords within the configured proximity distance of a match span.

**Returns**: `bool`

**Raises**: `TypeError`, `ValueError` (invalid indices)

## Constants

| Constant | Default | Description |
|---|---|---|
| `MAX_INPUT_SIZE` | 10 MB | Maximum text size accepted by the scanner |
| `MAX_MATCHES` | 50,000 | Maximum matches per scan |
| `MAX_SCAN_SECONDS` | 120 | Global scan timeout in seconds |
| `REGEX_TIMEOUT_SECONDS` | 5 | Per-pattern regex timeout |

## Exceptions

All exceptions inherit from `RedactionError`:

| Exception | When |
|---|---|
| `EmptyInputError` | Input is `None` or empty string |
| `ShortInputError` | Input has fewer than 4 printable characters |
| `InvalidCardNumberError` | Card number is empty, non-string, or invalid |
| `SubCategoryNotFoundError` | Category or sub-category not found in `PATTERNS` |

## Pattern Coverage

**560 patterns** across **126 categories** in three tiers:

### Generic Patterns

Universal formats not tied to any country or vendor:

- **Credit Cards**: Visa, MasterCard, Amex, Discover, JCB, Diners Club, UnionPay, PAN, masked PAN, track data, expiry
- **Banking & Financial**: IBAN, SWIFT/BIC, ABA routing, wire transfers (Fedwire, ACH, SEPA), check/MICR data, securities (CUSIP, ISIN, SEDOL, FIGI, LEI, ticker), loans/mortgages, regulatory (SAR, CTR, AML), authentication, customer data
- **Contact Info**: Email, phone (E.164), IPv4, IPv6, MAC address
- **PII**: Date of birth, gender, GPS coordinates, postal codes, device IDs (IMEI, ICCID, MEID), medical records, insurance, social media, education, legal, employment, biometric, property
- **Secrets & Tokens**: Bearer, JWT, private keys, API keys, database connection strings, session IDs
- **Classification Labels**: Supervisory controlled/confidential (CSI, MRA/MRIA), attorney-client privilege, TOP SECRET/SECRET/FOUO/CUI, corporate confidential, MNPI, PII/PHI/HIPAA/GDPR/PCI-DSS labels
- **Cryptocurrency**: Bitcoin, Ethereum, Litecoin, Bitcoin Cash, Monero, Ripple
- **Other**: VIN, dates (ISO/US/EU), URLs with credentials

### Custom Patterns (16 patterns)

Vendor-specific tokens and secrets:

- **Cloud**: AWS Access Key, AWS Secret Key, Google API Key
- **Code Platforms**: GitHub tokens (classic, fine-grained, OAuth), NPM, PyPI
- **Payments**: Stripe secret/publishable keys
- **Messaging**: Slack (bot, user, webhook), SendGrid, Twilio, Mailgun

### Geographic Patterns (80+ countries)

Country-specific IDs, passports, driver's licences, tax numbers, and health cards:

| Region | Countries | Patterns |
|---|---|---|
| **North America** | US (all 50 state DLs), Canada (all provinces), Mexico | 100 |
| **Europe** | 32 countries | 134 |
| **Asia-Pacific** | 15 countries | 66 |
| **Latin America** | 10 countries | 34 |
| **Middle East** | 10 countries | 21 |
| **Africa** | 10 countries | 33 |

See [PATTERNS.md](PATTERNS.md) for the complete list, or browse the [docs/](docs/) folder for language-agnostic regex and keyword references.

## Documentation Reference Library

The `docs/` folder contains all patterns and keywords in plain markdown, independent of the Python code:

```
docs/
├── patterns/          # Raw regex patterns (copy-paste into any language)
│   ├── generic/
│   ├── custom/
│   └── regions/
└── keywords/          # Context keywords for proximity detection
    ├── generic/
    ├── custom/
    └── regions/
```

Use these files to integrate dlpscan's detection rules into any tool or language — the regex syntax is standard PCRE-compatible.

## Project Structure

```
dlpscan/
├── __init__.py                    # Package exports
├── scanner.py                     # Core scanning, redaction, validation
├── input.py                       # CLI entry point
├── exceptions.py                  # Exception hierarchy
├── patterns/                      # Regex pattern definitions
│   ├── __init__.py                # Aggregates all patterns into PATTERNS dict
│   ├── generic/                   # Universal patterns (credit cards, PII, banking...)
│   ├── custom/                    # Vendor-specific (AWS, GitHub, Stripe...)
│   └── regions/                   # Country-specific (north_america, europe, ...)
└── context/                       # Context keywords (mirrors patterns/ structure)
    ├── __init__.py                # Aggregates into CONTEXT_KEYWORDS dict
    ├── generic/
    ├── custom/
    └── regions/
```

## Testing

```bash
python -m unittest tests.unit -v
```

68 tests covering redaction, Luhn validation, input validation, category filtering, context detection, classification labels, regional patterns, secrets detection, false positive reduction, delimiter handling, and edge cases.

## License

MIT
