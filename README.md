# dlpscan

A Python package for detecting and redacting sensitive information in text. Uses regex pattern matching with context-aware keyword proximity to minimize false positives.

**560 patterns** across **126 categories** covering credit cards, government IDs, passports, driver's licences, tax numbers, banking data, securities, authentication tokens, classification labels, and more — spanning 80+ countries.

## Installation

```bash
pip install dlpscan
```

After installation, the `dlpscan` CLI command is available:

```bash
dlpscan                         # Interactive mode
dlpscan file.txt                # Scan a file
dlpscan ./src/                  # Scan a directory recursively
echo "text" | dlpscan           # Pipe input
dlpscan -f json file.txt        # JSON output
dlpscan -f sarif ./src/         # SARIF output (GitHub Code Scanning)
```

## Format Support

dlpscan can scan binary document formats by extracting text first. Install optional dependencies for the formats you need:

```bash
pip install dlpscan[pdf]          # PDF support (pdfplumber)
pip install dlpscan[office]       # DOCX, XLSX, PPTX (python-docx, openpyxl, python-pptx)
pip install dlpscan[email]        # Outlook MSG (extract-msg). EML uses stdlib.
pip install dlpscan[all-formats]  # Everything
```

Supported formats: `.pdf`, `.docx`, `.xlsx`, `.pptx`, `.eml`, `.msg`, plus all plain text formats (`.txt`, `.csv`, `.json`, `.xml`, `.py`, `.js`, etc.). Files up to 100 MB by default.

## Input Guard (Application Integration)

The `InputGuard` module lets developers protect their applications against sensitive data ingestion. Import it, configure what to scan for, and use it to validate, sanitize, or reject user inputs.

### Basic usage

```python
from dlpscan import InputGuard, Preset, Action

# Block PCI-DSS data and SSN/SIN — raise on detection
guard = InputGuard(presets=[Preset.PCI_DSS, Preset.SSN_SIN])
guard.scan("My card is 4532015112830366")  # raises InputGuardError

# Quick boolean check
if guard.check(user_input):
    process(user_input)  # Clean
else:
    reject(user_input)   # Contains sensitive data

# Always get sanitized text
clean = guard.sanitize("card: 4532015112830366")
# "card: XXXXXXXXXXXXXXXX"
```

### Presets

| Preset | What it blocks |
|---|---|
| `Preset.PCI_DSS` | Credit card numbers, PANs, track data, card expiry |
| `Preset.SSN_SIN` | US SSN, ITIN, Canada SIN |
| `Preset.PII` | Personal identifiers, geolocation, device IDs, contact info |
| `Preset.PII_STRICT` | All PII + all 80+ regional national IDs, passports, DLs |
| `Preset.CREDENTIALS` | API keys, tokens, secrets, database connection strings |
| `Preset.FINANCIAL` | Banking, credit cards, securities, crypto, wire transfers |
| `Preset.HEALTHCARE` | Medical identifiers, insurance codes |
| `Preset.CONTACT_INFO` | Email, phone, IP, MAC |

Combine multiple presets: `InputGuard(presets=[Preset.PCI_DSS, Preset.CREDENTIALS])`

### Actions

```python
# REJECT: raise InputGuardError (default)
guard = InputGuard(presets=[Preset.PCI_DSS], action=Action.REJECT)

# REDACT: return sanitized text
guard = InputGuard(presets=[Preset.PCI_DSS], action=Action.REDACT)
result = guard.scan("card: 4532015112830366")
print(result.redacted_text)  # "card: XXXXXXXXXXXXXXXX"

# FLAG: return findings without modifying text
guard = InputGuard(presets=[Preset.PCI_DSS], action=Action.FLAG)
result = guard.scan("card: 4532015112830366")
print(result.is_clean)       # False
print(result.findings)       # [Match(...)]

# TOKENIZE: reversible replacement with tokens
guard = InputGuard(presets=[Preset.PCI_DSS], action=Action.TOKENIZE)
result = guard.scan("card: 4532015112830366")
print(result.redacted_text)  # "card: TOK_CC_a8f3b2c1"
restored = guard.detokenize(result.redacted_text)
print(restored)              # "card: 4532015112830366"

# OBFUSCATE: replace with realistic fake data (irreversible)
guard = InputGuard(presets=[Preset.PCI_DSS], action=Action.OBFUSCATE)
result = guard.scan("card: 4532015112830366")
print(result.redacted_text)  # "card: 4758286118069724" (fake but valid-looking)
```

### Denylist vs Allowlist mode

```python
from dlpscan import InputGuard, Mode, Action

# DENYLIST (default): block specific categories
guard = InputGuard(
    mode=Mode.DENYLIST,
    categories={'Credit Card Numbers', 'Contact Information'},
    action=Action.REJECT,
)

# ALLOWLIST: allow only specified categories, block everything else
guard = InputGuard(
    mode=Mode.ALLOWLIST,
    categories={'Contact Information'},  # Only emails/phones are OK
    action=Action.REJECT,
)
guard.scan("email: user@test.com")      # OK — email is allowed
guard.scan("SSN: 123-45-6789")          # raises InputGuardError
```

### Decorator

```python
guard = InputGuard(presets=[Preset.PCI_DSS, Preset.SSN_SIN])

# Protect specific parameters
@guard.protect(param="comment")
def save_comment(user_id: int, comment: str):
    db.save(user_id, comment)

# Protect multiple parameters
@guard.protect(params=["name", "address"])
def save_profile(name: str, address: str, age: int):
    db.save(name, address, age)

# Protect all string arguments
@guard.protect()
def handle_request(body: str, query: str):
    process(body, query)

# With REDACT action, arguments are sanitized before the function runs
guard = InputGuard(presets=[Preset.CREDENTIALS], action=Action.REDACT)

@guard.protect(param="log_message")
def write_log(log_message: str):
    # log_message is already sanitized — no secrets in logs
    logger.info(log_message)
```

### Custom patterns

```python
from dlpscan import InputGuard, Action

# Register custom patterns directly in the guard
with InputGuard(
    action=Action.REJECT,
    custom_patterns={
        'Internal IDs': {
            'Project Code': r'\bPRJ-\d{6}\b',
            'Employee Badge': r'\bEMP\d{5}\b',
        },
    },
) as guard:
    guard.scan("Project PRJ-123456")  # raises InputGuardError
# Patterns automatically unregistered on exit
```

### Per-category confidence tuning

```python
guard = InputGuard(
    presets=[Preset.PCI_DSS, Preset.CONTACT_INFO],
    action=Action.REJECT,
    confidence_overrides={
        'Credit Card Numbers': 0.9,    # High bar for credit cards
        'Contact Information': 0.5,    # Lower bar for emails/phones
    },
)
```

### Streaming scanner

```python
from dlpscan.streaming import StreamScanner

scanner = StreamScanner(
    categories={'Credit Card Numbers'},
    buffer_size=4096,
    on_match=lambda m: alert(m),
)

for chunk in incoming_stream():
    matches = scanner.feed(chunk)
    for m in matches:
        print(f"ALERT: {m.category}")

# Flush remaining buffer
matches = scanner.flush()
```

### Webhook scanner

```python
from dlpscan.streaming import WebhookScanner
from dlpscan.guard import Preset, Action, InputGuardError

webhook = WebhookScanner(presets=[Preset.PCI_DSS], action=Action.REJECT)

# Scan JSON payload — extracts all nested string values
try:
    result = webhook.scan_payload(request.body, content_type='application/json')
except InputGuardError:
    return {"error": "Sensitive data detected"}, 400

# Scan custom headers for leaked tokens
result = webhook.scan_headers(dict(request.headers))
```

### Advanced options

```python
from dlpscan import InputGuard, Preset, Action, Allowlist

guard = InputGuard(
    presets=[Preset.PCI_DSS, Preset.SSN_SIN],
    action=Action.REJECT,
    min_confidence=0.5,          # Ignore low-confidence matches
    require_context=True,        # Only flag matches with context keywords
    redaction_char='*',          # Use * instead of X for redaction
    allowlist=Allowlist(         # Suppress known false positives
        texts=['test@example.com'],
        patterns=['Hashtag'],
    ),
    on_detect=lambda r: log_alert(r),  # Callback on detection
)
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

### Scan files and directories

```python
from dlpscan import scan_file, scan_directory

# Scan a single file
for match in scan_file('data.csv', categories={'Credit Card Numbers'}):
    print(f"{match.sub_category}: {match.text} (confidence: {match.confidence:.0%})")

# Scan a directory recursively
for path, match in scan_directory('./src/', skip_paths=['*.md', 'tests/**']):
    print(f"{path}:{match.span[0]} {match.sub_category}")
```

### Confidence scoring

```python
from dlpscan import enhanced_scan_text

text = "My credit card number is 4532015112830366"
for m in enhanced_scan_text(text):
    print(f"{m.sub_category}: confidence={m.confidence:.0%}, context={m.has_context}")
    # Visa: confidence=100%, context=True
```

### Allowlist known false positives

```python
from dlpscan import enhanced_scan_text, Allowlist

al = Allowlist(
    texts=['test@example.com'],           # Exact text to ignore
    patterns=['Gender Marker', 'Hashtag'], # Pattern types to ignore
)

results = enhanced_scan_text("Contact test@example.com")
filtered = al.filter_matches(results)
```

### Redact output (enterprise)

```python
from dlpscan import enhanced_scan_text

text = "My credit card is 4532015112830366"
for m in enhanced_scan_text(text):
    print(m.redacted_text)  # '453...366'
    print(m.to_dict(redact=True))  # {'text': '453...366', ...}
```

CLI:
```bash
dlpscan --redact file.txt           # Redacts matched text in output
dlpscan --redact -f json file.txt   # Redacted JSON output
```

### Plugin system

```python
from dlpscan import register_validator, register_post_processor

# Validator: return True to keep match, False to discard
def validate_employee_id(match):
    return match.text.startswith('EMP')

register_validator('Employee ID', validate_employee_id)

# Post-processor: transform the full match list
def remove_test_data(matches):
    return [m for m in matches if 'test' not in m.text.lower()]

register_post_processor(remove_test_data)
```

### Metrics and observability

```python
from dlpscan import set_metrics_callback, ScanMetrics

def my_callback(metrics: ScanMetrics) -> None:
    print(f"Scan took {metrics.duration_ms:.1f}ms, found {metrics.match_count} matches")
    print(f"Scanned {metrics.bytes_scanned} bytes across {metrics.categories_scanned} categories")

set_metrics_callback(my_callback)
# All subsequent scans invoke the callback automatically.
```

### Structured JSON logging

```python
from dlpscan import configure_logging

# JSON logging to stderr (for ELK, Splunk, Datadog)
configure_logging(level='INFO', json_format=True)

# Plain text logging
configure_logging(level='DEBUG', json_format=False)
```

### Async scanning

```python
import asyncio
from dlpscan import async_scan_text, async_scan_file

async def main():
    async for match in async_scan_text("My SSN is 123-45-6789"):
        print(match.sub_category, match.confidence)

    async for match in async_scan_file("data.csv"):
        print(match.text)

asyncio.run(main())
```

### File processing pipeline

```python
from dlpscan import Pipeline

# Process a batch of files concurrently
with Pipeline(max_workers=4, min_confidence=0.5) as pipe:
    results = pipe.process_files(['report.pdf', 'data.xlsx', 'notes.docx'])
    for r in results:
        if r.success:
            print(f"{r.file_path} ({r.format_detected}): {r.match_count} matches")
        else:
            print(f"{r.file_path}: ERROR — {r.error}")

    # Process a directory
    results = pipe.process_directory('./documents/')

    # Submit for async processing
    future = pipe.submit('large_report.pdf')
    result = future.result()
```

```python
# Extract text from any supported format
from dlpscan import extract_text

result = extract_text('report.pdf')
print(result.text[:200])
print(result.metadata)   # {'page_count': 5, 'pdf_metadata': {...}}
print(result.format)     # 'pdf'

# Register a custom extractor
from dlpscan import register_extractor, ExtractionResult

def extract_rtf(path):
    text = my_rtf_parser(path)
    return ExtractionResult(text=text, format='rtf')

register_extractor('.rtf', extract_rtf)
```

### Check context proximity

```python
from dlpscan import scan_for_context

text = "My credit card number is 4532015112830366"
scan_for_context(text, start_index=25, end_index=41,
                 category='Credit Card Numbers', sub_category='Visa')
# True — "credit card" keyword found within proximity distance
```

## Enterprise Features

### Audit logging

```python
from dlpscan.audit import (
    AuditLogger, FileAuditHandler, set_audit_logger, event_from_scan,
)
from dlpscan.guard import InputGuard, Preset, Action

# Set up file-based audit logging
logger = AuditLogger(handlers=[FileAuditHandler("/var/log/dlp-audit.jsonl")])
set_audit_logger(logger)

guard = InputGuard(presets=[Preset.PCI_DSS], action=Action.REDACT)
result = guard.scan("Card: 4111111111111111")
event = event_from_scan(result, action="redact", source="api")
```

### Rate limiting

```python
from dlpscan.rate_limit import RateLimiter, rate_limited

limiter = RateLimiter(max_requests=100, window_seconds=60)

@rate_limited(limiter)
def scan_input(text):
    return guard.scan(text)
```

### SIEM integration

```python
from dlpscan.siem import SplunkHECAdapter, create_siem_from_env

# Direct configuration
adapter = SplunkHECAdapter(url="https://splunk:8088", token="my-token")
adapter.send({"action": "redact", "categories": ["Credit Card Numbers"]})

# Or from environment variables (DLPSCAN_SIEM_TYPE, DLPSCAN_SIEM_URL, etc.)
adapter = create_siem_from_env()
```

### Role-based detokenization

```python
from dlpscan.guard import TokenVault
from dlpscan.guard.rbac import Role, RBACPolicy, SecureTokenVault

vault = TokenVault()
policy = RBACPolicy(default_role=Role.VIEWER, role_overrides={"admin": Role.ADMIN})
secure = SecureTokenVault(vault=vault, policy=policy)

token = secure.tokenize("4111111111111111", "Credit Card Numbers")
original = secure.detokenize(token, user_id="admin")  # Works
# secure.detokenize(token, user_id="viewer")  # Raises PermissionDeniedError
```

### Compliance reporting

```python
from dlpscan.compliance import ComplianceReporter
from dlpscan.guard import InputGuard, Preset, Action

guard = InputGuard(presets=[Preset.PCI_DSS], action=Action.FLAG)
reporter = ComplianceReporter(title="Q1 2026 DLP Report")

for text in scan_targets:
    result = guard.scan(text)
    reporter.add_scan_result(result, source="batch")

report = reporter.generate()
print(report.compliance_status)  # {"PCI-DSS": False, "HIPAA": True, ...}
html = reporter.to_html()        # Full HTML report
```

### Environment variable configuration

```bash
export DLPSCAN_ACTION=redact
export DLPSCAN_PRESETS=pci_dss,ssn_sin
export DLPSCAN_MIN_CONFIDENCE=0.5
export DLPSCAN_AUDIT_FILE=/var/log/dlp.jsonl
export DLPSCAN_SIEM_TYPE=splunk
export DLPSCAN_SIEM_URL=https://splunk:8088
export DLPSCAN_SIEM_TOKEN=my-token
```

```python
from dlpscan.env_config import configure_from_env
configure_from_env()  # One-call setup
```

### Reproducible obfuscation

```python
from dlpscan.guard import InputGuard, Preset, Action, set_obfuscation_seed

set_obfuscation_seed(42)  # Deterministic output
guard = InputGuard(presets=[Preset.PCI_DSS], action=Action.OBFUSCATE)
result = guard.scan("Card: 4111111111111111")
# Same seed → same fake data every time
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

### `enhanced_scan_text(text, categories=None, require_context=False, max_matches=50000, deduplicate=True)`

Scan text for sensitive data.

| Parameter | Type | Description |
|---|---|---|
| `text` | `str` | Input text to scan |
| `categories` | `set[str]` or `None` | Category names to scan. `None` scans all. |
| `require_context` | `bool` | If `True`, only return matches with nearby keywords. |
| `max_matches` | `int` | Maximum matches to return (default 50,000). |
| `deduplicate` | `bool` | If `True`, remove overlapping matches keeping highest confidence. |

**Yields**: `Match` objects with `.text`, `.category`, `.sub_category`, `.has_context`, `.confidence`, `.span`. Supports tuple unpacking for backward compatibility: `text, sub_category, has_context, category = match`

### `scan_file(file_path, categories=None, require_context=False, max_matches=50000, deduplicate=True, encoding='utf-8')`

Scan a file for sensitive data, processing in chunks for memory efficiency.

**Yields**: `Match` objects with span offsets relative to the full file.

### `scan_directory(dir_path, categories=None, require_context=False, max_matches=50000, deduplicate=True, skip_paths=None)`

Recursively scan all text files in a directory. Skips binary files and common non-text directories (`.git`, `node_modules`, `__pycache__`, etc.).

**Yields**: `(relative_path, Match)` tuples.

### `scan_stream(stream, categories=None, require_context=False, max_matches=50000, deduplicate=True)`

Scan a text stream (StringIO, stdin, etc.) for sensitive data.

**Yields**: `Match` objects with span offsets relative to stream start.

### `redact_sensitive_info(match, redaction_char='X')`

Redact a matched string, preserving delimiter characters (`-`, `.`, ` `, `/`, `\`, `_`, en dash, em dash, non-breaking space).

**Raises**: `EmptyInputError`, `TypeError`, `ShortInputError` (< 4 printable chars)

### `redact_sensitive_info_with_patterns(text, category, sub_category)`

Redact all occurrences of a specific pattern in text using regex substitution.

**Raises**: `SubCategoryNotFoundError`, `EmptyInputError`

### `is_luhn_valid(card_number)`

Validate a credit card number using the Luhn algorithm. Handles spaces and hyphens.

**Raises**: `InvalidCardNumberError`

### `register_patterns(category, patterns, context=None, specificity=None, context_required=None)`

Register custom patterns at runtime for domain-specific scanning.

### `unregister_patterns(category)`

Remove previously registered custom patterns.

### `scan_for_context(text, start_index, end_index, category, sub_category)`

Check for contextual keywords within the configured proximity distance of a match span.

**Returns**: `bool`

**Raises**: `TypeError`, `ValueError` (invalid indices)

### `load_config(path=None, start_dir=None)`

Load dlpscan configuration from `pyproject.toml [tool.dlpscan]` or `.dlpscanrc` (JSON). Auto-discovers config files by walking up from the current directory.

### `Allowlist(texts=None, patterns=None, paths=None)`

Filter for suppressing known false positives by exact text, pattern name, or file path glob.

## Configuration

dlpscan can be configured via `pyproject.toml` or `.dlpscanrc` (JSON):

```toml
# pyproject.toml
[tool.dlpscan]
min_confidence = 0.5
require_context = false
deduplicate = true
max_matches = 50000
format = "text"
allowlist = ["test@example.com", "AKIAIOSFODNN7EXAMPLE"]
ignore_patterns = ["Gender Marker", "Hashtag"]
ignore_paths = ["*.md", "tests/**"]
```

```json
// .dlpscanrc
{
    "min_confidence": 0.5,
    "allowlist": ["test@example.com"],
    "ignore_patterns": ["Gender Marker"]
}
```

CLI arguments always override config file settings.

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
├── input.py                       # CLI entry point (argparse)
├── models.py                      # Match dataclass, specificity scores
├── config.py                      # Configuration file loading
├── allowlist.py                   # Allowlist filtering and inline ignore
├── hooks.py                       # Pre-commit hook for git
├── metrics.py                     # Callback-based observability system
├── plugins.py                     # Plugin validators and post-processors
├── logging_config.py              # Structured JSON logging
├── async_scanner.py               # Async scanning wrappers
├── extractors.py                  # Text extraction from binary formats
├── pipeline.py                    # Queue-based file processing pipeline
├── streaming.py                   # Real-time stream & webhook scanners
├── audit.py                       # Enterprise audit logging framework
├── rate_limit.py                  # Token bucket rate limiter
├── env_config.py                  # DLPSCAN_* environment variable configuration
├── siem.py                        # SIEM integration (Splunk, ES, Syslog, Datadog)
├── compliance.py                  # Compliance reporting (PCI-DSS, HIPAA, SOC2, GDPR)
├── guard/                         # Developer input guard subpackage
│   ├── __init__.py                # Subpackage exports
│   ├── core.py                    # InputGuard class, ScanResult, InputGuardError
│   ├── enums.py                   # Action, Mode enums
│   ├── presets.py                 # Preset enum, PRESET_CATEGORIES mappings
│   ├── transforms.py              # TokenVault, obfuscation generators
│   ├── rbac.py                    # Role-based access control for detokenization
│   └── vault_backends.py          # Pluggable vault storage backends
├── exceptions.py                  # Exception hierarchy
├── py.typed                       # PEP 561 type marker
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
python -m unittest tests.unit -v          # Unit tests (335 tests)
python -m unittest tests.test_integration  # Integration tests
python tests/benchmarks.py                 # Performance benchmarks

# With coverage
pip install dlpscan[dev]
coverage run -m unittest tests.unit -v
coverage report
```

288 tests covering redaction, Luhn validation, input validation, category filtering, context detection, classification labels, regional patterns, secrets detection, false positive reduction, delimiter handling, Match dataclass, confidence scoring, overlap deduplication, file/stream/directory scanning, allowlist filtering, config loading, SARIF output, custom pattern registration, output redaction, metrics/observability, plugin system, structured logging, async scanning, text extraction, the file processing pipeline, InputGuard module, custom patterns via InputGuard, per-category confidence tuning, pipeline structured output, streaming scanner, webhook scanner, tokenization, and obfuscation.

## Docker

```bash
docker build -t dlpscan .
echo "My SSN is 123-45-6789" | docker run -i dlpscan --redact
docker run -v $(pwd):/data dlpscan /data/src/ -f sarif --redact
```

## License

MIT
