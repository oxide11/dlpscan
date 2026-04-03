# DLP Pattern & Keyword Reference Library

Language-agnostic regex patterns and context keywords for detecting sensitive data. Use these with any language or tool that supports standard regex (PCRE, Python `re`, JavaScript, Go, Java, .NET, etc.).

## Structure

```
docs/
├── patterns/          # Regex patterns for matching sensitive data
│   ├── generic/       # Universal formats (credit cards, emails, IBANs, etc.)
│   ├── custom/        # Vendor-specific (AWS keys, GitHub tokens, Stripe, etc.)
│   └── regions/       # Country-specific IDs, passports, DLs, tax numbers
│       ├── north_america.md
│       ├── europe.md
│       ├── asia_pacific.md
│       ├── latin_america.md
│       ├── middle_east.md
│       └── africa.md
└── keywords/          # Context keywords for proximity-based detection
    ├── generic/       # (mirrors patterns/ structure)
    ├── custom/
    └── regions/
```

## How to Use

### Patterns

Each pattern file contains a table of regex patterns:

| Pattern Name | Regex |
|---|---|
| Visa | `\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b` |

Copy the regex directly into your language/tool. All patterns use standard syntax — no proprietary extensions.

### Delimiter Handling

Multi-group numeric patterns use a flexible delimiter class that matches 9 separator styles:

```
[-.\s/\\_\u2013\u2014\u00a0]?
```

This single character class handles: dash `-`, dot `.`, space, forward slash `/`, backslash `\`, underscore `_`, en dash `–` (U+2013), em dash `—` (U+2014), and non-breaking space (U+00A0). If you are porting these patterns to another language, replace this class with whatever delimiter handling your use case requires.

### Keywords (Context Detection)

Matching a regex alone can produce false positives (e.g., a 9-digit number could be an SSN or a zip code). The keyword files provide **context keywords** to check for near each match:

| Pattern Name | Keywords |
|---|---|
| USA SSN | `social security number`, `ssn`, `social security no` |

**How proximity detection works:** After a regex match is found, check whether any of the associated keywords appear within N characters before or after the match. Each category specifies its recommended proximity distance.

## Coverage

- **587 patterns** across **127 categories**
- **32 European countries** — national IDs, passports, driver's licences, tax numbers
- **15 Asia-Pacific countries** — Aadhaar, MyKad, My Number, NRIC, and more
- **10 Latin American countries** — CPF, CURP, RUT, cedulas
- **10 Middle Eastern countries** — Emirates ID, TC Kimlik, Teudat Zehut
- **10 African countries** — NIN, BVN, Ghana Card, Kenya ID
- **US & Canada** — all 50 state DLs, provincial DLs, health cards, SIN/SSN
- **Credit cards** — PAN, CVV/CVC, track data, expiry, BIN/IIN, masked PAN
- **Banking** — wire transfers, securities (CUSIP/ISIN/SEDOL), MICR, loans, PCI data
- **PII** — device IDs, geolocation, postal codes, medical/insurance, social media, biometric
- **Classification labels** — supervisory, privileged, TOP SECRET, MNPI, HIPAA, GDPR, PCI-DSS
- **Secrets & tokens** — AWS, GitHub, Stripe, Slack, JWT, private keys, OTP, session IDs
