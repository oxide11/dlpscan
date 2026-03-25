# Banking — Regex Patterns

> Language-agnostic regex patterns for sensitive data detection.
> All patterns use standard regex syntax compatible with PCRE, Python `re`, JavaScript, Go, Java, etc.

---

## Banking and Financial

| Pattern Name | Regex |
|---|---|
| IBAN Generic | `\b[A-Z]{2}\d{2}[\s]?[\dA-Z]{4}(?:[\s]?[\dA-Z]{4}){2,7}(?:[\s]?[\dA-Z]{1,4})?\b` |
| SWIFT/BIC | `\b[A-Z]{4}[A-Z]{2}[A-Z2-9][A-NP-Z0-9](?:[A-Z\d]{3})?\b` |
