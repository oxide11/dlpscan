# Patterns: Banking And Financial

## Banking and Financial

| Pattern Name | Regex |
|---|---|
| IBAN Generic | `\b[A-Z]{2}\d{2}[\s]?[\dA-Z]{4}(?:[\s]?[\dA-Z]{4}){2,7}(?:[\s]?[\dA-Z]{1,4})?\b` |
| SWIFT/BIC | `\b[A-Z]{4}[A-Z]{2}[A-Z2-9][A-NP-Z0-9](?:[A-Z\d]{3})?\b` |
| ABA Routing Number | `\b(?:0[1-9]\|[12]\d\|3[0-2]\|6[1-9]\|7[0-2])\d{7}\b` |
| US Bank Account Number | `\b\d{8,17}\b` |
| Canada Transit Number | `\b\d{5}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}\b` |
