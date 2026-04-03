# Patterns: Securities Identifiers

## Securities Identifiers

| Pattern Name | Regex |
|---|---|
| CUSIP | `\b[0-9A-Z]{6}[0-9A-Z]{2}\d\b` |
| ISIN | `\b[A-Z]{2}[0-9A-Z]{9}\d\b` |
| SEDOL | `\b[0-9BCDFGHJKLMNPQRSTVWXYZ]{6}\d\b` |
| FIGI | `\bBBG[A-Z0-9]{9}\b` |
| LEI | `\b[A-Z0-9]{4}00[A-Z0-9]{12}\d{2}\b` |
| Ticker Symbol | `(?<!\w)\$[A-Z]{1,5}\b` |
