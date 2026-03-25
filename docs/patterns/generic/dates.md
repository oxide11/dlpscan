# Dates — Regex Patterns

> Language-agnostic regex patterns for sensitive data detection.
> All patterns use standard regex syntax compatible with PCRE, Python `re`, JavaScript, Go, Java, etc.

---

## Dates

| Pattern Name | Regex |
|---|---|
| Date EU | `\b(?:0[1-9]\|[12]\d\|3[01])[-/](?:0[1-9]\|1[0-2])[-/]\d{4}\b` |
| Date ISO | `\b\d{4}[-/](?:0[1-9]\|1[0-2])[-/](?:0[1-9]\|[12]\d\|3[01])\b` |
| Date US | `\b(?:0[1-9]\|1[0-2])[-/](?:0[1-9]\|[12]\d\|3[01])[-/]\d{4}\b` |
