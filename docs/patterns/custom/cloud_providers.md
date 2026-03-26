# Cloud Providers — Regex Patterns

> Language-agnostic regex patterns for sensitive data detection.
> All patterns use standard regex syntax compatible with PCRE, Python `re`, JavaScript, Go, Java, etc.

---

## Cloud Provider Secrets

| Pattern Name | Regex |
|---|---|
| AWS Access Key | `\bAKIA[0-9A-Z]{16}\b` |
| AWS Secret Key | `(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])` |
| Google API Key | `\bAIza[0-9A-Za-z_\-]{35}\b` |
