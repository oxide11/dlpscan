# Urls — Regex Patterns

> Language-agnostic regex patterns for sensitive data detection.
> All patterns use standard regex syntax compatible with PCRE, Python `re`, JavaScript, Go, Java, etc.

---

## URLs with Credentials

| Pattern Name | Regex |
|---|---|
| URL with Password | `https?://[^:\s]+:[^@\s]+@[^\s]+` |
| URL with Token | `https?://[^\s]*[?&](?:token\|key\|api_key\|apikey\|access_token\|secret\|password\|passwd\|pwd)=[^\s&]+`  (flags: `i`)|
