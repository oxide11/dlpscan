# Secrets — Regex Patterns

> Language-agnostic regex patterns for sensitive data detection.
> All patterns use standard regex syntax compatible with PCRE, Python `re`, JavaScript, Go, Java, etc.

---

## Generic Secrets

| Pattern Name | Regex |
|---|---|
| Bearer Token | `[Bb]earer\s+[A-Za-z0-9\-._~+/]+=*` |
| Database Connection String | `(?:mongodb(?:\+srv)?\|mysql\|postgres(?:ql)?\|redis\|mssql)://[^:\s]+:[^@\s]+@[^\s]+`  (flags: `i`)|
| Generic API Key | `(?:api[_-]?key\|apikey\|api[_-]?secret\|api[_-]?token)\s*[=:]\s*["\']?[A-Za-z0-9\-._~+/]{16,}["\']?`  (flags: `i`)|
| Generic Secret Assignment | `(?:password\|passwd\|pwd\|secret\|token\|credential)\s*[=:]\s*["\']?[^\s"\']{8,}["\']?`  (flags: `i`)|
| JWT Token | `\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}` |
| Private Key | `-----BEGIN (?:RSA \|EC \|DSA \|OPENSSH )?PRIVATE KEY-----` |
