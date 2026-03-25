# Payment Services — Regex Patterns

> Language-agnostic regex patterns for sensitive data detection.
> All patterns use standard regex syntax compatible with PCRE, Python `re`, JavaScript, Go, Java, etc.

---

## Payment Service Secrets

| Pattern Name | Regex |
|---|---|
| Stripe Publishable Key | `\bpk_(?:live\|test)_[A-Za-z0-9]{24,}\b` |
| Stripe Secret Key | `\bsk_(?:live\|test)_[A-Za-z0-9]{24,}\b` |
