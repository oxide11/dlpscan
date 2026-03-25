# Messaging Services — Regex Patterns

> Language-agnostic regex patterns for sensitive data detection.
> All patterns use standard regex syntax compatible with PCRE, Python `re`, JavaScript, Go, Java, etc.

---

## Messaging Service Secrets

| Pattern Name | Regex |
|---|---|
| Mailgun API Key | `\bkey-[0-9a-zA-Z]{32}\b` |
| SendGrid API Key | `\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b` |
| Slack Bot Token | `\bxoxb-[0-9A-Za-z\-]+\b` |
| Slack User Token | `\bxoxp-[0-9A-Za-z\-]+\b` |
| Slack Webhook | `https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+` |
| Twilio API Key | `\bSK[0-9a-f]{32}\b` |
