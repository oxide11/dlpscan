# Cryptocurrency — Regex Patterns

> Language-agnostic regex patterns for sensitive data detection.
> All patterns use standard regex syntax compatible with PCRE, Python `re`, JavaScript, Go, Java, etc.

---

## Cryptocurrency

| Pattern Name | Regex |
|---|---|
| Bitcoin Address (Bech32) | `\bbc1[a-zA-HJ-NP-Za-km-z0-9]{25,89}\b` |
| Bitcoin Address (Legacy) | `\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b` |
| Bitcoin Cash Address | `\b(?:bitcoincash:)?[qp][a-z0-9]{41}\b` |
| Ethereum Address | `\b0x[0-9a-fA-F]{40}\b` |
| Litecoin Address | `\b[LM][a-km-zA-HJ-NP-Z1-9]{26,33}\b` |
| Monero Address | `\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b` |
| Ripple Address | `\br[1-9A-HJ-NP-Za-km-z]{24,34}\b` |
