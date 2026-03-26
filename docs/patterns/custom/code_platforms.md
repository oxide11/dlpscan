# Code Platforms — Regex Patterns

> Language-agnostic regex patterns for sensitive data detection.
> All patterns use standard regex syntax compatible with PCRE, Python `re`, JavaScript, Go, Java, etc.

---

## Code Platform Secrets

| Pattern Name | Regex |
|---|---|
| GitHub OAuth Token | `\bgho_[A-Za-z0-9]{36}\b` |
| GitHub Token (Classic) | `\bghp_[A-Za-z0-9]{36}\b` |
| GitHub Token (Fine-Grained) | `\bgithub_pat_[A-Za-z0-9_]{22,82}\b` |
| NPM Token | `\bnpm_[A-Za-z0-9]{36}\b` |
| PyPI Token | `\bpypi-[A-Za-z0-9_\-]{16,}\b` |
