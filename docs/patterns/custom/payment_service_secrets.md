# Patterns: Payment Service Secrets

## Payment Service Secrets

| Pattern Name | Regex |
|---|---|
| Stripe Secret Key | `\bsk_(?:live\|test)_[A-Za-z0-9]{24,}\b` |
| Stripe Publishable Key | `\bpk_(?:live\|test)_[A-Za-z0-9]{24,}\b` |
