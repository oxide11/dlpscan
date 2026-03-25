# Payment Services — Context Keywords

> Keywords used for proximity-based context detection.
> When a regex pattern match is found, the scanner checks for these keywords
> within a configurable character distance before/after the match to improve accuracy.

---

## Payment Service Secrets

**Proximity distance:** 80 characters

| Pattern Name | Keywords |
|---|---|
| Stripe Publishable Key | `stripe`, `publishable`, `stripe key` |
| Stripe Secret Key | `stripe`, `payment`, `stripe secret` |
