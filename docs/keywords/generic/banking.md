# Banking — Context Keywords

> Keywords used for proximity-based context detection.
> When a regex pattern match is found, the scanner checks for these keywords
> within a configurable character distance before/after the match to improve accuracy.

---

## Banking and Financial

**Proximity distance:** 50 characters

| Pattern Name | Keywords |
|---|---|
| IBAN Generic | `iban`, `international bank account number` |
| SWIFT/BIC | `swift`, `bic`, `bank identifier code`, `swift code` |
