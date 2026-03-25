# Urls — Context Keywords

> Keywords used for proximity-based context detection.
> When a regex pattern match is found, the scanner checks for these keywords
> within a configurable character distance before/after the match to improve accuracy.

---

## URLs with Credentials

**Proximity distance:** 80 characters

| Pattern Name | Keywords |
|---|---|
| URL with Password | `url`, `link`, `endpoint`, `connection`, `connect` |
| URL with Token | `url`, `link`, `endpoint`, `api`, `callback` |
