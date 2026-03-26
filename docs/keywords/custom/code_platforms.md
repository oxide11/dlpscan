# Code Platforms — Context Keywords

> Keywords used for proximity-based context detection.
> When a regex pattern match is found, the scanner checks for these keywords
> within a configurable character distance before/after the match to improve accuracy.

---

## Code Platform Secrets

**Proximity distance:** 80 characters

| Pattern Name | Keywords |
|---|---|
| GitHub OAuth Token | `github oauth`, `oauth token` |
| GitHub Token (Classic) | `github`, `gh token`, `personal access token` |
| GitHub Token (Fine-Grained) | `github`, `fine-grained`, `pat` |
| NPM Token | `npm`, `node package`, `npm token` |
| PyPI Token | `pypi`, `python package`, `pip` |
