# Cloud Providers — Context Keywords

> Keywords used for proximity-based context detection.
> When a regex pattern match is found, the scanner checks for these keywords
> within a configurable character distance before/after the match to improve accuracy.

---

## Cloud Provider Secrets

**Proximity distance:** 80 characters

| Pattern Name | Keywords |
|---|---|
| AWS Access Key | `aws`, `amazon`, `access key`, `aws key` |
| AWS Secret Key | `aws secret`, `secret access key`, `aws_secret` |
| Google API Key | `google`, `gcp`, `google api`, `google cloud` |
