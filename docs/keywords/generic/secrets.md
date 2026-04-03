# Secrets — Context Keywords

> Keywords used for proximity-based context detection.
> When a regex pattern match is found, the scanner checks for these keywords
> within a configurable character distance before/after the match to improve accuracy.

---

## Generic Secrets

**Proximity distance:** 80 characters

| Pattern Name | Keywords |
|---|---|
| Bearer Token | `authorization`, `bearer`, `auth token` |
| Database Connection String | `database`, `db connection`, `connection string`, `mongodb`, `postgres`, `mysql`, `redis` |
| Generic API Key | `api key`, `api_key`, `apikey`, `api secret` |
| Generic Secret Assignment | `password`, `secret`, `credential`, `passwd` |
| JWT Token | `jwt`, `json web token`, `auth`, `token` |
| Private Key | `private key`, `rsa`, `ssh key`, `pem` |
