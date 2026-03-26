# Source Code and Secrets Control

Detects secrets, credentials, API keys, tokens, and connection strings that
may be embedded in source code, configuration files, or documentation.
Aligns with SOC 2, ISO 27001, NIST 800-53, and secure development lifecycle
requirements.

## Control Objective

Prevent the exposure of authentication credentials, API keys, private keys,
access tokens, and connection strings in code repositories, logs, chat
messages, and documents. Detect secrets from all major cloud providers,
code platforms, messaging services, and payment processors.

---

## Patterns

### Generic Secrets

| Category | Source |
|----------|--------|
| Bearer Token | [generic_secrets](../patterns/generic/generic_secrets.md) |
| JWT Token | [generic_secrets](../patterns/generic/generic_secrets.md) |
| Private Key | [generic_secrets](../patterns/generic/generic_secrets.md) |
| Generic API Key | [generic_secrets](../patterns/generic/generic_secrets.md) |
| Generic Secret Assignment | [generic_secrets](../patterns/generic/generic_secrets.md) |
| Database Connection String | [generic_secrets](../patterns/generic/generic_secrets.md) |

### URLs with Embedded Credentials

| Category | Source |
|----------|--------|
| URL with Password | [urls_with_credentials](../patterns/generic/urls_with_credentials.md) |
| URL with Token | [urls_with_credentials](../patterns/generic/urls_with_credentials.md) |

### Cloud Provider Secrets

| Category | Source |
|----------|--------|
| AWS Access Key | [cloud_provider_secrets](../patterns/custom/cloud_provider_secrets.md) |
| AWS Secret Key | [cloud_provider_secrets](../patterns/custom/cloud_provider_secrets.md) |
| Google API Key | [cloud_provider_secrets](../patterns/custom/cloud_provider_secrets.md) |

### Code Platform Secrets

| Category | Source |
|----------|--------|
| GitHub Token (Classic) | [code_platform_secrets](../patterns/custom/code_platform_secrets.md) |
| GitHub Token (Fine-Grained) | [code_platform_secrets](../patterns/custom/code_platform_secrets.md) |
| GitHub OAuth Token | [code_platform_secrets](../patterns/custom/code_platform_secrets.md) |
| NPM Token | [code_platform_secrets](../patterns/custom/code_platform_secrets.md) |
| PyPI Token | [code_platform_secrets](../patterns/custom/code_platform_secrets.md) |

### Messaging Service Secrets

| Category | Source |
|----------|--------|
| Slack Bot Token | [messaging_service_secrets](../patterns/custom/messaging_service_secrets.md) |
| Slack User Token | [messaging_service_secrets](../patterns/custom/messaging_service_secrets.md) |
| Slack Webhook | [messaging_service_secrets](../patterns/custom/messaging_service_secrets.md) |
| SendGrid API Key | [messaging_service_secrets](../patterns/custom/messaging_service_secrets.md) |
| Twilio API Key | [messaging_service_secrets](../patterns/custom/messaging_service_secrets.md) |
| Mailgun API Key | [messaging_service_secrets](../patterns/custom/messaging_service_secrets.md) |

### Payment Service Secrets

| Category | Source |
|----------|--------|
| Stripe Secret Key | [payment_service_secrets](../patterns/custom/payment_service_secrets.md) |
| Stripe Publishable Key | [payment_service_secrets](../patterns/custom/payment_service_secrets.md) |

### Authentication Tokens

| Category | Source |
|----------|--------|
| Session ID | [authentication_tokens](../patterns/generic/authentication_tokens.md) |

### Banking Authentication (Infrastructure Secrets)

| Category | Source |
|----------|--------|
| Encryption Key | [banking_authentication](../patterns/generic/banking_authentication.md) |
| HSM Key | [banking_authentication](../patterns/generic/banking_authentication.md) |

---

## Keywords

| Keyword Source | Proximity | Mapped Patterns |
|---------------|-----------|-----------------|
| [generic_secrets](../keywords/generic/generic_secrets.md) | 80 chars | Bearer, JWT, Private Key, API Key, DB Connection |
| [urls_with_credentials](../keywords/generic/urls_with_credentials.md) | 80 chars | URL with Password/Token |
| [cloud_provider_secrets](../keywords/custom/cloud_provider_secrets.md) | 80 chars | AWS, Google keys |
| [code_platform_secrets](../keywords/custom/code_platform_secrets.md) | 80 chars | GitHub, NPM, PyPI tokens |
| [messaging_service_secrets](../keywords/custom/messaging_service_secrets.md) | 80 chars | Slack, SendGrid, Twilio, Mailgun |
| [payment_service_secrets](../keywords/custom/payment_service_secrets.md) | 80 chars | Stripe keys |
| [authentication_tokens](../keywords/generic/authentication_tokens.md) | 50 chars | Session ID |
| [banking_authentication](../keywords/generic/banking_authentication.md) | 50 chars | Encryption Key, HSM Key |

---

## Common Leak Vectors

This baseline is designed to detect secrets in:

| Vector | Example |
|--------|---------|
| **Git commits** | Hardcoded API keys in source code |
| **CI/CD logs** | Secrets printed in build output |
| **Configuration files** | `.env`, `config.yaml`, `docker-compose.yml` |
| **Documentation** | API keys pasted in README or wiki pages |
| **Chat & email** | Credentials shared via Slack, Teams, email |
| **Log files** | Connection strings in application logs |
| **Jupyter notebooks** | Embedded tokens in notebook cells |

## Framework Mapping

| Framework | Controls | Key Patterns |
|-----------|----------|--------------|
| **SOC 2** (CC6.1) | Logical access security | All API keys, tokens, credentials |
| **ISO 27001** (A.9) | Access control | Private keys, connection strings |
| **NIST 800-53** (IA-5) | Authenticator management | All secrets and tokens |
| **CIS Controls** (16) | Application software security | Generic secrets, embedded credentials |
| **OWASP Top 10** (A07) | Authentication failures | Hardcoded secrets, leaked tokens |
