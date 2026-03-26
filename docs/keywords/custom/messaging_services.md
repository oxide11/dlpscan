# Messaging Services — Context Keywords

> Keywords used for proximity-based context detection.
> When a regex pattern match is found, the scanner checks for these keywords
> within a configurable character distance before/after the match to improve accuracy.

---

## Messaging Service Secrets

**Proximity distance:** 80 characters

| Pattern Name | Keywords |
|---|---|
| Mailgun API Key | `mailgun`, `email` |
| SendGrid API Key | `sendgrid`, `email api` |
| Slack Bot Token | `slack`, `bot token`, `slack bot` |
| Slack User Token | `slack`, `user token`, `slack user` |
| Slack Webhook | `slack`, `webhook`, `incoming webhook` |
| Twilio API Key | `twilio`, `sms`, `messaging` |
