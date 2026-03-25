# Middle East — Regex Patterns

> Language-agnostic regex patterns for sensitive data detection.
> All patterns use standard regex syntax compatible with PCRE, Python `re`, JavaScript, Go, Java, etc.

---

## Middle East - Bahrain

| Pattern Name | Regex |
|---|---|
| Bahrain CPR | `\b\d{9}\b` |
| Bahrain Passport | `\b\d{7,9}\b` |

## Middle East - Iran

| Pattern Name | Regex |
|---|---|
| Iran Melli Code | `\b\d{10}\b` |
| Iran Passport | `\b[A-Z]\d{8}\b` |

## Middle East - Iraq

| Pattern Name | Regex |
|---|---|
| Iraq National ID | `\b\d{12}\b` |
| Iraq Passport | `\b[A-HJ-NP-Z0-9]{9}\b` |

## Middle East - Israel

| Pattern Name | Regex |
|---|---|
| Israel Passport | `\b\d{7,8}\b` |
| Israel Teudat Zehut | `\b\d{9}\b` |

## Middle East - Jordan

| Pattern Name | Regex |
|---|---|
| Jordan National ID | `\b\d{10}\b` |
| Jordan Passport | `\b[A-Z]\d{7}\b` |

## Middle East - Kuwait

| Pattern Name | Regex |
|---|---|
| Kuwait Civil ID | `\b[1-3]\d{11}\b` |
| Kuwait Passport | `\b[A-Z]?\d{7,9}\b` |

## Middle East - Lebanon

| Pattern Name | Regex |
|---|---|
| Lebanon ID | `\b\d{7,12}\b` |
| Lebanon Passport | `\b(?:RL\|LR)\d{6,7}\b` |

## Middle East - Qatar

| Pattern Name | Regex |
|---|---|
| Qatar Passport | `\b[A-Z]\d{7}\b` |
| Qatar QID | `\b[23]\d{10}\b` |

## Middle East - Saudi Arabia

| Pattern Name | Regex |
|---|---|
| Saudi Arabia National ID | `\b[12]\d{9}\b` |
| Saudi Arabia Passport | `\b[A-Z]\d{7,8}\b` |

## Middle East - UAE

| Pattern Name | Regex |
|---|---|
| UAE Emirates ID | `\b784[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{7}[-.\s/\\_\u2013\u2014\u00a0]?\d\b` |
| UAE Passport | `\b[A-Z]?\d{7,9}\b` |
| UAE Visa Number | `\b[1-7]01/?(?:19\|20)\d{2}/?\d{7}\b` |
