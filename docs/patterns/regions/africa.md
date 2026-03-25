# Africa — Regex Patterns

> Language-agnostic regex patterns for sensitive data detection.
> All patterns use standard regex syntax compatible with PCRE, Python `re`, JavaScript, Go, Java, etc.

---

## Africa - Egypt

| Pattern Name | Regex |
|---|---|
| Egypt National ID | `\b[23]\d{13}\b` |
| Egypt Passport | `\b[A-Z]?\d{7,8}\b` |
| Egypt Tax ID | `\b\d{3}-?\d{3}-?\d{3}\b` |

## Africa - Ethiopia

| Pattern Name | Regex |
|---|---|
| Ethiopia National ID | `\b\d{12}\b` |
| Ethiopia Passport | `\b[A-Z]{2}\d{7}\b` |
| Ethiopia TIN | `\b\d{10}\b` |

## Africa - Ghana

| Pattern Name | Regex |
|---|---|
| Ghana Card | `\b(?:GHA\|[A-Z]{3})-\d{9}-\d\b` |
| Ghana NHIS | `\b(?:GHA\|[A-Z]{3})-\d{9}-\d\b` |
| Ghana Passport | `\b[A-Z]\d{7}\b` |
| Ghana TIN | `\b[CGQV]\d{10}\b` |

## Africa - Kenya

| Pattern Name | Regex |
|---|---|
| Kenya KRA PIN | `\b[A-Z]\d{9}[A-Z]\b` |
| Kenya NHIF | `\b\d{6,9}\b` |
| Kenya National ID | `\b\d{7,8}\b` |
| Kenya Passport | `\b[A-Z]\d{7,8}\b` |

## Africa - Morocco

| Pattern Name | Regex |
|---|---|
| Morocco CIN | `\b[A-Z]{1,2}\d{5,6}\b` |
| Morocco Passport | `\b[A-Z]{2}\d{7}\b` |
| Morocco Tax ID | `\b\d{8}\b` |

## Africa - Nigeria

| Pattern Name | Regex |
|---|---|
| Nigeria BVN | `\b\d{11}\b` |
| Nigeria Driver Licence | `\b[A-Z]{3}\d{5,9}[A-Z]{0,2}\d{0,2}\b` |
| Nigeria NIN | `\b\d{11}\b` |
| Nigeria Passport | `\b[A-Z]\d{8}\b` |
| Nigeria TIN | `\b\d{12,13}\b` |
| Nigeria Voter Card | `\b[0-9A-Z]{19}\b` |

## Africa - South Africa

| Pattern Name | Regex |
|---|---|
| South Africa DL | `\b\d{10}[A-Z]{2}\b` |
| South Africa ID | `\b\d{13}\b` |
| South Africa Passport | `\b[A-Z]?\d{8,9}\b` |

## Africa - Tanzania

| Pattern Name | Regex |
|---|---|
| Tanzania NIDA | `\b\d{20}\b` |
| Tanzania Passport | `\b[A-Z]{2}\d{7}\b` |
| Tanzania TIN | `\b\d{9}\b` |

## Africa - Tunisia

| Pattern Name | Regex |
|---|---|
| Tunisia CIN | `\b\d{8}\b` |
| Tunisia Passport | `\b[A-Z]\d{6}\b` |

## Africa - Uganda

| Pattern Name | Regex |
|---|---|
| Uganda NIN | `\bC[MF]\d{8}[A-Z0-9]{4}\b` |
| Uganda Passport | `\b[A-Z]\d{7,8}\b` |
