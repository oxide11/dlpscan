# Credit Cards — Regex Patterns

> Language-agnostic regex patterns for sensitive data detection.
> All patterns use standard regex syntax compatible with PCRE, Python `re`, JavaScript, Go, Java, etc.

---

## Card Expiration Dates

| Pattern Name | Regex |
|---|---|
| Card Expiry | `\b(?:0[1-9]\|1[0-2])\s?/\s?(?:\d{2}\|\d{4})\b` |

## Card Track Data

| Pattern Name | Regex |
|---|---|
| Track 1 Data | `%B\d{13,19}\^[A-Z\s/]+\^\d{4}\d*` |
| Track 2 Data | `;\d{13,19}=\d{4}\d*\?` |

## Credit Card Numbers

| Pattern Name | Regex |
|---|---|
| Amex | `\b3[47]\d{2}[-.\s/\\_\u2013\u2014\u00a0]?\d{6}[-.\s/\\_\u2013\u2014\u00a0]?\d{5}\b` |
| Diners Club | `\b3(?:0[0-5]\|[68]\d)\d[-.\s/\\_\u2013\u2014\u00a0]?\d{6}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}\b` |
| Discover | `\b6(?:011\|5\d{2}\|4[4-9]\d)[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}\b` |
| JCB | `\b35(?:2[89]\|[3-8]\d)[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}\b` |
| MasterCard | `\b(?:5[1-5]\d{2}\|2(?:2[2-9]\d\|2[3-9]\d\|[3-6]\d{2}\|7[01]\d\|720))[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}\b` |
| UnionPay | `\b62\d{2}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}(?:[-.\s/\\_\u2013\u2014\u00a0]?\d{1,3})?\b` |
| Visa | `\b4\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}\b` |

## Credit Card Security Codes

| Pattern Name | Regex |
|---|---|
| Amex CID | `\b\d{4}\b` |
| CVV/CVC/CCV | `\b\d{3}\b` |

## Primary Account Numbers

| Pattern Name | Regex |
|---|---|
| BIN/IIN | `\b\d{6,8}\b` |
| Masked PAN | `\b\d{4}[-.\s/\\_\u2013\u2014\u00a0]?[Xx*]{4}[-.\s/\\_\u2013\u2014\u00a0]?[Xx*]{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}\b` |
| PAN | `\b\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{1,7}\b` |
