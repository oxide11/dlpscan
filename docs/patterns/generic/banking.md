# Banking — Regex Patterns

> Language-agnostic regex patterns for sensitive data detection.
> All patterns use standard regex syntax compatible with PCRE, Python `re`, JavaScript, Go, Java, etc.

---

## Banking Authentication

| Pattern Name | Regex |
|---|---|
| Encryption Key | `\b[0-9A-Fa-f]{32,48}\b` |
| HSM Key | `\b[0-9A-Fa-f]{32,64}\b` |
| PIN | `\b\d{4,6}\b` |
| PIN Block | `\b[0-9A-F]{16}\b` |

## Banking and Financial

| Pattern Name | Regex |
|---|---|
| ABA Routing Number | `\b(?:0[1-9]\|[12]\d\|3[0-2]\|6[1-9]\|7[0-2])\d{7}\b` |
| Canada Transit Number | `\b\d{5}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}\b` |
| IBAN Generic | `\b[A-Z]{2}\d{2}[\s]?[\dA-Z]{4}(?:[\s]?[\dA-Z]{4}){2,7}(?:[\s]?[\dA-Z]{1,4})?\b` |
| SWIFT/BIC | `\b[A-Z]{4}[A-Z]{2}[A-Z2-9][A-NP-Z0-9](?:[A-Z\d]{3})?\b` |
| US Bank Account Number | `\b\d{8,17}\b` |

## Check and MICR Data

| Pattern Name | Regex |
|---|---|
| Cashier Check Number | `\b\d{8,15}\b` |
| Check Number | `\b\d{4,6}\b` |
| MICR Line | `[⑈❰]?\d{9}[⑈❰]?\s?\d{6,17}[⑈❰]?\s?\d{4,6}` |

## Customer Financial Data

| Pattern Name | Regex |
|---|---|
| Account Balance | `(?<!\w)[\$€£¥]\s?\d{1,3}(?:[,.\s]\d{3})*(?:\.\d{2})?\b` |
| Balance with Currency Code | `\b(?:USD\|EUR\|GBP\|JPY\|CAD\|AUD\|CHF)\s?\d{1,3}(?:[,.\s]\d{3})*(?:\.\d{2})?\b` |
| Credit Score | `\b[3-8]\d{2}\b` |
| DTI Ratio | `\b\d{1,2}\.\d{1,2}%\b` |
| Income Amount | `(?<!\w)[\$€£¥]\s?\d{1,3}(?:[,.\s]\d{3})*(?:\.\d{2})?\b` |

## Internal Banking References

| Pattern Name | Regex |
|---|---|
| Branch Code | `\b\d{4,6}\b` |
| Customer ID | `\b\d{6,12}\b` |
| Internal Account Ref | `\b[A-Z]{2,4}\d{8,14}\b` |
| Teller ID | `\b[A-Z]{1,3}\d{4,8}\b` |

## Loan and Mortgage Data

| Pattern Name | Regex |
|---|---|
| LTV Ratio | `\b\d{1,3}\.\d{1,2}%\b` |
| Loan Number | `\b[A-Z0-9]{8,15}\b` |
| MERS MIN | `\b\d{18}\b` |
| Universal Loan Identifier | `\b[A-Z0-9]{23,45}\b` |

## PCI Sensitive Data

| Pattern Name | Regex |
|---|---|
| Cardholder Name Pattern | `\b[A-Z][a-z]+\s[A-Z][a-z]+\b` |
| Dynamic CVV | `\b\d{3}\b` |
| PVKI | `\b\d{1}\b` |
| PVV | `\b\d{4}\b` |
| Service Code | `\b\d{3}\b` |

## Regulatory Identifiers

| Pattern Name | Regex |
|---|---|
| AML Case ID | `\b[A-Z]{2,4}[-]?\d{6,12}\b` |
| CTR Number | `\b\d{14,20}\b` |
| Compliance Case Number | `\b[A-Z]{2,5}[-]?\d{4}[-]?\d{4,8}\b` |
| FinCEN Report Number | `\b\d{14}\b` |
| OFAC SDN Entry | `\b\d{4,6}\b` |
| SAR Filing Number | `\b\d{14,20}\b` |

## Securities Identifiers

| Pattern Name | Regex |
|---|---|
| CUSIP | `\b[0-9A-Z]{6}[0-9A-Z]{2}\d\b` |
| FIGI | `\bBBG[A-Z0-9]{9}\b` |
| ISIN | `\b[A-Z]{2}[0-9A-Z]{9}\d\b` |
| LEI | `\b[A-Z0-9]{4}00[A-Z0-9]{12}\d{2}\b` |
| SEDOL | `\b[0-9BCDFGHJKLMNPQRSTVWXYZ]{6}\d\b` |
| Ticker Symbol | `\b[A-Z]{1,5}\b` |

## Wire Transfer Data

| Pattern Name | Regex |
|---|---|
| ACH Batch Number | `\b\d{7}\b` |
| ACH Trace Number | `\b\d{15}\b` |
| CHIPS UID | `\b\d{6,16}\b` |
| Fedwire IMAD | `\b\d{8}[A-Z]{4}[A-Z0-9]{8}\d{6}\b` |
| SEPA Reference | `\b[A-Z0-9]{12,35}\b` |
| Wire Reference Number | `\b[A-Z0-9]{16,35}\b` |
