# Patterns: Customer Financial Data

## Customer Financial Data

| Pattern Name | Regex |
|---|---|
| Account Balance | `(?<!\w)[\$\u20ac\u00a3\u00a5]\s?\d{1,3}(?:[,.\s]\d{3})*(?:\.\d{2})?\b` |
| Balance with Currency Code | `\b(?:USD\|EUR\|GBP\|JPY\|CAD\|AUD\|CHF)\s?\d{1,3}(?:[,.\s]\d{3})*(?:\.\d{2})?\b` |
| Income Amount | `(?<!\w)[\$\u20ac\u00a3\u00a5]\s?\d{1,3}(?:[,.\s]\d{3})*(?:\.\d{2})?\b` |
| DTI Ratio | `\b\d{1,2}\.\d{1,2}%\b` |
