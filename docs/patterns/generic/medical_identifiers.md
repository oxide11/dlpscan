# Patterns: Medical Identifiers

## Medical Identifiers

| Pattern Name | Regex |
|---|---|
| Health Plan ID | `\b[A-Z]{3}\d{9}\b` |
| DEA Number | `\b[A-Z]{2}\d{7}\b` |
| ICD-10 Code | `\b[A-TV-Z]\d{2}(?:\.\d{1,4})?\b` |
| NDC Code | `\b\d{4,5}-\d{3,4}-\d{1,2}\b` |
