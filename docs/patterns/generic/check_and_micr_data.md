# Patterns: Check And Micr Data

## Check and MICR Data

| Pattern Name | Regex |
|---|---|
| MICR Line | `[⑈❰]?\d{9}[⑈❰]?\s?\d{6,17}[⑈❰]?\s?\d{4,6}` |
| Check Number | `\b\d{4,6}\b` |
| Cashier Check Number | `\b\d{8,15}\b` |
