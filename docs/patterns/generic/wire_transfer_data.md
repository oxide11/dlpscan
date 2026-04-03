# Patterns: Wire Transfer Data

## Wire Transfer Data

| Pattern Name | Regex |
|---|---|
| Fedwire IMAD | `\b\d{8}[A-Z]{4}[A-Z0-9]{8}\d{6}\b` |
| CHIPS UID | `\b\d{6}[A-Z0-9]{4,10}\b` |
| Wire Reference Number | `\b(?=[A-Z0-9]*[A-Z])(?=[A-Z0-9]*\d)[A-Z0-9]{16,35}\b` |
| ACH Trace Number | `\b(?:0[1-9]\|[12]\d\|3[0-2]\|6[1-9]\|7[0-2])\d{13}\b` |
| ACH Batch Number | `\b\d{7}\b` |
| SEPA Reference | `\b(?=[A-Z0-9]*[A-Z])(?=[A-Z0-9]*\d)[A-Z0-9]{12,35}\b` |
