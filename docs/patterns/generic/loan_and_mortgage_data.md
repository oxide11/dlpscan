# Patterns: Loan And Mortgage Data

## Loan and Mortgage Data

| Pattern Name | Regex |
|---|---|
| Loan Number | `\b(?=[A-Z0-9]*[A-Z])(?=[A-Z0-9]*\d)[A-Z0-9]{8,15}\b` |
| MERS MIN | `\b\d{18}\b` |
| Universal Loan Identifier | `\b[A-Z0-9]{4}00[A-Z0-9]{17,39}\b` |
| LTV Ratio | `\b\d{1,3}\.\d{1,2}%\b` |
