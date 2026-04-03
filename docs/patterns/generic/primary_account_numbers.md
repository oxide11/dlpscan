# Patterns: Primary Account Numbers

## Primary Account Numbers

| Pattern Name | Regex |
|---|---|
| PAN | `\b\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{1,7}\b` |
| Masked PAN | `\b\d{4}[-.\s/\\_\u2013\u2014\u00a0]?[Xx*]{4}[-.\s/\\_\u2013\u2014\u00a0]?[Xx*]{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}\b` |
