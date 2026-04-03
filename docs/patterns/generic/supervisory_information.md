# Patterns: Supervisory Information

## Supervisory Information

| Pattern Name | Regex |
|---|---|
| Supervisory Controlled | `\b[Ss]upervisory\s+[Cc]ontrolled\s+[Ii]nformation\b` |
| Supervisory Confidential | `\b[Ss]upervisory\s+[Cc]onfidential\b` |
| CSI | `\b(?:[Cc]onfidential\s+[Ss]upervisory\s+[Ii]nformation\|CSI)\b` |
| Non-Public Supervisory | `\b[Nn]on-?[Pp]ublic\s+[Ss]upervisory\s+[Ii]nformation\b` |
| Restricted Supervisory | `\b[Rr]estricted\s+[Ss]upervisory\s+[Ii]nformation\b` |
| Examination Findings | `\b(?:MRA\|MRIA\|[Mm]atter[s]?\s+[Rr]equiring\s+(?:[Ii]mmediate\s+)?[Aa]ttention)\b` |
