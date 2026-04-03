# Patterns: Corporate Classification

## Corporate Classification

| Pattern Name | Regex |
|---|---|
| Internal Only | `\b[Ii]nternal\s+(?:[Uu]se\s+)?[Oo]nly\b` |
| Restricted | `\b(?:RESTRICTED\|[Rr]estricted\s+[Dd]ata\|[Rr]estricted\s+[Ii]nformation)\b` |
| Corporate Confidential | `\b(?:[Cc]ompany\s+[Cc]onfidential\|[Cc]orporate\s+[Cc]onfidential\|[Ss]trictly\s+[Cc]onfidential)\b` |
| Highly Confidential | `\b[Hh]ighly\s+[Cc]onfidential\b` |
| Do Not Distribute | `\b(?:[Nn]ot\s+[Ff]or\s+[Dd]istribution\|[Dd]o\s+[Nn]ot\s+[Dd]istribute\|[Nn]o\s+[Dd]istribution)\b` |
| Need to Know | `\b[Nn]eed\s+[Tt]o\s+[Kk]now(?:\s+[Bb]asis)?\b` |
| Eyes Only | `\b[Ee]yes\s+[Oo]nly\b` |
| Proprietary | `\b(?:[Pp]roprietary\s+(?:[Ii]nformation\|[Dd]ata\|[Mm]aterial)\|[Tt]rade\s+[Ss]ecret)\b` |
| Embargoed | `\b[Ee]mbargoed?\s+(?:[Ii]nformation\|[Dd]ata\|[Uu]ntil\|[Mm]aterial)\b` |
