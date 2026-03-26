# Patterns: Privacy Classification

## Privacy Classification

| Pattern Name | Regex |
|---|---|
| PII Label | `\b(?:PII\|[Pp]ersonally\s+[Ii]dentifiable\s+[Ii]nformation)\b` |
| PHI Label | `\b(?:PHI\|[Pp]rotected\s+[Hh]ealth\s+[Ii]nformation)\b` |
| HIPAA | `\bHIPAA\b` |
| GDPR Personal Data | `\b(?:GDPR\|[Pp]ersonal\s+[Dd]ata\s+(?:under\|per\|pursuant))\b` |
| PCI-DSS | `\b(?:PCI[-\s]?DSS\|[Cc]ardholder\s+[Dd]ata\s+[Ee]nvironment\|CDE)\b` |
| FERPA | `\b(?:FERPA\|[Ff]amily\s+[Ee]ducational\s+[Rr]ights)\b` |
| GLBA | `\b(?:GLBA\|[Gg]ramm[-\s][Ll]each[-\s][Bb]liley)\b` |
| CCPA/CPRA | `\b(?:CCPA\|CPRA\|[Cc]alifornia\s+[Cc]onsumer\s+[Pp]rivacy)\b` |
| SOX | `\b(?:SOX\|[Ss]arbanes[-\s][Oo]xley)\b` |
| NPI | `\b(?:NPI\|[Nn]on-?[Pp]ublic\s+[Pp]ersonal\s+[Ii]nformation)\b` |
