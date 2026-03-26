# Patterns: Data Classification Labels

## Data Classification Labels

| Pattern Name | Regex |
|---|---|
| Top Secret | `\b(?:TOP\s+SECRET\|TS//SCI\|TS//SI)\b` |
| Secret Classification | `\b(?:SECRET(?://NOFORN)?\|CLASSIFIED\s+SECRET)\b` |
| Confidential Classification | `\bCLASSIFIED\s+CONFIDENTIAL\b` |
| FOUO | `\b(?:FOUO\|[Ff]or\s+[Oo]fficial\s+[Uu]se\s+[Oo]nly)\b` |
| CUI | `\b(?:CUI\|[Cc]ontrolled\s+[Uu]nclassified\s+[Ii]nformation)\b` |
| SBU | `\b(?:SBU\|[Ss]ensitive\s+[Bb]ut\s+[Uu]nclassified)\b` |
| LES | `\b(?:LES\|[Ll]aw\s+[Ee]nforcement\s+[Ss]ensitive)\b` |
| NOFORN | `\bNOFORN\b` |
