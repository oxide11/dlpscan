# Classification Labels — Regex Patterns

> Language-agnostic regex patterns for sensitive data detection.
> All patterns use standard regex syntax compatible with PCRE, Python `re`, JavaScript, Go, Java, etc.

---

## RBC Classification

| Pattern Name | Regex |
|---|---|
| TT_Confidential | `\bTT_Confidential\b` |
| TT_MBI | `\bTT_MBI\b` |
| TT_SPI | `\bTT_SPI\b` |
| CNB_Confidential | `\bCNB_Confidential\b` |
| Sensitive - Business | `\bSensitive\s*[-–—]\s*Business\b` |
| Sensitive - Personal | `\bSensitive\s*[-–—]\s*Personal\b` |
| CNB_Restricted | `\bCNB_Restricted\b` |
| CNB_Internal | `\bCNB_Internal\b` |
| CNB_Public | `\bCNB_Public\b` |
| Public | `\bPublic\b` |

## Corporate Classification

| Pattern Name | Regex |
|---|---|
| Corporate Confidential | `\b(?:[Cc]ompany\s+[Cc]onfidential\|[Cc]orporate\s+[Cc]onfidential\|[Ss]trictly\s+[Cc]onfidential)\b` |
| Do Not Distribute | `\b(?:[Nn]ot\s+[Ff]or\s+[Dd]istribution\|[Dd]o\s+[Nn]ot\s+[Dd]istribute\|[Nn]o\s+[Dd]istribution)\b` |
| Embargoed | `\b[Ee]mbargoed?\s+(?:[Ii]nformation\|[Dd]ata\|[Uu]ntil\|[Mm]aterial)\b` |
| Eyes Only | `\b[Ee]yes\s+[Oo]nly\b` |
| Highly Confidential | `\b[Hh]ighly\s+[Cc]onfidential\b` |
| Internal Only | `\b[Ii]nternal\s+(?:[Uu]se\s+)?[Oo]nly\b` |
| Need to Know | `\b[Nn]eed\s+[Tt]o\s+[Kk]now(?:\s+[Bb]asis)?\b` |
| Proprietary | `\b(?:[Pp]roprietary\s+(?:[Ii]nformation\|[Dd]ata\|[Mm]aterial)\|[Tt]rade\s+[Ss]ecret)\b` |
| Restricted | `\b(?:RESTRICTED\|[Rr]estricted\s+[Dd]ata\|[Rr]estricted\s+[Ii]nformation)\b` |

## Data Classification Labels

| Pattern Name | Regex |
|---|---|
| CUI | `\b(?:CUI\|[Cc]ontrolled\s+[Uu]nclassified\s+[Ii]nformation)\b` |
| Confidential Classification | `\bCLASSIFIED\s+CONFIDENTIAL\b` |
| FOUO | `\b(?:FOUO\|[Ff]or\s+[Oo]fficial\s+[Uu]se\s+[Oo]nly)\b` |
| LES | `\b(?:LES\|[Ll]aw\s+[Ee]nforcement\s+[Ss]ensitive)\b` |
| NOFORN | `\bNOFORN\b` |
| SBU | `\b(?:SBU\|[Ss]ensitive\s+[Bb]ut\s+[Uu]nclassified)\b` |
| Secret Classification | `\b(?:SECRET(?://NOFORN)?\|CLASSIFIED\s+SECRET)\b` |
| Top Secret | `\b(?:TOP\s+SECRET\|TS//SCI\|TS//SI)\b` |

## Financial Regulatory Labels

| Pattern Name | Regex |
|---|---|
| Draft Not for Circulation | `\b[Dd]raft\s*[-–—]\s*[Nn]ot\s+[Ff]or\s+[Cc]irculation\b` |
| Information Barrier | `\b(?:[Ii]nformation\s+[Bb]arrier\|[Cc]hinese\s+[Ww]all)\b` |
| Inside Information | `\b[Ii]nside(?:r)?\s+[Ii]nformation\b` |
| Investment Restricted | `\b[Rr]estricted\s+[Ll]ist\b` |
| MNPI | `\b(?:MNPI\|[Mm]aterial\s+[Nn]on-?[Pp]ublic\s+[Ii]nformation)\b` |
| Market Sensitive | `\b[Mm]arket\s+[Ss]ensitive\b` |
| Pre-Decisional | `\b[Pp]re-?[Dd]ecisional\b` |

## Privacy Classification

| Pattern Name | Regex |
|---|---|
| CCPA/CPRA | `\b(?:CCPA\|CPRA\|[Cc]alifornia\s+[Cc]onsumer\s+[Pp]rivacy)\b` |
| FERPA | `\b(?:FERPA\|[Ff]amily\s+[Ee]ducational\s+[Rr]ights)\b` |
| GDPR Personal Data | `\b(?:GDPR\|[Pp]ersonal\s+[Dd]ata\s+(?:under\|per\|pursuant))\b` |
| GLBA | `\b(?:GLBA\|[Gg]ramm[-\s][Ll]each[-\s][Bb]liley)\b` |
| HIPAA | `\bHIPAA\b` |
| NPI | `\b(?:NPI\|[Nn]on-?[Pp]ublic\s+[Pp]ersonal\s+[Ii]nformation)\b` |
| PCI-DSS | `\b(?:PCI[-\s]?DSS\|[Cc]ardholder\s+[Dd]ata\s+[Ee]nvironment\|CDE)\b` |
| PHI Label | `\b(?:PHI\|[Pp]rotected\s+[Hh]ealth\s+[Ii]nformation)\b` |
| PII Label | `\b(?:PII\|[Pp]ersonally\s+[Ii]dentifiable\s+[Ii]nformation)\b` |
| SOX | `\b(?:SOX\|[Ss]arbanes[-\s][Oo]xley)\b` |

## Privileged Information

| Pattern Name | Regex |
|---|---|
| Attorney-Client Privilege | `\b[Aa]ttorney[-\s][Cc]lient\s+[Pp]rivileged?\b` |
| Legal Privilege | `\b[Ll]egal(?:ly)?\s+[Pp]rivileged\b` |
| Litigation Hold | `\b(?:[Ll]itigation\|[Ll]egal)\s+[Hh]old\b` |
| Privileged Information | `\b[Pp]rivileged\s+[Ii]nformation\b` |
| Privileged and Confidential | `\b[Pp]rivileged\s+(?:and\|&)\s+[Cc]onfidential\b` |
| Protected by Privilege | `\b[Pp]rotected\s+(?:by\|under)\s+[Pp]rivilege\b` |
| Work Product | `\b[Ww]ork\s+[Pp]roduct(?:\s+[Dd]octrine)?\b` |

## Supervisory Information

| Pattern Name | Regex |
|---|---|
| CSI | `\b(?:[Cc]onfidential\s+[Ss]upervisory\s+[Ii]nformation\|CSI)\b` |
| Examination Findings | `\b(?:MRA\|MRIA\|[Mm]atter[s]?\s+[Rr]equiring\s+(?:[Ii]mmediate\s+)?[Aa]ttention)\b` |
| Non-Public Supervisory | `\b[Nn]on-?[Pp]ublic\s+[Ss]upervisory\s+[Ii]nformation\b` |
| Restricted Supervisory | `\b[Rr]estricted\s+[Ss]upervisory\s+[Ii]nformation\b` |
| Supervisory Confidential | `\b[Ss]upervisory\s+[Cc]onfidential\b` |
| Supervisory Controlled | `\b[Ss]upervisory\s+[Cc]ontrolled\s+[Ii]nformation\b` |
