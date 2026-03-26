# Confidential Documents Policy

Detects classification labels, privilege markings, and sensitivity markers
that indicate a document is confidential, restricted, or subject to special
handling requirements. Covers RBC classification labels, legal privilege
designations, and confidential supervisory information.

## Control Objective

Prevent the unauthorized distribution of documents bearing confidentiality
markings, legal privilege designations, or supervisory classification labels.
Enforce document handling policies by detecting content that has been
explicitly marked as restricted.

---

## Patterns & Keywords

### RBC Classification Labels

| Pattern Name | Regex | Keywords (proximity: 80 chars) |
|---|---|---|
| TT_Confidential | `\bTT_Confidential\b` | `confidential`, `classification`, `label`, `sensitive`, `restricted` |
| TT_MBI | `\bTT_MBI\b` | `mbi`, `material business information`, `classification`, `sensitive` |
| TT_SPI | `\bTT_SPI\b` | `spi`, `sensitive personal information`, `classification`, `personal` |
| CNB_Confidential | `\bCNB_Confidential\b` | `confidential`, `cnb`, `classification`, `restricted`, `sensitive` |
| Sensitive - Business | `\b[Ss]ensitive\s*[-–—]\s*[Bb]usiness\b` | `sensitive`, `business`, `classification`, `restricted`, `internal` |
| Sensitive - Personal | `\b[Ss]ensitive\s*[-–—]\s*[Pp]ersonal\b` | `sensitive`, `personal`, `classification`, `pii`, `privacy` |
| CNB_Restricted | `\bCNB_Restricted\b` | `restricted`, `cnb`, `classification`, `limited distribution`, `need to know` |
| CNB_Internal | `\bCNB_Internal\b` | `internal`, `cnb`, `classification`, `employees only`, `not for external` |
| CNB_Public | `\bCNB_Public\b` | `public`, `cnb`, `classification`, `unrestricted` |
| Public | `\b[Pp]ublic\b` | `public`, `unrestricted`, `open`, `classification` |

### Legal Privilege Markings

| Pattern Name | Regex | Keywords (proximity: 100 chars) |
|---|---|---|
| Attorney-Client Privilege | `\b[Aa]ttorney[-\s][Cc]lient\s+[Pp]rivileged?\b` | `attorney`, `client`, `privilege`, `legal counsel`, `law firm`, `privileged communication` |
| Privileged and Confidential | `\b[Pp]rivileged\s+(?:and\|&)\s+[Cc]onfidential\b` | `privileged`, `confidential`, `legal`, `attorney`, `counsel` |
| Work Product | `\b[Ww]ork\s+[Pp]roduct(?:\s+[Dd]octrine)?\b` | `work product`, `attorney`, `litigation`, `legal`, `prepared in anticipation` |
| Privileged Information | `\b[Pp]rivileged\s+[Ii]nformation\b` | `privileged`, `legal`, `attorney`, `counsel`, `protected` |
| Legal Privilege | `\b[Ll]egal(?:ly)?\s+[Pp]rivileged\b` | `legal`, `privilege`, `attorney`, `counsel`, `protected communication` |
| Litigation Hold | `\b(?:[Ll]itigation\|[Ll]egal)\s+[Hh]old\b` | `litigation`, `legal hold`, `preservation`, `hold notice`, `document retention` |
| Protected by Privilege | `\b[Pp]rotected\s+(?:by\|under)\s+[Pp]rivilege\b` | `privilege`, `protected`, `attorney`, `legal`, `exempt from disclosure` |

### Supervisory Information

| Pattern Name | Regex | Keywords (proximity: 80 chars) |
|---|---|---|
| Supervisory Controlled | `\b[Ss]upervisory\s+[Cc]ontrolled\s+[Ii]nformation\b` | `supervisory`, `controlled`, `occ`, `fdic`, `federal reserve`, `regulator`, `examination` |
| Supervisory Confidential | `\b[Ss]upervisory\s+[Cc]onfidential\b` | `supervisory`, `confidential`, `regulator`, `examination`, `bank examination` |
| CSI | `\b(?:[Cc]onfidential\s+[Ss]upervisory\s+[Ii]nformation\|CSI)\b` | `confidential supervisory`, `csi`, `examination report`, `regulatory report`, `supervisory letter` |
| Non-Public Supervisory | `\b[Nn]on-?[Pp]ublic\s+[Ss]upervisory\s+[Ii]nformation\b` | `non-public`, `supervisory`, `regulatory`, `examination`, `not for release` |
| Restricted Supervisory | `\b[Rr]estricted\s+[Ss]upervisory\s+[Ii]nformation\b` | `restricted`, `supervisory`, `regulatory`, `compliance`, `enforcement` |
| Examination Findings | `\b(?:MRA\|MRIA\|[Mm]atter[s]?\s+[Rr]equiring\s+(?:[Ii]mmediate\s+)?[Aa]ttention)\b` | `examination`, `mra`, `mria`, `findings`, `regulatory`, `corrective action`, `consent order` |

---

## Classification Tier Mapping

| Tier | Labels | Typical Handling |
|------|--------|-----------------|
| **Public** | CNB_Public, Public | No restrictions |
| **Internal** | CNB_Internal | Employees only |
| **Sensitive** | Sensitive - Business, Sensitive - Personal | Need-to-know, role-based access |
| **Confidential** | TT_Confidential, CNB_Confidential | Encrypted storage, audit trail |
| **Restricted** | CNB_Restricted, TT_MBI, TT_SPI | Strict access control, no external sharing |
| **Legally Protected** | Attorney-Client Privilege, Work Product, Litigation Hold | Legal department control, no external sharing |
| **Supervisory** | CSI, Supervisory Controlled | Information barriers, regulatory compliance |

## Use Cases

- **Email DLP** -- Block outbound emails containing privileged or classified markings
- **File share scanning** -- Flag documents with classification labels in shared drives
- **Chat monitoring** -- Detect confidential document content shared via messaging
- **CI/CD pipeline** -- Prevent classified content from entering code repositories
- **Print monitoring** -- Detect classified content being sent to print queues
