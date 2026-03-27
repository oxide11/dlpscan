# Classification Labels — Context Keywords

> Keywords used for proximity-based context detection.
> When a regex pattern match is found, the scanner checks for these keywords
> within a configurable character distance before/after the match to improve accuracy.

---

## RBC Classification

**Proximity distance:** 80 characters

| Pattern Name | Keywords |
|---|---|
| TT_Confidential | `tt_confidential`, `confidential`, `classification`, `label`, `marking` |
| TT_MBI | `tt_mbi`, `mbi`, `material business information`, `classification`, `label` |
| TT_SPI | `tt_spi`, `spi`, `sensitive personal information`, `classification`, `label` |
| CNB_Confidential | `cnb_confidential`, `confidential`, `cnb`, `classification`, `label` |
| Sensitive - Business | `sensitive`, `business`, `classification`, `label`, `marking` |
| Sensitive - Personal | `sensitive`, `personal`, `classification`, `label`, `marking` |
| CNB_Restricted | `cnb_restricted`, `restricted`, `cnb`, `classification`, `label` |
| CNB_Internal | `cnb_internal`, `internal`, `cnb`, `classification`, `label` |
| CNB_Public | `cnb_public`, `public`, `cnb`, `classification`, `label` |
| Public | `public`, `classification`, `label`, `unclassified`, `unrestricted` |

## Corporate Classification

**Proximity distance:** 80 characters

| Pattern Name | Keywords |
|---|---|
| Corporate Confidential | `confidential`, `company`, `corporate`, `business`, `proprietary` |
| Do Not Distribute | `distribute`, `distribution`, `circulation`, `forward`, `share` |
| Embargoed | `embargo`, `embargoed`, `hold until`, `not for release`, `publication date` |
| Eyes Only | `eyes only`, `recipient only`, `personal`, `addressee only` |
| Highly Confidential | `highly confidential`, `sensitive`, `restricted`, `executive only` |
| Internal Only | `internal`, `company`, `employees only`, `staff only`, `not for external` |
| Need to Know | `need to know`, `restricted access`, `limited distribution`, `authorized personnel` |
| Proprietary | `proprietary`, `trade secret`, `intellectual property`, `confidential business` |
| Restricted | `restricted`, `limited distribution`, `access controlled`, `need to know` |

## Data Classification Labels

**Proximity distance:** 100 characters

| Pattern Name | Keywords |
|---|---|
| CUI | `cui`, `controlled unclassified`, `sensitive information`, `marking` |
| Confidential Classification | `classified`, `confidential`, `national security`, `government` |
| FOUO | `official use`, `fouo`, `government`, `not for public release` |
| LES | `law enforcement`, `sensitive`, `les`, `police`, `investigation` |
| NOFORN | `noforn`, `foreign nationals`, `not releasable`, `classification` |
| SBU | `sensitive`, `unclassified`, `sbu`, `government` |
| Secret Classification | `classified`, `secret`, `national security`, `clearance`, `noforn` |
| Top Secret | `classified`, `top secret`, `ts`, `sci`, `national security`, `clearance` |

## Financial Regulatory Labels

**Proximity distance:** 80 characters

| Pattern Name | Keywords |
|---|---|
| Draft Not for Circulation | `draft`, `circulation`, `preliminary`, `not final`, `review only` |
| Information Barrier | `information barrier`, `chinese wall`, `wall crossing`, `restricted side`, `public side` |
| Inside Information | `inside information`, `insider`, `material`, `non-public`, `trading restriction` |
| Investment Restricted | `restricted list`, `watch list`, `grey list`, `restricted securities`, `trading restriction` |
| MNPI | `mnpi`, `material`, `non-public`, `insider`, `trading`, `securities` |
| Market Sensitive | `market sensitive`, `price sensitive`, `stock`, `securities`, `trading` |
| Pre-Decisional | `pre-decisional`, `draft`, `deliberative`, `not final`, `preliminary` |

## Privacy Classification

**Proximity distance:** 80 characters

| Pattern Name | Keywords |
|---|---|
| CCPA/CPRA | `ccpa`, `cpra`, `california consumer`, `california privacy`, `consumer rights` |
| FERPA | `ferpa`, `educational records`, `student records`, `student privacy` |
| GDPR Personal Data | `gdpr`, `personal data`, `data subject`, `data protection`, `eu regulation` |
| GLBA | `glba`, `gramm-leach-bliley`, `financial privacy`, `consumer financial` |
| HIPAA | `hipaa`, `health insurance portability`, `medical privacy`, `health data` |
| NPI | `npi`, `non-public personal`, `financial privacy`, `glba`, `consumer information` |
| PCI-DSS | `pci`, `pci-dss`, `cardholder data`, `payment card`, `card data environment` |
| PHI Label | `phi`, `protected health`, `health information`, `medical records`, `patient data` |
| PII Label | `pii`, `personally identifiable`, `personal information`, `sensitive data` |
| SOX | `sox`, `sarbanes-oxley`, `financial reporting`, `internal controls`, `audit` |

## Privileged Information

**Proximity distance:** 100 characters

| Pattern Name | Keywords |
|---|---|
| Attorney-Client Privilege | `attorney`, `client`, `privilege`, `legal counsel`, `law firm`, `privileged communication` |
| Legal Privilege | `legal`, `privilege`, `attorney`, `counsel`, `protected communication` |
| Litigation Hold | `litigation`, `legal hold`, `preservation`, `hold notice`, `document retention` |
| Privileged Information | `privileged`, `legal`, `attorney`, `counsel`, `protected` |
| Privileged and Confidential | `privileged`, `confidential`, `legal`, `attorney`, `counsel` |
| Protected by Privilege | `privilege`, `protected`, `attorney`, `legal`, `exempt from disclosure` |
| Work Product | `work product`, `attorney`, `litigation`, `legal`, `prepared in anticipation` |

## Supervisory Information

**Proximity distance:** 80 characters

| Pattern Name | Keywords |
|---|---|
| CSI | `confidential supervisory`, `csi`, `examination report`, `regulatory report`, `supervisory letter` |
| Examination Findings | `examination`, `mra`, `mria`, `findings`, `regulatory`, `corrective action`, `consent order` |
| Non-Public Supervisory | `non-public`, `supervisory`, `regulatory`, `examination`, `not for release` |
| Restricted Supervisory | `restricted`, `supervisory`, `regulatory`, `compliance`, `enforcement` |
| Supervisory Confidential | `supervisory`, `confidential`, `regulator`, `examination`, `bank examination` |
| Supervisory Controlled | `supervisory`, `controlled`, `occ`, `fdic`, `federal reserve`, `regulator`, `examination` |
