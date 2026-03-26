# Confidential Documents Policy

Detects classification labels, privilege markings, regulatory designations,
and sensitivity markers that indicate a document is confidential, restricted,
or subject to special handling requirements. Covers corporate, government,
financial, legal, and privacy classification schemes.

## Control Objective

Prevent the unauthorized distribution of documents bearing confidentiality
markings, legal privilege designations, regulatory classification labels,
or privacy sensitivity indicators. Enforce document handling policies by
detecting content that has been explicitly marked as restricted.

---

## Patterns

### Corporate Classification

| Category | Source |
|----------|--------|
| Internal Only | [corporate_classification](../patterns/generic/corporate_classification.md) |
| Restricted | [corporate_classification](../patterns/generic/corporate_classification.md) |
| Corporate Confidential | [corporate_classification](../patterns/generic/corporate_classification.md) |
| Highly Confidential | [corporate_classification](../patterns/generic/corporate_classification.md) |
| Do Not Distribute | [corporate_classification](../patterns/generic/corporate_classification.md) |
| Need to Know | [corporate_classification](../patterns/generic/corporate_classification.md) |
| Eyes Only | [corporate_classification](../patterns/generic/corporate_classification.md) |
| Proprietary | [corporate_classification](../patterns/generic/corporate_classification.md) |
| Embargoed | [corporate_classification](../patterns/generic/corporate_classification.md) |

### Government & Data Classification Labels

| Category | Source |
|----------|--------|
| Top Secret | [data_classification_labels](../patterns/generic/data_classification_labels.md) |
| Secret Classification | [data_classification_labels](../patterns/generic/data_classification_labels.md) |
| Confidential Classification | [data_classification_labels](../patterns/generic/data_classification_labels.md) |
| FOUO (For Official Use Only) | [data_classification_labels](../patterns/generic/data_classification_labels.md) |
| CUI (Controlled Unclassified Info) | [data_classification_labels](../patterns/generic/data_classification_labels.md) |
| SBU (Sensitive But Unclassified) | [data_classification_labels](../patterns/generic/data_classification_labels.md) |
| LES (Law Enforcement Sensitive) | [data_classification_labels](../patterns/generic/data_classification_labels.md) |
| NOFORN | [data_classification_labels](../patterns/generic/data_classification_labels.md) |

### Privacy & Regulatory Classification

| Category | Source |
|----------|--------|
| PII Label | [privacy_classification](../patterns/generic/privacy_classification.md) |
| PHI Label | [privacy_classification](../patterns/generic/privacy_classification.md) |
| HIPAA | [privacy_classification](../patterns/generic/privacy_classification.md) |
| GDPR Personal Data | [privacy_classification](../patterns/generic/privacy_classification.md) |
| PCI-DSS | [privacy_classification](../patterns/generic/privacy_classification.md) |
| FERPA | [privacy_classification](../patterns/generic/privacy_classification.md) |
| GLBA | [privacy_classification](../patterns/generic/privacy_classification.md) |
| CCPA/CPRA | [privacy_classification](../patterns/generic/privacy_classification.md) |
| SOX | [privacy_classification](../patterns/generic/privacy_classification.md) |
| NPI | [privacy_classification](../patterns/generic/privacy_classification.md) |

### Legal Privilege Markings

| Category | Source |
|----------|--------|
| Attorney-Client Privilege | [privileged_information](../patterns/generic/privileged_information.md) |
| Privileged and Confidential | [privileged_information](../patterns/generic/privileged_information.md) |
| Work Product | [privileged_information](../patterns/generic/privileged_information.md) |
| Privileged Information | [privileged_information](../patterns/generic/privileged_information.md) |
| Legal Privilege | [privileged_information](../patterns/generic/privileged_information.md) |
| Litigation Hold | [privileged_information](../patterns/generic/privileged_information.md) |
| Protected by Privilege | [privileged_information](../patterns/generic/privileged_information.md) |

### Financial Regulatory Labels

| Category | Source |
|----------|--------|
| MNPI | [financial_regulatory_labels](../patterns/generic/financial_regulatory_labels.md) |
| Inside Information | [financial_regulatory_labels](../patterns/generic/financial_regulatory_labels.md) |
| Pre-Decisional | [financial_regulatory_labels](../patterns/generic/financial_regulatory_labels.md) |
| Draft Not for Circulation | [financial_regulatory_labels](../patterns/generic/financial_regulatory_labels.md) |
| Market Sensitive | [financial_regulatory_labels](../patterns/generic/financial_regulatory_labels.md) |
| Information Barrier | [financial_regulatory_labels](../patterns/generic/financial_regulatory_labels.md) |
| Investment Restricted | [financial_regulatory_labels](../patterns/generic/financial_regulatory_labels.md) |

### Supervisory Information

| Category | Source |
|----------|--------|
| Supervisory Controlled | [supervisory_information](../patterns/generic/supervisory_information.md) |
| Supervisory Confidential | [supervisory_information](../patterns/generic/supervisory_information.md) |
| CSI | [supervisory_information](../patterns/generic/supervisory_information.md) |
| Non-Public Supervisory | [supervisory_information](../patterns/generic/supervisory_information.md) |
| Restricted Supervisory | [supervisory_information](../patterns/generic/supervisory_information.md) |
| Examination Findings | [supervisory_information](../patterns/generic/supervisory_information.md) |

---

## Keywords

| Keyword Source | Proximity | Mapped Patterns |
|---------------|-----------|-----------------|
| [corporate_classification](../keywords/generic/corporate_classification.md) | 80 chars | Internal Only, Restricted, Confidential, etc. |
| [data_classification_labels](../keywords/generic/data_classification_labels.md) | 100 chars | Top Secret, FOUO, CUI, NOFORN |
| [privacy_classification](../keywords/generic/privacy_classification.md) | 80 chars | PII, PHI, HIPAA, GDPR, PCI-DSS, SOX |
| [privileged_information](../keywords/generic/privileged_information.md) | 100 chars | Attorney-Client, Work Product, Litigation Hold |
| [financial_regulatory_labels](../keywords/generic/financial_regulatory_labels.md) | 80 chars | MNPI, Inside Info, Market Sensitive |
| [supervisory_information](../keywords/generic/supervisory_information.md) | 80 chars | Supervisory, CSI, Examination |

---

## Classification Tier Mapping

| Tier | Labels | Typical Handling |
|------|--------|-----------------|
| **Public** | *(no labels detected)* | No restrictions |
| **Internal** | Internal Only, Proprietary | Employees only |
| **Confidential** | Corporate Confidential, Confidential Classification, CUI | Need-to-know, encrypted storage |
| **Highly Restricted** | Highly Confidential, Top Secret, NOFORN, Eyes Only | Strict access control, audit trail |
| **Legally Protected** | Attorney-Client Privilege, Work Product, Litigation Hold | Legal department control, no external sharing |
| **Regulatory** | MNPI, CSI, Supervisory Controlled | Information barriers, regulatory compliance |

## Use Cases

- **Email DLP** -- Block outbound emails containing privileged or classified markings
- **File share scanning** -- Flag documents with classification labels in shared drives
- **Chat monitoring** -- Detect confidential document content shared via messaging
- **CI/CD pipeline** -- Prevent classified content from entering code repositories
- **Print monitoring** -- Detect classified content being sent to print queues
