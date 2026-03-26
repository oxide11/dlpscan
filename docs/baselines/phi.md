# Personal Health Information (PHI) and Health Data Control

Detects protected health information (PHI) and related health data subject
to HIPAA, HITECH, and international health privacy regulations. Covers
medical identifiers, health plan information, biometric data, and
individual identifiers when associated with health context.

## Control Objective

Prevent the unauthorized use or disclosure of individually identifiable
health information as defined by the HIPAA Privacy Rule (45 CFR 164.501),
including any information that relates to the health condition, provision
of healthcare, or payment for healthcare of an individual.

---

## Patterns

### Medical Identifiers

| Category | Source |
|----------|--------|
| Health Plan ID | [medical_identifiers](../patterns/generic/medical_identifiers.md) |
| DEA Number | [medical_identifiers](../patterns/generic/medical_identifiers.md) |
| ICD-10 Code | [medical_identifiers](../patterns/generic/medical_identifiers.md) |
| NDC Code | [medical_identifiers](../patterns/generic/medical_identifiers.md) |

### Biometric Identifiers (HIPAA 18 Identifiers)

| Category | Source |
|----------|--------|
| Biometric Hash | [biometric_identifiers](../patterns/generic/biometric_identifiers.md) |
| Biometric Template ID | [biometric_identifiers](../patterns/generic/biometric_identifiers.md) |

### Personal Identifiers (PHI Context)

| Category | Source |
|----------|--------|
| Date of Birth | [personal_identifiers](../patterns/generic/personal_identifiers.md) |
| Gender Marker | [personal_identifiers](../patterns/generic/personal_identifiers.md) |

### Contact Information (PHI Context)

| Category | Source |
|----------|--------|
| Email Address | [contact_information](../patterns/generic/contact_information.md) |
| E.164 Phone Number | [contact_information](../patterns/generic/contact_information.md) |
| IPv4 Address | [contact_information](../patterns/generic/contact_information.md) |
| IPv6 Address | [contact_information](../patterns/generic/contact_information.md) |

### Insurance & Health Plan Data

| Category | Source |
|----------|--------|
| Insurance Policy Number | [insurance_identifiers](../patterns/generic/insurance_identifiers.md) |
| Insurance Claim Number | [insurance_identifiers](../patterns/generic/insurance_identifiers.md) |

### Device Identifiers (Medical Devices)

| Category | Source |
|----------|--------|
| IMEI | [device_identifiers](../patterns/generic/device_identifiers.md) |
| ICCID | [device_identifiers](../patterns/generic/device_identifiers.md) |

### Government IDs (PHI Cross-Reference)

| Region | Categories | Source |
|--------|-----------|--------|
| **United States** | SSN, MBI (Medicare Beneficiary ID), NPI (National Provider ID) | [north_america](../patterns/regions/north_america.md) |
| **Brazil** | SUS Card (Unified Health System) | [latin_america](../patterns/regions/latin_america.md) |
| **United Kingdom** | NHS Number | [europe](../patterns/regions/europe.md) |

### Privacy Classification Labels

| Category | Source |
|----------|--------|
| PHI Label | [privacy_classification](../patterns/generic/privacy_classification.md) |
| HIPAA | [privacy_classification](../patterns/generic/privacy_classification.md) |
| GDPR Personal Data | [privacy_classification](../patterns/generic/privacy_classification.md) |

---

## Keywords

| Keyword Source | Proximity | Mapped Patterns |
|---------------|-----------|-----------------|
| [medical_identifiers](../keywords/generic/medical_identifiers.md) | 50 chars | Health Plan ID, DEA, ICD-10, NDC |
| [biometric_identifiers](../keywords/generic/biometric_identifiers.md) | 50 chars | Biometric Hash, Template ID |
| [personal_identifiers](../keywords/generic/personal_identifiers.md) | 30 chars | DOB, Gender |
| [contact_information](../keywords/generic/contact_information.md) | 50 chars | Email, Phone, IP |
| [insurance_identifiers](../keywords/generic/insurance_identifiers.md) | 50 chars | Policy Number, Claim Number |
| [device_identifiers](../keywords/generic/device_identifiers.md) | 50 chars | IMEI, ICCID |
| [privacy_classification](../keywords/generic/privacy_classification.md) | 80 chars | PHI, HIPAA labels |
| [north_america](../keywords/regions/north_america.md) | 50 chars | SSN, MBI, NPI |
| [europe](../keywords/regions/europe.md) | 50 chars | NHS Number |
| [latin_america](../keywords/regions/latin_america.md) | 50 chars | SUS Card |

---

## HIPAA 18 Identifier Coverage

The HIPAA Privacy Rule defines 18 categories of identifiers that constitute
PHI. This baseline covers:

| # | HIPAA Identifier | dlpscan Pattern |
|---|-----------------|-----------------|
| 1 | Names | Cardholder Name Pattern (shared) |
| 2 | Geographic data (smaller than state) | Postal Codes, GPS Coordinates |
| 3 | Dates (except year) | Date of Birth, Date formats |
| 4 | Phone numbers | E.164 Phone Number |
| 5 | Fax numbers | E.164 Phone Number |
| 6 | Email addresses | Email Address |
| 7 | Social Security numbers | SSN (regional) |
| 8 | Medical record numbers | Health Plan ID |
| 9 | Health plan beneficiary numbers | Insurance Policy Number, MBI |
| 10 | Account numbers | Insurance Claim Number |
| 11 | Certificate/license numbers | DEA Number, NPI |
| 12 | Vehicle identifiers | VIN |
| 13 | Device identifiers | IMEI, ICCID |
| 14 | Web URLs | URL with Credentials |
| 15 | IP addresses | IPv4, IPv6 |
| 16 | Biometric identifiers | Biometric Hash, Template ID |
| 17 | Full-face photographs | (image OCR scanning) |
| 18 | Any other unique identifying number | ICD-10, NDC codes |
