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

## Patterns & Keywords

### Medical Identifiers

| Pattern Name | Regex | Keywords (proximity: 50 chars) |
|---|---|---|
| Health Plan ID | `\b[A-Z]{3}\d{9}\b` | `health plan`, `insurance id`, `beneficiary`, `member id`, `subscriber id` |
| DEA Number | `\b[A-Z]{2}\d{7}\b` | `dea`, `dea number`, `drug enforcement`, `prescriber`, `controlled substance` |
| ICD-10 Code | `\b[A-TV-Z]\d{2}(?:\.\d{1,4})?\b` | `icd`, `icd-10`, `diagnosis code`, `diagnostic code`, `condition code`, `icd code` |
| NDC Code | `\b\d{4,5}-\d{3,4}-\d{1,2}\b` | `ndc`, `national drug code`, `drug code`, `medication code`, `pharmaceutical` |
| Medical Record Number | `\b\d{6,10}\b` | `mrn`, `medical record`, `patient id`, `patient number`, `chart number`, `medical id`, `health record` |

### Insurance & Health Plan Data

| Pattern Name | Regex | Keywords (proximity: 50 chars) |
|---|---|---|
| Insurance Policy Number | `\b[A-Z]{2,4}\d{6,12}\b` | `policy number`, `policy no`, `insurance policy`, `policy id`, `coverage number`, `policy#` |
| Insurance Claim Number | `\b[A-Z]{1,3}\d{8,15}\b` | `claim number`, `claim no`, `claim id`, `claim#`, `claims reference`, `incident number` |
| Insurance Group Number | `\b\d{5,10}\b` | `group number`, `group no`, `group id`, `plan group`, `insurance group`, `grp` |

### Biometric Identifiers (HIPAA 18 Identifiers)

| Pattern Name | Regex | Keywords (proximity: 50 chars) |
|---|---|---|
| Biometric Hash | `\b[0-9a-f]{64}\b` | `biometric`, `fingerprint hash`, `fingerprint`, `facial recognition`, `iris scan`, `palm print`, `voiceprint`, `retina scan` |
| Biometric Template ID | `\b[A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12}\b` | `biometric template`, `facial template`, `fingerprint template`, `enrollment id`, `biometric id` |

### Personal Identifiers (PHI Context)

| Pattern Name | Regex | Keywords (proximity: 30 chars) |
|---|---|---|
| Date of Birth | `\b(?:0[1-9]\|1[0-2])[-/](?:0[1-9]\|[12]\d\|3[01])[-/](?:19\|20)\d{2}\b` | `date of birth`, `dob`, `born on`, `birth date`, `birthday`, `birthdate`, `d.o.b` |
| Gender Marker | `\b(?:male\|female\|non-binary\|transgender\|M\|F\|X)\b` | `gender`, `sex`, `identified as`, `gender identity`, `biological sex` |
| Age Value | `\b(?:1[89]\|[2-9]\d\|1[0-4]\d)\b` | `age`, `years old`, `yr old`, `yrs old`, `aged`, `age group` |

### Contact Information (PHI Context)

| Pattern Name | Regex | Keywords (proximity: 50 chars) |
|---|---|---|
| Email Address | `\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b` | `email`, `e-mail`, `email address`, `mail to`, `contact` |
| E.164 Phone Number | `\+[1-9]\d{6,14}\b` | `phone`, `telephone`, `tel`, `mobile`, `contact number` |
| IPv4 Address | `\b(?:(?:25[0-5]\|2[0-4]\d\|[01]?\d\d?)\.){3}(?:25[0-5]\|2[0-4]\d\|[01]?\d\d?)\b` | `ip address`, `ip`, `server`, `host`, `network` |
| IPv6 Address | `\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b` | `ip address`, `ipv6`, `server`, `host`, `network` |

### Device Identifiers (Medical Devices)

| Pattern Name | Regex | Keywords (proximity: 50 chars) |
|---|---|---|
| IMEI | `\b\d{2}[-.\s]?\d{6}[-.\s]?\d{6}[-.\s]?\d\b` | `imei`, `international mobile equipment identity`, `device imei`, `handset id`, `phone imei`, `equipment identity` |
| ICCID | `\b89\d{2}[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{3,4}\d?\b` | `iccid`, `sim card number`, `sim number`, `integrated circuit card`, `sim id`, `sim serial` |
| Device Serial Number | `\b[A-Z0-9]{8,20}\b` | `serial number`, `serial no`, `sn`, `device serial`, `hardware serial`, `serial#` |

### Date Formats (HIPAA Identifier #3)

| Pattern Name | Regex | Keywords (proximity: 50 chars) |
|---|---|---|
| Date ISO | `\b\d{4}[-/](?:0[1-9]\|1[0-2])[-/](?:0[1-9]\|[12]\d\|3[01])\b` | `date of birth`, `dob`, `birth date`, `birthday`, `born on`, `born`, `birthdate` |
| Date US | `\b(?:0[1-9]\|1[0-2])[-/](?:0[1-9]\|[12]\d\|3[01])[-/]\d{4}\b` | `date of birth`, `dob`, `birth date`, `birthday`, `born on`, `born`, `birthdate` |
| Date EU | `\b(?:0[1-9]\|[12]\d\|3[01])[-/](?:0[1-9]\|1[0-2])[-/]\d{4}\b` | `date of birth`, `dob`, `birth date`, `birthday`, `born on`, `born`, `birthdate` |

### Geographic Data (HIPAA Identifier #2)

| Pattern Name | Regex | Keywords (proximity: 50 chars) |
|---|---|---|
| GPS Coordinates | `-?\d{1,3}\.\d{4,8},\s?-?\d{1,3}\.\d{4,8}` | `latitude`, `longitude`, `lat`, `lng`, `lon`, `coordinates`, `gps`, `geolocation`, `location`, `coord` |
| US ZIP Code | `\b\d{5}(?:-\d{4})?\b` | `zip`, `zip code`, `zipcode`, `postal code`, `mailing address`, `zip+4` |

### Privacy Classification Labels

| Pattern Name | Regex | Keywords (proximity: 80 chars) |
|---|---|---|
| PHI Label | `\b(?:PHI\|[Pp]rotected\s+[Hh]ealth\s+[Ii]nformation)\b` | `phi`, `protected health`, `health information`, `medical records`, `patient data` |
| HIPAA | `\bHIPAA\b` | `hipaa`, `health insurance portability`, `medical privacy`, `health data` |
| GDPR Personal Data | `\b(?:GDPR\|[Pp]ersonal\s+[Dd]ata\s+(?:under\|per\|pursuant))\b` | `gdpr`, `personal data`, `data subject`, `data protection`, `eu regulation` |

### Government Health IDs (Regional)

| Region | Pattern Name | Regex | Keywords |
|--------|---|---|---|
| US | SSN | `\b\d{3}-\d{2}-\d{4}\b` | `ssn`, `social security`, `social security number` |
| US | MBI (Medicare) | `\b[1-9][A-Z](?:[0-9A-Z]){2}[0-9]-[A-Z][A-Z0-9]{2}[0-9]-[A-Z]{2}[0-9]{2}\b` | `mbi`, `medicare`, `medicare beneficiary`, `cms` |
| US | NPI (Provider) | `\b\d{10}\b` | `npi`, `national provider`, `provider id`, `prescriber` |
| UK | NHS Number | `\b\d{3}\s?\d{3}\s?\d{4}\b` | `nhs`, `nhs number`, `national health service` |
| Brazil | SUS Card | `\b\d{15}\b` | `sus`, `cartão sus`, `sistema único de saúde` |

---

## HIPAA 18 Identifier Coverage

| # | HIPAA Identifier | dlpscan Pattern | Regex |
|---|-----------------|-----------------|-------|
| 1 | Names | Cardholder Name Pattern (shared) | `\b[A-Z][a-z]+\s[A-Z][a-z]+\b` |
| 2 | Geographic data (smaller than state) | GPS Coordinates, ZIP Code | See Geographic Data above |
| 3 | Dates (except year) | Date of Birth, Date ISO/US/EU | See Date Formats above |
| 4 | Phone numbers | E.164 Phone Number | `\+[1-9]\d{6,14}\b` |
| 5 | Fax numbers | E.164 Phone Number | `\+[1-9]\d{6,14}\b` |
| 6 | Email addresses | Email Address | `\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b` |
| 7 | Social Security numbers | SSN (regional) | `\b\d{3}-\d{2}-\d{4}\b` |
| 8 | Medical record numbers | Medical Record Number | `\b\d{6,10}\b` |
| 9 | Health plan beneficiary numbers | Insurance Policy Number, MBI | See above |
| 10 | Account numbers | Insurance Claim Number | `\b[A-Z]{1,3}\d{8,15}\b` |
| 11 | Certificate/license numbers | DEA Number, NPI | `\b[A-Z]{2}\d{7}\b`, `\b\d{10}\b` |
| 12 | Vehicle identifiers | VIN | `\b[A-HJ-NPR-Z0-9]{17}\b` |
| 13 | Device identifiers | IMEI, ICCID | See Device Identifiers above |
| 14 | Web URLs | URL with Credentials | `https?://[^:\s]+:[^@\s]+@[^\s]+` |
| 15 | IP addresses | IPv4, IPv6 | See Contact Information above |
| 16 | Biometric identifiers | Biometric Hash, Template ID | See Biometric Identifiers above |
| 17 | Full-face photographs | *(image OCR scanning)* | -- |
| 18 | Any other unique identifying number | ICD-10, NDC codes | See Medical Identifiers above |
