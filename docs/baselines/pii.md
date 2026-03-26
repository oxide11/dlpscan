# Personal Identifiable Information (PII)

Detects personally identifiable information that can be used to identify,
contact, or locate an individual. Aligns with GDPR, CCPA/CPRA, FERPA, GLBA,
and general privacy protection requirements.

## Control Objective

Prevent the unauthorized disclosure of personal identifiers, contact details,
biometric data, government-issued IDs, and other information that can be
linked to a specific individual.

---

## Patterns

### Personal Identifiers

| Category | Source |
|----------|--------|
| Date of Birth | [personal_identifiers](../patterns/generic/personal_identifiers.md) |
| Gender Marker | [personal_identifiers](../patterns/generic/personal_identifiers.md) |

### Contact Information

| Category | Source |
|----------|--------|
| Email Address | [contact_information](../patterns/generic/contact_information.md) |
| E.164 Phone Number | [contact_information](../patterns/generic/contact_information.md) |
| IPv4 Address | [contact_information](../patterns/generic/contact_information.md) |
| IPv6 Address | [contact_information](../patterns/generic/contact_information.md) |
| MAC Address | [contact_information](../patterns/generic/contact_information.md) |

### Biometric Identifiers

| Category | Source |
|----------|--------|
| Biometric Hash | [biometric_identifiers](../patterns/generic/biometric_identifiers.md) |
| Biometric Template ID | [biometric_identifiers](../patterns/generic/biometric_identifiers.md) |

### Employment & Education

| Category | Source |
|----------|--------|
| Employee ID | [employment_identifiers](../patterns/generic/employment_identifiers.md) |
| Work Permit Number | [employment_identifiers](../patterns/generic/employment_identifiers.md) |
| EDU Email | [education_identifiers](../patterns/generic/education_identifiers.md) |

### Location & Address

| Category | Source |
|----------|--------|
| GPS Coordinates | [geolocation](../patterns/generic/geolocation.md) |
| GPS DMS | [geolocation](../patterns/generic/geolocation.md) |
| Geohash | [geolocation](../patterns/generic/geolocation.md) |
| US ZIP+4 Code | [postal_codes](../patterns/generic/postal_codes.md) |
| UK Postcode | [postal_codes](../patterns/generic/postal_codes.md) |
| Canada Postal Code | [postal_codes](../patterns/generic/postal_codes.md) |
| Japan Postal Code | [postal_codes](../patterns/generic/postal_codes.md) |
| Brazil CEP | [postal_codes](../patterns/generic/postal_codes.md) |

### Digital Identifiers

| Category | Source |
|----------|--------|
| IMEI | [device_identifiers](../patterns/generic/device_identifiers.md) |
| IMEISV | [device_identifiers](../patterns/generic/device_identifiers.md) |
| MEID | [device_identifiers](../patterns/generic/device_identifiers.md) |
| ICCID | [device_identifiers](../patterns/generic/device_identifiers.md) |
| IDFA/IDFV | [device_identifiers](../patterns/generic/device_identifiers.md) |
| Twitter Handle | [social_media_identifiers](../patterns/generic/social_media_identifiers.md) |

### Authentication Tokens

| Category | Source |
|----------|--------|
| Session ID | [authentication_tokens](../patterns/generic/authentication_tokens.md) |

### Other Identifiers

| Category | Source |
|----------|--------|
| Date ISO / US / EU | [dates](../patterns/generic/dates.md) |
| VIN | [vehicle_identification](../patterns/generic/vehicle_identification.md) |
| Insurance Policy Number | [insurance_identifiers](../patterns/generic/insurance_identifiers.md) |
| Insurance Claim Number | [insurance_identifiers](../patterns/generic/insurance_identifiers.md) |
| Parcel Number | [property_identifiers](../patterns/generic/property_identifiers.md) |
| Title Deed Number | [property_identifiers](../patterns/generic/property_identifiers.md) |
| US Federal Case Number | [legal_identifiers](../patterns/generic/legal_identifiers.md) |
| Court Docket Number | [legal_identifiers](../patterns/generic/legal_identifiers.md) |

### Regional Government-Issued IDs

| Region | Categories | Source |
|--------|-----------|--------|
| **North America** | SSN, ITIN, EIN, Passport, Passport Card, DEA Number, NPI, MBI, DoD ID, Known Traveler Number, State Driver Licenses | [north_america](../patterns/regions/north_america.md) |
| **Europe** | UK NIN, UK UTR, UK Passport, UK Sort Code, UK NHS, UK DL, Germany ID, Germany Passport | [europe](../patterns/regions/europe.md) |
| **Asia Pacific** | India PAN, Aadhaar, Passport, DL, Voter ID, Ration Card; China Resident ID, Passport; Hong Kong ID | [asia_pacific](../patterns/regions/asia_pacific.md) |
| **Latin America** | Brazil CPF, CNPJ, RG, CNH, SUS Card, Passport; Argentina DNI, CUIL/CUIT, Passport | [latin_america](../patterns/regions/latin_america.md) |
| **Middle East** | Saudi Arabia National ID, Passport; UAE Emirates ID, Visa Number, Passport; Israel | [middle_east](../patterns/regions/middle_east.md) |
| **Africa** | South Africa ID, Passport, DL; Nigeria NIN, BVN, TIN, Voter Card, DL, Passport | [africa](../patterns/regions/africa.md) |

---

## Keywords

| Keyword Source | Proximity | Mapped Patterns |
|---------------|-----------|-----------------|
| [personal_identifiers](../keywords/generic/personal_identifiers.md) | 30 chars | Date of Birth, Gender Marker |
| [contact_information](../keywords/generic/contact_information.md) | 50 chars | Email, Phone, IP, MAC |
| [biometric_identifiers](../keywords/generic/biometric_identifiers.md) | 50 chars | Biometric Hash, Template ID |
| [employment_identifiers](../keywords/generic/employment_identifiers.md) | 50 chars | Employee ID, Work Permit |
| [education_identifiers](../keywords/generic/education_identifiers.md) | 50 chars | EDU Email |
| [geolocation](../keywords/generic/geolocation.md) | 50 chars | GPS, Geohash |
| [postal_codes](../keywords/generic/postal_codes.md) | 50 chars | ZIP, Postcode, Postal Code, CEP |
| [device_identifiers](../keywords/generic/device_identifiers.md) | 50 chars | IMEI, MEID, ICCID, IDFA |
| [social_media_identifiers](../keywords/generic/social_media_identifiers.md) | 50 chars | Twitter Handle |
| [dates](../keywords/generic/dates.md) | 50 chars | Date formats |
| [vehicle_identification](../keywords/generic/vehicle_identification.md) | 50 chars | VIN |
| [insurance_identifiers](../keywords/generic/insurance_identifiers.md) | 50 chars | Policy Number, Claim Number |
| [property_identifiers](../keywords/generic/property_identifiers.md) | 50 chars | Parcel, Title Deed |
| [legal_identifiers](../keywords/generic/legal_identifiers.md) | 50 chars | Case Number, Docket |
| [authentication_tokens](../keywords/generic/authentication_tokens.md) | 50 chars | Session ID |
| [north_america](../keywords/regions/north_america.md) | 50 chars | SSN, ITIN, EIN, Passport, DL |
| [europe](../keywords/regions/europe.md) | 50 chars | NIN, UTR, NHS, Passport |
| [asia_pacific](../keywords/regions/asia_pacific.md) | 50 chars | PAN, Aadhaar, Resident ID |
| [latin_america](../keywords/regions/latin_america.md) | 50 chars | CPF, CNPJ, DNI, CUIL |
| [middle_east](../keywords/regions/middle_east.md) | 50 chars | Emirates ID, National ID |
| [africa](../keywords/regions/africa.md) | 50 chars | SA ID, NIN, BVN |

---

## Applicable Regulations

- **GDPR** (EU) -- Articles 4, 9; personal data and special categories
- **CCPA/CPRA** (California) -- Personal information definition
- **FERPA** (US) -- Student education records
- **GLBA** (US) -- Nonpublic personal financial information
- **PIPEDA** (Canada) -- Personal information
- **LGPD** (Brazil) -- Personal and sensitive personal data
- **POPIA** (South Africa) -- Personal information
