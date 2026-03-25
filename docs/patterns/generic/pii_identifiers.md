# Pii Identifiers — Regex Patterns

> Language-agnostic regex patterns for sensitive data detection.
> All patterns use standard regex syntax compatible with PCRE, Python `re`, JavaScript, Go, Java, etc.

---

## Authentication Tokens

| Pattern Name | Regex |
|---|---|
| CSRF Token | `\b[0-9a-zA-Z_-]{32,64}\b` |
| OTP Code | `\b\d{6,8}\b` |
| Refresh Token | `\b[0-9a-zA-Z_-]{40,}\b` |
| Session ID | `\b[0-9a-f]{32,64}\b` |

## Biometric Identifiers

| Pattern Name | Regex |
|---|---|
| Biometric Hash | `\b[0-9a-f]{64}\b` |
| Biometric Template ID | `\b[A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12}\b` |

## Device Identifiers

| Pattern Name | Regex |
|---|---|
| Android Device ID | `\b[0-9a-f]{16}\b` |
| Device Serial Number | `\b[A-Z0-9]{8,20}\b` |
| ICCID | `\b89\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{3,4}\d?\b` |
| IDFA/IDFV | `\b[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\b` |
| IMEI | `\b\d{2}[-\s]?\d{6}[-\s]?\d{6}[-\s]?\d\b` |
| IMEISV | `\b\d{2}[-\s]?\d{6}[-\s]?\d{6}[-\s]?\d{2}\b` |
| IMSI | `\b\d{15}\b` |
| MEID | `\b[0-9A-F]{2}[-\s]?[0-9A-F]{6}[-\s]?[0-9A-F]{6}\b` |

## Education Identifiers

| Pattern Name | Regex |
|---|---|
| EDU Email | `\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.edu\b`  (flags: `i`)|
| GPA | `\b[0-4]\.\d{1,2}\b` |
| Student ID | `\b\d{7,10}\b` |

## Employment Identifiers

| Pattern Name | Regex |
|---|---|
| Employee ID | `\b[A-Z]{1,3}\d{4,8}\b` |
| Work Permit Number | `\b[A-Z]{2,3}\d{7,10}\b` |

## Geolocation

| Pattern Name | Regex |
|---|---|
| GPS Coordinates | `-?\d{1,3}\.\d{4,8},\s?-?\d{1,3}\.\d{4,8}` |
| GPS DMS | `\d{1,3}[°]\d{1,2}[\'′]\d{1,2}(?:\.\d+)?[\"″]?\s?[NSEW]` |
| Geohash | `\b(?=[0-9bcdefghjkmnpqrstuvwxyz]*\d)[0-9bcdefghjkmnpqrstuvwxyz]{7,12}\b` |

## Insurance Identifiers

| Pattern Name | Regex |
|---|---|
| Insurance Claim Number | `\b[A-Z]{1,3}\d{8,15}\b` |
| Insurance Group Number | `\b\d{5,10}\b` |
| Insurance Policy Number | `\b[A-Z]{2,4}\d{6,12}\b` |

## Legal Identifiers

| Pattern Name | Regex |
|---|---|
| Bar Number | `\b\d{5,8}\b` |
| Court Docket Number | `\b\d{2,4}-?[A-Z]{1,4}-?\d{4,8}\b` |
| US Federal Case Number | `\b\d:\d{2}-[a-z]{2}-\d{4,5}\b` |

## Medical Identifiers

| Pattern Name | Regex |
|---|---|
| DEA Number | `\b[A-Z]{2}\d{7}\b` |
| Health Plan ID | `\b[A-Z]{3}\d{9}\b` |
| ICD-10 Code | `\b[A-Z]\d{2}(?:\.\d{1,4})?\b` |
| Medical Record Number | `\b\d{6,10}\b` |
| NDC Code | `\b\d{4,5}-\d{3,4}-\d{1,2}\b` |

## Personal Identifiers

| Pattern Name | Regex |
|---|---|
| Age Value | `\b(?:1[89]\|[2-9]\d\|1[0-4]\d)\b` |
| Date of Birth | `\b(?:0[1-9]\|1[0-2])[-/](?:0[1-9]\|[12]\d\|3[01])[-/](?:19\|20)\d{2}\b` |
| Gender Marker | `\b(?:male\|female\|non-binary\|transgender\|M\|F\|X)\b`  (flags: `i`)|

## Postal Codes

| Pattern Name | Regex |
|---|---|
| Australia Postcode | `\b\d{4}\b` |
| Brazil CEP | `\b\d{5}-?\d{3}\b` |
| Canada Postal Code | `\b[A-Z]\d[A-Z]\s?\d[A-Z]\d\b` |
| Germany PLZ | `\b\d{5}\b` |
| India PIN Code | `\b[1-9]\d{5}\b` |
| Japan Postal Code | `\b\d{3}-\d{4}\b` |
| UK Postcode | `\b[A-Z]{1,2}\d[A-Z0-9]?\s?\d[A-Z]{2}\b` |
| US ZIP Code | `\b\d{5}(?:-\d{4})?\b` |

## Property Identifiers

| Pattern Name | Regex |
|---|---|
| Parcel Number | `\b\d{3}-\d{3}-\d{3}(?:-\d{3})?\b` |
| Title Deed Number | `\b\d{4,}-?\d{4,}\b` |

## Social Media Identifiers

| Pattern Name | Regex |
|---|---|
| Hashtag | `(?<!\w)#[A-Za-z]\w{2,49}\b` |
| Social Media User ID | `\b\d{6,20}\b` |
| Twitter Handle | `(?<!\w)@[A-Za-z_]\w{0,14}\b` |
