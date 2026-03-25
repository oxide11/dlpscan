# Pii Identifiers — Context Keywords

> Keywords used for proximity-based context detection.
> When a regex pattern match is found, the scanner checks for these keywords
> within a configurable character distance before/after the match to improve accuracy.

---

## Authentication Tokens

**Proximity distance:** 50 characters

| Pattern Name | Keywords |
|---|---|
| CSRF Token | `csrf`, `csrf_token`, `xsrf`, `anti-forgery`, `request token`, `authenticity_token`, `_token` |
| OTP Code | `otp`, `one-time password`, `one time password`, `verification code`, `two-factor`, `2fa`, `mfa code`, `authenticator code`, `totp` |
| Refresh Token | `refresh_token`, `refresh token`, `rt_token`, `oauth refresh` |
| Session ID | `session id`, `session_id`, `sessionid`, `sess_id`, `session token`, `phpsessid`, `jsessionid`, `asp.net_sessionid` |

## Biometric Identifiers

**Proximity distance:** 50 characters

| Pattern Name | Keywords |
|---|---|
| Biometric Hash | `biometric`, `fingerprint hash`, `fingerprint`, `facial recognition`, `iris scan`, `palm print`, `voiceprint`, `retina scan` |
| Biometric Template ID | `biometric template`, `facial template`, `fingerprint template`, `enrollment id`, `biometric id` |

## Device Identifiers

**Proximity distance:** 50 characters

| Pattern Name | Keywords |
|---|---|
| Android Device ID | `android id`, `device id`, `android device`, `ssaid` |
| Device Serial Number | `serial number`, `serial no`, `sn`, `device serial`, `hardware serial`, `serial#` |
| IDFA/IDFV | `idfa`, `idfv`, `advertising identifier`, `identifier for advertisers`, `vendor identifier`, `apple device id` |
| IMEI | `imei`, `international mobile equipment identity`, `device imei`, `handset id`, `phone imei` |
| IMSI | `imsi`, `international mobile subscriber`, `subscriber identity`, `sim id` |

## Education Identifiers

**Proximity distance:** 50 characters

| Pattern Name | Keywords |
|---|---|
| EDU Email | `student email`, `edu email`, `university email`, `academic email`, `school email`, `college email` |
| GPA | `gpa`, `grade point average`, `cumulative gpa`, `cgpa`, `academic standing`, `grades` |
| Student ID | `student id`, `student number`, `student no`, `enrollment number`, `matriculation`, `university id`, `school id` |

## Employment Identifiers

**Proximity distance:** 50 characters

| Pattern Name | Keywords |
|---|---|
| Employee ID | `employee id`, `employee number`, `emp id`, `staff id`, `personnel number`, `emp no`, `worker id`, `badge number` |
| Work Permit Number | `work permit`, `work visa`, `employment authorization`, `ead`, `labor permit`, `work authorization` |

## Geolocation

**Proximity distance:** 50 characters

| Pattern Name | Keywords |
|---|---|
| GPS Coordinates | `latitude`, `longitude`, `lat`, `lng`, `lon`, `coordinates`, `gps`, `geolocation`, `location`, `coord` |
| GPS DMS | `latitude`, `longitude`, `coordinates`, `gps`, `dms`, `degrees minutes seconds` |
| Geohash | `geohash`, `geo hash`, `location hash` |

## Insurance Identifiers

**Proximity distance:** 50 characters

| Pattern Name | Keywords |
|---|---|
| Insurance Claim Number | `claim number`, `claim no`, `claim id`, `claim#`, `claims reference`, `incident number` |
| Insurance Group Number | `group number`, `group no`, `group id`, `plan group`, `insurance group`, `grp` |
| Insurance Policy Number | `policy number`, `policy no`, `insurance policy`, `policy id`, `coverage number`, `policy#` |

## Legal Identifiers

**Proximity distance:** 50 characters

| Pattern Name | Keywords |
|---|---|
| Bar Number | `bar number`, `bar no`, `attorney number`, `bar id`, `bar license`, `attorney id` |
| Court Docket Number | `docket number`, `docket no`, `court case`, `case file`, `case reference`, `court number` |
| US Federal Case Number | `case number`, `case no`, `docket`, `civil action`, `case#`, `filing number` |

## Medical Identifiers

**Proximity distance:** 50 characters

| Pattern Name | Keywords |
|---|---|
| DEA Number | `dea`, `dea number`, `drug enforcement`, `prescriber`, `controlled substance` |
| Health Plan ID | `health plan`, `insurance id`, `beneficiary`, `member id`, `subscriber id` |
| ICD-10 Code | `icd`, `icd-10`, `diagnosis code`, `diagnostic code`, `condition code`, `icd code` |
| Medical Record Number | `mrn`, `medical record`, `patient id`, `patient number`, `chart number`, `medical id`, `health record` |
| NDC Code | `ndc`, `national drug code`, `drug code`, `medication code`, `pharmaceutical` |

## Personal Identifiers

**Proximity distance:** 30 characters

| Pattern Name | Keywords |
|---|---|
| Age Value | `age`, `years old`, `yr old`, `yrs old`, `aged`, `age group` |
| Date of Birth | `date of birth`, `dob`, `born on`, `birth date`, `birthday`, `birthdate`, `d.o.b` |
| Gender Marker | `gender`, `sex`, `identified as`, `gender identity`, `biological sex` |

## Postal Codes

**Proximity distance:** 50 characters

| Pattern Name | Keywords |
|---|---|
| Australia Postcode | `postcode`, `post code`, `australian address` |
| Brazil CEP | `cep`, `codigo postal`, `brazilian address` |
| Canada Postal Code | `postal code`, `code postal`, `canadian address` |
| Germany PLZ | `plz`, `postleitzahl`, `postal code`, `german address` |
| India PIN Code | `pin code`, `pincode`, `postal index number`, `indian address` |
| Japan Postal Code | `postal code`, `yubin bangou`, `japanese address` |
| UK Postcode | `postcode`, `post code`, `postal code`, `uk address` |
| US ZIP Code | `zip`, `zip code`, `zipcode`, `postal code`, `mailing address`, `zip+4` |

## Property Identifiers

**Proximity distance:** 50 characters

| Pattern Name | Keywords |
|---|---|
| Parcel Number | `parcel number`, `apn`, `assessor parcel`, `parcel id`, `lot number`, `property id` |
| Title Deed Number | `title number`, `deed number`, `deed of trust`, `title deed`, `land title`, `property title` |

## Social Media Identifiers

**Proximity distance:** 50 characters

| Pattern Name | Keywords |
|---|---|
| Hashtag | `hashtag`, `tagged`, `trending`, `topic` |
| Social Media User ID | `user id`, `user_id`, `userid`, `profile id`, `account id`, `facebook id`, `instagram id`, `tiktok id` |
| Twitter Handle | `twitter`, `tweet`, `@`, `x.com`, `twitter handle`, `twitter username`, `follow` |
