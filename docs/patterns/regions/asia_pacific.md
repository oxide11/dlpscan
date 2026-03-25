# Asia Pacific — Regex Patterns

> Language-agnostic regex patterns for sensitive data detection.
> All patterns use standard regex syntax compatible with PCRE, Python `re`, JavaScript, Go, Java, etc.

---

## Asia-Pacific - Australia

| Pattern Name | Regex |
|---|---|
| Australia DL ACT | `\b\d{6,10}\b` |
| Australia DL NSW | `\b\d{8}\b` |
| Australia DL NT | `\b\d{5,7}\b` |
| Australia DL QLD | `\b\d{8,9}\b` |
| Australia DL SA | `\b[A-Z]?\d{5,6}\b` |
| Australia DL TAS | `\b[A-Z]\d{5,6}\b` |
| Australia DL VIC | `\b\d{8,10}\b` |
| Australia DL WA | `\b\d{7}\b` |
| Australia Medicare | `\b[2-6]\d{3}[\s]?\d{5}[\s]?\d[\s]?\d?\b` |
| Australia Passport | `\b[A-Z]{1,2}\d{7}\b` |
| Australia TFN | `\b\d{3}[\s]?\d{3}[\s]?\d{2,3}\b` |

## Asia-Pacific - Bangladesh

| Pattern Name | Regex |
|---|---|
| Bangladesh NID | `\b(?:\d{10}\|\d{17})\b` |
| Bangladesh Passport | `\b[A-Z]{2}\d{7}\b` |
| Bangladesh TIN | `\b\d{12}\b` |

## Asia-Pacific - China

| Pattern Name | Regex |
|---|---|
| China Passport | `\b[EGD][A-Z]?\d{7,8}\b` |
| China Resident ID | `\b\d{6}(?:18\|19\|20)\d{2}(?:0[1-9]\|1[0-2])(?:0[1-9]\|[12]\d\|3[01])\d{3}[\dXx]\b` |
| Hong Kong ID | `\b[A-Z]{1,2}\d{6}\s?\(?[0-9A]\)?\b` |
| Macau ID | `\b[1578]\d{6}\s?\(?[0-9]\)?\b` |
| Taiwan National ID | `\b[A-Z][12489]\d{8}\b` |

## Asia-Pacific - India

| Pattern Name | Regex |
|---|---|
| India Aadhaar | `\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b` |
| India DL | `\b[A-Z]{2}[-\s]?\d{2}[-\s]?(?:19\|20)\d{2}[-\s]?\d{7}\b` |
| India PAN | `\b[A-Z]{5}\d{4}[A-Z]\b` |
| India Passport | `\b[A-Z][1-9]\d{5}[1-9]\b` |
| India Ration Card | `\b\d{2}[\s-]?\d{8}\b` |
| India Voter ID | `\b[A-Z]{3}\d{7}\b` |

## Asia-Pacific - Indonesia

| Pattern Name | Regex |
|---|---|
| Indonesia NIK | `\b\d{16}\b` |
| Indonesia NPWP | `\b\d{2}\.?\d{3}\.?\d{3}\.?\d[-.]?\d{3}\.?\d{3}\b` |
| Indonesia Passport | `\b[A-Z]{1,2}\d{6,7}\b` |

## Asia-Pacific - Japan

| Pattern Name | Regex |
|---|---|
| Japan DL | `\b\d{12}\b` |
| Japan Health Insurance | `\b\d{8}\b` |
| Japan Juminhyo Code | `\b\d{11}\b` |
| Japan My Number | `\b\d{12}\b` |
| Japan Passport | `\b[A-Z]{2}\d{7}\b` |
| Japan Residence Card | `\b[A-Z]{2}\d{8}[A-Z]{2}\b` |

## Asia-Pacific - Malaysia

| Pattern Name | Regex |
|---|---|
| Malaysia MyKad | `\b\d{2}(?:0[1-9]\|1[0-2])(?:0[1-9]\|[12]\d\|3[01])[-\s]?\d{2}[-\s]?\d{4}\b` |
| Malaysia Passport | `\b[A-Z]\d{8}\b` |

## Asia-Pacific - New Zealand

| Pattern Name | Regex |
|---|---|
| New Zealand DL | `\b[A-Z]{2}\d{6}\b` |
| New Zealand IRD | `\b\d{8,9}\b` |
| New Zealand NHI | `\b[A-HJ-NP-Z]{3}\d{4}\b` |
| New Zealand Passport | `\b[A-Z]{2}\d{6}\b` |

## Asia-Pacific - Pakistan

| Pattern Name | Regex |
|---|---|
| Pakistan CNIC | `\b\d{5}[-\s]?\d{7}[-\s]?\d\b` |
| Pakistan NICOP | `\b\d{5}[-\s]?\d{7}[-\s]?\d\b` |
| Pakistan Passport | `\b[A-Z]{2}\d{7}\b` |

## Asia-Pacific - Philippines

| Pattern Name | Regex |
|---|---|
| Philippines Passport | `\b[A-Z]{1,2}\d{6,7}[A-Z]?\b` |
| Philippines PhilHealth | `\b\d{2}-?\d{9}-?\d\b` |
| Philippines PhilSys | `\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b` |
| Philippines SSS | `\b\d{2}-?\d{7}-?\d\b` |
| Philippines TIN | `\b\d{3}-?\d{3}-?\d{3}(?:-?\d{3})?\b` |
| Philippines UMID | `\b\d{4}-?\d{7}-?\d\b` |

## Asia-Pacific - Singapore

| Pattern Name | Regex |
|---|---|
| Singapore DL | `\b[STFGM]\d{7}[A-Z]\b` |
| Singapore FIN | `\b[FGM]\d{7}[A-Z]\b` |
| Singapore NRIC | `\b[ST]\d{7}[A-Z]\b` |
| Singapore Passport | `\b[A-Z]\d{7}[A-Z]\b` |

## Asia-Pacific - South Korea

| Pattern Name | Regex |
|---|---|
| South Korea DL | `\b\d{2}[-\s]?\d{2}[-\s]?\d{6}[-\s]?\d{2}\b` |
| South Korea Passport | `\b[MSROD]\d{8}\b` |
| South Korea RRN | `\b\d{2}(?:0[1-9]\|1[0-2])(?:0[1-9]\|[12]\d\|3[01])[-\s]?[1-8]\d{6}\b` |

## Asia-Pacific - Sri Lanka

| Pattern Name | Regex |
|---|---|
| Sri Lanka NIC New | `\b\d{12}\b` |
| Sri Lanka NIC Old | `\b\d{9}[VXvx]\b` |
| Sri Lanka Passport | `\b[A-Z]\d{7}\b` |

## Asia-Pacific - Thailand

| Pattern Name | Regex |
|---|---|
| Thailand DL | `\b\d{13}\b` |
| Thailand National ID | `\b\d[-\s]?\d{4}[-\s]?\d{5}[-\s]?\d{2}[-\s]?\d\b` |
| Thailand Passport | `\b[A-Z]{2}\d{7}\b` |
| Thailand Tax ID | `\b\d{13}\b` |

## Asia-Pacific - Vietnam

| Pattern Name | Regex |
|---|---|
| Vietnam CCCD | `\b\d{12}\b` |
| Vietnam Passport | `\b[A-Z]\d{8}\b` |
| Vietnam Tax Code | `\b\d{10}(?:-\d{3})?\b` |
