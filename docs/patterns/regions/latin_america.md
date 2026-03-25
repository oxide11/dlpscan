# Latin America — Regex Patterns

> Language-agnostic regex patterns for sensitive data detection.
> All patterns use standard regex syntax compatible with PCRE, Python `re`, JavaScript, Go, Java, etc.

---

## Latin America - Argentina

| Pattern Name | Regex |
|---|---|
| Argentina CUIL/CUIT | `\b(?:20\|2[3-7]\|30\|33)[-.\s/\\_\u2013\u2014\u00a0]?\d{8}[-.\s/\\_\u2013\u2014\u00a0]?\d\b` |
| Argentina DNI | `\b\d{7,8}\b` |
| Argentina Passport | `\b[A-Z]{3}\d{6}\b` |

## Latin America - Brazil

| Pattern Name | Regex |
|---|---|
| Brazil CNH | `\b\d{11}\b` |
| Brazil CNPJ | `\b\d{2}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{2}\b` |
| Brazil CPF | `\b\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{2}\b` |
| Brazil Passport | `\b[A-Z]{2}\d{6}\b` |
| Brazil RG | `\b\d{1,2}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?[\dXx]\b` |
| Brazil SUS Card | `\b[1-2]\d{10}00[01]\d\b\|\b[789]\d{14}\b` |

## Latin America - Chile

| Pattern Name | Regex |
|---|---|
| Chile Passport | `\b[A-Z]?\d{7,8}\b` |
| Chile RUN/RUT | `\b\d{1,2}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?[\dkK]\b` |

## Latin America - Colombia

| Pattern Name | Regex |
|---|---|
| Colombia Cedula | `\b\d{6,10}\b` |
| Colombia NIT | `\b\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d\b` |
| Colombia NUIP | `\b\d{6,10}\b` |
| Colombia Passport | `\b[A-Z]{2}\d{6,7}\b` |

## Latin America - Costa Rica

| Pattern Name | Regex |
|---|---|
| Costa Rica Cedula | `\b\d{1}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}\b` |
| Costa Rica DIMEX | `\b\d{11,12}\b` |
| Costa Rica Passport | `\b[A-Z]\d{8}\b` |

## Latin America - Ecuador

| Pattern Name | Regex |
|---|---|
| Ecuador Cedula | `\b\d{10}\b` |
| Ecuador Passport | `\b[A-Z]\d{7,8}\b` |
| Ecuador RUC | `\b\d{13}\b` |

## Latin America - Paraguay

| Pattern Name | Regex |
|---|---|
| Paraguay Cedula | `\b\d{5,7}\b` |
| Paraguay Passport | `\b[A-Z]\d{6,8}\b` |
| Paraguay RUC | `\b\d{6,8}[-.\s/\\_\u2013\u2014\u00a0]?\d\b` |

## Latin America - Peru

| Pattern Name | Regex |
|---|---|
| Peru Carnet Extranjeria | `\b\d{9,12}\b` |
| Peru DNI | `\b\d{8}\b` |
| Peru Passport | `\b[A-Z]{2}\d{6,7}\b` |
| Peru RUC | `\b(?:10\|15\|17\|20)\d{9}\b` |

## Latin America - Uruguay

| Pattern Name | Regex |
|---|---|
| Uruguay Cedula | `\b\d{1}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d\b` |
| Uruguay Passport | `\b[A-Z]\d{6,8}\b` |
| Uruguay RUT | `\b\d{12}\b` |

## Latin America - Venezuela

| Pattern Name | Regex |
|---|---|
| Venezuela Cedula | `\b[VvEe][-.\s/\\_\u2013\u2014\u00a0]?\d{6,9}\b` |
| Venezuela Passport | `\b[A-Z]\d{7,8}\b` |
| Venezuela RIF | `\b[VEJGvejg][-.\s/\\_\u2013\u2014\u00a0]?\d{8}[-.\s/\\_\u2013\u2014\u00a0]?\d\b` |
