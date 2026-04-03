# Patterns: Europe

## Europe - United Kingdom

| Pattern Name | Regex |
|---|---|
| UK NIN | `\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b` |
| UK UTR | `\b\d{5}\s?\d{5}\b` |
| UK Passport | `\b\d{9}\b` |
| UK Sort Code | `\b\d{2}[-.\s/\\_\u2013\u2014\u00a0]?\d{2}[-.\s/\\_\u2013\u2014\u00a0]?\d{2}\b` |
| British NHS | `\b\d{3}\s?\d{3}\s?\d{4}\b` |
| UK Phone Number | `(?:\+44[-.\s]?\|0)(?:\d[-.\s]?){9,10}(?!\d)` |
| UK DL | `\b[A-Z]{5}\d{6}[A-Z0-9]{5}\b` |

## Europe - Germany

| Pattern Name | Regex |
|---|---|
| Germany ID | `\b[CFGHJKLMNPRTVWXYZ0-9]{9}\b` |
| Germany Passport | `\bC[A-Z0-9]{8}\b` |
| Germany Tax ID | `\b\d{11}\b` |
| Germany Social Insurance | `\b\d{2}[0-3]\d[01]\d{2}\d[A-Z]\d{3}\b` |
| Germany DL | `\b[A-Z0-9]{11}\b` |
| Germany IBAN | `\bDE\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{2}\b` |

## Europe - France

| Pattern Name | Regex |
|---|---|
| France NIR | `\b[12]\d{2}(?:0[1-9]\|1[0-2])(?:\d{2}\|2[AB])\d{3}\d{3}\d{2}\b` |
| France Passport | `\b\d{2}[A-Z]{2}\d{5}\b` |
| France CNI | `\b[A-Z0-9]{12}\b` |
| France DL | `\b\d{2}[A-Z]{2}\d{5}\b` |
| France IBAN | `\bFR\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{3}\b` |

## Europe - Italy

| Pattern Name | Regex |
|---|---|
| Italy Codice Fiscale | `\b[A-Z]{6}\d{2}[A-EHLMPR-T]\d{2}[A-Z]\d{3}[A-Z]\b` |
| Italy Passport | `\b[A-Z]{2}\d{7}\b` |
| Italy DL | `\b[A-Z]{2}\d{7}[A-Z]\b` |
| Italy SSN | `\b[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]\b` |
| Italy Partita IVA | `\b\d{11}\b` |

## Europe - Netherlands

| Pattern Name | Regex |
|---|---|
| Netherlands BSN | `\b\d{9}\b` |
| Netherlands Passport | `\b[A-Z]{2}[A-Z0-9]{6}\d\b` |
| Netherlands DL | `\b\d{10}\b` |
| Netherlands IBAN | `\bNL\d{2}\s?[A-Z]{4}\s?\d{4}\s?\d{4}\s?\d{2}\b` |

## Europe - Spain

| Pattern Name | Regex |
|---|---|
| Spain DNI | `\b\d{8}[A-Z]\b` |
| Spain NIE | `\b[XYZ]\d{7}[A-Z]\b` |
| Spain Passport | `\b[A-Z]{3}\d{6}\b` |
| Spain NSS | `\b\d{2}[-/]?\d{8}[-/]?\d{2}\b` |
| Spain DL | `\b\d{8}[A-Z]\b` |

## Europe - Poland

| Pattern Name | Regex |
|---|---|
| Poland PESEL | `\b\d{11}\b` |
| Poland NIP | `\b\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{2}[-.\s/\\_\u2013\u2014\u00a0]?\d{2}\b` |
| Poland REGON | `\b\d{9}(?:\d{5})?\b` |
| Poland ID Card | `\b[A-Z]{3}\d{6}\b` |
| Poland Passport | `\b[A-Z]{2}\d{7}\b` |
| Poland DL | `\b\d{5}[-.\s/\\_\u2013\u2014\u00a0]?\d{2}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}\b` |

## Europe - Sweden

| Pattern Name | Regex |
|---|---|
| Sweden PIN | `\b\d{6}[-+]?\d{4}\b` |
| Sweden Passport | `\b\d{8}\b` |
| Sweden DL | `\b\d{6}[-]?\d{4}\b` |
| Sweden Organisation Number | `\b\d{6}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}\b` |

## Europe - Portugal

| Pattern Name | Regex |
|---|---|
| Portugal NIF | `\b[12356789]\d{8}\b` |
| Portugal CC | `\b\d{8}\s?\d\s?[A-Z]{2}\d\b` |
| Portugal Passport | `\b[A-Z]{1,2}\d{6}\b` |
| Portugal NISS | `\b\d{11}\b` |

## Europe - Switzerland

| Pattern Name | Regex |
|---|---|
| Switzerland AHV | `\b756[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{2}\b` |
| Switzerland Passport | `\b[A-Z]\d{7}\b` |
| Switzerland DL | `\b\d{6,7}\b` |
| Switzerland UID | `\bCHE[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}\b` |

## Europe - Turkey

| Pattern Name | Regex |
|---|---|
| Turkey TC Kimlik | `\b[1-9]\d{10}\b` |
| Turkey Passport | `\b[A-Z]\d{7}\b` |
| Turkey DL | `\b\d{6}\b` |
| Turkey Tax ID | `\b\d{10}\b` |

## Europe - Austria

| Pattern Name | Regex |
|---|---|
| Austria SVN | `\b\d{4}[-\s]?\d{6}\b` |
| Austria Passport | `\b[A-Z]\d{7}\b` |
| Austria ID Card | `\b\d{8}\b` |
| Austria DL | `\b\d{8}\b` |
| Austria Tax Number | `\b\d{2}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}\b` |

## Europe - Belgium

| Pattern Name | Regex |
|---|---|
| Belgium NRN | `\b\d{2}[.\s]?\d{2}[.\s]?\d{2}[-.\s]?\d{3}[.\s]?\d{2}\b` |
| Belgium Passport | `\b[A-Z]{2}\d{6}\b` |
| Belgium DL | `\b\d{10}\b` |
| Belgium VAT | `\bBE\s?0?\d{3}\.?\d{3}\.?\d{3}\b` |

## Europe - Ireland

| Pattern Name | Regex |
|---|---|
| Ireland PPS | `\b\d{7}[A-Z]{1,2}\b` |
| Ireland Passport | `\b[A-Z]{2}\d{7}\b` |
| Ireland DL | `\b\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}\b` |
| Ireland Eircode | `\b[A-Z]\d{2}\s?[A-Z0-9]{4}\b` |

## Europe - Denmark

| Pattern Name | Regex |
|---|---|
| Denmark CPR | `\b[0-3]\d[01]\d{3}[-]?\d{4}\b` |
| Denmark Passport | `\b\d{9}\b` |
| Denmark DL | `\b\d{8}\b` |

## Europe - Finland

| Pattern Name | Regex |
|---|---|
| Finland HETU | `\b[0-3]\d[01]\d{3}[-+A]\d{3}[A-Z0-9]\b` |
| Finland Passport | `\b[A-Z]{2}\d{7}\b` |
| Finland DL | `\b\d{8,10}\b` |

## Europe - Norway

| Pattern Name | Regex |
|---|---|
| Norway FNR | `\b[0-3]\d[01]\d{3}\d{5}\b` |
| Norway D-Number | `\b[4-7]\d[01]\d{3}\d{5}\b` |
| Norway Passport | `\b\d{8}\b` |
| Norway DL | `\b\d{11}\b` |

## Europe - Czech Republic

| Pattern Name | Regex |
|---|---|
| Czech Birth Number | `\b\d{2}[0-7]\d[0-3]\d/?-?\d{3,4}\b` |
| Czech Passport | `\b\d{8}\b` |
| Czech DL | `\b[A-Z]{2}\d{6}\b` |
| Czech ICO | `\b\d{8}\b` |

## Europe - Hungary

| Pattern Name | Regex |
|---|---|
| Hungary Personal ID | `\b\d[-]?\d{6}[-]?\d{4}\b` |
| Hungary TAJ | `\b\d{3}\s?\d{3}\s?\d{3}\b` |
| Hungary Tax Number | `\b\d{10}\b` |
| Hungary Passport | `\b[A-Z]{2}\d{6,7}\b` |
| Hungary DL | `\b[A-Z]{2}\d{6}\b` |

## Europe - Romania

| Pattern Name | Regex |
|---|---|
| Romania CNP | `\b[1-8]\d{12}\b` |
| Romania CIF | `\b\d{2,10}\b` |
| Romania Passport | `\b\d{8,9}\b` |
| Romania DL | `\b\d{9}\b` |

## Europe - Greece

| Pattern Name | Regex |
|---|---|
| Greece AFM | `\b\d{9}\b` |
| Greece AMKA | `\b[0-3]\d[01]\d{3}\d{5}\b` |
| Greece ID Card | `\b[A-Z]{2}\d{6}\b` |
| Greece Passport | `\b[A-Z]{2}\d{7}\b` |
| Greece DL | `\b[A-Z]{2}\d{6}\b` |

## Europe - Croatia

| Pattern Name | Regex |
|---|---|
| Croatia OIB | `\b\d{11}\b` |
| Croatia Passport | `\b\d{9}\b` |
| Croatia ID Card | `\b\d{9}\b` |
| Croatia DL | `\b\d{8,9}\b` |

## Europe - Bulgaria

| Pattern Name | Regex |
|---|---|
| Bulgaria EGN | `\b\d{10}\b` |
| Bulgaria LNC | `\b\d{10}\b` |
| Bulgaria ID Card | `\b\d{9}\b` |
| Bulgaria Passport | `\b\d{9}\b` |

## Europe - Slovakia

| Pattern Name | Regex |
|---|---|
| Slovakia Birth Number | `\b\d{2}[0-7]\d[0-3]\d/?-?\d{3,4}\b` |
| Slovakia Passport | `\b[A-Z]{2}\d{6}\b` |
| Slovakia DL | `\b[A-Z]{2}\d{6}\b` |

## Europe - Lithuania

| Pattern Name | Regex |
|---|---|
| Lithuania Asmens Kodas | `\b[3-6]\d{2}[01]\d[0-3]\d{5}\b` |
| Lithuania Passport | `\b\d{8}\b` |
| Lithuania DL | `\b\d{8}\b` |

## Europe - Latvia

| Pattern Name | Regex |
|---|---|
| Latvia Personas Kods | `\b[0-3]\d[01]\d{3}[-]?\d{5}\b` |
| Latvia Passport | `\b[A-Z]{2}\d{7}\b` |
| Latvia DL | `\b[A-Z]{2}\d{6}\b` |

## Europe - Estonia

| Pattern Name | Regex |
|---|---|
| Estonia Isikukood | `\b[1-6]\d{2}[01]\d[0-3]\d{5}\b` |
| Estonia Passport | `\b[A-Z]{2}\d{7}\b` |
| Estonia DL | `\b[A-Z]{2}\d{6}\b` |

## Europe - Slovenia

| Pattern Name | Regex |
|---|---|
| Slovenia EMSO | `\b[0-3]\d[01]\d{3}\d{6}\d\b` |
| Slovenia Tax Number | `\b\d{8}\b` |
| Slovenia Passport | `\b[A-Z]{2}\d{7}\b` |
| Slovenia DL | `\b\d{8}\b` |

## Europe - Luxembourg

| Pattern Name | Regex |
|---|---|
| Luxembourg NIN | `\b\d{4}[01]\d[0-3]\d\d{5}\b` |
| Luxembourg Passport | `\b[A-Z]{2}\d{6}\b` |
| Luxembourg DL | `\b\d{6}\b` |

## Europe - Malta

| Pattern Name | Regex |
|---|---|
| Malta ID Card | `\b\d{3,7}[A-Z]\b` |
| Malta Passport | `\b\d{7}\b` |
| Malta TIN | `\b\d{3,9}[A-Z]?\b` |

## Europe - Cyprus

| Pattern Name | Regex |
|---|---|
| Cyprus ID Card | `\b\d{7,8}\b` |
| Cyprus Passport | `\b[A-Z]\d{7,8}\b` |
| Cyprus TIN | `\b\d{8}[A-Z]\b` |

## Europe - Iceland

| Pattern Name | Regex |
|---|---|
| Iceland Kennitala | `\b[0-3]\d[01]\d{3}[-]?\d{4}\b` |
| Iceland Passport | `\b[A-Z]\d{7}\b` |

## Europe - Liechtenstein

| Pattern Name | Regex |
|---|---|
| Liechtenstein PIN | `\b\d{12}\b` |
| Liechtenstein Passport | `\b[A-Z]\d{5}\b` |

## Europe - EU

| Pattern Name | Regex |
|---|---|
| EU ETD | `\b[A-Z]{3}\d{6}\b` |
| EU VAT Generic | `\b(?:AT\|BE\|BG\|CY\|CZ\|DE\|DK\|EE\|EL\|ES\|FI\|FR\|HR\|HU\|IE\|IT\|LT\|LU\|LV\|MT\|NL\|PL\|PT\|RO\|SE\|SI\|SK)[A-Z0-9]{8,12}\b` |
