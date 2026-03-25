# Supported Patterns

dlpscan v0.2.0 supports **111 patterns** across **12 categories**.

---

## 1. Personal Identification (28 patterns)

| # | Pattern | Format | Example |
|---|---------|--------|---------|
| 1 | Canada SIN | XXX-XXX-XXX | `123-456-789` |
| 2 | USA SSN | XXX-XX-XXXX | `123-45-6789` |
| 3 | USA ITIN | 9XX-XX-XXXX | `912-34-5678` |
| 4 | USA EIN | XX-XXXXXXX | `12-3456789` |
| 5 | UK NIN | XX999999X | `AB123456C` |
| 6 | UK UTR | 10 digits | `1234567890` |
| 7 | Singapore NIRC | X9999999X | `S1234567A` |
| 8 | Australia TFN | 8-9 digits | `12345678` |
| 9 | India PAN | XXXXX9999X | `ABCDE1234F` |
| 10 | India Aadhaar | XXXX XXXX XXXX | `1234 5678 9012` |
| 11 | Germany ID | 9 alphanumeric | `CFGHJK012` |
| 12 | France NIR | 15 digits | `185073512301234` |
| 13 | Italy Codice Fiscale | 16 alphanumeric | `RSSMRA85M01H501Z` |
| 14 | Netherlands BSN | 8-9 digits | `123456789` |
| 15 | South Korea RRN | XXXXXX-XXXXXXX | `850101-1234567` |
| 16 | Japan My Number | 12 digits | `123456789012` |
| 17 | Mexico CURP | 18 alphanumeric | `GARC850101HDFRRL09` |
| 18 | Mexico RFC | 12-13 alphanumeric | `GARC850101AAA` |
| 19 | South Africa ID | 13 digits | `8501015009087` |
| 20 | China Resident ID | 17 digits + digit/X | `11010119850101001X` |
| 21 | Brazil CPF | XXX.XXX.XXX-XX | `123.456.789-09` |
| 22 | Spain DNI/NIE | [XYZ]?XXXXXXX[A-Z] | `X1234567L` |
| 23 | Canada BN | 9 digits + 2 letters + 4 digits | `123456789RC0001` |
| 24 | Poland PESEL | 11 digits | `85010112345` |
| 25 | Sweden PIN | YYMMDD-XXXX | `850101-1234` |
| 26 | Portugal NIF | 9 digits | `123456789` |
| 27 | Switzerland AHV | 756.XXXX.XXXX.XX | `756.1234.5678.90` |
| 28 | Turkey TC Kimlik | 11 digits (non-zero start) | `12345678901` |

## 2. Credit Card Numbers (7 patterns)

All credit card matches are validated using the **Luhn algorithm** to reduce false positives.

| # | Pattern | Prefix | Digits | Example |
|---|---------|--------|--------|---------|
| 29 | Visa | 4 | 16 | `4111 1111 1111 1111` |
| 30 | MasterCard | 51-55, 2221-2720 | 16 | `5500 0000 0000 0004` |
| 31 | Amex | 34, 37 | 15 | `3782 822463 10005` |
| 32 | Discover | 6011, 644-649, 65 | 16 | `6011 0000 0000 0004` |
| 33 | JCB | 3528-3589 | 16 | `3530 1113 3330 0000` |
| 34 | Diners Club | 300-305, 36, 38 | 14 | `3056 930902 5904` |
| 35 | UnionPay | 62 | 16-19 | `6200 0000 0000 0000` |

## 3. Driver Licenses (9 patterns)

| # | Pattern | Format | Example |
|---|---------|--------|---------|
| 36 | Generic | 1-2 letters + 4-9 digits | `AB12345` |
| 37 | California DL | letter + 7 digits | `A1234567` |
| 38 | New York DL | letter + 7-18 digits | `A1234567` |
| 39 | India DL | 2 letters + 13 digits | `MH1234567890123` |
| 40 | Ontario | X9999-99999-99999 | `A1234-56789-01234` |
| 41 | British Columbia | 7 digits | `1234567` |
| 42 | Alberta DL | letter + 4-9 digits | `A123456` |
| 43 | Quebec DL | 2 letters + 4-9 digits | `AB123456` |
| 44 | Nova Scotia DL | 2 letters + 4-9 digits | `AB123456` |

## 4. Health Cards & Medical Identifiers (9 patterns)

| # | Pattern | Format | Example |
|---|---------|--------|---------|
| 45 | Ontario | 10 digits | `1234567890` |
| 46 | British NHS | 10 digits | `1234567890` |
| 47 | Australia Medicare | 11 digits | `12345678901` |
| 48 | Alberta HC | X9999-99999 | `A1234-56789` |
| 49 | Quebec HC | 12 digits | `123456789012` |
| 50 | Nova Scotia HC | 10 digits | `1234567890` |
| 51 | US DEA Number | 2 letters + 7 digits | `AB1234567` |
| 52 | US NPI | 10 digits (starts 1/2) | `1234567890` |
| 53 | US MBI | Alphanumeric MBI format | `1A00-A00-AA00` |

## 5. Passports (11 patterns)

| # | Pattern | Format | Example |
|---|---------|--------|---------|
| 54 | Canada | 2 letters + 6 digits | `AB123456` |
| 55 | USA Passport | 9 digits | `123456789` |
| 56 | EU ETD | 3 letters + 6 digits | `ABC123456` |
| 57 | Japan Passport | M/S/R/C + 7 digits | `M1234567` |
| 58 | UK Passport | 9 digits | `123456789` |
| 59 | Germany Passport | C + 8 alphanumeric | `CABCDEFG1` |
| 60 | France Passport | 2 digits + 2 letters + 5 digits | `12AB34567` |
| 61 | India Passport | letter + 7 digits | `A1234567` |
| 62 | China Passport | E/G + 8 digits | `E12345678` |
| 63 | Australia Passport | letter + 7 digits | `A1234567` |
| 64 | Brazil Passport | 2 letters + 6 digits | `AB123456` |

## 6. Bank Account Numbers (5 patterns)

| # | Pattern | Format | Example |
|---|---------|--------|---------|
| 65 | IBAN Generic | CC99 XXXX XXXX ... | `GB29 NWBK 6016 1331 9268 19` |
| 66 | USA Routing Number | 9 digits | `021000021` |
| 67 | Canada Bank Code | XXXXX-XXX | `12345-001` |
| 68 | UK Sort Code | XX-XX-XX | `12-34-56` |
| 69 | SWIFT/BIC | 8 or 11 characters | `DEUTDEFF` |

## 7. Contact Information (7 patterns)

| # | Pattern | Format | Example |
|---|---------|--------|---------|
| 70 | Email Address | user@domain.tld | `john.doe@example.com` |
| 71 | US Phone Number | (XXX) XXX-XXXX | `(555) 123-4567` |
| 72 | UK Phone Number | +44 XXXX XXXXXX | `+44 7911 123456` |
| 73 | E.164 Phone Number | +CCCXXXXXXXXX | `+14155552671` |
| 74 | IPv4 Address | X.X.X.X | `192.168.1.1` |
| 75 | IPv6 Address | X:X:X:X:X:X:X:X | `2001:0db8:85a3:0000:0000:8a2e:0370:7334` |
| 76 | MAC Address | XX:XX:XX:XX:XX:XX | `00:1A:2B:3C:4D:5E` |

## 8. API Keys and Secrets (22 patterns)

| # | Pattern | Prefix/Format | Example |
|---|---------|---------------|---------|
| 77 | AWS Access Key | `AKIA` + 16 chars | `AKIAIOSFODNN7EXAMPLE` |
| 78 | AWS Secret Key | 40 base64 chars | (40-char string) |
| 79 | Google API Key | `AIza` + 35 chars | `AIzaSyA1234567890abcdefghijklmnopqrst` |
| 80 | GitHub Token (Classic) | `ghp_` + 36 chars | `ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345` |
| 81 | GitHub Token (Fine-Grained) | `github_pat_` + 22-82 chars | `github_pat_...` |
| 82 | GitHub OAuth Token | `gho_` + 36 chars | `gho_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345` |
| 83 | Stripe Secret Key | `sk_live_` / `sk_test_` | `sk_live_aBcDeFgHiJkLmNoPqRsTuVw` |
| 84 | Stripe Publishable Key | `pk_live_` / `pk_test_` | `pk_test_aBcDeFgHiJkLmNoPqRsTuVw` |
| 85 | Slack Bot Token | `xoxb-` | `xoxb-123-456-abc` |
| 86 | Slack User Token | `xoxp-` | `xoxp-123-456-abc` |
| 87 | Slack Webhook | `https://hooks.slack.com/...` | (full webhook URL) |
| 88 | Bearer Token | `Bearer` + token | `Bearer eyJhbGciOi...` |
| 89 | JWT Token | `eyJ` + 3 base64 segments | `eyJhbGciOi...` |
| 90 | Private Key | `-----BEGIN ... PRIVATE KEY-----` | (PEM header) |
| 91 | Generic API Key | `api_key=...` / `api-secret: ...` | `api_key=abc123def456ghi789` |
| 92 | Generic Secret Assignment | `password=...` / `secret: ...` | `password=myS3cretP@ss` |
| 93 | Database Connection String | `protocol://user:pass@host` | `postgres://admin:pw@localhost/db` |
| 94 | SendGrid API Key | `SG.` + 22 + `.` + 43 chars | `SG.xxxxx.yyyyy` |
| 95 | Twilio API Key | `SK` + 32 hex chars | `SK1234abcd5678efgh9012ijkl3456mnop` |
| 96 | Mailgun API Key | `key-` + 32 chars | `key-1234567890abcdef1234567890abcdef` |
| 97 | NPM Token | `npm_` + 36 chars | `npm_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345` |
| 98 | PyPI Token | `pypi-` + 16+ chars | `pypi-AgEIcHlwaS5vcmcC...` |

## 9. Cryptocurrency (7 patterns)

| # | Pattern | Prefix | Example |
|---|---------|--------|---------|
| 99 | Bitcoin Address (Legacy) | `1` or `3` | `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa` |
| 100 | Bitcoin Address (Bech32) | `bc1` | `bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4` |
| 101 | Ethereum Address | `0x` + 40 hex | `0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18` |
| 102 | Litecoin Address | `L` or `M` | `LaMT348PWRnrqeeWArpwQPbuanpXDZGEUz` |
| 103 | Bitcoin Cash Address | `bitcoincash:` / `q`/`p` | `bitcoincash:qpm2qsznhks23z7629...` |
| 104 | Monero Address | `4` | `4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkb...` |
| 105 | Ripple Address | `r` | `rN7n3473SaZBCG4dFL83w7p1W9cgZw6w3v` |

## 10. Vehicle Identification (1 pattern)

| # | Pattern | Format | Example |
|---|---------|--------|---------|
| 106 | VIN | 17 alphanumeric (no I/O/Q) | `1HGCM82633A004352` |

## 11. Dates (3 patterns)

These patterns are **context-gated** — they are most useful when detected near keywords like "date of birth", "DOB", "birthday", etc.

| # | Pattern | Format | Example |
|---|---------|--------|---------|
| 107 | Date ISO | YYYY-MM-DD | `1990-01-15` |
| 108 | Date US | MM/DD/YYYY | `01/15/1990` |
| 109 | Date EU | DD/MM/YYYY | `15/01/1990` |

## 12. URLs with Credentials (2 patterns)

| # | Pattern | Description | Example |
|---|---------|-------------|---------|
| 110 | URL with Password | Embedded user:pass in URL | `https://admin:secret@host.com/path` |
| 111 | URL with Token | Token/key in query string | `https://api.example.com?api_key=abc123` |
