# Supported Patterns

dlpscan v0.2.0 supports **111 patterns** across **35 categories**, organized into three sections.

---

## Section 1: Generic Patterns

Universal formats not tied to any specific country or vendor.

### Credit Card Numbers (7 patterns)

All credit card matches are validated using the **Luhn algorithm** to reduce false positives.

| # | Pattern | Prefix | Digits | Example |
|---|---------|--------|--------|---------|
| 1 | Visa | 4 | 16 | `4111 1111 1111 1111` |
| 2 | MasterCard | 51-55, 2221-2720 | 16 | `5500 0000 0000 0004` |
| 3 | Amex | 34, 37 | 15 | `3782 822463 10005` |
| 4 | Discover | 6011, 644-649, 65 | 16 | `6011 0000 0000 0004` |
| 5 | JCB | 3528-3589 | 16 | `3530 1113 3330 0000` |
| 6 | Diners Club | 300-305, 36, 38 | 14 | `3056 930902 5904` |
| 7 | UnionPay | 62 | 16-19 | `6200 0000 0000 0000` |

### Contact Information (5 patterns)

| # | Pattern | Format | Example |
|---|---------|--------|---------|
| 8 | Email Address | user@domain.tld | `john.doe@example.com` |
| 9 | E.164 Phone Number | +CCCXXXXXXXXX | `+14155552671` |
| 10 | IPv4 Address | X.X.X.X | `192.168.1.1` |
| 11 | IPv6 Address | X:X:X:X:X:X:X:X | `2001:0db8:85a3:0000:0000:8a2e:0370:7334` |
| 12 | MAC Address | XX:XX:XX:XX:XX:XX | `00:1A:2B:3C:4D:5E` |

### Banking and Financial (2 patterns)

| # | Pattern | Format | Example |
|---|---------|--------|---------|
| 13 | IBAN Generic | CC99 XXXX XXXX ... | `GB29 NWBK 6016 1331 9268 19` |
| 14 | SWIFT/BIC | 8 or 11 characters | `DEUTDEFF` |

### Cryptocurrency (7 patterns)

| # | Pattern | Prefix | Example |
|---|---------|--------|---------|
| 15 | Bitcoin Address (Legacy) | `1` or `3` | `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa` |
| 16 | Bitcoin Address (Bech32) | `bc1` | `bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4` |
| 17 | Ethereum Address | `0x` + 40 hex | `0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18` |
| 18 | Litecoin Address | `L` or `M` | `LaMT348PWRnrqeeWArpwQPbuanpXDZGEUz` |
| 19 | Bitcoin Cash Address | `bitcoincash:` / `q`/`p` | `bitcoincash:qpm2qsznhks23z7629...` |
| 20 | Monero Address | `4` | `4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkb...` |
| 21 | Ripple Address | `r` | `rN7n3473SaZBCG4dFL83w7p1W9cgZw6w3v` |

### Vehicle Identification (1 pattern)

| # | Pattern | Format | Example |
|---|---------|--------|---------|
| 22 | VIN | 17 alphanumeric (no I/O/Q) | `1HGCM82633A004352` |

### Dates (3 patterns)

Context-gated — most useful when detected near keywords like "date of birth", "DOB", "birthday".

| # | Pattern | Format | Example |
|---|---------|--------|---------|
| 23 | Date ISO | YYYY-MM-DD | `1990-01-15` |
| 24 | Date US | MM/DD/YYYY | `01/15/1990` |
| 25 | Date EU | DD/MM/YYYY | `15/01/1990` |

### URLs with Credentials (2 patterns)

| # | Pattern | Description | Example |
|---|---------|-------------|---------|
| 26 | URL with Password | Embedded user:pass in URL | `https://admin:secret@host.com/path` |
| 27 | URL with Token | Token/key in query string | `https://api.example.com?api_key=abc123` |

### Generic Secrets (6 patterns)

| # | Pattern | Format | Example |
|---|---------|--------|---------|
| 28 | Bearer Token | `Bearer` + token string | `Bearer eyJhbGciOi...` |
| 29 | JWT Token | 3 base64url segments | `eyJhbGciOi.eyJzdWIi.SflKxwRJ` |
| 30 | Private Key | PEM header | `-----BEGIN RSA PRIVATE KEY-----` |
| 31 | Generic API Key | `api_key=...` | `api_key=abc123def456ghi789` |
| 32 | Generic Secret Assignment | `password=...` | `password=myS3cretP@ss` |
| 33 | Database Connection String | `protocol://user:pass@host` | `postgres://admin:pw@localhost/db` |

---

## Section 2: Custom Patterns

Vendor and service-specific secrets and tokens.

### Cloud Provider Secrets (3 patterns)

| # | Pattern | Prefix/Format | Example |
|---|---------|---------------|---------|
| 34 | AWS Access Key | `AKIA` + 16 chars | `AKIAIOSFODNN7EXAMPLE` |
| 35 | AWS Secret Key | 40 base64 chars | (40-character string) |
| 36 | Google API Key | `AIza` + 35 chars | `AIzaSyA1234567890abcdefghijklmnopqrst` |

### Code Platform Secrets (5 patterns)

| # | Pattern | Prefix | Example |
|---|---------|--------|---------|
| 37 | GitHub Token (Classic) | `ghp_` | `ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345` |
| 38 | GitHub Token (Fine-Grained) | `github_pat_` | `github_pat_...` |
| 39 | GitHub OAuth Token | `gho_` | `gho_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345` |
| 40 | NPM Token | `npm_` | `npm_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345` |
| 41 | PyPI Token | `pypi-` | `pypi-AgEIcHlwaS5vcmcC...` |

### Payment Service Secrets (2 patterns)

| # | Pattern | Prefix | Example |
|---|---------|--------|---------|
| 42 | Stripe Secret Key | `sk_live_` / `sk_test_` | `sk_live_aBcDeFgHiJkLmNoPqRsTuVw` |
| 43 | Stripe Publishable Key | `pk_live_` / `pk_test_` | `pk_test_aBcDeFgHiJkLmNoPqRsTuVw` |

### Messaging Service Secrets (6 patterns)

| # | Pattern | Prefix | Example |
|---|---------|--------|---------|
| 44 | Slack Bot Token | `xoxb-` | `xoxb-123-456-abc` |
| 45 | Slack User Token | `xoxp-` | `xoxp-123-456-abc` |
| 46 | Slack Webhook | `https://hooks.slack.com/...` | (full webhook URL) |
| 47 | SendGrid API Key | `SG.` | `SG.xxxxx.yyyyy` |
| 48 | Twilio API Key | `SK` + 32 hex | `SK1234abcd5678efgh9012ijkl3456mnop` |
| 49 | Mailgun API Key | `key-` + 32 chars | `key-1234567890abcdef1234567890abcdef` |

---

## Section 3: Geographic Regions

Country and region-specific identifiers.

### North America — United States (12 patterns)

| # | Pattern | Format | Example |
|---|---------|--------|---------|
| 50 | USA SSN | XXX-XX-XXXX | `123-45-6789` |
| 51 | USA ITIN | 9XX-XX-XXXX | `912-34-5678` |
| 52 | USA EIN | XX-XXXXXXX | `12-3456789` |
| 53 | USA Passport | 9 digits | `123456789` |
| 54 | USA Routing Number | 9 digits | `021000021` |
| 55 | US DEA Number | 2 letters + 7 digits | `AB1234567` |
| 56 | US NPI | 10 digits (starts 1/2) | `1234567890` |
| 57 | US MBI | Alphanumeric MBI format | `1A00-A00-AA00` |
| 58 | US Phone Number | (XXX) XXX-XXXX | `(555) 123-4567` |
| 59 | California DL | letter + 7 digits | `A1234567` |
| 60 | New York DL | letter + 7-18 digits | `A1234567` |
| 61 | Generic DL | 1-2 letters + 4-9 digits | `AB12345` |

### North America — Canada (13 patterns)

| # | Pattern | Format | Example |
|---|---------|--------|---------|
| 62 | Canada SIN | XXX-XXX-XXX | `123-456-789` |
| 63 | Canada BN | 9 digits + 2 letters + 4 digits | `123456789RC0001` |
| 64 | Canada Passport | 2 letters + 6 digits | `AB123456` |
| 65 | Canada Bank Code | XXXXX-XXX | `12345-001` |
| 66 | Ontario DL | X9999-99999-99999 | `A1234-56789-01234` |
| 67 | Ontario HC | 10 digits | `1234567890` |
| 68 | British Columbia DL | 7 digits | `1234567` |
| 69 | Alberta DL | letter + 4-9 digits | `A123456` |
| 70 | Alberta HC | X9999-99999 | `A1234-56789` |
| 71 | Quebec DL | 2 letters + 4-9 digits | `AB123456` |
| 72 | Quebec HC | 12 digits | `123456789012` |
| 73 | Nova Scotia DL | 2 letters + 4-9 digits | `AB123456` |
| 74 | Nova Scotia HC | 10 digits | `1234567890` |

### North America — Mexico (2 patterns)

| # | Pattern | Format | Example |
|---|---------|--------|---------|
| 75 | Mexico CURP | 18 alphanumeric | `GARC850101HDFRRL09` |
| 76 | Mexico RFC | 12-13 alphanumeric | `GARC850101AAA` |

### Europe — United Kingdom (6 patterns)

| # | Pattern | Format | Example |
|---|---------|--------|---------|
| 77 | UK NIN | XX999999X | `AB123456C` |
| 78 | UK UTR | 10 digits | `1234567890` |
| 79 | UK Passport | 9 digits | `123456789` |
| 80 | UK Sort Code | XX-XX-XX | `12-34-56` |
| 81 | British NHS | 10 digits | `1234567890` |
| 82 | UK Phone Number | +44 XXXX XXXXXX | `+44 7911 123456` |

### Europe — Germany (2 patterns)

| # | Pattern | Format | Example |
|---|---------|--------|---------|
| 83 | Germany ID | 9 alphanumeric | `CFGHJK012` |
| 84 | Germany Passport | C + 8 alphanumeric | `CABCDEFG1` |

### Europe — France (2 patterns)

| # | Pattern | Format | Example |
|---|---------|--------|---------|
| 85 | France NIR | 15 digits | `185073512301234` |
| 86 | France Passport | 2 digits + 2 letters + 5 digits | `12AB34567` |

### Europe — Italy (1 pattern)

| # | Pattern | Format | Example |
|---|---------|--------|---------|
| 87 | Italy Codice Fiscale | 16 alphanumeric | `RSSMRA85M01H501Z` |

### Europe — Netherlands (1 pattern)

| # | Pattern | Format | Example |
|---|---------|--------|---------|
| 88 | Netherlands BSN | 8-9 digits | `123456789` |

### Europe — Spain (1 pattern)

| # | Pattern | Format | Example |
|---|---------|--------|---------|
| 89 | Spain DNI/NIE | [XYZ]?XXXXXXX[A-Z] | `X1234567L` |

### Europe — Poland (1 pattern)

| # | Pattern | Format | Example |
|---|---------|--------|---------|
| 90 | Poland PESEL | 11 digits | `85010112345` |

### Europe — Sweden (1 pattern)

| # | Pattern | Format | Example |
|---|---------|--------|---------|
| 91 | Sweden PIN | YYMMDD-XXXX | `850101-1234` |

### Europe — Portugal (1 pattern)

| # | Pattern | Format | Example |
|---|---------|--------|---------|
| 92 | Portugal NIF | 9 digits | `123456789` |

### Europe — Switzerland (1 pattern)

| # | Pattern | Format | Example |
|---|---------|--------|---------|
| 93 | Switzerland AHV | 756.XXXX.XXXX.XX | `756.1234.5678.90` |

### Europe — Turkey (1 pattern)

| # | Pattern | Format | Example |
|---|---------|--------|---------|
| 94 | Turkey TC Kimlik | 11 digits (non-zero start) | `12345678901` |

### Europe — EU (1 pattern)

| # | Pattern | Format | Example |
|---|---------|--------|---------|
| 95 | EU ETD | 3 letters + 6 digits | `ABC123456` |

### Asia-Pacific — India (4 patterns)

| # | Pattern | Format | Example |
|---|---------|--------|---------|
| 96 | India PAN | XXXXX9999X | `ABCDE1234F` |
| 97 | India Aadhaar | XXXX XXXX XXXX | `1234 5678 9012` |
| 98 | India Passport | letter + 7 digits | `A1234567` |
| 99 | India DL | 2 letters + 13 digits | `MH1234567890123` |

### Asia-Pacific — Singapore (1 pattern)

| # | Pattern | Format | Example |
|---|---------|--------|---------|
| 100 | Singapore NIRC | X9999999X | `S1234567A` |

### Asia-Pacific — Australia (3 patterns)

| # | Pattern | Format | Example |
|---|---------|--------|---------|
| 101 | Australia TFN | 8-9 digits | `12345678` |
| 102 | Australia Medicare | 11 digits | `12345678901` |
| 103 | Australia Passport | letter + 7 digits | `A1234567` |

### Asia-Pacific — Japan (2 patterns)

| # | Pattern | Format | Example |
|---|---------|--------|---------|
| 104 | Japan My Number | 12 digits | `123456789012` |
| 105 | Japan Passport | M/S/R/C + 7 digits | `M1234567` |

### Asia-Pacific — South Korea (1 pattern)

| # | Pattern | Format | Example |
|---|---------|--------|---------|
| 106 | South Korea RRN | XXXXXX-XXXXXXX | `850101-1234567` |

### Asia-Pacific — China (2 patterns)

| # | Pattern | Format | Example |
|---|---------|--------|---------|
| 107 | China Resident ID | 17 digits + digit/X | `11010119850101001X` |
| 108 | China Passport | E/G + 8 digits | `E12345678` |

### South America — Brazil (2 patterns)

| # | Pattern | Format | Example |
|---|---------|--------|---------|
| 109 | Brazil CPF | XXX.XXX.XXX-XX | `123.456.789-09` |
| 110 | Brazil Passport | 2 letters + 6 digits | `AB123456` |

### Africa — South Africa (1 pattern)

| # | Pattern | Format | Example |
|---|---------|--------|---------|
| 111 | South Africa ID | 13 digits | `8501015009087` |
