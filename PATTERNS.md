# Supported Patterns

dlpscan v0.3.0 supports **587 patterns** across **127 categories**, organized into three sections.

---

## Section 1: Generic Patterns

Universal formats not tied to any specific country or vendor.

### Authentication Tokens (4 patterns)

- CSRF Token
- OTP Code
- Refresh Token
- Session ID

### Banking Authentication (4 patterns)

- Encryption Key
- HSM Key
- PIN
- PIN Block

### Banking and Financial (5 patterns)

- ABA Routing Number
- Canada Transit Number
- IBAN Generic
- SWIFT/BIC
- US Bank Account Number

### Biometric Identifiers (2 patterns)

- Biometric Hash
- Biometric Template ID

### Card Expiration Dates (1 patterns)

- Card Expiry

### Card Track Data (2 patterns)

- Track 1 Data
- Track 2 Data

### Check and MICR Data (3 patterns)

- Cashier Check Number
- Check Number
- MICR Line

### Contact Information (5 patterns)

- E.164 Phone Number
- Email Address
- IPv4 Address
- IPv6 Address
- MAC Address

### Corporate Classification (9 patterns)

- Corporate Confidential
- Do Not Distribute
- Embargoed
- Eyes Only
- Highly Confidential
- Internal Only
- Need to Know
- Proprietary
- Restricted

### Credit Card Numbers (7 patterns)

- Amex
- Diners Club
- Discover
- JCB
- MasterCard
- UnionPay
- Visa

### Credit Card Security Codes (2 patterns)

- Amex CID
- CVV/CVC/CCV

### Cryptocurrency (7 patterns)

- Bitcoin Address (Bech32)
- Bitcoin Address (Legacy)
- Bitcoin Cash Address
- Ethereum Address
- Litecoin Address
- Monero Address
- Ripple Address

### Customer Financial Data (5 patterns)

- Account Balance
- Balance with Currency Code
- Credit Score
- DTI Ratio
- Income Amount

### Data Classification Labels (8 patterns)

- CUI
- Confidential Classification
- FOUO
- LES
- NOFORN
- SBU
- Secret Classification
- Top Secret

### Dates (3 patterns)

- Date EU
- Date ISO
- Date US

### Device Identifiers (8 patterns)

- Android Device ID
- Device Serial Number
- ICCID
- IDFA/IDFV
- IMEI
- IMEISV
- IMSI
- MEID

### Education Identifiers (3 patterns)

- EDU Email
- GPA
- Student ID

### Employment Identifiers (2 patterns)

- Employee ID
- Work Permit Number

### Financial Regulatory Labels (7 patterns)

- Draft Not for Circulation
- Information Barrier
- Inside Information
- Investment Restricted
- MNPI
- Market Sensitive
- Pre-Decisional

### Generic Secrets (6 patterns)

- Bearer Token
- Database Connection String
- Generic API Key
- Generic Secret Assignment
- JWT Token
- Private Key

### Geolocation (3 patterns)

- GPS Coordinates
- GPS DMS
- Geohash

### Insurance Identifiers (3 patterns)

- Insurance Claim Number
- Insurance Group Number
- Insurance Policy Number

### Internal Banking References (4 patterns)

- Branch Code
- Customer ID
- Internal Account Ref
- Teller ID

### Legal Identifiers (3 patterns)

- Bar Number
- Court Docket Number
- US Federal Case Number

### Loan and Mortgage Data (4 patterns)

- LTV Ratio
- Loan Number
- MERS MIN
- Universal Loan Identifier

### Medical Identifiers (5 patterns)

- DEA Number
- Health Plan ID
- ICD-10 Code
- Medical Record Number
- NDC Code

### PCI Sensitive Data (5 patterns)

- Cardholder Name Pattern
- Dynamic CVV
- PVKI
- PVV
- Service Code

### Personal Identifiers (3 patterns)

- Age Value
- Date of Birth
- Gender Marker

### Postal Codes (8 patterns)

- Australia Postcode
- Brazil CEP
- Canada Postal Code
- Germany PLZ
- India PIN Code
- Japan Postal Code
- UK Postcode
- US ZIP Code

### Primary Account Numbers (3 patterns)

- BIN/IIN
- Masked PAN
- PAN

### Privacy Classification (10 patterns)

- CCPA/CPRA
- FERPA
- GDPR Personal Data
- GLBA
- HIPAA
- NPI
- PCI-DSS
- PHI Label
- PII Label
- SOX

### Privileged Information (7 patterns)

- Attorney-Client Privilege
- Legal Privilege
- Litigation Hold
- Privileged Information
- Privileged and Confidential
- Protected by Privilege
- Work Product

### Property Identifiers (2 patterns)

- Parcel Number
- Title Deed Number

### Regulatory Identifiers (6 patterns)

- AML Case ID
- CTR Number
- Compliance Case Number
- FinCEN Report Number
- OFAC SDN Entry
- SAR Filing Number

### Securities Identifiers (6 patterns)

- CUSIP
- FIGI
- ISIN
- LEI
- SEDOL
- Ticker Symbol

### Social Media Identifiers (3 patterns)

- Hashtag
- Social Media User ID
- Twitter Handle

### Supervisory Information (6 patterns)

- CSI
- Examination Findings
- Non-Public Supervisory
- Restricted Supervisory
- Supervisory Confidential
- Supervisory Controlled

### URLs with Credentials (2 patterns)

- URL with Password
- URL with Token

### Vehicle Identification (1 patterns)

- VIN

### Wire Transfer Data (6 patterns)

- ACH Batch Number
- ACH Trace Number
- CHIPS UID
- Fedwire IMAD
- SEPA Reference
- Wire Reference Number

---

## Section 2: Custom Patterns

Vendor-specific tokens, keys, and secrets.

### Cloud Provider Secrets (3 patterns)

- AWS Access Key
- AWS Secret Key
- Google API Key

### Code Platform Secrets (5 patterns)

- GitHub OAuth Token
- GitHub Token (Classic)
- GitHub Token (Fine-Grained)
- NPM Token
- PyPI Token

### Messaging Service Secrets (6 patterns)

- Mailgun API Key
- SendGrid API Key
- Slack Bot Token
- Slack User Token
- Slack Webhook
- Twilio API Key

### Payment Service Secrets (2 patterns)

- Stripe Publishable Key
- Stripe Secret Key

---

## Section 3: Geographic Regions

Country-specific identification documents, tax numbers, driver's licences, and passports.

### North America (100 patterns, 4 categories)

**Canada** (29): Alberta DL, Alberta HC, BC HC, British Columbia DL, Canada BN, Canada Bank Code, Canada NEXUS, Canada PR Card, Canada Passport, Canada SIN, Manitoba DL, Manitoba HC, NWT DL, New Brunswick DL, New Brunswick HC, Newfoundland DL, Newfoundland HC, Nova Scotia DL, Nova Scotia HC, Nunavut DL, Ontario DL, Ontario HC, PEI DL, PEI HC, Quebec DL, Quebec HC, Saskatchewan DL, Saskatchewan HC, Yukon DL

**Mexico** (7): Mexico CURP, Mexico Clave Elector, Mexico INE CIC, Mexico INE OCR, Mexico NSS, Mexico Passport, Mexico RFC

**US Generic DL** (1): Generic US DL

**United States** (63): Alabama DL, Alaska DL, Arizona DL, Arkansas DL, California DL, Colorado DL, Connecticut DL, DC DL, Delaware DL, Florida DL, Georgia DL, Hawaii DL, Idaho DL, Illinois DL, Indiana DL, Iowa DL, Kansas DL, Kentucky DL, Louisiana DL, Maine DL, Maryland DL, Massachusetts DL, Michigan DL, Minnesota DL, Mississippi DL, Missouri DL, Montana DL, Nebraska DL, Nevada DL, New Hampshire DL, New Jersey DL, New Mexico DL, New York DL, North Carolina DL, North Dakota DL, Ohio DL, Oklahoma DL, Oregon DL, Pennsylvania DL, Rhode Island DL, South Carolina DL, South Dakota DL, Tennessee DL, Texas DL, US DEA Number, US DoD ID, US Known Traveler Number, US MBI, US NPI, US Phone Number, USA EIN, USA ITIN, USA Passport, USA Passport Card, USA Routing Number, USA SSN, Utah DL, Vermont DL, Virginia DL, Washington DL, West Virginia DL, Wisconsin DL, Wyoming DL

### Europe (134 patterns, 34 categories)

**Austria** (5): Austria DL, Austria ID Card, Austria Passport, Austria SVN, Austria Tax Number

**Belgium** (4): Belgium DL, Belgium NRN, Belgium Passport, Belgium VAT

**Bulgaria** (4): Bulgaria EGN, Bulgaria ID Card, Bulgaria LNC, Bulgaria Passport

**Croatia** (4): Croatia DL, Croatia ID Card, Croatia OIB, Croatia Passport

**Cyprus** (3): Cyprus ID Card, Cyprus Passport, Cyprus TIN

**Czech Republic** (4): Czech Birth Number, Czech DL, Czech ICO, Czech Passport

**Denmark** (3): Denmark CPR, Denmark DL, Denmark Passport

**EU** (2): EU ETD, EU VAT Generic

**Estonia** (3): Estonia DL, Estonia Isikukood, Estonia Passport

**Finland** (3): Finland DL, Finland HETU, Finland Passport

**France** (5): France CNI, France DL, France IBAN, France NIR, France Passport

**Germany** (6): Germany DL, Germany IBAN, Germany ID, Germany Passport, Germany Social Insurance, Germany Tax ID

**Greece** (5): Greece AFM, Greece AMKA, Greece DL, Greece ID Card, Greece Passport

**Hungary** (5): Hungary DL, Hungary Passport, Hungary Personal ID, Hungary TAJ, Hungary Tax Number

**Iceland** (2): Iceland Kennitala, Iceland Passport

**Ireland** (4): Ireland DL, Ireland Eircode, Ireland PPS, Ireland Passport

**Italy** (5): Italy Codice Fiscale, Italy DL, Italy Partita IVA, Italy Passport, Italy SSN

**Latvia** (3): Latvia DL, Latvia Passport, Latvia Personas Kods

**Liechtenstein** (2): Liechtenstein PIN, Liechtenstein Passport

**Lithuania** (3): Lithuania Asmens Kodas, Lithuania DL, Lithuania Passport

**Luxembourg** (3): Luxembourg DL, Luxembourg NIN, Luxembourg Passport

**Malta** (3): Malta ID Card, Malta Passport, Malta TIN

**Netherlands** (4): Netherlands BSN, Netherlands DL, Netherlands IBAN, Netherlands Passport

**Norway** (4): Norway D-Number, Norway DL, Norway FNR, Norway Passport

**Poland** (6): Poland DL, Poland ID Card, Poland NIP, Poland PESEL, Poland Passport, Poland REGON

**Portugal** (4): Portugal CC, Portugal NIF, Portugal NISS, Portugal Passport

**Romania** (4): Romania CIF, Romania CNP, Romania DL, Romania Passport

**Slovakia** (3): Slovakia Birth Number, Slovakia DL, Slovakia Passport

**Slovenia** (4): Slovenia DL, Slovenia EMSO, Slovenia Passport, Slovenia Tax Number

**Spain** (5): Spain DL, Spain DNI, Spain NIE, Spain NSS, Spain Passport

**Sweden** (4): Sweden DL, Sweden Organisation Number, Sweden PIN, Sweden Passport

**Switzerland** (4): Switzerland AHV, Switzerland DL, Switzerland Passport, Switzerland UID

**Turkey** (4): Turkey DL, Turkey Passport, Turkey TC Kimlik, Turkey Tax ID

**United Kingdom** (7): British NHS, UK DL, UK NIN, UK Passport, UK Phone Number, UK Sort Code, UK UTR

### Asia-Pacific (66 patterns, 15 categories)

**Australia** (11): Australia DL ACT, Australia DL NSW, Australia DL NT, Australia DL QLD, Australia DL SA, Australia DL TAS, Australia DL VIC, Australia DL WA, Australia Medicare, Australia Passport, Australia TFN

**Bangladesh** (3): Bangladesh NID, Bangladesh Passport, Bangladesh TIN

**China** (5): China Passport, China Resident ID, Hong Kong ID, Macau ID, Taiwan National ID

**India** (6): India Aadhaar, India DL, India PAN, India Passport, India Ration Card, India Voter ID

**Indonesia** (3): Indonesia NIK, Indonesia NPWP, Indonesia Passport

**Japan** (6): Japan DL, Japan Health Insurance, Japan Juminhyo Code, Japan My Number, Japan Passport, Japan Residence Card

**Malaysia** (2): Malaysia MyKad, Malaysia Passport

**New Zealand** (4): New Zealand DL, New Zealand IRD, New Zealand NHI, New Zealand Passport

**Pakistan** (3): Pakistan CNIC, Pakistan NICOP, Pakistan Passport

**Philippines** (6): Philippines Passport, Philippines PhilHealth, Philippines PhilSys, Philippines SSS, Philippines TIN, Philippines UMID

**Singapore** (4): Singapore DL, Singapore FIN, Singapore NRIC, Singapore Passport

**South Korea** (3): South Korea DL, South Korea Passport, South Korea RRN

**Sri Lanka** (3): Sri Lanka NIC New, Sri Lanka NIC Old, Sri Lanka Passport

**Thailand** (4): Thailand DL, Thailand National ID, Thailand Passport, Thailand Tax ID

**Vietnam** (3): Vietnam CCCD, Vietnam Passport, Vietnam Tax Code

### Latin America (34 patterns, 10 categories)

**Argentina** (3): Argentina CUIL/CUIT, Argentina DNI, Argentina Passport

**Brazil** (6): Brazil CNH, Brazil CNPJ, Brazil CPF, Brazil Passport, Brazil RG, Brazil SUS Card

**Chile** (2): Chile Passport, Chile RUN/RUT

**Colombia** (4): Colombia Cedula, Colombia NIT, Colombia NUIP, Colombia Passport

**Costa Rica** (3): Costa Rica Cedula, Costa Rica DIMEX, Costa Rica Passport

**Ecuador** (3): Ecuador Cedula, Ecuador Passport, Ecuador RUC

**Paraguay** (3): Paraguay Cedula, Paraguay Passport, Paraguay RUC

**Peru** (4): Peru Carnet Extranjeria, Peru DNI, Peru Passport, Peru RUC

**Uruguay** (3): Uruguay Cedula, Uruguay Passport, Uruguay RUT

**Venezuela** (3): Venezuela Cedula, Venezuela Passport, Venezuela RIF

### Middle East (21 patterns, 10 categories)

**Bahrain** (2): Bahrain CPR, Bahrain Passport

**Iran** (2): Iran Melli Code, Iran Passport

**Iraq** (2): Iraq National ID, Iraq Passport

**Israel** (2): Israel Passport, Israel Teudat Zehut

**Jordan** (2): Jordan National ID, Jordan Passport

**Kuwait** (2): Kuwait Civil ID, Kuwait Passport

**Lebanon** (2): Lebanon ID, Lebanon Passport

**Qatar** (2): Qatar Passport, Qatar QID

**Saudi Arabia** (2): Saudi Arabia National ID, Saudi Arabia Passport

**UAE** (3): UAE Emirates ID, UAE Passport, UAE Visa Number

### Africa (33 patterns, 10 categories)

**Egypt** (3): Egypt National ID, Egypt Passport, Egypt Tax ID

**Ethiopia** (3): Ethiopia National ID, Ethiopia Passport, Ethiopia TIN

**Ghana** (4): Ghana Card, Ghana NHIS, Ghana Passport, Ghana TIN

**Kenya** (4): Kenya KRA PIN, Kenya NHIF, Kenya National ID, Kenya Passport

**Morocco** (3): Morocco CIN, Morocco Passport, Morocco Tax ID

**Nigeria** (6): Nigeria BVN, Nigeria Driver Licence, Nigeria NIN, Nigeria Passport, Nigeria TIN, Nigeria Voter Card

**South Africa** (3): South Africa DL, South Africa ID, South Africa Passport

**Tanzania** (3): Tanzania NIDA, Tanzania Passport, Tanzania TIN

**Tunisia** (2): Tunisia CIN, Tunisia Passport

**Uganda** (2): Uganda NIN, Uganda Passport
