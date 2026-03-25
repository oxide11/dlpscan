# Supported Patterns

dlpscan v0.3.0 supports **437 patterns** across **95 categories**, organized into three sections.

---

## Section 1: Generic Patterns

Universal formats not tied to any specific country or vendor.

### Banking and Financial (2 patterns)

- IBAN Generic
- SWIFT/BIC

### Contact Information (5 patterns)

- E.164 Phone Number
- Email Address
- IPv4 Address
- IPv6 Address
- MAC Address

### Credit Card Numbers (7 patterns)

- Amex
- Diners Club
- Discover
- JCB
- MasterCard
- UnionPay
- Visa

### Cryptocurrency (7 patterns)

- Bitcoin Address (Bech32)
- Bitcoin Address (Legacy)
- Bitcoin Cash Address
- Ethereum Address
- Litecoin Address
- Monero Address
- Ripple Address

### Dates (3 patterns)

- Date EU
- Date ISO
- Date US

### Generic Secrets (6 patterns)

- Bearer Token
- Database Connection String
- Generic API Key
- Generic Secret Assignment
- JWT Token
- Private Key

### URLs with Credentials (2 patterns)

- URL with Password
- URL with Token

### Vehicle Identification (1 patterns)

- VIN

## Section 2: Custom Patterns

Vendor-specific API keys, tokens, and secrets.

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

## Section 3: Geographic Regions

Country and region-specific identity documents, tax numbers, and government IDs.

### Africa

#### Africa - Egypt (3 patterns)

- Egypt National ID
- Egypt Passport
- Egypt Tax ID

#### Africa - Ethiopia (3 patterns)

- Ethiopia National ID
- Ethiopia Passport
- Ethiopia TIN

#### Africa - Ghana (4 patterns)

- Ghana Card
- Ghana NHIS
- Ghana Passport
- Ghana TIN

#### Africa - Kenya (4 patterns)

- Kenya KRA PIN
- Kenya NHIF
- Kenya National ID
- Kenya Passport

#### Africa - Morocco (3 patterns)

- Morocco CIN
- Morocco Passport
- Morocco Tax ID

#### Africa - Nigeria (6 patterns)

- Nigeria BVN
- Nigeria Driver Licence
- Nigeria NIN
- Nigeria Passport
- Nigeria TIN
- Nigeria Voter Card

#### Africa - South Africa (3 patterns)

- South Africa DL
- South Africa ID
- South Africa Passport

#### Africa - Tanzania (3 patterns)

- Tanzania NIDA
- Tanzania Passport
- Tanzania TIN

#### Africa - Tunisia (2 patterns)

- Tunisia CIN
- Tunisia Passport

#### Africa - Uganda (2 patterns)

- Uganda NIN
- Uganda Passport

### Asia-Pacific

#### Asia-Pacific - Australia (11 patterns)

- Australia DL ACT
- Australia DL NSW
- Australia DL NT
- Australia DL QLD
- Australia DL SA
- Australia DL TAS
- Australia DL VIC
- Australia DL WA
- Australia Medicare
- Australia Passport
- Australia TFN

#### Asia-Pacific - Bangladesh (3 patterns)

- Bangladesh NID
- Bangladesh Passport
- Bangladesh TIN

#### Asia-Pacific - China (5 patterns)

- China Passport
- China Resident ID
- Hong Kong ID
- Macau ID
- Taiwan National ID

#### Asia-Pacific - India (6 patterns)

- India Aadhaar
- India DL
- India PAN
- India Passport
- India Ration Card
- India Voter ID

#### Asia-Pacific - Indonesia (3 patterns)

- Indonesia NIK
- Indonesia NPWP
- Indonesia Passport

#### Asia-Pacific - Japan (6 patterns)

- Japan DL
- Japan Health Insurance
- Japan Juminhyo Code
- Japan My Number
- Japan Passport
- Japan Residence Card

#### Asia-Pacific - Malaysia (2 patterns)

- Malaysia MyKad
- Malaysia Passport

#### Asia-Pacific - New Zealand (4 patterns)

- New Zealand DL
- New Zealand IRD
- New Zealand NHI
- New Zealand Passport

#### Asia-Pacific - Pakistan (3 patterns)

- Pakistan CNIC
- Pakistan NICOP
- Pakistan Passport

#### Asia-Pacific - Philippines (6 patterns)

- Philippines Passport
- Philippines PhilHealth
- Philippines PhilSys
- Philippines SSS
- Philippines TIN
- Philippines UMID

#### Asia-Pacific - Singapore (4 patterns)

- Singapore DL
- Singapore FIN
- Singapore NRIC
- Singapore Passport

#### Asia-Pacific - South Korea (3 patterns)

- South Korea DL
- South Korea Passport
- South Korea RRN

#### Asia-Pacific - Sri Lanka (3 patterns)

- Sri Lanka NIC New
- Sri Lanka NIC Old
- Sri Lanka Passport

#### Asia-Pacific - Thailand (4 patterns)

- Thailand DL
- Thailand National ID
- Thailand Passport
- Thailand Tax ID

#### Asia-Pacific - Vietnam (3 patterns)

- Vietnam CCCD
- Vietnam Passport
- Vietnam Tax Code

### Europe

#### Europe - Austria (5 patterns)

- Austria DL
- Austria ID Card
- Austria Passport
- Austria SVN
- Austria Tax Number

#### Europe - Belgium (4 patterns)

- Belgium DL
- Belgium NRN
- Belgium Passport
- Belgium VAT

#### Europe - Bulgaria (4 patterns)

- Bulgaria EGN
- Bulgaria ID Card
- Bulgaria LNC
- Bulgaria Passport

#### Europe - Croatia (4 patterns)

- Croatia DL
- Croatia ID Card
- Croatia OIB
- Croatia Passport

#### Europe - Cyprus (3 patterns)

- Cyprus ID Card
- Cyprus Passport
- Cyprus TIN

#### Europe - Czech Republic (4 patterns)

- Czech Birth Number
- Czech DL
- Czech ICO
- Czech Passport

#### Europe - Denmark (3 patterns)

- Denmark CPR
- Denmark DL
- Denmark Passport

#### Europe - EU (2 patterns)

- EU ETD
- EU VAT Generic

#### Europe - Estonia (3 patterns)

- Estonia DL
- Estonia Isikukood
- Estonia Passport

#### Europe - Finland (3 patterns)

- Finland DL
- Finland HETU
- Finland Passport

#### Europe - France (5 patterns)

- France CNI
- France DL
- France IBAN
- France NIR
- France Passport

#### Europe - Germany (6 patterns)

- Germany DL
- Germany IBAN
- Germany ID
- Germany Passport
- Germany Social Insurance
- Germany Tax ID

#### Europe - Greece (5 patterns)

- Greece AFM
- Greece AMKA
- Greece DL
- Greece ID Card
- Greece Passport

#### Europe - Hungary (5 patterns)

- Hungary DL
- Hungary Passport
- Hungary Personal ID
- Hungary TAJ
- Hungary Tax Number

#### Europe - Iceland (2 patterns)

- Iceland Kennitala
- Iceland Passport

#### Europe - Ireland (4 patterns)

- Ireland DL
- Ireland Eircode
- Ireland PPS
- Ireland Passport

#### Europe - Italy (5 patterns)

- Italy Codice Fiscale
- Italy DL
- Italy Partita IVA
- Italy Passport
- Italy SSN

#### Europe - Latvia (3 patterns)

- Latvia DL
- Latvia Passport
- Latvia Personas Kods

#### Europe - Liechtenstein (2 patterns)

- Liechtenstein PIN
- Liechtenstein Passport

#### Europe - Lithuania (3 patterns)

- Lithuania Asmens Kodas
- Lithuania DL
- Lithuania Passport

#### Europe - Luxembourg (3 patterns)

- Luxembourg DL
- Luxembourg NIN
- Luxembourg Passport

#### Europe - Malta (3 patterns)

- Malta ID Card
- Malta Passport
- Malta TIN

#### Europe - Netherlands (4 patterns)

- Netherlands BSN
- Netherlands DL
- Netherlands IBAN
- Netherlands Passport

#### Europe - Norway (4 patterns)

- Norway D-Number
- Norway DL
- Norway FNR
- Norway Passport

#### Europe - Poland (6 patterns)

- Poland DL
- Poland ID Card
- Poland NIP
- Poland PESEL
- Poland Passport
- Poland REGON

#### Europe - Portugal (4 patterns)

- Portugal CC
- Portugal NIF
- Portugal NISS
- Portugal Passport

#### Europe - Romania (4 patterns)

- Romania CIF
- Romania CNP
- Romania DL
- Romania Passport

#### Europe - Slovakia (3 patterns)

- Slovakia Birth Number
- Slovakia DL
- Slovakia Passport

#### Europe - Slovenia (4 patterns)

- Slovenia DL
- Slovenia EMSO
- Slovenia Passport
- Slovenia Tax Number

#### Europe - Spain (5 patterns)

- Spain DL
- Spain DNI
- Spain NIE
- Spain NSS
- Spain Passport

#### Europe - Sweden (4 patterns)

- Sweden DL
- Sweden Organisation Number
- Sweden PIN
- Sweden Passport

#### Europe - Switzerland (4 patterns)

- Switzerland AHV
- Switzerland DL
- Switzerland Passport
- Switzerland UID

#### Europe - Turkey (4 patterns)

- Turkey DL
- Turkey Passport
- Turkey TC Kimlik
- Turkey Tax ID

#### Europe - United Kingdom (7 patterns)

- British NHS
- UK DL
- UK NIN
- UK Passport
- UK Phone Number
- UK Sort Code
- UK UTR

### Latin America

#### Latin America - Argentina (3 patterns)

- Argentina CUIL/CUIT
- Argentina DNI
- Argentina Passport

#### Latin America - Brazil (6 patterns)

- Brazil CNH
- Brazil CNPJ
- Brazil CPF
- Brazil Passport
- Brazil RG
- Brazil SUS Card

#### Latin America - Chile (2 patterns)

- Chile Passport
- Chile RUN/RUT

#### Latin America - Colombia (4 patterns)

- Colombia Cedula
- Colombia NIT
- Colombia NUIP
- Colombia Passport

#### Latin America - Costa Rica (3 patterns)

- Costa Rica Cedula
- Costa Rica DIMEX
- Costa Rica Passport

#### Latin America - Ecuador (3 patterns)

- Ecuador Cedula
- Ecuador Passport
- Ecuador RUC

#### Latin America - Paraguay (3 patterns)

- Paraguay Cedula
- Paraguay Passport
- Paraguay RUC

#### Latin America - Peru (4 patterns)

- Peru Carnet Extranjeria
- Peru DNI
- Peru Passport
- Peru RUC

#### Latin America - Uruguay (3 patterns)

- Uruguay Cedula
- Uruguay Passport
- Uruguay RUT

#### Latin America - Venezuela (3 patterns)

- Venezuela Cedula
- Venezuela Passport
- Venezuela RIF

### Middle East

#### Middle East - Bahrain (2 patterns)

- Bahrain CPR
- Bahrain Passport

#### Middle East - Iran (2 patterns)

- Iran Melli Code
- Iran Passport

#### Middle East - Iraq (2 patterns)

- Iraq National ID
- Iraq Passport

#### Middle East - Israel (2 patterns)

- Israel Passport
- Israel Teudat Zehut

#### Middle East - Jordan (2 patterns)

- Jordan National ID
- Jordan Passport

#### Middle East - Kuwait (2 patterns)

- Kuwait Civil ID
- Kuwait Passport

#### Middle East - Lebanon (2 patterns)

- Lebanon ID
- Lebanon Passport

#### Middle East - Qatar (2 patterns)

- Qatar Passport
- Qatar QID

#### Middle East - Saudi Arabia (2 patterns)

- Saudi Arabia National ID
- Saudi Arabia Passport

#### Middle East - UAE (3 patterns)

- UAE Emirates ID
- UAE Passport
- UAE Visa Number

### North America

#### North America - Canada (29 patterns)

- Alberta DL
- Alberta HC
- BC HC
- British Columbia DL
- Canada BN
- Canada Bank Code
- Canada NEXUS
- Canada PR Card
- Canada Passport
- Canada SIN
- Manitoba DL
- Manitoba HC
- NWT DL
- New Brunswick DL
- New Brunswick HC
- Newfoundland DL
- Newfoundland HC
- Nova Scotia DL
- Nova Scotia HC
- Nunavut DL
- Ontario DL
- Ontario HC
- PEI DL
- PEI HC
- Quebec DL
- Quebec HC
- Saskatchewan DL
- Saskatchewan HC
- Yukon DL

#### North America - Mexico (7 patterns)

- Mexico CURP
- Mexico Clave Elector
- Mexico INE CIC
- Mexico INE OCR
- Mexico NSS
- Mexico Passport
- Mexico RFC

#### North America - US Generic DL (1 patterns)

- Generic US DL

#### North America - United States (63 patterns)

- Alabama DL
- Alaska DL
- Arizona DL
- Arkansas DL
- California DL
- Colorado DL
- Connecticut DL
- DC DL
- Delaware DL
- Florida DL
- Georgia DL
- Hawaii DL
- Idaho DL
- Illinois DL
- Indiana DL
- Iowa DL
- Kansas DL
- Kentucky DL
- Louisiana DL
- Maine DL
- Maryland DL
- Massachusetts DL
- Michigan DL
- Minnesota DL
- Mississippi DL
- Missouri DL
- Montana DL
- Nebraska DL
- Nevada DL
- New Hampshire DL
- New Jersey DL
- New Mexico DL
- New York DL
- North Carolina DL
- North Dakota DL
- Ohio DL
- Oklahoma DL
- Oregon DL
- Pennsylvania DL
- Rhode Island DL
- South Carolina DL
- South Dakota DL
- Tennessee DL
- Texas DL
- US DEA Number
- US DoD ID
- US Known Traveler Number
- US MBI
- US NPI
- US Phone Number
- USA EIN
- USA ITIN
- USA Passport
- USA Passport Card
- USA Routing Number
- USA SSN
- Utah DL
- Vermont DL
- Virginia DL
- Washington DL
- West Virginia DL
- Wisconsin DL
- Wyoming DL

---

**Total: 437 patterns across 95 categories**
