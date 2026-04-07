# Pattern Reference

Complete inventory of all detection patterns in dlpscan.
**560 patterns** across **126 categories**.

## Table of Contents

- [Credit Card Numbers (7)](#credit-card-numbers)
- [Primary Account Numbers (2)](#primary-account-numbers)
- [Card Track Data (2)](#card-track-data)
- [Card Expiration Dates (1)](#card-expiration-dates)
- [Banking and Financial (5)](#banking-and-financial)
- [Wire Transfer Data (6)](#wire-transfer-data)
- [Check and MICR Data (3)](#check-and-micr-data)
- [Securities Identifiers (6)](#securities-identifiers)
- [Loan and Mortgage Data (4)](#loan-and-mortgage-data)
- [Regulatory Identifiers (6)](#regulatory-identifiers)
- [Banking Authentication (3)](#banking-authentication)
- [Customer Financial Data (4)](#customer-financial-data)
- [Internal Banking References (2)](#internal-banking-references)
- [PCI Sensitive Data (1)](#pci-sensitive-data)
- [Contact Information (5)](#contact-information)
- [Generic Secrets (6)](#generic-secrets)
- [Cryptocurrency (7)](#cryptocurrency)
- [Vehicle Identification (1)](#vehicle-identification)
- [Dates (3)](#dates)
- [URLs with Credentials (2)](#urls-with-credentials)
- [Personal Identifiers (2)](#personal-identifiers)
- [Geolocation (3)](#geolocation)
- [Postal Codes (5)](#postal-codes)
- [Device Identifiers (5)](#device-identifiers)
- [Medical Identifiers (4)](#medical-identifiers)
- [Insurance Identifiers (2)](#insurance-identifiers)
- [Authentication Tokens (1)](#authentication-tokens)
- [Social Media Identifiers (2)](#social-media-identifiers)
- [Education Identifiers (1)](#education-identifiers)
- [Legal Identifiers (2)](#legal-identifiers)
- [Employment Identifiers (2)](#employment-identifiers)
- [Biometric Identifiers (2)](#biometric-identifiers)
- [Property Identifiers (2)](#property-identifiers)
- [Supervisory Information (6)](#supervisory-information)
- [Privileged Information (7)](#privileged-information)
- [Data Classification Labels (8)](#data-classification-labels)
- [Corporate Classification (9)](#corporate-classification)
- [Financial Regulatory Labels (7)](#financial-regulatory-labels)
- [Privacy Classification (10)](#privacy-classification)
- [Cloud Provider Secrets (3)](#cloud-provider-secrets)
- [Code Platform Secrets (5)](#code-platform-secrets)
- [Payment Service Secrets (2)](#payment-service-secrets)
- [Messaging Service Secrets (6)](#messaging-service-secrets)
- [North America - United States (63)](#north-america-united-states)
- [North America - US Generic DL (1)](#north-america-us-generic-dl)
- [North America - Canada (29)](#north-america-canada)
- [North America - Mexico (7)](#north-america-mexico)
- [Europe - United Kingdom (7)](#europe-united-kingdom)
- [Europe - Germany (6)](#europe-germany)
- [Europe - France (5)](#europe-france)
- [Europe - Italy (5)](#europe-italy)
- [Europe - Netherlands (4)](#europe-netherlands)
- [Europe - Spain (5)](#europe-spain)
- [Europe - Poland (6)](#europe-poland)
- [Europe - Sweden (4)](#europe-sweden)
- [Europe - Portugal (4)](#europe-portugal)
- [Europe - Switzerland (4)](#europe-switzerland)
- [Europe - Turkey (4)](#europe-turkey)
- [Europe - Austria (5)](#europe-austria)
- [Europe - Belgium (4)](#europe-belgium)
- [Europe - Ireland (4)](#europe-ireland)
- [Europe - Denmark (3)](#europe-denmark)
- [Europe - Finland (3)](#europe-finland)
- [Europe - Norway (4)](#europe-norway)
- [Europe - Czech Republic (4)](#europe-czech-republic)
- [Europe - Hungary (5)](#europe-hungary)
- [Europe - Romania (4)](#europe-romania)
- [Europe - Greece (5)](#europe-greece)
- [Europe - Croatia (4)](#europe-croatia)
- [Europe - Bulgaria (4)](#europe-bulgaria)
- [Europe - Slovakia (3)](#europe-slovakia)
- [Europe - Lithuania (3)](#europe-lithuania)
- [Europe - Latvia (3)](#europe-latvia)
- [Europe - Estonia (3)](#europe-estonia)
- [Europe - Slovenia (4)](#europe-slovenia)
- [Europe - Luxembourg (3)](#europe-luxembourg)
- [Europe - Malta (3)](#europe-malta)
- [Europe - Cyprus (3)](#europe-cyprus)
- [Europe - Iceland (2)](#europe-iceland)
- [Europe - Liechtenstein (2)](#europe-liechtenstein)
- [Europe - EU (2)](#europe-eu)
- [Asia-Pacific - India (6)](#asia-pacific-india)
- [Asia-Pacific - China (5)](#asia-pacific-china)
- [Asia-Pacific - Japan (6)](#asia-pacific-japan)
- [Asia-Pacific - South Korea (3)](#asia-pacific-south-korea)
- [Asia-Pacific - Singapore (4)](#asia-pacific-singapore)
- [Asia-Pacific - Australia (11)](#asia-pacific-australia)
- [Asia-Pacific - New Zealand (4)](#asia-pacific-new-zealand)
- [Asia-Pacific - Philippines (6)](#asia-pacific-philippines)
- [Asia-Pacific - Thailand (4)](#asia-pacific-thailand)
- [Asia-Pacific - Malaysia (2)](#asia-pacific-malaysia)
- [Asia-Pacific - Indonesia (3)](#asia-pacific-indonesia)
- [Asia-Pacific - Vietnam (3)](#asia-pacific-vietnam)
- [Asia-Pacific - Pakistan (3)](#asia-pacific-pakistan)
- [Asia-Pacific - Bangladesh (3)](#asia-pacific-bangladesh)
- [Asia-Pacific - Sri Lanka (3)](#asia-pacific-sri-lanka)
- [Latin America - Brazil (6)](#latin-america-brazil)
- [Latin America - Argentina (3)](#latin-america-argentina)
- [Latin America - Colombia (4)](#latin-america-colombia)
- [Latin America - Chile (2)](#latin-america-chile)
- [Latin America - Peru (4)](#latin-america-peru)
- [Latin America - Venezuela (3)](#latin-america-venezuela)
- [Latin America - Ecuador (3)](#latin-america-ecuador)
- [Latin America - Uruguay (3)](#latin-america-uruguay)
- [Latin America - Paraguay (3)](#latin-america-paraguay)
- [Latin America - Costa Rica (3)](#latin-america-costa-rica)
- [Middle East - Saudi Arabia (2)](#middle-east-saudi-arabia)
- [Middle East - UAE (3)](#middle-east-uae)
- [Middle East - Israel (2)](#middle-east-israel)
- [Middle East - Qatar (2)](#middle-east-qatar)
- [Middle East - Kuwait (2)](#middle-east-kuwait)
- [Middle East - Bahrain (2)](#middle-east-bahrain)
- [Middle East - Jordan (2)](#middle-east-jordan)
- [Middle East - Lebanon (2)](#middle-east-lebanon)
- [Middle East - Iraq (2)](#middle-east-iraq)
- [Middle East - Iran (2)](#middle-east-iran)
- [Africa - South Africa (3)](#africa-south-africa)
- [Africa - Nigeria (6)](#africa-nigeria)
- [Africa - Kenya (4)](#africa-kenya)
- [Africa - Egypt (3)](#africa-egypt)
- [Africa - Ghana (4)](#africa-ghana)
- [Africa - Ethiopia (3)](#africa-ethiopia)
- [Africa - Tanzania (3)](#africa-tanzania)
- [Africa - Morocco (3)](#africa-morocco)
- [Africa - Tunisia (2)](#africa-tunisia)
- [Africa - Uganda (2)](#africa-uganda)

## Credit Card Numbers

7 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Visa | 0.40 | No | No |
| MasterCard | 0.40 | No | No |
| Amex | 0.40 | No | No |
| Discover | 0.40 | No | No |
| JCB | 0.40 | No | No |
| Diners Club | 0.40 | No | No |
| UnionPay | 0.90 | No | No |

## Primary Account Numbers

2 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| PAN | 0.60 | No | No |
| Masked PAN | 0.85 | No | No |

## Card Track Data

2 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Track 1 Data | 0.40 | No | No |
| Track 2 Data | 0.95 | No | No |

## Card Expiration Dates

1 pattern

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Card Expiry | 0.30 | No | No |

## Banking and Financial

5 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| IBAN Generic | 0.90 | No | No |
| SWIFT/BIC | 0.85 | No | No |
| ABA Routing Number | 0.55 | No | No |
| US Bank Account Number | 0.20 | No | No |
| Canada Transit Number | 0.40 | No | No |

## Wire Transfer Data

6 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Fedwire IMAD | 0.90 | No | No |
| CHIPS UID | 0.50 | No | No |
| Wire Reference Number | 0.40 | No | No |
| ACH Trace Number | 0.55 | No | No |
| ACH Batch Number | 0.20 | No | No |
| SEPA Reference | 0.50 | No | No |

## Check and MICR Data

3 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| MICR Line | 0.90 | No | No |
| Check Number | 0.15 | No | No |
| Cashier Check Number | 0.20 | No | No |

## Securities Identifiers

6 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| CUSIP | 0.70 | No | No |
| ISIN | 0.75 | No | No |
| SEDOL | 0.70 | No | No |
| FIGI | 0.90 | No | No |
| LEI | 0.80 | No | No |
| Ticker Symbol | 0.80 | No | No |

## Loan and Mortgage Data

4 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Loan Number | 0.45 | No | No |
| MERS MIN | 0.50 | No | No |
| Universal Loan Identifier | 0.75 | No | No |
| LTV Ratio | 0.40 | No | No |

## Regulatory Identifiers

6 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| SAR Filing Number | 0.40 | No | No |
| CTR Number | 0.40 | No | No |
| AML Case ID | 0.60 | No | No |
| OFAC SDN Entry | 0.15 | No | No |
| FinCEN Report Number | 0.30 | No | No |
| Compliance Case Number | 0.55 | No | No |

## Banking Authentication

3 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| PIN Block | 0.65 | No | No |
| HSM Key | 0.55 | No | No |
| Encryption Key | 0.50 | No | No |

## Customer Financial Data

4 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Account Balance | 0.50 | No | No |
| Balance with Currency Code | 0.55 | No | No |
| Income Amount | 0.40 | No | No |
| DTI Ratio | 0.45 | No | No |

## Internal Banking References

2 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Internal Account Ref | 0.50 | No | No |
| Teller ID | 0.35 | No | No |

## PCI Sensitive Data

1 pattern

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Cardholder Name Pattern | 0.10 | No | Yes |

## Contact Information

5 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Email Address | 0.90 | No | No |
| E.164 Phone Number | 0.70 | No | No |
| IPv4 Address | 0.60 | No | No |
| IPv6 Address | 0.80 | No | No |
| MAC Address | 0.80 | No | No |

## Generic Secrets

6 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Bearer Token | 0.80 | No | No |
| JWT Token | 0.95 | No | No |
| Private Key | 0.95 | No | No |
| Generic API Key | 0.50 | No | No |
| Generic Secret Assignment | 0.50 | No | No |
| Database Connection String | 0.90 | Yes | No |

## Cryptocurrency

7 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Bitcoin Address (Legacy) | 0.40 | No | No |
| Bitcoin Address (Bech32) | 0.40 | No | No |
| Ethereum Address | 0.40 | No | No |
| Litecoin Address | 0.40 | No | No |
| Bitcoin Cash Address | 0.75 | No | No |
| Monero Address | 0.85 | No | No |
| Ripple Address | 0.80 | No | No |

## Vehicle Identification

1 pattern

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| VIN | 0.70 | No | No |

## Dates

3 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Date ISO | 0.40 | No | No |
| Date US | 0.40 | No | No |
| Date EU | 0.35 | No | No |

## URLs with Credentials

2 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| URL with Password | 0.90 | No | No |
| URL with Token | 0.75 | Yes | No |

## Personal Identifiers

2 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Date of Birth | 0.40 | No | No |
| Gender Marker | 0.25 | Yes | Yes |

## Geolocation

3 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| GPS Coordinates | 0.80 | No | No |
| GPS DMS | 0.85 | No | No |
| Geohash | 0.60 | No | No |

## Postal Codes

5 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| US ZIP+4 Code | 0.55 | No | No |
| UK Postcode | 0.70 | No | No |
| Canada Postal Code | 0.75 | Yes | No |
| Japan Postal Code | 0.45 | No | No |
| Brazil CEP | 0.45 | No | No |

## Device Identifiers

5 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| IMEI | 0.40 | No | No |
| IMEISV | 0.55 | No | No |
| MEID | 0.70 | No | No |
| ICCID | 0.85 | No | No |
| IDFA/IDFV | 0.85 | No | No |

## Medical Identifiers

4 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Health Plan ID | 0.60 | No | No |
| DEA Number | 0.55 | No | No |
| ICD-10 Code | 0.50 | No | No |
| NDC Code | 0.65 | No | No |

## Insurance Identifiers

2 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Insurance Policy Number | 0.50 | No | No |
| Insurance Claim Number | 0.45 | No | No |

## Authentication Tokens

1 pattern

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Session ID | 0.55 | No | No |

## Social Media Identifiers

2 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Twitter Handle | 0.60 | No | No |
| Hashtag | 0.30 | No | No |

## Education Identifiers

1 pattern

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| EDU Email | 0.90 | Yes | No |

## Legal Identifiers

2 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| US Federal Case Number | 0.80 | No | No |
| Court Docket Number | 0.45 | No | No |

## Employment Identifiers

2 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Employee ID | 0.35 | No | No |
| Work Permit Number | 0.50 | No | No |

## Biometric Identifiers

2 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Biometric Hash | 0.70 | No | No |
| Biometric Template ID | 0.75 | No | No |

## Property Identifiers

2 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Parcel Number | 0.60 | No | No |
| Title Deed Number | 0.40 | No | No |

## Supervisory Information

6 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Supervisory Controlled | 0.40 | No | No |
| Supervisory Confidential | 0.40 | No | No |
| CSI | 0.40 | No | No |
| Non-Public Supervisory | 0.40 | No | No |
| Restricted Supervisory | 0.40 | No | No |
| Examination Findings | 0.45 | No | No |

## Privileged Information

7 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Attorney-Client Privilege | 0.40 | No | No |
| Privileged and Confidential | 0.40 | No | No |
| Work Product | 0.40 | No | No |
| Privileged Information | 0.40 | No | No |
| Legal Privilege | 0.40 | No | No |
| Litigation Hold | 0.45 | No | No |
| Protected by Privilege | 0.40 | No | No |

## Data Classification Labels

8 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Top Secret | 0.40 | No | No |
| Secret Classification | 0.40 | No | No |
| Confidential Classification | 0.40 | No | No |
| FOUO | 0.40 | No | No |
| CUI | 0.40 | No | No |
| SBU | 0.40 | No | No |
| LES | 0.45 | No | No |
| NOFORN | 0.40 | No | No |

## Corporate Classification

9 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Internal Only | 0.40 | No | No |
| Restricted | 0.40 | No | No |
| Corporate Confidential | 0.40 | No | No |
| Highly Confidential | 0.40 | No | No |
| Do Not Distribute | 0.40 | No | No |
| Need to Know | 0.45 | No | No |
| Eyes Only | 0.40 | No | No |
| Proprietary | 0.40 | No | No |
| Embargoed | 0.40 | No | No |

## Financial Regulatory Labels

7 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| MNPI | 0.40 | No | No |
| Inside Information | 0.40 | No | No |
| Pre-Decisional | 0.40 | No | No |
| Draft Not for Circulation | 0.40 | No | No |
| Market Sensitive | 0.40 | No | No |
| Information Barrier | 0.40 | No | No |
| Investment Restricted | 0.40 | No | No |

## Privacy Classification

10 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| PII Label | 0.40 | No | No |
| PHI Label | 0.40 | No | No |
| HIPAA | 0.40 | No | No |
| GDPR Personal Data | 0.40 | No | No |
| PCI-DSS | 0.40 | No | No |
| FERPA | 0.40 | No | No |
| GLBA | 0.40 | No | No |
| CCPA/CPRA | 0.40 | No | No |
| SOX | 0.45 | No | No |
| NPI | 0.70 | No | No |

## Cloud Provider Secrets

3 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| AWS Access Key | 0.95 | No | No |
| AWS Secret Key | 0.90 | No | No |
| Google API Key | 0.90 | No | No |

## Code Platform Secrets

5 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| GitHub Token (Classic) | 0.40 | No | No |
| GitHub Token (Fine-Grained) | 0.40 | No | No |
| GitHub OAuth Token | 0.95 | No | No |
| NPM Token | 0.40 | No | No |
| PyPI Token | 0.95 | No | No |

## Payment Service Secrets

2 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Stripe Secret Key | 0.95 | No | No |
| Stripe Publishable Key | 0.85 | No | No |

## Messaging Service Secrets

6 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Slack Bot Token | 0.95 | No | No |
| Slack User Token | 0.95 | No | No |
| Slack Webhook | 0.90 | No | No |
| SendGrid API Key | 0.95 | No | No |
| Twilio API Key | 0.40 | No | No |
| Mailgun API Key | 0.90 | No | No |

## North America - United States

63 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| USA SSN | 0.55 | No | No |
| USA ITIN | 0.60 | No | No |
| USA EIN | 0.70 | No | No |
| USA Passport | 0.40 | No | No |
| USA Passport Card | 0.80 | No | No |
| USA Routing Number | 0.55 | No | No |
| US DEA Number | 0.55 | No | No |
| US NPI | 0.40 | No | No |
| US MBI | 0.70 | No | No |
| US DoD ID | 0.70 | No | No |
| US Known Traveler Number | 0.70 | No | No |
| US Phone Number | 0.50 | No | No |
| Alabama DL | 0.40 | No | No |
| Alaska DL | 0.40 | No | No |
| Arizona DL | 0.40 | No | No |
| Arkansas DL | 0.40 | No | No |
| California DL | 0.40 | No | No |
| Colorado DL | 0.40 | No | No |
| Connecticut DL | 0.40 | No | No |
| Delaware DL | 0.40 | No | No |
| DC DL | 0.40 | No | No |
| Florida DL | 0.40 | No | No |
| Georgia DL | 0.40 | No | No |
| Hawaii DL | 0.40 | No | No |
| Idaho DL | 0.40 | No | No |
| Illinois DL | 0.40 | No | No |
| Indiana DL | 0.40 | No | No |
| Iowa DL | 0.40 | No | No |
| Kansas DL | 0.40 | No | No |
| Kentucky DL | 0.40 | No | No |
| Louisiana DL | 0.40 | No | No |
| Maine DL | 0.40 | No | No |
| Maryland DL | 0.40 | No | No |
| Massachusetts DL | 0.40 | No | No |
| Michigan DL | 0.40 | No | No |
| Minnesota DL | 0.40 | No | No |
| Mississippi DL | 0.40 | No | No |
| Missouri DL | 0.40 | No | No |
| Montana DL | 0.40 | No | No |
| Nebraska DL | 0.40 | No | No |
| Nevada DL | 0.40 | No | No |
| New Hampshire DL | 0.40 | No | No |
| New Jersey DL | 0.40 | No | No |
| New Mexico DL | 0.40 | No | No |
| New York DL | 0.40 | No | No |
| North Carolina DL | 0.40 | No | No |
| North Dakota DL | 0.40 | No | No |
| Ohio DL | 0.40 | No | No |
| Oklahoma DL | 0.40 | No | No |
| Oregon DL | 0.40 | No | No |
| Pennsylvania DL | 0.40 | No | No |
| Rhode Island DL | 0.40 | No | No |
| South Carolina DL | 0.40 | No | No |
| South Dakota DL | 0.40 | No | No |
| Tennessee DL | 0.40 | No | No |
| Texas DL | 0.40 | No | No |
| Utah DL | 0.40 | No | No |
| Vermont DL | 0.40 | No | No |
| Virginia DL | 0.40 | No | No |
| Washington DL | 0.40 | No | No |
| West Virginia DL | 0.40 | No | No |
| Wisconsin DL | 0.40 | No | No |
| Wyoming DL | 0.40 | No | No |

## North America - US Generic DL

1 pattern

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Generic US DL | 0.55 | No | No |

## North America - Canada

29 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Canada SIN | 0.55 | No | No |
| Canada BN | 0.40 | No | No |
| Canada Passport | 0.40 | No | No |
| Canada Bank Code | 0.70 | No | No |
| Canada PR Card | 0.40 | No | No |
| Canada NEXUS | 0.80 | No | No |
| Ontario DL | 0.40 | No | No |
| Ontario HC | 0.40 | No | No |
| Quebec DL | 0.40 | No | No |
| Quebec HC | 0.40 | No | No |
| British Columbia DL | 0.40 | No | No |
| BC HC | 0.40 | No | No |
| Alberta DL | 0.40 | No | No |
| Alberta HC | 0.40 | No | No |
| Saskatchewan DL | 0.40 | No | No |
| Saskatchewan HC | 0.55 | No | No |
| Manitoba DL | 0.40 | No | No |
| Manitoba HC | 0.40 | No | No |
| New Brunswick DL | 0.40 | No | No |
| New Brunswick HC | 0.40 | No | No |
| Nova Scotia DL | 0.40 | No | No |
| Nova Scotia HC | 0.40 | No | No |
| PEI DL | 0.40 | No | No |
| PEI HC | 0.40 | No | No |
| Newfoundland DL | 0.40 | No | No |
| Newfoundland HC | 0.40 | No | No |
| Yukon DL | 0.55 | No | No |
| NWT DL | 0.40 | No | No |
| Nunavut DL | 0.40 | No | No |

## North America - Mexico

7 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Mexico CURP | 0.40 | No | No |
| Mexico RFC | 0.40 | No | No |
| Mexico Clave Elector | 0.40 | No | No |
| Mexico INE CIC | 0.40 | No | No |
| Mexico INE OCR | 0.70 | No | No |
| Mexico Passport | 0.40 | No | No |
| Mexico NSS | 0.40 | No | No |

## Europe - United Kingdom

7 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| UK NIN | 0.65 | No | No |
| UK UTR | 0.70 | No | No |
| UK Passport | 0.80 | No | No |
| UK Sort Code | 0.50 | No | No |
| British NHS | 0.70 | No | No |
| UK Phone Number | 0.50 | No | No |
| UK DL | 0.55 | No | No |

## Europe - Germany

6 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Germany ID | 0.70 | No | No |
| Germany Passport | 0.80 | No | No |
| Germany Tax ID | 0.70 | No | No |
| Germany Social Insurance | 0.70 | No | No |
| Germany DL | 0.55 | No | No |
| Germany IBAN | 0.90 | No | No |

## Europe - France

5 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| France NIR | 0.70 | No | No |
| France Passport | 0.80 | No | No |
| France CNI | 0.70 | No | No |
| France DL | 0.55 | No | No |
| France IBAN | 0.90 | No | No |

## Europe - Italy

5 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Italy Codice Fiscale | 0.70 | No | No |
| Italy Passport | 0.80 | No | No |
| Italy DL | 0.55 | No | No |
| Italy SSN | 0.70 | No | No |
| Italy Partita IVA | 0.70 | No | No |

## Europe - Netherlands

4 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Netherlands BSN | 0.70 | No | No |
| Netherlands Passport | 0.80 | No | No |
| Netherlands DL | 0.55 | No | No |
| Netherlands IBAN | 0.90 | No | No |

## Europe - Spain

5 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Spain DNI | 0.70 | No | No |
| Spain NIE | 0.70 | No | No |
| Spain Passport | 0.80 | No | No |
| Spain NSS | 0.70 | No | No |
| Spain DL | 0.55 | No | No |

## Europe - Poland

6 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Poland PESEL | 0.40 | No | No |
| Poland NIP | 0.40 | No | No |
| Poland REGON | 0.40 | No | No |
| Poland ID Card | 0.70 | No | No |
| Poland Passport | 0.40 | No | No |
| Poland DL | 0.40 | No | No |

## Europe - Sweden

4 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Sweden PIN | 0.40 | No | No |
| Sweden Passport | 0.80 | No | No |
| Sweden DL | 0.55 | No | No |
| Sweden Organisation Number | 0.70 | No | No |

## Europe - Portugal

4 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Portugal NIF | 0.70 | No | No |
| Portugal CC | 0.70 | No | No |
| Portugal Passport | 0.80 | No | No |
| Portugal NISS | 0.70 | No | No |

## Europe - Switzerland

4 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Switzerland AHV | 0.70 | No | No |
| Switzerland Passport | 0.80 | No | No |
| Switzerland DL | 0.55 | No | No |
| Switzerland UID | 0.70 | No | No |

## Europe - Turkey

4 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Turkey TC Kimlik | 0.70 | No | No |
| Turkey Passport | 0.80 | No | No |
| Turkey DL | 0.55 | No | No |
| Turkey Tax ID | 0.70 | No | No |

## Europe - Austria

5 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Austria SVN | 0.70 | No | No |
| Austria Passport | 0.80 | No | No |
| Austria ID Card | 0.70 | No | No |
| Austria DL | 0.55 | No | No |
| Austria Tax Number | 0.70 | No | No |

## Europe - Belgium

4 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Belgium NRN | 0.70 | No | No |
| Belgium Passport | 0.80 | No | No |
| Belgium DL | 0.55 | No | No |
| Belgium VAT | 0.70 | No | No |

## Europe - Ireland

4 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Ireland PPS | 0.70 | No | No |
| Ireland Passport | 0.80 | No | No |
| Ireland DL | 0.55 | No | No |
| Ireland Eircode | 0.50 | No | No |

## Europe - Denmark

3 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Denmark CPR | 0.40 | No | No |
| Denmark Passport | 0.40 | No | No |
| Denmark DL | 0.40 | No | No |

## Europe - Finland

3 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Finland HETU | 0.40 | No | No |
| Finland Passport | 0.40 | No | No |
| Finland DL | 0.40 | No | No |

## Europe - Norway

4 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Norway FNR | 0.40 | No | No |
| Norway D-Number | 0.40 | No | No |
| Norway Passport | 0.40 | No | No |
| Norway DL | 0.40 | No | No |

## Europe - Czech Republic

4 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Czech Birth Number | 0.40 | No | No |
| Czech Passport | 0.40 | No | No |
| Czech DL | 0.40 | No | No |
| Czech ICO | 0.70 | No | No |

## Europe - Hungary

5 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Hungary Personal ID | 0.40 | No | No |
| Hungary TAJ | 0.40 | No | No |
| Hungary Tax Number | 0.70 | No | No |
| Hungary Passport | 0.40 | No | No |
| Hungary DL | 0.40 | No | No |

## Europe - Romania

4 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Romania CNP | 0.40 | No | No |
| Romania CIF | 0.70 | No | No |
| Romania Passport | 0.40 | No | No |
| Romania DL | 0.40 | No | No |

## Europe - Greece

5 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Greece AFM | 0.40 | No | No |
| Greece AMKA | 0.40 | No | No |
| Greece ID Card | 0.70 | No | No |
| Greece Passport | 0.80 | No | No |
| Greece DL | 0.55 | No | No |

## Europe - Croatia

4 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Croatia OIB | 0.40 | No | No |
| Croatia Passport | 0.40 | No | No |
| Croatia ID Card | 0.70 | No | No |
| Croatia DL | 0.40 | No | No |

## Europe - Bulgaria

4 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Bulgaria EGN | 0.40 | No | No |
| Bulgaria LNC | 0.40 | No | No |
| Bulgaria ID Card | 0.70 | No | No |
| Bulgaria Passport | 0.40 | No | No |

## Europe - Slovakia

3 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Slovakia Birth Number | 0.70 | No | No |
| Slovakia Passport | 0.40 | No | No |
| Slovakia DL | 0.40 | No | No |

## Europe - Lithuania

3 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Lithuania Asmens Kodas | 0.70 | No | No |
| Lithuania Passport | 0.80 | No | No |
| Lithuania DL | 0.55 | No | No |

## Europe - Latvia

3 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Latvia Personas Kods | 0.40 | No | No |
| Latvia Passport | 0.40 | No | No |
| Latvia DL | 0.40 | No | No |

## Europe - Estonia

3 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Estonia Isikukood | 0.40 | No | No |
| Estonia Passport | 0.40 | No | No |
| Estonia DL | 0.40 | No | No |

## Europe - Slovenia

4 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Slovenia EMSO | 0.40 | No | No |
| Slovenia Tax Number | 0.70 | No | No |
| Slovenia Passport | 0.80 | No | No |
| Slovenia DL | 0.55 | No | No |

## Europe - Luxembourg

3 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Luxembourg NIN | 0.70 | No | No |
| Luxembourg Passport | 0.80 | No | No |
| Luxembourg DL | 0.55 | No | No |

## Europe - Malta

3 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Malta ID Card | 0.40 | No | No |
| Malta Passport | 0.80 | No | No |
| Malta TIN | 0.70 | No | No |

## Europe - Cyprus

3 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Cyprus ID Card | 0.40 | No | No |
| Cyprus Passport | 0.40 | No | No |
| Cyprus TIN | 0.70 | No | No |

## Europe - Iceland

2 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Iceland Kennitala | 0.40 | No | No |
| Iceland Passport | 0.40 | No | No |

## Europe - Liechtenstein

2 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Liechtenstein PIN | 0.70 | No | No |
| Liechtenstein Passport | 0.80 | No | No |

## Europe - EU

2 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| EU ETD | 0.80 | No | No |
| EU VAT Generic | 0.70 | No | No |

## Asia-Pacific - India

6 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| India PAN | 0.70 | No | No |
| India Aadhaar | 0.70 | No | No |
| India Passport | 0.80 | No | No |
| India DL | 0.55 | No | No |
| India Voter ID | 0.70 | No | No |
| India Ration Card | 0.70 | No | No |

## Asia-Pacific - China

5 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| China Resident ID | 0.70 | No | No |
| China Passport | 0.80 | No | No |
| Hong Kong ID | 0.70 | No | No |
| Macau ID | 0.70 | No | No |
| Taiwan National ID | 0.70 | No | No |

## Asia-Pacific - Japan

6 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Japan My Number | 0.70 | No | No |
| Japan Passport | 0.80 | No | No |
| Japan DL | 0.55 | No | No |
| Japan Juminhyo Code | 0.70 | No | No |
| Japan Health Insurance | 0.70 | No | No |
| Japan Residence Card | 0.70 | No | No |

## Asia-Pacific - South Korea

3 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| South Korea RRN | 0.70 | No | No |
| South Korea Passport | 0.80 | No | No |
| South Korea DL | 0.55 | No | No |

## Asia-Pacific - Singapore

4 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Singapore NRIC | 0.40 | No | No |
| Singapore FIN | 0.70 | No | No |
| Singapore Passport | 0.40 | No | No |
| Singapore DL | 0.40 | No | No |

## Asia-Pacific - Australia

11 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Australia TFN | 0.40 | No | No |
| Australia Medicare | 0.70 | No | No |
| Australia Passport | 0.40 | No | No |
| Australia DL NSW | 0.40 | No | No |
| Australia DL VIC | 0.40 | No | No |
| Australia DL QLD | 0.40 | No | No |
| Australia DL WA | 0.70 | No | No |
| Australia DL SA | 0.40 | No | No |
| Australia DL TAS | 0.40 | No | No |
| Australia DL ACT | 0.40 | No | No |
| Australia DL NT | 0.40 | No | No |

## Asia-Pacific - New Zealand

4 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| New Zealand IRD | 0.40 | No | No |
| New Zealand Passport | 0.80 | No | No |
| New Zealand NHI | 0.70 | No | No |
| New Zealand DL | 0.55 | No | No |

## Asia-Pacific - Philippines

6 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Philippines PhilSys | 0.40 | No | No |
| Philippines TIN | 0.40 | No | No |
| Philippines SSS | 0.40 | No | No |
| Philippines PhilHealth | 0.70 | No | No |
| Philippines Passport | 0.40 | No | No |
| Philippines UMID | 0.40 | No | No |

## Asia-Pacific - Thailand

4 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Thailand National ID | 0.40 | No | No |
| Thailand Passport | 0.40 | No | No |
| Thailand DL | 0.55 | No | No |
| Thailand Tax ID | 0.70 | No | No |

## Asia-Pacific - Malaysia

2 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Malaysia MyKad | 0.70 | No | No |
| Malaysia Passport | 0.40 | No | No |

## Asia-Pacific - Indonesia

3 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Indonesia NIK | 0.40 | No | No |
| Indonesia NPWP | 0.70 | No | No |
| Indonesia Passport | 0.40 | No | No |

## Asia-Pacific - Vietnam

3 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Vietnam CCCD | 0.40 | No | No |
| Vietnam Passport | 0.40 | No | No |
| Vietnam Tax Code | 0.70 | No | No |

## Asia-Pacific - Pakistan

3 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Pakistan CNIC | 0.40 | No | No |
| Pakistan NICOP | 0.70 | No | No |
| Pakistan Passport | 0.80 | No | No |

## Asia-Pacific - Bangladesh

3 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Bangladesh NID | 0.40 | No | No |
| Bangladesh Passport | 0.40 | No | No |
| Bangladesh TIN | 0.70 | No | No |

## Asia-Pacific - Sri Lanka

3 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Sri Lanka NIC Old | 0.70 | No | No |
| Sri Lanka NIC New | 0.40 | No | No |
| Sri Lanka Passport | 0.80 | No | No |

## Latin America - Brazil

6 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Brazil CPF | 0.40 | No | No |
| Brazil CNPJ | 0.40 | No | No |
| Brazil RG | 0.40 | No | No |
| Brazil CNH | 0.40 | No | No |
| Brazil SUS Card | 0.70 | No | No |
| Brazil Passport | 0.40 | No | No |

## Latin America - Argentina

3 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Argentina DNI | 0.40 | No | No |
| Argentina CUIL/CUIT | 0.70 | No | No |
| Argentina Passport | 0.40 | No | No |

## Latin America - Colombia

4 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Colombia Cedula | 0.40 | No | No |
| Colombia NIT | 0.40 | No | No |
| Colombia NUIP | 0.70 | No | No |
| Colombia Passport | 0.40 | No | No |

## Latin America - Chile

2 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Chile RUN/RUT | 0.70 | No | No |
| Chile Passport | 0.40 | No | No |

## Latin America - Peru

4 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Peru DNI | 0.40 | No | No |
| Peru RUC | 0.40 | No | No |
| Peru Carnet Extranjeria | 0.70 | No | No |
| Peru Passport | 0.40 | No | No |

## Latin America - Venezuela

3 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Venezuela Cedula | 0.40 | No | No |
| Venezuela RIF | 0.70 | No | No |
| Venezuela Passport | 0.40 | No | No |

## Latin America - Ecuador

3 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Ecuador Cedula | 0.40 | No | No |
| Ecuador RUC | 0.70 | No | No |
| Ecuador Passport | 0.40 | No | No |

## Latin America - Uruguay

3 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Uruguay Cedula | 0.40 | No | No |
| Uruguay RUT | 0.70 | No | No |
| Uruguay Passport | 0.40 | No | No |

## Latin America - Paraguay

3 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Paraguay Cedula | 0.40 | No | No |
| Paraguay RUC | 0.70 | No | No |
| Paraguay Passport | 0.40 | No | No |

## Latin America - Costa Rica

3 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Costa Rica Cedula | 0.40 | No | No |
| Costa Rica DIMEX | 0.70 | No | No |
| Costa Rica Passport | 0.80 | No | No |

## Middle East - Saudi Arabia

2 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Saudi Arabia National ID | 0.70 | No | No |
| Saudi Arabia Passport | 0.40 | No | No |

## Middle East - UAE

3 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| UAE Emirates ID | 0.40 | No | No |
| UAE Visa Number | 0.70 | No | No |
| UAE Passport | 0.40 | No | No |

## Middle East - Israel

2 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Israel Teudat Zehut | 0.70 | No | No |
| Israel Passport | 0.80 | No | No |

## Middle East - Qatar

2 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Qatar QID | 0.70 | No | No |
| Qatar Passport | 0.40 | No | No |

## Middle East - Kuwait

2 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Kuwait Civil ID | 0.70 | No | No |
| Kuwait Passport | 0.40 | No | No |

## Middle East - Bahrain

2 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Bahrain CPR | 0.70 | No | No |
| Bahrain Passport | 0.40 | No | No |

## Middle East - Jordan

2 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Jordan National ID | 0.70 | No | No |
| Jordan Passport | 0.40 | No | No |

## Middle East - Lebanon

2 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Lebanon ID | 0.70 | No | No |
| Lebanon Passport | 0.40 | No | No |

## Middle East - Iraq

2 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Iraq National ID | 0.70 | No | No |
| Iraq Passport | 0.40 | No | No |

## Middle East - Iran

2 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Iran Melli Code | 0.70 | No | No |
| Iran Passport | 0.40 | No | No |

## Africa - South Africa

3 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| South Africa ID | 0.65 | No | No |
| South Africa Passport | 0.40 | No | No |
| South Africa DL | 0.55 | No | No |

## Africa - Nigeria

6 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Nigeria NIN | 0.40 | No | No |
| Nigeria BVN | 0.40 | No | No |
| Nigeria TIN | 0.40 | No | No |
| Nigeria Voter Card | 0.40 | No | No |
| Nigeria Driver Licence | 0.65 | No | No |
| Nigeria Passport | 0.40 | No | No |

## Africa - Kenya

4 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Kenya National ID | 0.40 | No | No |
| Kenya KRA PIN | 0.40 | No | No |
| Kenya NHIF | 0.65 | No | No |
| Kenya Passport | 0.40 | No | No |

## Africa - Egypt

3 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Egypt National ID | 0.40 | No | No |
| Egypt Tax ID | 0.65 | No | No |
| Egypt Passport | 0.40 | No | No |

## Africa - Ghana

4 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Ghana Card | 0.40 | No | No |
| Ghana TIN | 0.40 | No | No |
| Ghana NHIS | 0.65 | No | No |
| Ghana Passport | 0.40 | No | No |

## Africa - Ethiopia

3 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Ethiopia National ID | 0.40 | No | No |
| Ethiopia TIN | 0.65 | No | No |
| Ethiopia Passport | 0.40 | No | No |

## Africa - Tanzania

3 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Tanzania NIDA | 0.40 | No | No |
| Tanzania TIN | 0.65 | No | No |
| Tanzania Passport | 0.80 | No | No |

## Africa - Morocco

3 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Morocco CIN | 0.40 | No | No |
| Morocco Tax ID | 0.65 | No | No |
| Morocco Passport | 0.40 | No | No |

## Africa - Tunisia

2 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Tunisia CIN | 0.65 | No | No |
| Tunisia Passport | 0.40 | No | No |

## Africa - Uganda

2 patterns

| Pattern | Specificity | Case Insensitive | Context Required |
|---|:---:|:---:|:---:|
| Uganda NIN | 0.65 | No | No |
| Uganda Passport | 0.40 | No | No |
