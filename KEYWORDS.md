# Context Keywords Reference

Complete inventory of all context keywords used by dlpscan for proximity-based detection boosting.
**560 keyword groups** across **126 categories** with **2718 individual keywords**.

## How Context Keywords Work

When a pattern match is found, dlpscan checks whether supporting keywords appear
within a configurable distance (typically 50-100 characters) of the match. If context
keywords are present, the confidence score is boosted. For low-specificity patterns
(e.g., generic number formats), context keywords are required to report a match.

## Table of Contents

- [Credit Card Numbers (7 groups)](#credit-card-numbers)
- [Primary Account Numbers (2 groups)](#primary-account-numbers)
- [Card Track Data (2 groups)](#card-track-data)
- [Card Expiration Dates (1 groups)](#card-expiration-dates)
- [Contact Information (5 groups)](#contact-information)
- [Banking and Financial (5 groups)](#banking-and-financial)
- [Wire Transfer Data (6 groups)](#wire-transfer-data)
- [Check and MICR Data (3 groups)](#check-and-micr-data)
- [Securities Identifiers (6 groups)](#securities-identifiers)
- [Loan and Mortgage Data (4 groups)](#loan-and-mortgage-data)
- [Regulatory Identifiers (6 groups)](#regulatory-identifiers)
- [Banking Authentication (3 groups)](#banking-authentication)
- [Customer Financial Data (4 groups)](#customer-financial-data)
- [Internal Banking References (2 groups)](#internal-banking-references)
- [PCI Sensitive Data (1 groups)](#pci-sensitive-data)
- [Cryptocurrency (7 groups)](#cryptocurrency)
- [Vehicle Identification (1 groups)](#vehicle-identification)
- [Dates (3 groups)](#dates)
- [URLs with Credentials (2 groups)](#urls-with-credentials)
- [Generic Secrets (6 groups)](#generic-secrets)
- [Personal Identifiers (2 groups)](#personal-identifiers)
- [Geolocation (3 groups)](#geolocation)
- [Postal Codes (5 groups)](#postal-codes)
- [Device Identifiers (5 groups)](#device-identifiers)
- [Medical Identifiers (4 groups)](#medical-identifiers)
- [Insurance Identifiers (2 groups)](#insurance-identifiers)
- [Authentication Tokens (1 groups)](#authentication-tokens)
- [Social Media Identifiers (2 groups)](#social-media-identifiers)
- [Education Identifiers (1 groups)](#education-identifiers)
- [Legal Identifiers (2 groups)](#legal-identifiers)
- [Employment Identifiers (2 groups)](#employment-identifiers)
- [Biometric Identifiers (2 groups)](#biometric-identifiers)
- [Property Identifiers (2 groups)](#property-identifiers)
- [Supervisory Information (6 groups)](#supervisory-information)
- [Privileged Information (7 groups)](#privileged-information)
- [Data Classification Labels (8 groups)](#data-classification-labels)
- [Corporate Classification (9 groups)](#corporate-classification)
- [Financial Regulatory Labels (7 groups)](#financial-regulatory-labels)
- [Privacy Classification (10 groups)](#privacy-classification)
- [Cloud Provider Secrets (3 groups)](#cloud-provider-secrets)
- [Code Platform Secrets (5 groups)](#code-platform-secrets)
- [Payment Service Secrets (2 groups)](#payment-service-secrets)
- [Messaging Service Secrets (6 groups)](#messaging-service-secrets)
- [North America - United States (63 groups)](#north-america-united-states)
- [North America - US Generic DL (1 groups)](#north-america-us-generic-dl)
- [North America - Canada (29 groups)](#north-america-canada)
- [North America - Mexico (7 groups)](#north-america-mexico)
- [Europe - United Kingdom (7 groups)](#europe-united-kingdom)
- [Europe - Germany (6 groups)](#europe-germany)
- [Europe - France (5 groups)](#europe-france)
- [Europe - Italy (5 groups)](#europe-italy)
- [Europe - Netherlands (4 groups)](#europe-netherlands)
- [Europe - Spain (5 groups)](#europe-spain)
- [Europe - Poland (6 groups)](#europe-poland)
- [Europe - Sweden (4 groups)](#europe-sweden)
- [Europe - Portugal (4 groups)](#europe-portugal)
- [Europe - Switzerland (4 groups)](#europe-switzerland)
- [Europe - Turkey (4 groups)](#europe-turkey)
- [Europe - Austria (5 groups)](#europe-austria)
- [Europe - Belgium (4 groups)](#europe-belgium)
- [Europe - Ireland (4 groups)](#europe-ireland)
- [Europe - Denmark (3 groups)](#europe-denmark)
- [Europe - Finland (3 groups)](#europe-finland)
- [Europe - Norway (4 groups)](#europe-norway)
- [Europe - Czech Republic (4 groups)](#europe-czech-republic)
- [Europe - Hungary (5 groups)](#europe-hungary)
- [Europe - Romania (4 groups)](#europe-romania)
- [Europe - Greece (5 groups)](#europe-greece)
- [Europe - Croatia (4 groups)](#europe-croatia)
- [Europe - Bulgaria (4 groups)](#europe-bulgaria)
- [Europe - Slovakia (3 groups)](#europe-slovakia)
- [Europe - Lithuania (3 groups)](#europe-lithuania)
- [Europe - Latvia (3 groups)](#europe-latvia)
- [Europe - Estonia (3 groups)](#europe-estonia)
- [Europe - Slovenia (4 groups)](#europe-slovenia)
- [Europe - Luxembourg (3 groups)](#europe-luxembourg)
- [Europe - Malta (3 groups)](#europe-malta)
- [Europe - Cyprus (3 groups)](#europe-cyprus)
- [Europe - Iceland (2 groups)](#europe-iceland)
- [Europe - Liechtenstein (2 groups)](#europe-liechtenstein)
- [Europe - EU (2 groups)](#europe-eu)
- [Asia-Pacific - India (6 groups)](#asia-pacific-india)
- [Asia-Pacific - China (5 groups)](#asia-pacific-china)
- [Asia-Pacific - Japan (6 groups)](#asia-pacific-japan)
- [Asia-Pacific - South Korea (3 groups)](#asia-pacific-south-korea)
- [Asia-Pacific - Singapore (4 groups)](#asia-pacific-singapore)
- [Asia-Pacific - Australia (11 groups)](#asia-pacific-australia)
- [Asia-Pacific - New Zealand (4 groups)](#asia-pacific-new-zealand)
- [Asia-Pacific - Philippines (6 groups)](#asia-pacific-philippines)
- [Asia-Pacific - Thailand (4 groups)](#asia-pacific-thailand)
- [Asia-Pacific - Malaysia (2 groups)](#asia-pacific-malaysia)
- [Asia-Pacific - Indonesia (3 groups)](#asia-pacific-indonesia)
- [Asia-Pacific - Vietnam (3 groups)](#asia-pacific-vietnam)
- [Asia-Pacific - Pakistan (3 groups)](#asia-pacific-pakistan)
- [Asia-Pacific - Bangladesh (3 groups)](#asia-pacific-bangladesh)
- [Asia-Pacific - Sri Lanka (3 groups)](#asia-pacific-sri-lanka)
- [Latin America - Brazil (6 groups)](#latin-america-brazil)
- [Latin America - Argentina (3 groups)](#latin-america-argentina)
- [Latin America - Colombia (4 groups)](#latin-america-colombia)
- [Latin America - Chile (2 groups)](#latin-america-chile)
- [Latin America - Peru (4 groups)](#latin-america-peru)
- [Latin America - Venezuela (3 groups)](#latin-america-venezuela)
- [Latin America - Ecuador (3 groups)](#latin-america-ecuador)
- [Latin America - Uruguay (3 groups)](#latin-america-uruguay)
- [Latin America - Paraguay (3 groups)](#latin-america-paraguay)
- [Latin America - Costa Rica (3 groups)](#latin-america-costa-rica)
- [Middle East - Saudi Arabia (2 groups)](#middle-east-saudi-arabia)
- [Middle East - UAE (3 groups)](#middle-east-uae)
- [Middle East - Israel (2 groups)](#middle-east-israel)
- [Middle East - Qatar (2 groups)](#middle-east-qatar)
- [Middle East - Kuwait (2 groups)](#middle-east-kuwait)
- [Middle East - Bahrain (2 groups)](#middle-east-bahrain)
- [Middle East - Jordan (2 groups)](#middle-east-jordan)
- [Middle East - Lebanon (2 groups)](#middle-east-lebanon)
- [Middle East - Iraq (2 groups)](#middle-east-iraq)
- [Middle East - Iran (2 groups)](#middle-east-iran)
- [Africa - South Africa (3 groups)](#africa-south-africa)
- [Africa - Nigeria (6 groups)](#africa-nigeria)
- [Africa - Kenya (4 groups)](#africa-kenya)
- [Africa - Egypt (3 groups)](#africa-egypt)
- [Africa - Ghana (4 groups)](#africa-ghana)
- [Africa - Ethiopia (3 groups)](#africa-ethiopia)
- [Africa - Tanzania (3 groups)](#africa-tanzania)
- [Africa - Morocco (3 groups)](#africa-morocco)
- [Africa - Tunisia (2 groups)](#africa-tunisia)
- [Africa - Uganda (2 groups)](#africa-uganda)

## Credit Card Numbers

7 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Visa | 50 | `visa`, `credit card`, `card number`, `card no`, `pan`, `primary account` |
| MasterCard | 50 | `mastercard`, `credit card`, `card number`, `card no`, `pan`, `primary account` |
| Amex | 50 | `amex`, `american express`, `credit card`, `card number`, `pan`, `primary account` |
| Discover | 50 | `discover`, `credit card`, `card number`, `pan`, `primary account` |
| JCB | 50 | `jcb`, `credit card`, `card number`, `pan`, `primary account` |
| Diners Club | 50 | `diners club`, `diners`, `credit card`, `card number`, `pan`, `primary account` |
| UnionPay | 50 | `unionpay`, `union pay`, `credit card`, `card number`, `pan`, `primary account` |

## Primary Account Numbers

2 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| PAN | 50 | `pan`, `primary account number`, `account number`, `card number`, `cardholder number`, `full card` |
| Masked PAN | 50 | `masked pan`, `truncated pan`, `masked card`, `truncated card`, `last four`, `first six` |

## Card Track Data

2 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Track 1 Data | 50 | `track 1`, `track1`, `magnetic stripe`, `magstripe`, `swipe data`, `card track` |
| Track 2 Data | 50 | `track 2`, `track2`, `magnetic stripe`, `magstripe`, `swipe data`, `card track` |

## Card Expiration Dates

1 keyword group

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Card Expiry | 30 | `expiry`, `expiration`, `exp date`, `exp`, `valid thru`, `valid through`, `good thru`, `card expires`, `mm/yy` |

## Contact Information

5 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Email Address | 50 | `email`, `e-mail`, `email address`, `mail to`, `contact` |
| E.164 Phone Number | 50 | `phone`, `telephone`, `tel`, `mobile`, `contact number` |
| IPv4 Address | 50 | `ip address`, `ip`, `server`, `host`, `network` |
| IPv6 Address | 50 | `ip address`, `ipv6`, `server`, `host`, `network` |
| MAC Address | 50 | `mac address`, `hardware address`, `physical address`, `mac` |

## Banking and Financial

5 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| IBAN Generic | 50 | `iban`, `international bank account number`, `bank account` |
| SWIFT/BIC | 50 | `swift`, `bic`, `bank identifier code`, `swift code`, `routing code` |
| ABA Routing Number | 50 | `routing number`, `routing no`, `aba`, `aba routing`, `transit routing`, `bank routing`, `rtn` |
| US Bank Account Number | 50 | `account number`, `account no`, `bank account`, `checking account`, `savings account`, `acct`, `acct no`, `deposit account` |
| Canada Transit Number | 50 | `transit number`, `institution number`, `canadian bank`, `bank transit` |

## Wire Transfer Data

6 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Fedwire IMAD | 50 | `imad`, `input message accountability`, `fedwire`, `fed reference`, `wire reference` |
| CHIPS UID | 50 | `chips`, `chips uid`, `chips transfer`, `clearing house`, `interbank payment` |
| Wire Reference Number | 50 | `wire reference`, `wire transfer`, `wire number`, `remittance reference`, `payment reference`, `transfer reference` |
| ACH Trace Number | 50 | `ach trace`, `trace number`, `trace id`, `ach transaction`, `ach payment`, `nacha` |
| ACH Batch Number | 50 | `ach batch`, `batch number`, `batch id`, `ach file`, `nacha batch` |
| SEPA Reference | 50 | `sepa`, `sepa reference`, `end-to-end`, `e2e reference`, `sepa transfer`, `sepa credit` |

## Check and MICR Data

3 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| MICR Line | 50 | `micr`, `magnetic ink`, `check bottom`, `cheque line`, `micr line`, `e13b` |
| Check Number | 50 | `check number`, `check no`, `cheque number`, `check#`, `ck no`, `check num` |
| Cashier Check Number | 50 | `cashier check`, `cashiers check`, `certified check`, `money order`, `bank check`, `official check` |

## Securities Identifiers

6 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| CUSIP | 50 | `cusip`, `committee on uniform securities`, `security identifier`, `bond cusip`, `cusip number` |
| ISIN | 50 | `isin`, `international securities`, `securities identification`, `isin code`, `isin number` |
| SEDOL | 50 | `sedol`, `stock exchange daily official list`, `london stock`, `uk securities` |
| FIGI | 50 | `figi`, `financial instrument global identifier`, `bloomberg`, `bbg`, `openfigi` |
| LEI | 50 | `lei`, `legal entity identifier`, `gleif`, `entity identifier`, `lei code` |
| Ticker Symbol | 50 | `ticker`, `stock symbol`, `trading symbol`, `nyse`, `nasdaq`, `equity symbol`, `stock ticker` |

## Loan and Mortgage Data

4 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Loan Number | 50 | `loan number`, `loan no`, `loan id`, `loan account`, `loan#`, `lending number` |
| MERS MIN | 50 | `mers`, `mortgage identification number`, `min number`, `mers min`, `mortgage electronic` |
| Universal Loan Identifier | 50 | `uli`, `universal loan identifier`, `hmda`, `loan identifier` |
| LTV Ratio | 50 | `ltv`, `loan-to-value`, `loan to value`, `ltv ratio`, `combined ltv`, `cltv` |

## Regulatory Identifiers

6 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| SAR Filing Number | 50 | `sar`, `suspicious activity report`, `sar filing`, `sar number`, `suspicious activity` |
| CTR Number | 50 | `ctr`, `currency transaction report`, `ctr filing`, `ctr number`, `cash transaction` |
| AML Case ID | 50 | `aml`, `anti-money laundering`, `money laundering`, `aml case`, `aml investigation`, `bsa` |
| OFAC SDN Entry | 50 | `ofac`, `sdn`, `specially designated`, `sanctions`, `ofac list`, `blocked persons` |
| FinCEN Report Number | 50 | `fincen`, `financial crimes`, `fincen report`, `fincen filing`, `bsa filing` |
| Compliance Case Number | 50 | `compliance case`, `investigation number`, `regulatory case`, `compliance id`, `audit case`, `examination number` |

## Banking Authentication

3 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| PIN Block | 50 | `pin block`, `encrypted pin`, `pin encryption`, `iso 9564`, `pin format` |
| HSM Key | 50 | `hsm`, `hardware security module`, `hsm key`, `master key`, `key material` |
| Encryption Key | 50 | `kek`, `zmk`, `tmk`, `zone master key`, `key encrypting`, `terminal master key`, `transport key`, `working key` |

## Customer Financial Data

4 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Account Balance | 50 | `balance`, `account balance`, `available balance`, `current balance`, `ledger balance`, `closing balance` |
| Balance with Currency Code | 50 | `balance`, `amount`, `total`, `funds`, `available`, `ledger` |
| Income Amount | 50 | `income`, `salary`, `annual income`, `monthly income`, `gross income`, `net income`, `compensation`, `wages`, `earnings` |
| DTI Ratio | 50 | `dti`, `debt-to-income`, `debt to income`, `dti ratio`, `debt ratio` |

## Internal Banking References

2 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Internal Account Ref | 50 | `internal reference`, `account reference`, `internal id`, `system id`, `core banking id` |
| Teller ID | 50 | `teller id`, `teller number`, `officer id`, `banker id`, `employee id`, `user id` |

## PCI Sensitive Data

1 keyword group

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Cardholder Name Pattern | 30 | `cardholder`, `cardholder name`, `name on card`, `card holder`, `card member` |

## Cryptocurrency

7 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Bitcoin Address (Legacy) | 50 | `bitcoin`, `btc`, `wallet`, `crypto` |
| Bitcoin Address (Bech32) | 50 | `bitcoin`, `btc`, `segwit`, `wallet` |
| Ethereum Address | 50 | `ethereum`, `eth`, `ether`, `wallet`, `crypto` |
| Litecoin Address | 50 | `litecoin`, `ltc`, `wallet` |
| Bitcoin Cash Address | 50 | `bitcoin cash`, `bch`, `wallet` |
| Monero Address | 50 | `monero`, `xmr`, `wallet` |
| Ripple Address | 50 | `ripple`, `xrp`, `wallet` |

## Vehicle Identification

1 keyword group

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| VIN | 50 | `vin`, `vehicle identification`, `vehicle id`, `chassis number`, `vehicle number` |

## Dates

3 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Date ISO | 50 | `date of birth`, `dob`, `birth date`, `birthday`, `born on`, `born`, `birthdate` |
| Date US | 50 | `date of birth`, `dob`, `birth date`, `birthday`, `born on`, `born`, `birthdate` |
| Date EU | 50 | `date of birth`, `dob`, `birth date`, `birthday`, `born on`, `born`, `birthdate` |

## URLs with Credentials

2 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| URL with Password | 80 | `url`, `link`, `endpoint`, `connection`, `connect` |
| URL with Token | 80 | `url`, `link`, `endpoint`, `api`, `callback` |

## Generic Secrets

6 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Bearer Token | 80 | `authorization`, `bearer`, `auth token` |
| JWT Token | 80 | `jwt`, `json web token`, `auth`, `token` |
| Private Key | 80 | `private key`, `rsa`, `ssh key`, `pem` |
| Generic API Key | 80 | `api key`, `api_key`, `apikey`, `api secret` |
| Generic Secret Assignment | 80 | `password`, `secret`, `credential`, `passwd` |
| Database Connection String | 80 | `database`, `db connection`, `connection string`, `mongodb`, `postgres`, `mysql`, `redis` |

## Personal Identifiers

2 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Date of Birth | 30 | `date of birth`, `dob`, `born on`, `birth date`, `birthday`, `birthdate`, `d.o.b` |
| Gender Marker | 30 | `gender`, `sex`, `identified as`, `gender identity`, `biological sex` |

## Geolocation

3 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| GPS Coordinates | 50 | `latitude`, `longitude`, `lat`, `lng`, `lon`, `coordinates`, `gps`, `geolocation`, `location`, `coord` |
| GPS DMS | 50 | `latitude`, `longitude`, `coordinates`, `gps`, `dms`, `degrees minutes seconds` |
| Geohash | 50 | `geohash`, `geo hash`, `location hash` |

## Postal Codes

5 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| US ZIP+4 Code | 50 | `zip`, `zip code`, `zipcode`, `postal code`, `postcode`, `mailing address`, `zip+4`, `united states`, `usa` |
| UK Postcode | 50 | `postcode`, `post code`, `postal code`, `zip code`, `uk address`, `united kingdom` |
| Canada Postal Code | 50 | `postal code`, `postcode`, `zip code`, `code postal`, `canadian address`, `canada` |
| Japan Postal Code | 50 | `postal code`, `postcode`, `zip code`, `yubin bangou`, `japanese address`, `japan` |
| Brazil CEP | 50 | `cep`, `postal code`, `postcode`, `zip code`, `codigo postal`, `brazilian address`, `brazil` |

## Device Identifiers

5 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| IMEI | 50 | `imei`, `international mobile equipment identity`, `device imei`, `handset id`, `phone imei`, `equipment identity` |
| IMEISV | 50 | `imeisv`, `imei software version`, `imei sv`, `software version number` |
| MEID | 50 | `meid`, `mobile equipment identifier`, `cdma device`, `equipment id` |
| ICCID | 50 | `iccid`, `sim card number`, `sim number`, `integrated circuit card`, `sim id`, `sim serial` |
| IDFA/IDFV | 50 | `idfa`, `idfv`, `advertising identifier`, `identifier for advertisers`, `vendor identifier`, `apple device id` |

## Medical Identifiers

4 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Health Plan ID | 50 | `health plan`, `insurance id`, `beneficiary`, `member id`, `subscriber id` |
| DEA Number | 50 | `dea`, `dea number`, `drug enforcement`, `prescriber`, `controlled substance` |
| ICD-10 Code | 50 | `icd`, `icd-10`, `diagnosis code`, `diagnostic code`, `condition code`, `icd code` |
| NDC Code | 50 | `ndc`, `national drug code`, `drug code`, `medication code`, `pharmaceutical` |

## Insurance Identifiers

2 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Insurance Policy Number | 50 | `policy number`, `policy no`, `insurance policy`, `policy id`, `coverage number`, `policy#` |
| Insurance Claim Number | 50 | `claim number`, `claim no`, `claim id`, `claim#`, `claims reference`, `incident number` |

## Authentication Tokens

1 keyword group

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Session ID | 50 | `session id`, `session_id`, `sessionid`, `sess_id`, `session token`, `phpsessid`, `jsessionid`, `asp.net_sessionid` |

## Social Media Identifiers

2 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Twitter Handle | 50 | `twitter`, `tweet`, `x.com`, `twitter handle`, `twitter username`, `follow` |
| Hashtag | 50 | `hashtag`, `tagged`, `trending`, `topic` |

## Education Identifiers

1 keyword group

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| EDU Email | 50 | `student email`, `edu email`, `university email`, `academic email`, `school email`, `college email` |

## Legal Identifiers

2 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| US Federal Case Number | 50 | `case number`, `case no`, `docket`, `civil action`, `case#`, `filing number` |
| Court Docket Number | 50 | `docket number`, `docket no`, `court case`, `case file`, `case reference`, `court number` |

## Employment Identifiers

2 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Employee ID | 50 | `employee id`, `employee number`, `emp id`, `staff id`, `personnel number`, `emp no`, `worker id`, `badge number` |
| Work Permit Number | 50 | `work permit`, `work visa`, `employment authorization`, `ead`, `labor permit`, `work authorization` |

## Biometric Identifiers

2 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Biometric Hash | 50 | `biometric`, `fingerprint hash`, `fingerprint`, `facial recognition`, `iris scan`, `palm print`, `voiceprint`, `retina scan` |
| Biometric Template ID | 50 | `biometric template`, `facial template`, `fingerprint template`, `enrollment id`, `biometric id` |

## Property Identifiers

2 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Parcel Number | 50 | `parcel number`, `apn`, `assessor parcel`, `parcel id`, `lot number`, `property id` |
| Title Deed Number | 50 | `title number`, `deed number`, `deed of trust`, `title deed`, `land title`, `property title` |

## Supervisory Information

6 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Supervisory Controlled | 80 | `supervisory`, `controlled`, `occ`, `fdic`, `federal reserve`, `regulator`, `examination` |
| Supervisory Confidential | 80 | `supervisory`, `confidential`, `regulator`, `examination`, `bank examination` |
| CSI | 80 | `confidential supervisory`, `csi`, `examination report`, `regulatory report`, `supervisory letter` |
| Non-Public Supervisory | 80 | `non-public`, `supervisory`, `regulatory`, `examination`, `not for release` |
| Restricted Supervisory | 80 | `restricted`, `supervisory`, `regulatory`, `compliance`, `enforcement` |
| Examination Findings | 80 | `examination`, `mra`, `mria`, `findings`, `regulatory`, `corrective action`, `consent order` |

## Privileged Information

7 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Attorney-Client Privilege | 100 | `attorney`, `client`, `privilege`, `legal counsel`, `law firm`, `privileged communication` |
| Privileged and Confidential | 100 | `privileged`, `confidential`, `legal`, `attorney`, `counsel` |
| Work Product | 100 | `work product`, `attorney`, `litigation`, `legal`, `prepared in anticipation` |
| Privileged Information | 100 | `privileged`, `legal`, `attorney`, `counsel`, `protected` |
| Legal Privilege | 100 | `legal`, `privilege`, `attorney`, `counsel`, `protected communication` |
| Litigation Hold | 100 | `litigation`, `legal hold`, `preservation`, `hold notice`, `document retention` |
| Protected by Privilege | 100 | `privilege`, `protected`, `attorney`, `legal`, `exempt from disclosure` |

## Data Classification Labels

8 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Top Secret | 100 | `classified`, `top secret`, `ts`, `sci`, `national security`, `clearance` |
| Secret Classification | 100 | `classified`, `secret`, `national security`, `clearance`, `noforn` |
| Confidential Classification | 100 | `classified`, `confidential`, `national security`, `government`, `security classification`, `clearance` |
| FOUO | 100 | `official use`, `fouo`, `government`, `not for public release`, `classified`, `security classification`, `clearance` |
| CUI | 100 | `cui`, `controlled unclassified`, `sensitive information`, `marking`, `classified`, `security classification`, `clearance` |
| SBU | 100 | `sensitive`, `unclassified`, `sbu`, `government`, `classified`, `security classification`, `clearance` |
| LES | 100 | `law enforcement`, `sensitive`, `les`, `police`, `investigation`, `classified`, `security classification`, `clearance` |
| NOFORN | 100 | `noforn`, `foreign nationals`, `not releasable`, `classification`, `classified`, `security classification`, `clearance` |

## Corporate Classification

9 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Internal Only | 80 | `internal`, `company`, `employees only`, `staff only`, `not for external` |
| Restricted | 80 | `restricted`, `limited distribution`, `access controlled`, `need to know` |
| Corporate Confidential | 80 | `confidential`, `company`, `corporate`, `business`, `proprietary` |
| Highly Confidential | 80 | `highly confidential`, `sensitive`, `restricted`, `executive only` |
| Do Not Distribute | 80 | `distribute`, `distribution`, `circulation`, `forward`, `share` |
| Need to Know | 80 | `need to know`, `restricted access`, `limited distribution`, `authorized personnel` |
| Eyes Only | 80 | `eyes only`, `recipient only`, `personal`, `addressee only` |
| Proprietary | 80 | `proprietary`, `trade secret`, `intellectual property`, `confidential business` |
| Embargoed | 80 | `embargo`, `embargoed`, `hold until`, `not for release`, `publication date` |

## Financial Regulatory Labels

7 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| MNPI | 80 | `mnpi`, `material`, `non-public`, `insider`, `trading`, `securities` |
| Inside Information | 80 | `inside information`, `insider`, `material`, `non-public`, `trading restriction` |
| Pre-Decisional | 80 | `pre-decisional`, `draft`, `deliberative`, `not final`, `preliminary` |
| Draft Not for Circulation | 80 | `draft`, `circulation`, `preliminary`, `not final`, `review only` |
| Market Sensitive | 80 | `market sensitive`, `price sensitive`, `stock`, `securities`, `trading` |
| Information Barrier | 80 | `information barrier`, `chinese wall`, `wall crossing`, `restricted side`, `public side` |
| Investment Restricted | 80 | `restricted list`, `watch list`, `grey list`, `restricted securities`, `trading restriction` |

## Privacy Classification

10 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| PII Label | 80 | `pii`, `personally identifiable`, `personal information`, `sensitive data` |
| PHI Label | 80 | `phi`, `protected health`, `health information`, `medical records`, `patient data` |
| HIPAA | 80 | `hipaa`, `health insurance portability`, `medical privacy`, `health data` |
| GDPR Personal Data | 80 | `gdpr`, `personal data`, `data subject`, `data protection`, `eu regulation` |
| PCI-DSS | 80 | `pci`, `pci-dss`, `cardholder data`, `payment card`, `card data environment` |
| FERPA | 80 | `ferpa`, `educational records`, `student records`, `student privacy` |
| GLBA | 80 | `glba`, `gramm-leach-bliley`, `financial privacy`, `consumer financial` |
| CCPA/CPRA | 80 | `ccpa`, `cpra`, `california consumer`, `california privacy`, `consumer rights` |
| SOX | 80 | `sox`, `sarbanes-oxley`, `financial reporting`, `internal controls`, `audit` |
| NPI | 80 | `npi`, `non-public personal`, `financial privacy`, `glba`, `consumer information` |

## Cloud Provider Secrets

3 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| AWS Access Key | 80 | `aws`, `amazon`, `access key`, `aws key` |
| AWS Secret Key | 80 | `aws secret`, `secret access key`, `aws_secret` |
| Google API Key | 80 | `google`, `gcp`, `google api`, `google cloud` |

## Code Platform Secrets

5 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| GitHub Token (Classic) | 80 | `github`, `gh token`, `personal access token` |
| GitHub Token (Fine-Grained) | 80 | `github`, `fine-grained`, `pat` |
| GitHub OAuth Token | 80 | `github oauth`, `oauth token` |
| NPM Token | 80 | `npm`, `node package`, `npm token` |
| PyPI Token | 80 | `pypi`, `python package`, `pip` |

## Payment Service Secrets

2 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Stripe Secret Key | 80 | `stripe`, `payment`, `stripe secret` |
| Stripe Publishable Key | 80 | `stripe`, `publishable`, `stripe key` |

## Messaging Service Secrets

6 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Slack Bot Token | 80 | `slack`, `bot token`, `slack bot` |
| Slack User Token | 80 | `slack`, `user token`, `slack user` |
| Slack Webhook | 80 | `slack`, `webhook`, `incoming webhook` |
| SendGrid API Key | 80 | `sendgrid`, `email api` |
| Twilio API Key | 80 | `twilio`, `sms`, `messaging` |
| Mailgun API Key | 80 | `mailgun`, `email` |

## North America - United States

63 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| USA SSN | 50 | `social security number`, `ssn`, `social security no` |
| USA ITIN | 50 | `individual taxpayer`, `itin`, `taxpayer identification` |
| USA EIN | 50 | `employer identification`, `ein`, `federal tax id`, `fein` |
| USA Passport | 50 | `us passport`, `usa passport`, `american passport`, `passport number`, `passport book` |
| USA Passport Card | 50 | `passport card`, `us passport card`, `usa passport card` |
| USA Routing Number | 50 | `routing number`, `aba routing`, `routing transit` |
| US DEA Number | 50 | `dea number`, `dea registration`, `dea no`, `drug enforcement` |
| US NPI | 50 | `npi`, `national provider identifier`, `provider number` |
| US MBI | 50 | `mbi`, `medicare beneficiary`, `beneficiary identifier`, `medicare number`, `medicare id` |
| US DoD ID | 50 | `dod id`, `military id`, `edipi`, `cac card`, `common access card`, `department of defense` |
| US Known Traveler Number | 50 | `known traveler`, `ktn`, `global entry`, `trusted traveler`, `pass id`, `nexus`, `sentri` |
| US Phone Number | 50 | `phone`, `telephone`, `tel`, `cell`, `mobile`, `call`, `fax` |
| Alabama DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `alabama dl`, `alabama license` |
| Alaska DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `alaska dl`, `alaska license` |
| Arizona DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `arizona dl`, `arizona license` |
| Arkansas DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `arkansas dl`, `arkansas license` |
| California DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `california dl`, `california license` |
| Colorado DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `colorado dl`, `colorado license` |
| Connecticut DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `connecticut dl`, `connecticut license` |
| Delaware DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `delaware dl`, `delaware license` |
| DC DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `dc dl`, `district of columbia license` |
| Florida DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `florida dl`, `florida license` |
| Georgia DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `georgia dl`, `georgia license` |
| Hawaii DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `hawaii dl`, `hawaii license` |
| Idaho DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `idaho dl`, `idaho license` |
| Illinois DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `illinois dl`, `illinois license` |
| Indiana DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `indiana dl`, `indiana license` |
| Iowa DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `iowa dl`, `iowa license` |
| Kansas DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `kansas dl`, `kansas license` |
| Kentucky DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `kentucky dl`, `kentucky license` |
| Louisiana DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `louisiana dl`, `louisiana license` |
| Maine DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `maine dl`, `maine license` |
| Maryland DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `maryland dl`, `maryland license` |
| Massachusetts DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `massachusetts dl`, `massachusetts license` |
| Michigan DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `michigan dl`, `michigan license` |
| Minnesota DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `minnesota dl`, `minnesota license` |
| Mississippi DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `mississippi dl`, `mississippi license` |
| Missouri DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `missouri dl`, `missouri license` |
| Montana DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `montana dl`, `montana license` |
| Nebraska DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `nebraska dl`, `nebraska license` |
| Nevada DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `nevada dl`, `nevada license` |
| New Hampshire DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `new hampshire dl`, `new hampshire license` |
| New Jersey DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `new jersey dl`, `new jersey license` |
| New Mexico DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `new mexico dl`, `new mexico license` |
| New York DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `new york dl`, `new york license` |
| North Carolina DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `north carolina dl`, `north carolina license` |
| North Dakota DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `north dakota dl`, `north dakota license` |
| Ohio DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `ohio dl`, `ohio license` |
| Oklahoma DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `oklahoma dl`, `oklahoma license` |
| Oregon DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `oregon dl`, `oregon license` |
| Pennsylvania DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `pennsylvania dl`, `pennsylvania license` |
| Rhode Island DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `rhode island dl`, `rhode island license` |
| South Carolina DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `south carolina dl`, `south carolina license` |
| South Dakota DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `south dakota dl`, `south dakota license` |
| Tennessee DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `tennessee dl`, `tennessee license` |
| Texas DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `texas dl`, `texas license` |
| Utah DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `utah dl`, `utah license` |
| Vermont DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `vermont dl`, `vermont license` |
| Virginia DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `virginia dl`, `virginia license` |
| Washington DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `washington dl`, `washington license` |
| West Virginia DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `west virginia dl`, `west virginia license` |
| Wisconsin DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `wisconsin dl`, `wisconsin license` |
| Wyoming DL | 50 | `driver license`, `drivers license`, `driver's license`, `driving licence`, `dl`, `wyoming dl`, `wyoming license` |

## North America - US Generic DL

1 keyword group

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Generic US DL | 50 | `driver`, `license`, `licence`, `dl`, `driving`, `driver's license`, `dl number`, `driving license`, `driving licence`, `license id`, `driver license`, `drivers license`, `licence number`, `license number`, `dl no` |

## North America - Canada

29 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Canada SIN | 50 | `social insurance number`, `sin`, `social insurance no` |
| Canada BN | 50 | `business number`, `canada bn`, `cra business` |
| Canada Passport | 50 | `canadian passport`, `canada passport`, `passport canada` |
| Canada Bank Code | 50 | `transit number`, `institution number`, `bank transit` |
| Canada PR Card | 50 | `permanent resident`, `pr card`, `permanent resident card`, `immigration`, `landed immigrant` |
| Canada NEXUS | 50 | `nexus`, `nexus card`, `pass id`, `trusted traveler`, `nexus number`, `cbp pass` |
| Ontario DL | 50 | `ontario driver's licence`, `ontario dl`, `on dl` |
| Ontario HC | 50 | `ohip`, `ontario health card`, `ontario health insurance`, `health card number`, `ohip number` |
| Quebec DL | 50 | `quebec driver's licence`, `quebec dl`, `qc dl`, `permis de conduire` |
| Quebec HC | 50 | `ramq`, `carte soleil`, `quebec health card`, `regie assurance maladie`, `health insurance quebec` |
| British Columbia DL | 50 | `british columbia driver's licence`, `bc dl`, `bc driver's licence` |
| BC HC | 50 | `bc msp`, `medical services plan`, `bc health card`, `bc phn`, `personal health number` |
| Alberta DL | 50 | `alberta driver's licence`, `alberta dl`, `ab dl` |
| Alberta HC | 50 | `ahcip`, `alberta health card`, `alberta phn`, `alberta health care insurance`, `ab health` |
| Saskatchewan DL | 50 | `saskatchewan driver's licence`, `saskatchewan dl`, `sk dl` |
| Saskatchewan HC | 50 | `saskatchewan health card`, `sk health`, `sk phn`, `saskatchewan health number` |
| Manitoba DL | 50 | `manitoba driver's licence`, `manitoba dl`, `mb dl` |
| Manitoba HC | 50 | `manitoba phin`, `manitoba health card`, `mb health`, `personal health identification number` |
| New Brunswick DL | 50 | `new brunswick driver's licence`, `new brunswick dl`, `nb dl` |
| New Brunswick HC | 50 | `new brunswick health card`, `nb medicare`, `nb health`, `new brunswick medicare` |
| Nova Scotia DL | 50 | `nova scotia driver's licence`, `nova scotia dl`, `ns dl` |
| Nova Scotia HC | 50 | `nova scotia msi`, `msi card`, `msi number`, `nova scotia health card`, `ns health` |
| PEI DL | 50 | `pei driver's licence`, `prince edward island dl`, `pe dl` |
| PEI HC | 50 | `pei health card`, `prince edward island health`, `pe health card` |
| Newfoundland DL | 50 | `newfoundland driver's licence`, `newfoundland dl`, `nl dl`, `labrador dl` |
| Newfoundland HC | 50 | `newfoundland mcp`, `mcp card`, `mcp number`, `medical care plan`, `nl health card` |
| Yukon DL | 50 | `yukon driver's licence`, `yukon dl`, `yt dl` |
| NWT DL | 50 | `northwest territories driver's licence`, `nwt dl`, `nt dl` |
| Nunavut DL | 50 | `nunavut driver's licence`, `nunavut dl`, `nu dl` |

## North America - Mexico

7 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Mexico CURP | 50 | `curp`, `clave unica`, `clave unica de registro`, `registro de poblacion`, `population registry` |
| Mexico RFC | 50 | `rfc`, `registro federal`, `registro federal de contribuyentes`, `federal taxpayer`, `tax id mexico` |
| Mexico Clave Elector | 50 | `clave de elector`, `credencial para votar`, `credencial elector`, `ine`, `ife`, `voter credential` |
| Mexico INE CIC | 50 | `cic`, `codigo de identificacion`, `ine cic`, `credential identification code` |
| Mexico INE OCR | 50 | `ocr`, `ine ocr`, `optical character recognition`, `credencial ocr` |
| Mexico Passport | 50 | `pasaporte mexicano`, `mexico passport`, `mexican passport`, `pasaporte` |
| Mexico NSS | 50 | `nss`, `numero de seguro social`, `imss`, `seguro social`, `instituto mexicano del seguro social` |

## Europe - United Kingdom

7 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| UK NIN | 50 | `national insurance number`, `nin`, `national insurance no`, `ni number` |
| UK UTR | 50 | `unique taxpayer reference`, `utr`, `tax reference`, `self assessment` |
| UK Passport | 50 | `uk passport`, `british passport`, `united kingdom passport`, `hmpo` |
| UK Sort Code | 50 | `sort code`, `uk sort`, `bank sort`, `bank account` |
| British NHS | 50 | `nhs number`, `nhs no`, `national health service`, `nhs` |
| UK Phone Number | 50 | `phone`, `telephone`, `tel`, `mobile`, `uk phone` |
| UK DL | 50 | `driving licence`, `driver licence`, `dvla`, `uk driving`, `uk dl` |

## Europe - Germany

6 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Germany ID | 50 | `personalausweis`, `german id`, `identification number`, `ausweisnummer`, `national id`, `identity card`, `id card` |
| Germany Passport | 50 | `german passport`, `germany passport`, `reisepass` |
| Germany Tax ID | 50 | `steueridentifikationsnummer`, `steuer-id`, `tax identification`, `tin`, `steuernummer` |
| Germany Social Insurance | 50 | `sozialversicherungsnummer`, `social insurance`, `sv-nummer`, `rentenversicherung` |
| Germany DL | 50 | `fuhrerschein`, `driving licence`, `german driving`, `fahrerlaubnis` |
| Germany IBAN | 50 | `iban`, `german bank`, `bankverbindung`, `kontonummer` |

## Europe - France

5 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| France NIR | 50 | `insee`, `nir`, `securite sociale`, `french social security`, `numero de securite` |
| France Passport | 50 | `french passport`, `france passport`, `passeport` |
| France CNI | 50 | `carte nationale`, `carte identite`, `cni`, `french id card`, `national id`, `identity card`, `id card` |
| France DL | 50 | `permis de conduire`, `french driving`, `permis` |
| France IBAN | 50 | `iban`, `french bank`, `compte bancaire`, `rib` |

## Europe - Italy

5 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Italy Codice Fiscale | 50 | `codice fiscale`, `fiscal code`, `italian tax`, `cf`, `national id`, `identity card`, `id card`, `carta d'identita` |
| Italy Passport | 50 | `italian passport`, `italy passport`, `passaporto` |
| Italy DL | 50 | `patente di guida`, `italian driving`, `patente` |
| Italy SSN | 50 | `italian ssn`, `tessera sanitaria`, `health card` |
| Italy Partita IVA | 50 | `partita iva`, `vat number`, `p.iva`, `piva` |

## Europe - Netherlands

4 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Netherlands BSN | 50 | `burgerservicenummer`, `bsn`, `citizen service number`, `sofinummer`, `national id`, `identity card`, `id card` |
| Netherlands Passport | 50 | `dutch passport`, `netherlands passport`, `nl passport` |
| Netherlands DL | 50 | `rijbewijs`, `dutch driving`, `netherlands driving licence` |
| Netherlands IBAN | 50 | `iban`, `dutch bank`, `nl bank`, `rekeningnummer` |

## Europe - Spain

5 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Spain DNI | 50 | `dni`, `documento nacional de identidad`, `spanish id`, `national id`, `identity card`, `id card` |
| Spain NIE | 50 | `nie`, `numero de identidad de extranjero`, `foreigner id` |
| Spain Passport | 50 | `spanish passport`, `pasaporte`, `spain passport` |
| Spain NSS | 50 | `numero seguridad social`, `nss`, `spanish social security` |
| Spain DL | 50 | `permiso de conducir`, `carnet de conducir`, `spanish driving` |

## Europe - Poland

6 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Poland PESEL | 50 | `pesel`, `polish id`, `personal identification number`, `numer pesel`, `national id`, `identity card`, `id card` |
| Poland NIP | 50 | `nip`, `numer identyfikacji podatkowej`, `tax identification` |
| Poland REGON | 50 | `regon`, `statistical number`, `business registration` |
| Poland ID Card | 50 | `dowod osobisty`, `polish id card`, `identity card`, `national id`, `id card` |
| Poland Passport | 50 | `polish passport`, `paszport` |
| Poland DL | 50 | `prawo jazdy`, `polish driving`, `driving licence` |

## Europe - Sweden

4 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Sweden PIN | 50 | `personnummer`, `swedish id`, `personal identity number`, `swedish personal number`, `national id`, `identity card`, `id card` |
| Sweden Passport | 50 | `swedish passport`, `sverige pass` |
| Sweden DL | 50 | `korkort`, `swedish driving`, `driving licence` |
| Sweden Organisation Number | 50 | `organisationsnummer`, `org number`, `swedish company` |

## Europe - Portugal

4 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Portugal NIF | 50 | `nif`, `contribuinte`, `tax identification`, `numero fiscal` |
| Portugal CC | 50 | `cartao cidadao`, `citizen card`, `cartao de cidadao`, `cc number` |
| Portugal Passport | 50 | `portuguese passport`, `passaporte` |
| Portugal NISS | 50 | `niss`, `seguranca social`, `social security`, `numero seguranca` |

## Europe - Switzerland

4 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Switzerland AHV | 50 | `ahv`, `avs`, `swiss social security`, `ahv-nummer`, `oasi` |
| Switzerland Passport | 50 | `swiss passport`, `schweizer pass` |
| Switzerland DL | 50 | `fuhrerschein`, `swiss driving`, `fahrausweis`, `permis de conduire` |
| Switzerland UID | 50 | `uid`, `unternehmens-identifikationsnummer`, `swiss company`, `che number` |

## Europe - Turkey

4 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Turkey TC Kimlik | 50 | `tc kimlik`, `turkish id`, `kimlik numarasi`, `tc no`, `national id`, `identity card`, `id card`, `nufus cuzdani` |
| Turkey Passport | 50 | `turkish passport`, `turk pasaportu` |
| Turkey DL | 50 | `surucu belgesi`, `ehliyet`, `turkish driving` |
| Turkey Tax ID | 50 | `vergi kimlik`, `vergi numarasi`, `turkish tax`, `vkn` |

## Europe - Austria

5 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Austria SVN | 50 | `sozialversicherungsnummer`, `svnr`, `sv-nummer`, `austrian social security`, `versicherungsnummer` |
| Austria Passport | 50 | `austrian passport`, `osterreichischer reisepass`, `reisepass` |
| Austria ID Card | 50 | `personalausweis`, `austrian id`, `identity card`, `national id`, `id card` |
| Austria DL | 50 | `fuhrerschein`, `austrian driving`, `driving licence` |
| Austria Tax Number | 50 | `steuernummer`, `austrian tax`, `tax number`, `abgabenkontonummer` |

## Europe - Belgium

4 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Belgium NRN | 50 | `rijksregisternummer`, `nrn`, `national register number`, `registre national`, `insz`, `national id`, `identity card`, `id card` |
| Belgium Passport | 50 | `belgian passport`, `belgisch paspoort`, `passeport belge` |
| Belgium DL | 50 | `belgisch rijbewijs`, `belgian driving`, `permis de conduire belge` |
| Belgium VAT | 50 | `btw`, `tva`, `belgian vat`, `ondernemingsnummer`, `numero entreprise` |

## Europe - Ireland

4 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Ireland PPS | 50 | `pps`, `ppsn`, `personal public service`, `pps number`, `national id`, `identity card`, `id card` |
| Ireland Passport | 50 | `irish passport`, `ireland passport` |
| Ireland DL | 50 | `irish driving`, `driving licence`, `ceadunas tiomana` |
| Ireland Eircode | 50 | `eircode`, `irish postcode`, `postal code` |

## Europe - Denmark

3 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Denmark CPR | 50 | `cpr`, `personnummer`, `cpr-nummer`, `danish personal`, `civil registration`, `national id`, `identity card`, `id card` |
| Denmark Passport | 50 | `danish passport`, `dansk pas` |
| Denmark DL | 50 | `korekort`, `danish driving`, `driving licence` |

## Europe - Finland

3 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Finland HETU | 50 | `henkilotunnus`, `hetu`, `finnish personal identity`, `personal identity code`, `national id`, `identity card`, `id card` |
| Finland Passport | 50 | `finnish passport`, `suomen passi` |
| Finland DL | 50 | `ajokortti`, `finnish driving`, `driving licence` |

## Europe - Norway

4 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Norway FNR | 50 | `fodselsnummer`, `fnr`, `norwegian personal`, `birth number`, `personnummer`, `national id`, `identity card`, `id card` |
| Norway D-Number | 50 | `d-nummer`, `d-number`, `norwegian temporary` |
| Norway Passport | 50 | `norwegian passport`, `norsk pass` |
| Norway DL | 50 | `forerkort`, `norwegian driving`, `driving licence` |

## Europe - Czech Republic

4 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Czech Birth Number | 50 | `rodne cislo`, `birth number`, `czech personal`, `rc`, `national id`, `identity card`, `id card`, `obcansky prukaz` |
| Czech Passport | 50 | `czech passport`, `cesky pas` |
| Czech DL | 50 | `ridicsky prukaz`, `czech driving`, `driving licence` |
| Czech ICO | 50 | `ico`, `identifikacni cislo`, `business id` |

## Europe - Hungary

5 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Hungary Personal ID | 50 | `szemelyazonosito`, `personal id`, `hungarian id`, `szemelyi szam`, `national id`, `identity card`, `id card`, `szemelyi igazolvany` |
| Hungary TAJ | 50 | `taj szam`, `social security`, `taj`, `egeszsegbiztositasi` |
| Hungary Tax Number | 50 | `adoazonosito`, `tax number`, `hungarian tax`, `ado szam` |
| Hungary Passport | 50 | `hungarian passport`, `magyar utlevel` |
| Hungary DL | 50 | `jogositvany`, `hungarian driving`, `veztoi engedely` |

## Europe - Romania

4 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Romania CNP | 50 | `cnp`, `cod numeric personal`, `romanian personal`, `personal numeric code`, `national id`, `identity card`, `id card`, `carte de identitate` |
| Romania CIF | 50 | `cif`, `cod identificare fiscala`, `romanian tax`, `fiscal code` |
| Romania Passport | 50 | `romanian passport`, `pasaport` |
| Romania DL | 50 | `permis de conducere`, `romanian driving`, `driving licence` |

## Europe - Greece

5 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Greece AFM | 50 | `afm`, `arithmos forologikou mitroou`, `greek tax`, `tax number` |
| Greece AMKA | 50 | `amka`, `social security`, `arithmos mitroou koinonikis asfalisis` |
| Greece ID Card | 50 | `taftotita`, `greek id`, `deltio taftotitas`, `identity card`, `national id`, `id card` |
| Greece Passport | 50 | `greek passport`, `elliniko diavatirio` |
| Greece DL | 50 | `adeia odigisis`, `greek driving`, `driving licence` |

## Europe - Croatia

4 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Croatia OIB | 50 | `oib`, `osobni identifikacijski broj`, `croatian personal`, `personal identification number`, `national id`, `identity card`, `id card` |
| Croatia Passport | 50 | `croatian passport`, `hrvatska putovnica` |
| Croatia ID Card | 50 | `osobna iskaznica`, `croatian id`, `identity card`, `national id`, `id card` |
| Croatia DL | 50 | `vozacka dozvola`, `croatian driving`, `driving licence` |

## Europe - Bulgaria

4 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Bulgaria EGN | 50 | `egn`, `edinen grazhdanski nomer`, `bulgarian personal`, `unified civil number`, `national id`, `identity card`, `id card` |
| Bulgaria LNC | 50 | `lnch`, `lichna karta`, `foreigner number`, `personal number of foreigner` |
| Bulgaria ID Card | 50 | `lichna karta`, `bulgarian id`, `identity card`, `national id`, `id card` |
| Bulgaria Passport | 50 | `bulgarian passport`, `bulgarski pasport` |

## Europe - Slovakia

3 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Slovakia Birth Number | 50 | `rodne cislo`, `birth number`, `slovak personal`, `rc`, `national id`, `identity card`, `id card`, `obciansky preukaz` |
| Slovakia Passport | 50 | `slovak passport`, `slovensky pas` |
| Slovakia DL | 50 | `vodicsky preukaz`, `slovak driving`, `driving licence` |

## Europe - Lithuania

3 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Lithuania Asmens Kodas | 50 | `asmens kodas`, `lithuanian personal`, `personal code`, `ak`, `national id`, `identity card`, `id card` |
| Lithuania Passport | 50 | `lithuanian passport`, `lietuvos pasas` |
| Lithuania DL | 50 | `vairuotojo pazymejimas`, `lithuanian driving`, `driving licence` |

## Europe - Latvia

3 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Latvia Personas Kods | 50 | `personas kods`, `latvian personal`, `personal code`, `pk`, `national id`, `identity card`, `id card` |
| Latvia Passport | 50 | `latvian passport`, `latvijas pase` |
| Latvia DL | 50 | `vaditaja aplieciba`, `latvian driving`, `driving licence` |

## Europe - Estonia

3 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Estonia Isikukood | 50 | `isikukood`, `estonian personal`, `personal identification code`, `id-kood`, `national id`, `identity card`, `id card` |
| Estonia Passport | 50 | `estonian passport`, `eesti pass` |
| Estonia DL | 50 | `juhiluba`, `estonian driving`, `driving licence` |

## Europe - Slovenia

4 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Slovenia EMSO | 50 | `emso`, `enotna maticna stevilka`, `slovenian personal`, `personal number`, `national id`, `identity card`, `id card`, `osebna izkaznica` |
| Slovenia Tax Number | 50 | `davcna stevilka`, `slovenian tax`, `tax number` |
| Slovenia Passport | 50 | `slovenian passport`, `slovenski potni list` |
| Slovenia DL | 50 | `voznisko dovoljenje`, `slovenian driving`, `driving licence` |

## Europe - Luxembourg

3 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Luxembourg NIN | 50 | `matricule`, `luxembourg id`, `national identification`, `nin`, `national id`, `identity card`, `id card` |
| Luxembourg Passport | 50 | `luxembourg passport`, `passeport` |
| Luxembourg DL | 50 | `permis de conduire`, `luxembourg driving`, `driving licence` |

## Europe - Malta

3 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Malta ID Card | 50 | `maltese id`, `identity card`, `karta tal-identita`, `national id`, `id card` |
| Malta Passport | 50 | `maltese passport`, `passaport malti` |
| Malta TIN | 50 | `maltese tax`, `tin`, `tax identification` |

## Europe - Cyprus

3 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Cyprus ID Card | 50 | `cypriot id`, `identity card`, `taftotita`, `national id`, `id card` |
| Cyprus Passport | 50 | `cypriot passport`, `kypriako diavatirio` |
| Cyprus TIN | 50 | `cypriot tax`, `tin`, `tax identification` |

## Europe - Iceland

2 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Iceland Kennitala | 50 | `kennitala`, `icelandic id`, `personal id number`, `kt`, `national id`, `identity card`, `id card` |
| Iceland Passport | 50 | `icelandic passport`, `islenskt vegabref` |

## Europe - Liechtenstein

2 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Liechtenstein PIN | 50 | `liechtenstein personal`, `personal identification`, `pin`, `national id`, `identity card`, `id card` |
| Liechtenstein Passport | 50 | `liechtenstein passport` |

## Europe - EU

2 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| EU ETD | 50 | `eu emergency travel document`, `etd`, `emergency travel` |
| EU VAT Generic | 50 | `vat number`, `vat registration`, `eu vat`, `value added tax` |

## Asia-Pacific - India

6 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| India PAN | 50 | `permanent account number`, `pan`, `pan card`, `income tax`, `pan no` |
| India Aadhaar | 50 | `aadhaar`, `aadhar`, `aadhaar number`, `uid number`, `uidai` |
| India Passport | 50 | `indian passport`, `india passport`, `passport number`, `passport no`, `travel document` |
| India DL | 50 | `driving licence`, `driver licence`, `indian dl`, `driving license india`, `rto` |
| India Voter ID | 50 | `voter id`, `epic`, `election commission`, `voter card`, `electoral` |
| India Ration Card | 50 | `ration card`, `ration number`, `public distribution`, `food supply`, `bpl card` |

## Asia-Pacific - China

5 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| China Resident ID | 50 | `resident id`, `identity card`, `shenfenzheng`, `id card number`, `citizen id` |
| China Passport | 50 | `chinese passport`, `china passport`, `passport number`, `huzhao` |
| Hong Kong ID | 50 | `hong kong id`, `hkid`, `identity card`, `hk id card`, `hong kong identity` |
| Macau ID | 50 | `macau id`, `bir`, `macau identity`, `macau resident`, `bilhete de identidade` |
| Taiwan National ID | 50 | `taiwan id`, `national id`, `identity number`, `taiwan national`, `roc id` |

## Asia-Pacific - Japan

6 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Japan My Number | 50 | `my number`, `individual number`, `kojin bango`, `mynumber`, `social security tax` |
| Japan Passport | 50 | `japanese passport`, `japan passport`, `passport number`, `ryoken` |
| Japan DL | 50 | `driving licence`, `driver license`, `unten menkyo`, `japan licence`, `japanese dl` |
| Japan Juminhyo Code | 50 | `juminhyo`, `resident record`, `resident registration`, `juki net`, `basic resident registry` |
| Japan Health Insurance | 50 | `health insurance`, `hoken`, `insurer number`, `hokensho`, `medical insurance` |
| Japan Residence Card | 50 | `residence card`, `zairyu card`, `zairyu`, `residence permit`, `foreigner registration` |

## Asia-Pacific - South Korea

3 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| South Korea RRN | 50 | `resident registration`, `rrn`, `jumin deungnok`, `jumin`, `resident number` |
| South Korea Passport | 50 | `korean passport`, `korea passport`, `passport number`, `yeogwon` |
| South Korea DL | 50 | `driving licence`, `driver license`, `korean dl`, `unjon myonho`, `korea licence` |

## Asia-Pacific - Singapore

4 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Singapore NRIC | 50 | `nric`, `national registration`, `identity card`, `singapore id`, `ic number` |
| Singapore FIN | 50 | `fin`, `foreign identification`, `foreign id`, `work permit`, `employment pass` |
| Singapore Passport | 50 | `singapore passport`, `passport number`, `sg passport`, `travel document` |
| Singapore DL | 50 | `driving licence`, `driver license`, `singapore dl`, `singapore licence`, `traffic police` |

## Asia-Pacific - Australia

11 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Australia TFN | 50 | `tax file number`, `tfn`, `australian tax`, `ato`, `tax return` |
| Australia Medicare | 50 | `medicare`, `medicare number`, `medicare card`, `health insurance`, `bulk billing` |
| Australia Passport | 50 | `australian passport`, `australia passport`, `passport number`, `travel document` |
| Australia DL NSW | 50 | `nsw licence`, `new south wales licence`, `nsw driver`, `rms`, `service nsw` |
| Australia DL VIC | 50 | `vic licence`, `victoria licence`, `vicroads`, `victorian driver` |
| Australia DL QLD | 50 | `qld licence`, `queensland licence`, `tmr`, `queensland driver` |
| Australia DL WA | 50 | `wa licence`, `western australia licence`, `wa driver`, `dol wa` |
| Australia DL SA | 50 | `sa licence`, `south australia licence`, `sa driver`, `dpti` |
| Australia DL TAS | 50 | `tas licence`, `tasmania licence`, `tasmanian driver` |
| Australia DL ACT | 50 | `act licence`, `canberra licence`, `act driver` |
| Australia DL NT | 50 | `nt licence`, `northern territory licence`, `nt driver` |

## Asia-Pacific - New Zealand

4 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| New Zealand IRD | 50 | `ird`, `inland revenue`, `tax number`, `ird number`, `nz tax` |
| New Zealand Passport | 50 | `new zealand passport`, `nz passport`, `passport number`, `aotearoa passport` |
| New Zealand NHI | 50 | `nhi`, `national health index`, `health index`, `nhi number`, `health system` |
| New Zealand DL | 50 | `driving licence`, `driver licence`, `nz licence`, `nzta`, `waka kotahi` |

## Asia-Pacific - Philippines

6 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Philippines PhilSys | 50 | `philsys`, `national id`, `philid`, `psn`, `philippine identification` |
| Philippines TIN | 50 | `tin`, `tax identification`, `bir`, `bureau of internal revenue`, `taxpayer` |
| Philippines SSS | 50 | `sss`, `social security`, `sss number`, `social security system` |
| Philippines PhilHealth | 50 | `philhealth`, `health insurance`, `pin`, `philhealth number`, `medical insurance` |
| Philippines Passport | 50 | `philippine passport`, `philippines passport`, `passport number`, `dfa passport` |
| Philippines UMID | 50 | `umid`, `unified multi-purpose`, `crn`, `common reference number`, `umid card` |

## Asia-Pacific - Thailand

4 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Thailand National ID | 50 | `thai id`, `national id`, `bat prachakon`, `citizen id`, `identity card` |
| Thailand Passport | 50 | `thai passport`, `thailand passport`, `passport number`, `nangsue doen thang` |
| Thailand DL | 50 | `driving licence`, `driver license`, `thai dl`, `bai kap khi`, `land transport` |
| Thailand Tax ID | 50 | `tax id`, `tax number`, `revenue department`, `tin thailand`, `vat number` |

## Asia-Pacific - Malaysia

2 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Malaysia MyKad | 50 | `mykad`, `ic number`, `identity card`, `kad pengenalan`, `nric malaysia` |
| Malaysia Passport | 50 | `malaysian passport`, `malaysia passport`, `passport number`, `pasport` |

## Asia-Pacific - Indonesia

3 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Indonesia NIK | 50 | `nik`, `nomor induk kependudukan`, `ktp`, `identity card`, `kartu tanda penduduk` |
| Indonesia NPWP | 50 | `npwp`, `nomor pokok wajib pajak`, `tax id`, `taxpayer number`, `pajak` |
| Indonesia Passport | 50 | `indonesian passport`, `indonesia passport`, `passport number`, `paspor` |

## Asia-Pacific - Vietnam

3 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Vietnam CCCD | 50 | `cccd`, `cmnd`, `citizen id`, `can cuoc cong dan`, `identity card` |
| Vietnam Passport | 50 | `vietnamese passport`, `vietnam passport`, `passport number`, `ho chieu` |
| Vietnam Tax Code | 50 | `tax code`, `ma so thue`, `mst`, `tax id`, `tax number` |

## Asia-Pacific - Pakistan

3 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Pakistan CNIC | 50 | `cnic`, `computerized national identity`, `nadra`, `national identity card`, `identity card` |
| Pakistan NICOP | 50 | `nicop`, `national identity card overseas`, `overseas pakistani`, `nadra nicop` |
| Pakistan Passport | 50 | `pakistani passport`, `pakistan passport`, `passport number`, `travel document` |

## Asia-Pacific - Bangladesh

3 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Bangladesh NID | 50 | `nid`, `national id`, `voter id`, `national identity`, `smart card bangladesh` |
| Bangladesh Passport | 50 | `bangladeshi passport`, `bangladesh passport`, `passport number`, `e-passport` |
| Bangladesh TIN | 50 | `tin`, `tax identification`, `nbr`, `national board of revenue`, `taxpayer` |

## Asia-Pacific - Sri Lanka

3 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Sri Lanka NIC Old | 50 | `nic`, `national identity card`, `identity card`, `sri lanka id`, `jatika handunumpat` |
| Sri Lanka NIC New | 50 | `nic`, `national identity card`, `identity card`, `sri lanka id`, `new nic` |
| Sri Lanka Passport | 50 | `sri lankan passport`, `sri lanka passport`, `passport number`, `travel document` |

## Latin America - Brazil

6 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Brazil CPF | 50 | `cpf`, `cadastro de pessoas fisicas`, `cadastro pessoa fisica`, `contribuinte`, `receita federal` |
| Brazil CNPJ | 50 | `cnpj`, `cadastro nacional`, `pessoa juridica`, `empresa`, `razao social` |
| Brazil RG | 50 | `rg`, `registro geral`, `identidade`, `carteira de identidade`, `documento de identidade` |
| Brazil CNH | 50 | `cnh`, `carteira de habilitacao`, `habilitacao`, `driving licence`, `carteira nacional` |
| Brazil SUS Card | 50 | `sus`, `cartao nacional de saude`, `cns`, `saude`, `cartao sus` |
| Brazil Passport | 50 | `passaporte`, `brazilian passport`, `brazil passport`, `passport number` |

## Latin America - Argentina

3 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Argentina DNI | 50 | `dni`, `documento nacional de identidad`, `documento nacional`, `identidad`, `renaper` |
| Argentina CUIL/CUIT | 50 | `cuil`, `cuit`, `clave unica`, `identificacion tributaria`, `afip` |
| Argentina Passport | 50 | `pasaporte`, `argentinian passport`, `argentina passport`, `passport number` |

## Latin America - Colombia

4 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Colombia Cedula | 50 | `cedula`, `cedula de ciudadania`, `cc`, `documento identidad`, `registraduria` |
| Colombia NIT | 50 | `nit`, `numero de identificacion tributaria`, `dian`, `contribuyente`, `tax id` |
| Colombia NUIP | 50 | `nuip`, `numero unico de identificacion personal`, `identificacion personal`, `tarjeta identidad` |
| Colombia Passport | 50 | `pasaporte`, `colombian passport`, `colombia passport`, `passport number` |

## Latin America - Chile

2 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Chile RUN/RUT | 50 | `rut`, `run`, `rol unico tributario`, `rol unico nacional`, `cedula identidad` |
| Chile Passport | 50 | `pasaporte`, `chilean passport`, `chile passport`, `passport number` |

## Latin America - Peru

4 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Peru DNI | 50 | `dni`, `documento nacional de identidad`, `reniec`, `identidad`, `documento identidad` |
| Peru RUC | 50 | `ruc`, `registro unico de contribuyentes`, `sunat`, `contribuyente`, `tax id` |
| Peru Carnet Extranjeria | 50 | `carnet de extranjeria`, `carnet extranjeria`, `ce`, `migraciones`, `extranjero` |
| Peru Passport | 50 | `pasaporte`, `peruvian passport`, `peru passport`, `passport number` |

## Latin America - Venezuela

3 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Venezuela Cedula | 50 | `cedula`, `cedula de identidad`, `ci`, `saime`, `venezolano` |
| Venezuela RIF | 50 | `rif`, `registro de informacion fiscal`, `seniat`, `fiscal`, `contribuyente` |
| Venezuela Passport | 50 | `pasaporte`, `venezuelan passport`, `venezuela passport`, `passport number` |

## Latin America - Ecuador

3 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Ecuador Cedula | 50 | `cedula`, `cedula de identidad`, `cedula ciudadania`, `registro civil`, `identidad` |
| Ecuador RUC | 50 | `ruc`, `registro unico de contribuyentes`, `sri`, `contribuyente`, `tax id` |
| Ecuador Passport | 50 | `pasaporte`, `ecuadorian passport`, `ecuador passport`, `passport number` |

## Latin America - Uruguay

3 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Uruguay Cedula | 50 | `cedula`, `cedula de identidad`, `documento identidad`, `identidad`, `dnic` |
| Uruguay RUT | 50 | `rut`, `registro unico tributario`, `dgi`, `contribuyente`, `tax id` |
| Uruguay Passport | 50 | `pasaporte`, `uruguayan passport`, `uruguay passport`, `passport number` |

## Latin America - Paraguay

3 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Paraguay Cedula | 50 | `cedula`, `cedula de identidad`, `identidad civil`, `documento identidad`, `policia nacional` |
| Paraguay RUC | 50 | `ruc`, `registro unico de contribuyentes`, `set`, `dnit`, `contribuyente` |
| Paraguay Passport | 50 | `pasaporte`, `paraguayan passport`, `paraguay passport`, `passport number` |

## Latin America - Costa Rica

3 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Costa Rica Cedula | 50 | `cedula`, `cedula de identidad`, `tse`, `costarricense`, `tribunal supremo` |
| Costa Rica DIMEX | 50 | `dimex`, `documento migratorio`, `extranjero`, `migracion`, `residencia` |
| Costa Rica Passport | 50 | `pasaporte`, `costa rican passport`, `costa rica passport`, `passport number` |

## Middle East - Saudi Arabia

2 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Saudi Arabia National ID | 50 | `national id`, `iqama`, `saudi id`, `huwiyya`, `ministry of interior` |
| Saudi Arabia Passport | 50 | `saudi passport`, `saudi arabia passport`, `jawaz safar`, `passport number` |

## Middle East - UAE

3 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| UAE Emirates ID | 50 | `emirates id`, `eid`, `uae id`, `identity card`, `federal authority` |
| UAE Visa Number | 50 | `visa number`, `entry permit`, `uae visa`, `residence visa`, `visa file` |
| UAE Passport | 50 | `uae passport`, `emirati passport`, `passport number`, `passport` |

## Middle East - Israel

2 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Israel Teudat Zehut | 50 | `teudat zehut`, `mispar zehut`, `identity number`, `israeli id`, `zehut` |
| Israel Passport | 50 | `israeli passport`, `israel passport`, `darkon`, `passport number` |

## Middle East - Qatar

2 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Qatar QID | 50 | `qid`, `qatar id`, `resident permit`, `moi qatar`, `identity card` |
| Qatar Passport | 50 | `qatar passport`, `qatari passport`, `passport number`, `jawaz` |

## Middle East - Kuwait

2 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Kuwait Civil ID | 50 | `civil id`, `paci`, `kuwait id`, `civil information`, `identity card` |
| Kuwait Passport | 50 | `kuwaiti passport`, `kuwait passport`, `passport number`, `passport` |

## Middle East - Bahrain

2 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Bahrain CPR | 50 | `cpr`, `central population registration`, `bahrain id`, `personal number`, `identity card` |
| Bahrain Passport | 50 | `bahraini passport`, `bahrain passport`, `passport number`, `passport` |

## Middle East - Jordan

2 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Jordan National ID | 50 | `national number`, `raqam watani`, `jordanian id`, `civil status`, `identity card` |
| Jordan Passport | 50 | `jordanian passport`, `jordan passport`, `passport number`, `passport` |

## Middle East - Lebanon

2 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Lebanon ID | 50 | `lebanese id`, `national id`, `identity card`, `hawiyya`, `interior ministry` |
| Lebanon Passport | 50 | `lebanese passport`, `lebanon passport`, `passport number`, `general security` |

## Middle East - Iraq

2 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Iraq National ID | 50 | `national card`, `bitaqa wataniya`, `iraqi id`, `civil status`, `identity card` |
| Iraq Passport | 50 | `iraqi passport`, `iraq passport`, `passport number`, `passport` |

## Middle East - Iran

2 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Iran Melli Code | 50 | `melli code`, `shomareh melli`, `kart melli`, `national code`, `iranian id` |
| Iran Passport | 50 | `iranian passport`, `iran passport`, `passport number`, `gozarnameh` |

## Africa - South Africa

3 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| South Africa ID | 50 | `south african id`, `sa id`, `identity number`, `id number`, `home affairs` |
| South Africa Passport | 50 | `south african passport`, `sa passport`, `passport number`, `home affairs` |
| South Africa DL | 50 | `driver's licence`, `driving licence`, `south african dl`, `licence number`, `traffic department` |

## Africa - Nigeria

6 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Nigeria NIN | 50 | `nin`, `national identification number`, `nimc`, `national identity`, `identity number` |
| Nigeria BVN | 50 | `bvn`, `bank verification number`, `bank verification`, `nibss`, `cbn` |
| Nigeria TIN | 50 | `tin`, `tax identification number`, `firs`, `tax id`, `joint tax board` |
| Nigeria Voter Card | 50 | `voter card`, `pvc`, `voter identification`, `inec`, `permanent voter` |
| Nigeria Driver Licence | 50 | `driver's licence`, `driving licence`, `frsc`, `licence number`, `ndl` |
| Nigeria Passport | 50 | `nigerian passport`, `nigeria passport`, `passport number`, `immigration` |

## Africa - Kenya

4 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Kenya National ID | 50 | `national id`, `kenyan id`, `identity card`, `huduma namba`, `maisha namba` |
| Kenya KRA PIN | 50 | `kra pin`, `kra`, `kenya revenue`, `tax pin`, `itax` |
| Kenya NHIF | 50 | `nhif`, `national hospital insurance`, `health insurance`, `nhif number` |
| Kenya Passport | 50 | `kenyan passport`, `kenya passport`, `passport number`, `immigration` |

## Africa - Egypt

3 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Egypt National ID | 50 | `national id`, `raqam qawmi`, `egyptian id`, `identity card`, `civil registry` |
| Egypt Tax ID | 50 | `tax id`, `tax registration`, `maslahat al-darayeb`, `tax number`, `eta` |
| Egypt Passport | 50 | `egyptian passport`, `egypt passport`, `passport number`, `jawaz safar` |

## Africa - Ghana

4 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Ghana Card | 50 | `ghana card`, `nia`, `national identification`, `identity card`, `ghana id` |
| Ghana TIN | 50 | `tin`, `tax identification`, `gra`, `taxpayer`, `tax number` |
| Ghana NHIS | 50 | `nhis`, `national health insurance`, `health insurance`, `nhia`, `health card` |
| Ghana Passport | 50 | `ghanaian passport`, `ghana passport`, `passport number`, `immigration` |

## Africa - Ethiopia

3 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Ethiopia National ID | 50 | `fayda`, `national id`, `ethiopian id`, `identity number`, `fayda id` |
| Ethiopia TIN | 50 | `tin`, `tax identification`, `erca`, `ministry of revenue`, `tax number` |
| Ethiopia Passport | 50 | `ethiopian passport`, `ethiopia passport`, `passport number`, `immigration` |

## Africa - Tanzania

3 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Tanzania NIDA | 50 | `nida`, `national id`, `tanzanian id`, `nin`, `national identification` |
| Tanzania TIN | 50 | `tin`, `tax identification`, `tra`, `tanzania revenue`, `tax number` |
| Tanzania Passport | 50 | `tanzanian passport`, `tanzania passport`, `passport number`, `immigration` |

## Africa - Morocco

3 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Morocco CIN | 50 | `cin`, `cnie`, `carte nationale`, `carte identite`, `identite nationale` |
| Morocco Tax ID | 50 | `identifiant fiscal`, `if`, `dgi`, `tax id`, `impots` |
| Morocco Passport | 50 | `moroccan passport`, `morocco passport`, `passeport`, `passport number` |

## Africa - Tunisia

2 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Tunisia CIN | 50 | `cin`, `carte identite nationale`, `carte identite`, `tunisian id`, `identity card` |
| Tunisia Passport | 50 | `tunisian passport`, `tunisia passport`, `passeport`, `passport number` |

## Africa - Uganda

2 keyword groups

| Sub-Category | Distance | Keywords |
|---|:---:|---|
| Uganda NIN | 50 | `nin`, `national identification number`, `nira`, `national id`, `ugandan id` |
| Uganda Passport | 50 | `ugandan passport`, `uganda passport`, `passport number`, `immigration` |
