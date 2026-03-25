# Banking — Context Keywords

> Keywords used for proximity-based context detection.
> When a regex pattern match is found, the scanner checks for these keywords
> within a configurable character distance before/after the match to improve accuracy.

---

## Banking Authentication

**Proximity distance:** 50 characters

| Pattern Name | Keywords |
|---|---|
| Encryption Key | `kek`, `zmk`, `tmk`, `zone master key`, `key encrypting`, `terminal master key`, `transport key`, `working key` |
| HSM Key | `hsm`, `hardware security module`, `hsm key`, `master key`, `key material` |
| PIN | `pin`, `personal identification number`, `atm pin`, `debit pin`, `pin number`, `pin code`, `card pin` |
| PIN Block | `pin block`, `encrypted pin`, `pin encryption`, `iso 9564`, `pin format` |

## Banking and Financial

**Proximity distance:** 50 characters

| Pattern Name | Keywords |
|---|---|
| ABA Routing Number | `routing number`, `routing no`, `aba`, `aba routing`, `transit routing`, `bank routing`, `rtn` |
| Canada Transit Number | `transit number`, `institution number`, `canadian bank`, `bank transit` |
| IBAN Generic | `iban`, `international bank account number`, `bank account` |
| SWIFT/BIC | `swift`, `bic`, `bank identifier code`, `swift code`, `routing code` |
| US Bank Account Number | `account number`, `account no`, `bank account`, `checking account`, `savings account`, `acct`, `acct no`, `deposit account` |

## Check and MICR Data

**Proximity distance:** 50 characters

| Pattern Name | Keywords |
|---|---|
| Cashier Check Number | `cashier check`, `cashiers check`, `certified check`, `money order`, `bank check`, `official check` |
| Check Number | `check number`, `check no`, `cheque number`, `check#`, `ck no`, `check num` |
| MICR Line | `micr`, `magnetic ink`, `check bottom`, `cheque line`, `micr line`, `e13b` |

## Customer Financial Data

**Proximity distance:** 50 characters

| Pattern Name | Keywords |
|---|---|
| Account Balance | `balance`, `account balance`, `available balance`, `current balance`, `ledger balance`, `closing balance` |
| Balance with Currency Code | `balance`, `amount`, `total`, `funds`, `available`, `ledger` |
| Credit Score | `credit score`, `fico`, `fico score`, `credit rating`, `vantagescore`, `credit bureau`, `experian`, `equifax`, `transunion` |
| DTI Ratio | `dti`, `debt-to-income`, `debt to income`, `dti ratio`, `debt ratio` |
| Income Amount | `income`, `salary`, `annual income`, `monthly income`, `gross income`, `net income`, `compensation`, `wages`, `earnings` |

## Internal Banking References

**Proximity distance:** 50 characters

| Pattern Name | Keywords |
|---|---|
| Branch Code | `branch code`, `branch number`, `branch id`, `cost center`, `branch no`, `office code` |
| Customer ID | `customer id`, `cif`, `cid`, `customer number`, `client id`, `customer identification`, `client number` |
| Internal Account Ref | `internal reference`, `account reference`, `internal id`, `system id`, `core banking id` |
| Teller ID | `teller id`, `teller number`, `officer id`, `banker id`, `employee id`, `user id` |

## Loan and Mortgage Data

**Proximity distance:** 50 characters

| Pattern Name | Keywords |
|---|---|
| LTV Ratio | `ltv`, `loan-to-value`, `loan to value`, `ltv ratio`, `combined ltv`, `cltv` |
| Loan Number | `loan number`, `loan no`, `loan id`, `loan account`, `loan#`, `lending number` |
| MERS MIN | `mers`, `mortgage identification number`, `min number`, `mers min`, `mortgage electronic` |
| Universal Loan Identifier | `uli`, `universal loan identifier`, `hmda`, `loan identifier` |

## PCI Sensitive Data

**Proximity distance:** 30 characters

| Pattern Name | Keywords |
|---|---|
| Cardholder Name Pattern | `cardholder`, `cardholder name`, `name on card`, `card holder`, `card member` |
| Dynamic CVV | `icvv`, `dcvv`, `dynamic cvv`, `chip cvv`, `dynamic verification`, `cavv` |
| PVKI | `pvki`, `pin verification key indicator`, `key indicator` |
| PVV | `pvv`, `pin verification value`, `pin value` |
| Service Code | `service code`, `svc code`, `magstripe service`, `card service code` |

## Regulatory Identifiers

**Proximity distance:** 50 characters

| Pattern Name | Keywords |
|---|---|
| AML Case ID | `aml`, `anti-money laundering`, `money laundering`, `aml case`, `aml investigation`, `bsa` |
| CTR Number | `ctr`, `currency transaction report`, `ctr filing`, `ctr number`, `cash transaction` |
| Compliance Case Number | `compliance case`, `investigation number`, `regulatory case`, `compliance id`, `audit case`, `examination number` |
| FinCEN Report Number | `fincen`, `financial crimes`, `fincen report`, `fincen filing`, `bsa filing` |
| OFAC SDN Entry | `ofac`, `sdn`, `specially designated`, `sanctions`, `ofac list`, `blocked persons` |
| SAR Filing Number | `sar`, `suspicious activity report`, `sar filing`, `sar number`, `suspicious activity` |

## Securities Identifiers

**Proximity distance:** 50 characters

| Pattern Name | Keywords |
|---|---|
| CUSIP | `cusip`, `committee on uniform securities`, `security identifier`, `bond cusip`, `cusip number` |
| FIGI | `figi`, `financial instrument global identifier`, `bloomberg`, `bbg`, `openfigi` |
| ISIN | `isin`, `international securities`, `securities identification`, `isin code`, `isin number` |
| LEI | `lei`, `legal entity identifier`, `gleif`, `entity identifier`, `lei code` |
| SEDOL | `sedol`, `stock exchange daily official list`, `london stock`, `uk securities` |
| Ticker Symbol | `ticker`, `stock symbol`, `trading symbol`, `nyse`, `nasdaq`, `equity symbol`, `stock ticker` |

## Wire Transfer Data

**Proximity distance:** 50 characters

| Pattern Name | Keywords |
|---|---|
| ACH Batch Number | `ach batch`, `batch number`, `batch id`, `ach file`, `nacha batch` |
| ACH Trace Number | `ach trace`, `trace number`, `trace id`, `ach transaction`, `ach payment`, `nacha` |
| CHIPS UID | `chips`, `chips uid`, `chips transfer`, `clearing house`, `interbank payment` |
| Fedwire IMAD | `imad`, `input message accountability`, `fedwire`, `fed reference`, `wire reference` |
| SEPA Reference | `sepa`, `sepa reference`, `end-to-end`, `e2e reference`, `sepa transfer`, `sepa credit` |
| Wire Reference Number | `wire reference`, `wire transfer`, `wire number`, `remittance reference`, `payment reference`, `transfer reference` |
