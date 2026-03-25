# Credit Cards — Context Keywords

> Keywords used for proximity-based context detection.
> When a regex pattern match is found, the scanner checks for these keywords
> within a configurable character distance before/after the match to improve accuracy.

---

## Card Expiration Dates

**Proximity distance:** 30 characters

| Pattern Name | Keywords |
|---|---|
| Card Expiry | `expiry`, `expiration`, `exp date`, `exp`, `valid thru`, `valid through`, `good thru`, `card expires`, `mm/yy` |

## Card Track Data

**Proximity distance:** 50 characters

| Pattern Name | Keywords |
|---|---|
| Track 1 Data | `track 1`, `track1`, `magnetic stripe`, `magstripe`, `swipe data`, `card track` |
| Track 2 Data | `track 2`, `track2`, `magnetic stripe`, `magstripe`, `swipe data`, `card track` |

## Credit Card Numbers

**Proximity distance:** 50 characters

| Pattern Name | Keywords |
|---|---|
| Amex | `amex`, `american express`, `credit card`, `card number`, `pan`, `primary account` |
| Diners Club | `diners club`, `diners`, `credit card`, `card number`, `pan`, `primary account` |
| Discover | `discover`, `credit card`, `card number`, `pan`, `primary account` |
| JCB | `jcb`, `credit card`, `card number`, `pan`, `primary account` |
| MasterCard | `mastercard`, `mc`, `credit card`, `card number`, `card no`, `pan`, `primary account` |
| UnionPay | `unionpay`, `union pay`, `credit card`, `card number`, `pan`, `primary account` |
| Visa | `visa`, `cc`, `credit card`, `card number`, `card no`, `pan`, `primary account` |

## Credit Card Security Codes

**Proximity distance:** 30 characters

| Pattern Name | Keywords |
|---|---|
| Amex CID | `cid`, `card identification`, `amex security`, `amex cvv`, `four digit`, `4 digit security` |
| CVV/CVC/CCV | `cvv`, `cvc`, `ccv`, `cvv2`, `cvc2`, `security code`, `card verification`, `verification value`, `verification code`, `csv` |

## Primary Account Numbers

**Proximity distance:** 50 characters

| Pattern Name | Keywords |
|---|---|
| BIN/IIN | `bin`, `iin`, `bank identification number`, `issuer identification`, `card prefix`, `bin number` |
| Masked PAN | `masked pan`, `truncated pan`, `masked card`, `truncated card`, `last four`, `first six` |
| PAN | `pan`, `primary account number`, `account number`, `card number`, `cardholder number`, `full card` |
