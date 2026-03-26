# Payment Card Industry Information (PCI)

Detects payment card data subject to PCI-DSS requirements. Covers primary
account numbers, cardholder data, sensitive authentication data, and
supporting payment infrastructure identifiers.

## Control Objective

Prevent the unauthorized storage, transmission, or disclosure of cardholder
data and sensitive authentication data as defined by PCI-DSS requirements
3, 4, and 7.

---

## Patterns

### Credit Card Numbers (Primary Account Numbers)

| Category | Source |
|----------|--------|
| Visa | [credit_card_numbers](../patterns/generic/credit_card_numbers.md) |
| MasterCard | [credit_card_numbers](../patterns/generic/credit_card_numbers.md) |
| Amex | [credit_card_numbers](../patterns/generic/credit_card_numbers.md) |
| Discover | [credit_card_numbers](../patterns/generic/credit_card_numbers.md) |
| JCB | [credit_card_numbers](../patterns/generic/credit_card_numbers.md) |
| Diners Club | [credit_card_numbers](../patterns/generic/credit_card_numbers.md) |
| UnionPay | [credit_card_numbers](../patterns/generic/credit_card_numbers.md) |

### Primary Account Number Formats

| Category | Source |
|----------|--------|
| PAN (Full) | [primary_account_numbers](../patterns/generic/primary_account_numbers.md) |
| Masked PAN | [primary_account_numbers](../patterns/generic/primary_account_numbers.md) |

### Cardholder Data

| Category | Source |
|----------|--------|
| Cardholder Name Pattern | [pci_sensitive_data](../patterns/generic/pci_sensitive_data.md) |
| Card Expiry | [card_expiration_dates](../patterns/generic/card_expiration_dates.md) |

### Sensitive Authentication Data

| Category | Source |
|----------|--------|
| Track 1 Data | [card_track_data](../patterns/generic/card_track_data.md) |
| Track 2 Data | [card_track_data](../patterns/generic/card_track_data.md) |
| PIN Block | [banking_authentication](../patterns/generic/banking_authentication.md) |

### Payment Processing Infrastructure

| Category | Source |
|----------|--------|
| PIN | [banking_authentication](../patterns/generic/banking_authentication.md) |
| HSM Key | [banking_authentication](../patterns/generic/banking_authentication.md) |
| Encryption Key | [banking_authentication](../patterns/generic/banking_authentication.md) |

### Check and MICR Data

| Category | Source |
|----------|--------|
| MICR Line | [check_and_micr_data](../patterns/generic/check_and_micr_data.md) |
| Check Number | [check_and_micr_data](../patterns/generic/check_and_micr_data.md) |
| Cashier Check Number | [check_and_micr_data](../patterns/generic/check_and_micr_data.md) |

### Payment Service Secrets

| Category | Source |
|----------|--------|
| Stripe Secret Key | [payment_service_secrets](../patterns/custom/payment_service_secrets.md) |
| Stripe Publishable Key | [payment_service_secrets](../patterns/custom/payment_service_secrets.md) |

---

## Keywords

| Keyword Source | Proximity | Mapped Patterns |
|---------------|-----------|-----------------|
| [credit_card_numbers](../keywords/generic/credit_card_numbers.md) | 50 chars | Visa, MasterCard, Amex, Discover, JCB, Diners, UnionPay |
| [primary_account_numbers](../keywords/generic/primary_account_numbers.md) | 50 chars | PAN, Masked PAN |
| [pci_sensitive_data](../keywords/generic/pci_sensitive_data.md) | 30 chars | Cardholder Name |
| [card_expiration_dates](../keywords/generic/card_expiration_dates.md) | 30 chars | Card Expiry |
| [card_track_data](../keywords/generic/card_track_data.md) | 50 chars | Track 1, Track 2 |
| [banking_authentication](../keywords/generic/banking_authentication.md) | 50 chars | PIN Block, HSM Key, Encryption Key |
| [check_and_micr_data](../keywords/generic/check_and_micr_data.md) | 50 chars | MICR, Check Number |
| [payment_service_secrets](../keywords/custom/payment_service_secrets.md) | 80 chars | Stripe keys |

---

## PCI-DSS Requirement Mapping

| PCI-DSS Requirement | Patterns Covered |
|---------------------|------------------|
| **Req 3** -- Protect stored account data | Credit card numbers, PAN, cardholder name, card expiry, track data |
| **Req 3.3** -- Mask PAN when displayed | Masked PAN detection |
| **Req 3.4** -- Render PAN unreadable | Full PAN detection in plaintext |
| **Req 4** -- Encrypt transmission of cardholder data | All cardholder data patterns (detect unencrypted transmission) |
| **Req 7** -- Restrict access to cardholder data | Stripe keys, HSM keys, encryption keys |
| **Req 8** -- Identify users and authenticate access | PIN, PIN Block |
