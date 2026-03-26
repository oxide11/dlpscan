# Internal Financial Data Monitoring

Detects internal financial data including banking identifiers, transaction
records, securities data, cryptocurrency addresses, regulatory filings,
and customer financial information. Aligns with SOX, GLBA, BSA/AML,
FINRA, and internal risk management requirements.

## Control Objective

Prevent the unauthorized disclosure of non-public financial data including
customer account information, internal banking references, wire transfer
details, securities identifiers, regulatory filings, and market-sensitive
information.

---

## Patterns

### Banking & Account Data

| Category | Source |
|----------|--------|
| IBAN Generic | [banking_and_financial](../patterns/generic/banking_and_financial.md) |
| SWIFT/BIC | [banking_and_financial](../patterns/generic/banking_and_financial.md) |
| ABA Routing Number | [banking_and_financial](../patterns/generic/banking_and_financial.md) |
| US Bank Account Number | [banking_and_financial](../patterns/generic/banking_and_financial.md) |
| Canada Transit Number | [banking_and_financial](../patterns/generic/banking_and_financial.md) |

### Internal Banking References

| Category | Source |
|----------|--------|
| Internal Account Ref | [internal_banking_references](../patterns/generic/internal_banking_references.md) |
| Teller ID | [internal_banking_references](../patterns/generic/internal_banking_references.md) |

### Customer Financial Data

| Category | Source |
|----------|--------|
| Account Balance | [customer_financial_data](../patterns/generic/customer_financial_data.md) |
| Balance with Currency Code | [customer_financial_data](../patterns/generic/customer_financial_data.md) |
| Income Amount | [customer_financial_data](../patterns/generic/customer_financial_data.md) |
| DTI Ratio | [customer_financial_data](../patterns/generic/customer_financial_data.md) |

### Wire Transfer & Payment Data

| Category | Source |
|----------|--------|
| Fedwire IMAD | [wire_transfer_data](../patterns/generic/wire_transfer_data.md) |
| CHIPS UID | [wire_transfer_data](../patterns/generic/wire_transfer_data.md) |
| Wire Reference Number | [wire_transfer_data](../patterns/generic/wire_transfer_data.md) |
| ACH Trace Number | [wire_transfer_data](../patterns/generic/wire_transfer_data.md) |
| ACH Batch Number | [wire_transfer_data](../patterns/generic/wire_transfer_data.md) |
| SEPA Reference | [wire_transfer_data](../patterns/generic/wire_transfer_data.md) |

### Loan & Mortgage Data

| Category | Source |
|----------|--------|
| Loan Number | [loan_and_mortgage_data](../patterns/generic/loan_and_mortgage_data.md) |
| MERS MIN | [loan_and_mortgage_data](../patterns/generic/loan_and_mortgage_data.md) |
| Universal Loan Identifier | [loan_and_mortgage_data](../patterns/generic/loan_and_mortgage_data.md) |
| LTV Ratio | [loan_and_mortgage_data](../patterns/generic/loan_and_mortgage_data.md) |

### Securities Identifiers

| Category | Source |
|----------|--------|
| CUSIP | [securities_identifiers](../patterns/generic/securities_identifiers.md) |
| ISIN | [securities_identifiers](../patterns/generic/securities_identifiers.md) |
| SEDOL | [securities_identifiers](../patterns/generic/securities_identifiers.md) |
| FIGI | [securities_identifiers](../patterns/generic/securities_identifiers.md) |
| LEI | [securities_identifiers](../patterns/generic/securities_identifiers.md) |
| Ticker Symbol | [securities_identifiers](../patterns/generic/securities_identifiers.md) |

### Cryptocurrency

| Category | Source |
|----------|--------|
| Bitcoin Address (Legacy) | [cryptocurrency](../patterns/generic/cryptocurrency.md) |
| Bitcoin Address (Bech32) | [cryptocurrency](../patterns/generic/cryptocurrency.md) |
| Ethereum Address | [cryptocurrency](../patterns/generic/cryptocurrency.md) |
| Litecoin Address | [cryptocurrency](../patterns/generic/cryptocurrency.md) |
| Bitcoin Cash Address | [cryptocurrency](../patterns/generic/cryptocurrency.md) |
| Monero Address | [cryptocurrency](../patterns/generic/cryptocurrency.md) |
| Ripple Address | [cryptocurrency](../patterns/generic/cryptocurrency.md) |

### Regulatory Identifiers

| Category | Source |
|----------|--------|
| SAR Filing Number | [regulatory_identifiers](../patterns/generic/regulatory_identifiers.md) |
| CTR Number | [regulatory_identifiers](../patterns/generic/regulatory_identifiers.md) |
| AML Case ID | [regulatory_identifiers](../patterns/generic/regulatory_identifiers.md) |
| OFAC SDN Entry | [regulatory_identifiers](../patterns/generic/regulatory_identifiers.md) |
| FinCEN Report Number | [regulatory_identifiers](../patterns/generic/regulatory_identifiers.md) |
| Compliance Case Number | [regulatory_identifiers](../patterns/generic/regulatory_identifiers.md) |

### Financial Regulatory Labels

| Category | Source |
|----------|--------|
| MNPI | [financial_regulatory_labels](../patterns/generic/financial_regulatory_labels.md) |
| Inside Information | [financial_regulatory_labels](../patterns/generic/financial_regulatory_labels.md) |
| Pre-Decisional | [financial_regulatory_labels](../patterns/generic/financial_regulatory_labels.md) |
| Draft Not for Circulation | [financial_regulatory_labels](../patterns/generic/financial_regulatory_labels.md) |
| Market Sensitive | [financial_regulatory_labels](../patterns/generic/financial_regulatory_labels.md) |
| Information Barrier | [financial_regulatory_labels](../patterns/generic/financial_regulatory_labels.md) |
| Investment Restricted | [financial_regulatory_labels](../patterns/generic/financial_regulatory_labels.md) |

### Supervisory Information

| Category | Source |
|----------|--------|
| Supervisory Controlled | [supervisory_information](../patterns/generic/supervisory_information.md) |
| Supervisory Confidential | [supervisory_information](../patterns/generic/supervisory_information.md) |
| CSI | [supervisory_information](../patterns/generic/supervisory_information.md) |
| Non-Public Supervisory | [supervisory_information](../patterns/generic/supervisory_information.md) |
| Restricted Supervisory | [supervisory_information](../patterns/generic/supervisory_information.md) |
| Examination Findings | [supervisory_information](../patterns/generic/supervisory_information.md) |

### Banking Authentication

| Category | Source |
|----------|--------|
| PIN Block | [banking_authentication](../patterns/generic/banking_authentication.md) |
| HSM Key | [banking_authentication](../patterns/generic/banking_authentication.md) |
| Encryption Key | [banking_authentication](../patterns/generic/banking_authentication.md) |

---

## Keywords

| Keyword Source | Proximity | Mapped Patterns |
|---------------|-----------|-----------------|
| [banking_and_financial](../keywords/generic/banking_and_financial.md) | 50 chars | IBAN, SWIFT, ABA, Account Number |
| [internal_banking_references](../keywords/generic/internal_banking_references.md) | 50 chars | Internal Account Ref, Teller ID |
| [customer_financial_data](../keywords/generic/customer_financial_data.md) | 50 chars | Balance, Income, DTI |
| [wire_transfer_data](../keywords/generic/wire_transfer_data.md) | 50 chars | Fedwire, CHIPS, ACH, SEPA |
| [loan_and_mortgage_data](../keywords/generic/loan_and_mortgage_data.md) | 50 chars | Loan Number, MERS, ULI, LTV |
| [securities_identifiers](../keywords/generic/securities_identifiers.md) | 50 chars | CUSIP, ISIN, SEDOL, FIGI, LEI |
| [cryptocurrency](../keywords/generic/cryptocurrency.md) | 50 chars | Bitcoin, Ethereum, Litecoin, Monero |
| [regulatory_identifiers](../keywords/generic/regulatory_identifiers.md) | 50 chars | SAR, CTR, AML, OFAC, FinCEN |
| [financial_regulatory_labels](../keywords/generic/financial_regulatory_labels.md) | 80 chars | MNPI, Inside Info, Market Sensitive |
| [supervisory_information](../keywords/generic/supervisory_information.md) | 80 chars | Supervisory, CSI, Examination |
| [banking_authentication](../keywords/generic/banking_authentication.md) | 50 chars | PIN Block, HSM, Encryption Key |

---

## Regulatory Mapping

| Regulation | Scope | Key Patterns |
|-----------|-------|--------------|
| **SOX** (Sarbanes-Oxley) | Internal financial controls | Customer financial data, regulatory labels |
| **GLBA** (Gramm-Leach-Bliley) | Customer financial information | Account data, wire transfers, loan data |
| **BSA/AML** (Bank Secrecy Act) | Anti-money laundering | SAR, CTR, OFAC, FinCEN, AML Case ID |
| **FINRA** | Securities industry | MNPI, securities identifiers, information barriers |
| **Dodd-Frank** | Financial stability | Supervisory information, regulatory identifiers |
| **MiFID II** (EU) | Markets in financial instruments | ISIN, LEI, market sensitive data |
