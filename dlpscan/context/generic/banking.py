


BANKING_CONTEXT = {
    # -- Core Banking ----------------------------------------------------
    'Banking and Financial': {
        'Identifiers': {
            'IBAN Generic': ['iban', 'international bank account number', 'bank account'],
            'SWIFT/BIC': ['swift', 'bic', 'bank identifier code', 'swift code', 'routing code'],
            'ABA Routing Number': ['routing number', 'routing no', 'aba', 'aba routing', 'transit routing', 'bank routing', 'rtn'],
            'US Bank Account Number': ['account number', 'account no', 'bank account', 'checking account', 'savings account', 'acct', 'acct no', 'deposit account'],
            'Canada Transit Number': ['transit number', 'institution number', 'canadian bank', 'bank transit'],
        },
        'distance': 50,
    },
    # -- Wire Transfers & Payments ----------------------------------------
    'Wire Transfer Data': {
        'Identifiers': {
            'Fedwire IMAD': ['imad', 'input message accountability', 'fedwire', 'fed reference', 'wire reference'],
            'CHIPS UID': ['chips', 'chips uid', 'chips transfer', 'clearing house', 'interbank payment'],
            'Wire Reference Number': ['wire reference', 'wire transfer', 'wire number', 'remittance reference', 'payment reference', 'transfer reference'],
            'ACH Trace Number': ['ach trace', 'trace number', 'trace id', 'ach transaction', 'ach payment', 'nacha'],
            'ACH Batch Number': ['ach batch', 'batch number', 'batch id', 'ach file', 'nacha batch'],
            'SEPA Reference': ['sepa', 'sepa reference', 'end-to-end', 'e2e reference', 'sepa transfer', 'sepa credit'],
        },
        'distance': 50,
    },
    # -- Check/Cheque Data ------------------------------------------------
    'Check and MICR Data': {
        'Identifiers': {
            'MICR Line': ['micr', 'magnetic ink', 'check bottom', 'cheque line', 'micr line', 'e13b'],
            'Check Number': ['check number', 'check no', 'cheque number', 'check#', 'ck no', 'check num'],
            'Cashier Check Number': ['cashier check', 'cashiers check', 'certified check', 'money order', 'bank check', 'official check'],
        },
        'distance': 50,
    },
    # -- Securities Identifiers -------------------------------------------
    'Securities Identifiers': {
        'Identifiers': {
            'CUSIP': ['cusip', 'committee on uniform securities', 'security identifier', 'bond cusip', 'cusip number'],
            'ISIN': ['isin', 'international securities', 'securities identification', 'isin code', 'isin number'],
            'SEDOL': ['sedol', 'stock exchange daily official list', 'london stock', 'uk securities'],
            'FIGI': ['figi', 'financial instrument global identifier', 'bloomberg', 'bbg', 'openfigi'],
            'LEI': ['lei', 'legal entity identifier', 'gleif', 'entity identifier', 'lei code'],
            'Ticker Symbol': ['ticker', 'stock symbol', 'trading symbol', 'nyse', 'nasdaq', 'equity symbol', 'stock ticker'],
        },
        'distance': 50,
    },
    # -- Loan & Mortgage --------------------------------------------------
    'Loan and Mortgage Data': {
        'Identifiers': {
            'Loan Number': ['loan number', 'loan no', 'loan id', 'loan account', 'loan#', 'lending number'],
            'MERS MIN': ['mers', 'mortgage identification number', 'min number', 'mers min', 'mortgage electronic'],
            'Universal Loan Identifier': ['uli', 'universal loan identifier', 'hmda', 'loan identifier'],
            'LTV Ratio': ['ltv', 'loan-to-value', 'loan to value', 'ltv ratio', 'combined ltv', 'cltv'],
        },
        'distance': 50,
    },
    # -- Regulatory & Compliance ------------------------------------------
    'Regulatory Identifiers': {
        'Identifiers': {
            'SAR Filing Number': ['sar', 'suspicious activity report', 'sar filing', 'sar number', 'suspicious activity'],
            'CTR Number': ['ctr', 'currency transaction report', 'ctr filing', 'ctr number', 'cash transaction'],
            'AML Case ID': ['aml', 'anti-money laundering', 'money laundering', 'aml case', 'aml investigation', 'bsa'],
            'OFAC SDN Entry': ['ofac', 'sdn', 'specially designated', 'sanctions', 'ofac list', 'blocked persons'],
            'FinCEN Report Number': ['fincen', 'financial crimes', 'fincen report', 'fincen filing', 'bsa filing'],
            'Compliance Case Number': ['compliance case', 'investigation number', 'regulatory case', 'compliance id', 'audit case', 'examination number'],
        },
        'distance': 50,
    },
    # -- Authentication & Access ------------------------------------------
    'Banking Authentication': {
        'Identifiers': {
            'PIN Block': ['pin block', 'encrypted pin', 'pin encryption', 'iso 9564', 'pin format'],
            'HSM Key': ['hsm', 'hardware security module', 'hsm key', 'master key', 'key material'],
            'Encryption Key': ['kek', 'zmk', 'tmk', 'zone master key', 'key encrypting', 'terminal master key', 'transport key', 'working key'],
        },
        'distance': 50,
    },
    # -- Customer Data ----------------------------------------------------
    'Customer Financial Data': {
        'Identifiers': {
            'Account Balance': ['balance', 'account balance', 'available balance', 'current balance', 'ledger balance', 'closing balance'],
            'Balance with Currency Code': ['balance', 'amount', 'total', 'funds', 'available', 'ledger'],
            'Income Amount': ['income', 'salary', 'annual income', 'monthly income', 'gross income', 'net income', 'compensation', 'wages', 'earnings'],
            'DTI Ratio': ['dti', 'debt-to-income', 'debt to income', 'dti ratio', 'debt ratio'],
        },
        'distance': 50,
    },
    # -- Internal Banking References --------------------------------------
    'Internal Banking References': {
        'Identifiers': {
            'Internal Account Ref': ['internal reference', 'account reference', 'internal id', 'system id', 'core banking id'],
            'Teller ID': ['teller id', 'teller number', 'officer id', 'banker id', 'employee id', 'user id'],
        },
        'distance': 50,
    },
    # -- Payment Card Industry (PCI) --------------------------------------
    'PCI Sensitive Data': {
        'Identifiers': {
            'Cardholder Name Pattern': ['cardholder', 'cardholder name', 'name on card', 'card holder', 'card member'],
        },
        'distance': 30,
    },
}
