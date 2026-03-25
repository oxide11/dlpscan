import re

# Standard optional delimiter: matches dash, dot, space, or nothing.
_S = r'[-.\s]?'


BANKING_PATTERNS = {
    # ── Core Banking ────────────────────────────────────────────────
    'Banking and Financial': {
        'IBAN Generic': re.compile(r'\b[A-Z]{2}\d{2}[\s]?[\dA-Z]{4}(?:[\s]?[\dA-Z]{4}){2,7}(?:[\s]?[\dA-Z]{1,4})?\b'),
        'SWIFT/BIC': re.compile(r'\b[A-Z]{4}[A-Z]{2}[A-Z2-9][A-NP-Z0-9](?:[A-Z\d]{3})?\b'),
        # US ABA Routing Number (9 digits, first 2 digits 01-32 or 61-72)
        'ABA Routing Number': re.compile(r'\b(?:0[1-9]|[12]\d|3[0-2]|6[1-9]|7[0-2])\d{7}\b'),
        # US Bank Account Number (typically 8-17 digits)
        'US Bank Account Number': re.compile(r'\b\d{8,17}\b'),
        # Canadian Transit Number (5 digits - 3 digits)
        'Canada Transit Number': re.compile(rf'\b\d{{5}}{_S}\d{{3}}\b'),
    },
    # ── Wire Transfers & Payments ───────────────────────────────────
    'Wire Transfer Data': {
        # Fedwire IMAD/OMAD (Input/Output Message Accountability Data)
        'Fedwire IMAD': re.compile(r'\b\d{8}[A-Z]{4}[A-Z0-9]{8}\d{6}\b'),
        # CHIPS UID (6-digit participant + sequence)
        'CHIPS UID': re.compile(r'\b\d{6,16}\b'),
        # Wire Reference Number
        'Wire Reference Number': re.compile(r'\b[A-Z0-9]{16,35}\b'),
        # ACH Trace Number (15 digits: 8 routing + 7 sequence)
        'ACH Trace Number': re.compile(r'\b\d{15}\b'),
        # ACH Batch Number (7 digits)
        'ACH Batch Number': re.compile(r'\b\d{7}\b'),
        # SEPA End-to-End Reference (up to 35 chars)
        'SEPA Reference': re.compile(r'\b[A-Z0-9]{12,35}\b'),
    },
    # ── Check/Cheque Data ───────────────────────────────────────────
    'Check and MICR Data': {
        # MICR Line (routing + account + check number)
        'MICR Line': re.compile(r'[⑈❰]?\d{9}[⑈❰]?\s?\d{6,17}[⑈❰]?\s?\d{4,6}'),
        # Check Number (4-6 digits)
        'Check Number': re.compile(r'\b\d{4,6}\b'),
        # Cashier Check / Money Order Number
        'Cashier Check Number': re.compile(r'\b\d{8,15}\b'),
    },
    # ── Securities Identifiers ──────────────────────────────────────
    'Securities Identifiers': {
        # CUSIP (9 characters: 6 issuer + 2 issue + 1 check)
        'CUSIP': re.compile(r'\b[0-9A-Z]{6}[0-9A-Z]{2}\d\b'),
        # ISIN (2 letter country + 9 alphanum + 1 check digit)
        'ISIN': re.compile(r'\b[A-Z]{2}[0-9A-Z]{9}\d\b'),
        # SEDOL (7 characters, UK securities)
        'SEDOL': re.compile(r'\b[0-9BCDFGHJKLMNPQRSTVWXYZ]{6}\d\b'),
        # FIGI (12 characters, Bloomberg identifier)
        'FIGI': re.compile(r'\bBBG[A-Z0-9]{9}\b'),
        # LEI (Legal Entity Identifier, 20 alphanumeric)
        'LEI': re.compile(r'\b[A-Z0-9]{4}00[A-Z0-9]{12}\d{2}\b'),
        # Ticker Symbol (1-5 uppercase letters)
        'Ticker Symbol': re.compile(r'\b[A-Z]{1,5}\b'),
    },
    # ── Loan & Mortgage ─────────────────────────────────────────────
    'Loan and Mortgage Data': {
        # Loan Number (8-15 digits/alphanumeric)
        'Loan Number': re.compile(r'\b[A-Z0-9]{8,15}\b'),
        # MERS MIN (Mortgage Identification Number, 18 digits)
        'MERS MIN': re.compile(r'\b\d{18}\b'),
        # ULI (Universal Loan Identifier, 23-45 chars, starts with LEI)
        'Universal Loan Identifier': re.compile(r'\b[A-Z0-9]{23,45}\b'),
        # Loan-to-Value ratio (##.##%)
        'LTV Ratio': re.compile(r'\b\d{1,3}\.\d{1,2}%\b'),
    },
    # ── Regulatory & Compliance ─────────────────────────────────────
    'Regulatory Identifiers': {
        # SAR (Suspicious Activity Report) Filing Number
        'SAR Filing Number': re.compile(r'\b\d{14,20}\b'),
        # CTR (Currency Transaction Report) Number
        'CTR Number': re.compile(r'\b\d{14,20}\b'),
        # BSA/AML Case ID
        'AML Case ID': re.compile(r'\b[A-Z]{2,4}[-]?\d{6,12}\b'),
        # OFAC SDN List Entry ID
        'OFAC SDN Entry': re.compile(r'\b\d{4,6}\b'),
        # FinCEN Report Number
        'FinCEN Report Number': re.compile(r'\b\d{14}\b'),
        # Compliance Case/Investigation Number
        'Compliance Case Number': re.compile(r'\b[A-Z]{2,5}[-]?\d{4}[-]?\d{4,8}\b'),
    },
    # ── Authentication & Access ─────────────────────────────────────
    'Banking Authentication': {
        # ATM/Debit PIN (4-6 digits)
        'PIN': re.compile(r'\b\d{4,6}\b'),
        # PIN Block (16 hex characters, encrypted PIN)
        'PIN Block': re.compile(r'\b[0-9A-F]{16}\b'),
        # HSM Key (32-64 hex characters)
        'HSM Key': re.compile(r'\b[0-9A-Fa-f]{32,64}\b'),
        # KEK/ZMK/TMK (Key Encrypting Key, 32 or 48 hex)
        'Encryption Key': re.compile(r'\b[0-9A-Fa-f]{32,48}\b'),
    },
    # ── Customer Data ───────────────────────────────────────────────
    'Customer Financial Data': {
        # Account Balance (currency amount with decimals)
        'Account Balance': re.compile(r'(?<!\w)[\$€£¥]\s?\d{1,3}(?:[,.\s]\d{3})*(?:\.\d{2})?\b'),
        # Account Balance (numeric with currency code)
        'Balance with Currency Code': re.compile(r'\b(?:USD|EUR|GBP|JPY|CAD|AUD|CHF)\s?\d{1,3}(?:[,.\s]\d{3})*(?:\.\d{2})?\b'),
        # Income/Salary Amount
        'Income Amount': re.compile(r'(?<!\w)[\$€£¥]\s?\d{1,3}(?:[,.\s]\d{3})*(?:\.\d{2})?\b'),
        # Credit Score (300-850 range, FICO)
        'Credit Score': re.compile(r'\b[3-8]\d{2}\b'),
        # Debt-to-Income Ratio
        'DTI Ratio': re.compile(r'\b\d{1,2}\.\d{1,2}%\b'),
    },
    # ── Internal Banking References ─────────────────────────────────
    'Internal Banking References': {
        # Customer Identification Number (CIF/CID)
        'Customer ID': re.compile(r'\b\d{6,12}\b'),
        # Internal Account Reference
        'Internal Account Ref': re.compile(r'\b[A-Z]{2,4}\d{8,14}\b'),
        # Branch/Cost Center Code
        'Branch Code': re.compile(r'\b\d{4,6}\b'),
        # Teller/Officer ID
        'Teller ID': re.compile(r'\b[A-Z]{1,3}\d{4,8}\b'),
    },
    # ── Payment Card Industry (PCI) ─────────────────────────────────
    'PCI Sensitive Data': {
        # Card Verification Value from chip (iCVV/dCVV)
        'Dynamic CVV': re.compile(r'\b\d{3}\b'),
        # PIN Verification Key Indicator (PVKI)
        'PVKI': re.compile(r'\b\d{1}\b'),
        # PIN Verification Value (PVV, 4 digits)
        'PVV': re.compile(r'\b\d{4}\b'),
        # Service Code (3 digits on magstripe)
        'Service Code': re.compile(r'\b\d{3}\b'),
        # Cardholder Name
        'Cardholder Name Pattern': re.compile(r'\b[A-Z][a-z]+\s[A-Z][a-z]+\b'),
    },
}
