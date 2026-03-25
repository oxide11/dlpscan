import re


BANKING_PATTERNS = {
    'Banking and Financial': {
        'IBAN Generic': re.compile(r'\b[A-Z]{2}\d{2}[\s]?[\dA-Z]{4}(?:[\s]?[\dA-Z]{4}){2,7}(?:[\s]?[\dA-Z]{1,4})?\b'),
        'SWIFT/BIC': re.compile(r'\b[A-Z]{4}[A-Z]{2}[A-Z2-9][A-NP-Z0-9](?:[A-Z\d]{3})?\b'),
    },
}
