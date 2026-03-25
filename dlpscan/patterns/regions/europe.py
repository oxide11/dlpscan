import re


EUROPE_PATTERNS = {
    'Europe - United Kingdom': {
        'UK NIN': re.compile(r'\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b'),
        'UK UTR': re.compile(r'\b\d{10}\b'),
        'UK Passport': re.compile(r'\b\d{9}\b'),
        'UK Sort Code': re.compile(r'\b\d{2}-\d{2}-\d{2}\b'),
        'British NHS': re.compile(r'\b\d{10}\b'),
        'UK Phone Number': re.compile(r'(?:\+44[-.\s]?|0)(?:\d[-.\s]?){9,10}(?!\d)'),
    },
    'Europe - Germany': {
        'Germany ID': re.compile(r'\b[CFGHJKLMNPRTVWXYZ0-9]{9}\b'),
        'Germany Passport': re.compile(r'\bC[A-Z0-9]{8}\b'),
    },
    'Europe - France': {
        'France NIR': re.compile(r'\b[12]\d{2}(?:0[1-9]|1[0-2])\d{2}\d{3}\d{3}\d{2}\b'),
        'France Passport': re.compile(r'\b\d{2}[A-Z]{2}\d{5}\b'),
    },
    'Europe - Italy': {
        'Italy Codice Fiscale': re.compile(r'\b[A-Z]{6}\d{2}[A-EHLMPR-T]\d{2}[A-Z]\d{3}[A-Z]\b'),
    },
    'Europe - Netherlands': {
        'Netherlands BSN': re.compile(r'\b\d{8,9}\b'),
    },
    'Europe - Spain': {
        'Spain DNI/NIE': re.compile(r'\b[XYZ]?\d{7,8}[A-Z]\b'),
    },
    'Europe - Poland': {
        'Poland PESEL': re.compile(r'\b\d{11}\b'),
    },
    'Europe - Sweden': {
        'Sweden PIN': re.compile(r'\b\d{6}[-+]?\d{4}\b'),
    },
    'Europe - Portugal': {
        'Portugal NIF': re.compile(r'\b\d{9}\b'),
    },
    'Europe - Switzerland': {
        'Switzerland AHV': re.compile(r'\b756\.\d{4}\.\d{4}\.\d{2}\b'),
    },
    'Europe - Turkey': {
        'Turkey TC Kimlik': re.compile(r'\b[1-9]\d{10}\b'),
    },
    'Europe - EU': {
        'EU ETD': re.compile(r'\b[A-Z]{3}\d{6}\b'),
    },
}
