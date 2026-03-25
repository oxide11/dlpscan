import re


MIDDLE_EAST_PATTERNS = {
    'Middle East - Saudi Arabia': {
        'Saudi Arabia National ID': re.compile(r'\b[12]\d{9}\b'),
        'Saudi Arabia Passport': re.compile(r'\b[A-Z]\d{7,8}\b'),
    },
    'Middle East - UAE': {
        'UAE Emirates ID': re.compile(r'\b784-?\d{4}-?\d{7}-?\d\b'),
        'UAE Visa Number': re.compile(r'\b[1-7]01/?(?:19|20)\d{2}/?\d{7}\b'),
        'UAE Passport': re.compile(r'\b[A-Z]?\d{7,9}\b'),
    },
    'Middle East - Israel': {
        'Israel Teudat Zehut': re.compile(r'\b\d{9}\b'),
        'Israel Passport': re.compile(r'\b\d{7,8}\b'),
    },
    'Middle East - Qatar': {
        'Qatar QID': re.compile(r'\b[23]\d{10}\b'),
        'Qatar Passport': re.compile(r'\b[A-Z]\d{7}\b'),
    },
    'Middle East - Kuwait': {
        'Kuwait Civil ID': re.compile(r'\b[1-3]\d{11}\b'),
        'Kuwait Passport': re.compile(r'\b[A-Z]?\d{7,9}\b'),
    },
    'Middle East - Bahrain': {
        'Bahrain CPR': re.compile(r'\b\d{9}\b'),
        'Bahrain Passport': re.compile(r'\b\d{7,9}\b'),
    },
    'Middle East - Jordan': {
        'Jordan National ID': re.compile(r'\b\d{10}\b'),
        'Jordan Passport': re.compile(r'\b[A-Z]\d{7}\b'),
    },
    'Middle East - Lebanon': {
        'Lebanon ID': re.compile(r'\b\d{7,12}\b'),
        'Lebanon Passport': re.compile(r'\b(?:RL|LR)\d{6,7}\b'),
    },
    'Middle East - Iraq': {
        'Iraq National ID': re.compile(r'\b\d{12}\b'),
        'Iraq Passport': re.compile(r'\b[A-HJ-NP-Z0-9]{9}\b'),
    },
    'Middle East - Iran': {
        'Iran Melli Code': re.compile(r'\b\d{10}\b'),
        'Iran Passport': re.compile(r'\b[A-Z]\d{8}\b'),
    },
}
