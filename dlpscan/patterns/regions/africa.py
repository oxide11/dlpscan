import re


AFRICA_PATTERNS = {
    'Africa - South Africa': {
        'South Africa ID': re.compile(r'\b\d{13}\b'),
        'South Africa Passport': re.compile(r'\b[A-Z]?\d{8,9}\b'),
        'South Africa DL': re.compile(r'\b\d{10}[A-Z]{2}\b'),
    },
    'Africa - Nigeria': {
        'Nigeria NIN': re.compile(r'\b\d{11}\b'),
        'Nigeria BVN': re.compile(r'\b\d{11}\b'),
        'Nigeria TIN': re.compile(r'\b\d{12,13}\b'),
        'Nigeria Voter Card': re.compile(r'\b[0-9A-Z]{19}\b'),
        'Nigeria Driver Licence': re.compile(r'\b[A-Z]{3}\d{5,9}[A-Z]{0,2}\d{0,2}\b'),
        'Nigeria Passport': re.compile(r'\b[A-Z]\d{8}\b'),
    },
    'Africa - Kenya': {
        'Kenya National ID': re.compile(r'\b\d{7,8}\b'),
        'Kenya KRA PIN': re.compile(r'\b[A-Z]\d{9}[A-Z]\b'),
        'Kenya NHIF': re.compile(r'\b\d{6,9}\b'),
        'Kenya Passport': re.compile(r'\b[A-Z]\d{7,8}\b'),
    },
    'Africa - Egypt': {
        'Egypt National ID': re.compile(r'\b[23]\d{13}\b'),
        'Egypt Tax ID': re.compile(r'\b\d{3}-?\d{3}-?\d{3}\b'),
        'Egypt Passport': re.compile(r'\b[A-Z]?\d{7,8}\b'),
    },
    'Africa - Ghana': {
        'Ghana Card': re.compile(r'\b(?:GHA|[A-Z]{3})-\d{9}-\d\b'),
        'Ghana TIN': re.compile(r'\b[CGQV]\d{10}\b'),
        'Ghana NHIS': re.compile(r'\b(?:GHA|[A-Z]{3})-\d{9}-\d\b'),
        'Ghana Passport': re.compile(r'\b[A-Z]\d{7}\b'),
    },
    'Africa - Ethiopia': {
        'Ethiopia National ID': re.compile(r'\b\d{12}\b'),
        'Ethiopia TIN': re.compile(r'\b\d{10}\b'),
        'Ethiopia Passport': re.compile(r'\b[A-Z]{2}\d{7}\b'),
    },
    'Africa - Tanzania': {
        'Tanzania NIDA': re.compile(r'\b\d{20}\b'),
        'Tanzania TIN': re.compile(r'\b\d{9}\b'),
        'Tanzania Passport': re.compile(r'\b[A-Z]{2}\d{7}\b'),
    },
    'Africa - Morocco': {
        'Morocco CIN': re.compile(r'\b[A-Z]{1,2}\d{5,6}\b'),
        'Morocco Tax ID': re.compile(r'\b\d{8}\b'),
        'Morocco Passport': re.compile(r'\b[A-Z]{2}\d{7}\b'),
    },
    'Africa - Tunisia': {
        'Tunisia CIN': re.compile(r'\b\d{8}\b'),
        'Tunisia Passport': re.compile(r'\b[A-Z]\d{6}\b'),
    },
    'Africa - Uganda': {
        'Uganda NIN': re.compile(r'\bC[MF]\d{8}[A-Z0-9]{4}\b'),
        'Uganda Passport': re.compile(r'\b[A-Z]\d{7,8}\b'),
    },
}
