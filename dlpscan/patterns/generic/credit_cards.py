import re


CREDIT_CARDS_PATTERNS = {
    'Credit Card Numbers': {
        'Visa': re.compile(r'\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),
        'MasterCard': re.compile(r'\b(?:5[1-5]\d{2}|2(?:2[2-9]\d|2[3-9]\d|[3-6]\d{2}|7[01]\d|720))[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),
        'Amex': re.compile(r'\b3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}\b'),
        'Discover': re.compile(r'\b6(?:011|5\d{2}|4[4-9]\d)[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),
        'JCB': re.compile(r'\b35(?:2[89]|[3-8]\d)[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),
        'Diners Club': re.compile(r'\b3(?:0[0-5]|[68]\d)\d[\s-]?\d{6}[\s-]?\d{4}\b'),
        'UnionPay': re.compile(r'\b62\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}(?:[\s-]?\d{1,3})?\b'),
    },
}
