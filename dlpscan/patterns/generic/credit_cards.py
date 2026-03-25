import re

# Standard optional delimiter: matches dash, dot, space, or nothing.
_S = r'[-.\s]?'


CREDIT_CARDS_PATTERNS = {
    'Credit Card Numbers': {
        'Visa': re.compile(rf'\b4\d{{3}}{_S}\d{{4}}{_S}\d{{4}}{_S}\d{{4}}\b'),
        'MasterCard': re.compile(rf'\b(?:5[1-5]\d{{2}}|2(?:2[2-9]\d|2[3-9]\d|[3-6]\d{{2}}|7[01]\d|720)){_S}\d{{4}}{_S}\d{{4}}{_S}\d{{4}}\b'),
        'Amex': re.compile(rf'\b3[47]\d{{2}}{_S}\d{{6}}{_S}\d{{5}}\b'),
        'Discover': re.compile(rf'\b6(?:011|5\d{{2}}|4[4-9]\d){_S}\d{{4}}{_S}\d{{4}}{_S}\d{{4}}\b'),
        'JCB': re.compile(rf'\b35(?:2[89]|[3-8]\d){_S}\d{{4}}{_S}\d{{4}}{_S}\d{{4}}\b'),
        'Diners Club': re.compile(rf'\b3(?:0[0-5]|[68]\d)\d{_S}\d{{6}}{_S}\d{{4}}\b'),
        'UnionPay': re.compile(rf'\b62\d{{2}}{_S}\d{{4}}{_S}\d{{4}}{_S}\d{{4}}(?:{_S}\d{{1,3}})?\b'),
    },
    'Credit Card Security Codes': {
        # CVV/CVC/CCV: 3 digits (Visa, MC, Discover, JCB, UnionPay)
        'CVV/CVC/CCV': re.compile(r'\b\d{3}\b'),
        # Amex CID: 4 digits
        'Amex CID': re.compile(r'\b\d{4}\b'),
    },
    'Primary Account Numbers': {
        # Generic PAN: 13-19 digit card numbers (ISO/IEC 7812)
        'PAN': re.compile(rf'\b\d{{4}}{_S}\d{{4}}{_S}\d{{4}}{_S}\d{{1,7}}\b'),
        # Truncated/Masked PAN: first 6 and last 4 visible
        'Masked PAN': re.compile(rf'\b\d{{4}}{_S}[Xx*]{{4}}{_S}[Xx*]{{4}}{_S}\d{{4}}\b'),
        # BIN/IIN: first 6-8 digits of card number
        'BIN/IIN': re.compile(r'\b\d{6,8}\b'),
    },
    'Card Track Data': {
        # Track 1: starts with %B, contains PAN, name, expiry
        'Track 1 Data': re.compile(r'%B\d{13,19}\^[A-Z\s/]+\^\d{4}\d*'),
        # Track 2: starts with ;, contains PAN=expiry
        'Track 2 Data': re.compile(r';\d{13,19}=\d{4}\d*\?'),
    },
    'Card Expiration Dates': {
        # MM/YY or MM/YYYY
        'Card Expiry': re.compile(r'\b(?:0[1-9]|1[0-2])\s?/\s?(?:\d{2}|\d{4})\b'),
    },
}
