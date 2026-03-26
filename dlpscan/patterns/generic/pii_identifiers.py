import re

# Standard optional delimiter: matches dash, dot, space, or nothing.
_S = r'[-.\s/\\_\u2013\u2014\u00a0]?'


PII_IDENTIFIERS_PATTERNS = {
    'Personal Identifiers': {
        # Date of birth in various formats with DOB label
        'Date of Birth': re.compile(r'\b(?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])[-/](?:19|20)\d{2}\b'),
        # Gender markers
        'Gender Marker': re.compile(r'\b(?:male|female|non-binary|transgender)\b', re.IGNORECASE),
    },
    'Geolocation': {
        # Latitude/Longitude decimal degrees (e.g., 40.7128, -74.0060)
        'GPS Coordinates': re.compile(r'-?\d{1,3}\.\d{4,8},\s?-?\d{1,3}\.\d{4,8}'),
        # DMS format (e.g., 40°42'46"N 74°0'22"W)
        'GPS DMS': re.compile(r"""\d{1,3}[°]\d{1,2}[\'′]\d{1,2}(?:\.\d+)?[\"″]?\s?[NSEW]"""),
        # Geohash (Base32-encoded location, requires mix of digits and letters)
        'Geohash': re.compile(r'\b(?=[0-9bcdefghjkmnpqrstuvwxyz]*\d)[0-9bcdefghjkmnpqrstuvwxyz]{7,12}\b'),
    },
    'Postal Codes': {
        # US ZIP+4 (require the +4 to reduce false positives; plain 5-digit is too broad)
        'US ZIP+4 Code': re.compile(r'\b\d{5}-\d{4}\b'),
        # UK Postcode
        'UK Postcode': re.compile(r'\b[A-Z]{1,2}\d[A-Z0-9]?\s?\d[A-Z]{2}\b'),
        # Canadian Postal Code
        'Canada Postal Code': re.compile(r'\b[A-Z]\d[A-Z]\s?\d[A-Z]\d\b'),
        # Japan Postal Code (requires hyphen)
        'Japan Postal Code': re.compile(r'\b\d{3}-\d{4}\b'),
        # Brazil CEP (requires hyphen)
        'Brazil CEP': re.compile(r'\b\d{5}-\d{3}\b'),
    },
    'Device Identifiers': {
        # IMEI: 15 digits (TAC 8 + serial 6 + Luhn check 1), with optional delimiters
        'IMEI': re.compile(rf'\b\d{{2}}{_S}\d{{6}}{_S}\d{{6}}{_S}\d\b'),
        # IMEISV: 16 digits (IMEI without check digit + 2-digit software version)
        'IMEISV': re.compile(rf'\b\d{{2}}{_S}\d{{6}}{_S}\d{{6}}{_S}\d{{2}}\b'),
        # MEID (14 hex digits, mobile equipment ID for CDMA — uppercase hex with structure)
        'MEID': re.compile(rf'\b[0-9A-F]{{2}}{_S}[0-9A-F]{{6}}{_S}[0-9A-F]{{6}}\b'),
        # ICCID (SIM card number, 19-20 digits, starts with 89)
        'ICCID': re.compile(rf'\b89\d{{2}}{_S}\d{{4}}{_S}\d{{4}}{_S}\d{{4}}{_S}\d{{3,4}}\d?\b'),
        # iOS IDFA/IDFV (UUID format, uppercase)
        'IDFA/IDFV': re.compile(r'\b[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\b'),
    },
    'Medical Identifiers': {
        # Health Plan Beneficiary Number (3 letter prefix + 9 digits)
        'Health Plan ID': re.compile(r'\b[A-Z]{3}\d{9}\b'),
        # DEA Number (2 letter prefix + 7 digits)
        'DEA Number': re.compile(r'\b[A-Z]{2}\d{7}\b'),
        # ICD-10 Diagnosis Code (letter + 2 digits + optional decimal)
        'ICD-10 Code': re.compile(r'\b[A-TV-Z]\d{2}(?:\.\d{1,4})?\b'),
        # NDC Drug Code (National Drug Code, requires hyphens)
        'NDC Code': re.compile(r'\b\d{4,5}-\d{3,4}-\d{1,2}\b'),
    },
    'Insurance Identifiers': {
        # Generic Insurance Policy Number (letter prefix + digits)
        'Insurance Policy Number': re.compile(r'\b[A-Z]{2,4}\d{6,12}\b'),
        # Insurance Claim Number (letter prefix + digits)
        'Insurance Claim Number': re.compile(r'\b[A-Z]{1,3}\d{8,15}\b'),
    },
    'Authentication Tokens': {
        # Session ID (hex string, 32+ chars — lowercase hex only)
        'Session ID': re.compile(r'\b[0-9a-f]{32,64}\b'),
    },
    'Social Media Identifiers': {
        # Twitter/X handle
        'Twitter Handle': re.compile(r'(?<!\w)@[A-Za-z_]\w{0,14}\b'),
        # Hashtag (can contain PII in targeted contexts)
        'Hashtag': re.compile(r'(?<!\w)#[A-Za-z]\w{2,49}\b'),
    },
    'Education Identifiers': {
        # University Email (common .edu pattern)
        'EDU Email': re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.edu\b', re.IGNORECASE),
    },
    'Legal Identifiers': {
        # US Federal Case Number (e.g., 1:23-cv-04567)
        'US Federal Case Number': re.compile(r'\b\d:\d{2}-[a-z]{2}-\d{4,5}\b'),
        # State Case/Docket Number
        'Court Docket Number': re.compile(r'\b\d{2,4}-?[A-Z]{1,4}-?\d{4,8}\b'),
    },
    'Employment Identifiers': {
        # Employee ID (alphanumeric, letter prefix + digits)
        'Employee ID': re.compile(r'\b[A-Z]{1,3}\d{4,8}\b'),
        # Work Permit Number (letter prefix + digits)
        'Work Permit Number': re.compile(r'\b[A-Z]{2,3}\d{7,10}\b'),
    },
    'Biometric Identifiers': {
        # Fingerprint Hash (SHA-256, lowercase hex, 64 chars)
        'Biometric Hash': re.compile(r'\b[0-9a-f]{64}\b'),
        # Facial Recognition Template ID (UUID format)
        'Biometric Template ID': re.compile(r'\b[A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12}\b'),
    },
    'Property Identifiers': {
        # US APN/Parcel Number (requires hyphenated structure)
        'Parcel Number': re.compile(r'\b\d{3}-\d{3}-\d{3}(?:-\d{3})?\b'),
        # Title/Deed Number (requires hyphen)
        'Title Deed Number': re.compile(r'\b\d{4,}-\d{4,}\b'),
    },
}
