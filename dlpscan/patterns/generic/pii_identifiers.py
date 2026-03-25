import re


PII_IDENTIFIERS_PATTERNS = {
    'Personal Identifiers': {
        # Date of birth in various formats with DOB label
        'Date of Birth': re.compile(r'\b(?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])[-/](?:19|20)\d{2}\b'),
        # Age as a number (context-gated to avoid false positives)
        'Age Value': re.compile(r'\b(?:1[89]|[2-9]\d|1[0-4]\d)\b'),
        # Gender markers
        'Gender Marker': re.compile(r'\b(?:male|female|non-binary|transgender|M|F|X)\b', re.IGNORECASE),
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
        # US ZIP / ZIP+4
        'US ZIP Code': re.compile(r'\b\d{5}(?:-\d{4})?\b'),
        # UK Postcode
        'UK Postcode': re.compile(r'\b[A-Z]{1,2}\d[A-Z0-9]?\s?\d[A-Z]{2}\b'),
        # Canadian Postal Code
        'Canada Postal Code': re.compile(r'\b[A-Z]\d[A-Z]\s?\d[A-Z]\d\b'),
        # Australian Postcode
        'Australia Postcode': re.compile(r'\b\d{4}\b'),
        # German PLZ
        'Germany PLZ': re.compile(r'\b\d{5}\b'),
        # Japan Postal Code
        'Japan Postal Code': re.compile(r'\b\d{3}-\d{4}\b'),
        # India PIN Code
        'India PIN Code': re.compile(r'\b[1-9]\d{5}\b'),
        # Brazil CEP
        'Brazil CEP': re.compile(r'\b\d{5}-?\d{3}\b'),
    },
    'Device Identifiers': {
        # IMEI (15 digits, often with hyphens)
        'IMEI': re.compile(r'\b\d{2}[-]?\d{6}[-]?\d{6}[-]?\d\b'),
        # IMSI (15 digits, starts with MCC)
        'IMSI': re.compile(r'\b\d{15}\b'),
        # Android Device ID (64-bit hex)
        'Android Device ID': re.compile(r'\b[0-9a-f]{16}\b'),
        # iOS IDFA/IDFV (UUID format)
        'IDFA/IDFV': re.compile(r'\b[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\b'),
        # Serial Number (generic alphanumeric)
        'Device Serial Number': re.compile(r'\b[A-Z0-9]{8,20}\b'),
    },
    'Medical Identifiers': {
        # Medical Record Number (MRN) — typically 6-10 digits
        'Medical Record Number': re.compile(r'\b\d{6,10}\b'),
        # Health Plan Beneficiary Number
        'Health Plan ID': re.compile(r'\b[A-Z]{3}\d{9}\b'),
        # DEA Number (already in US region but useful generically)
        'DEA Number': re.compile(r'\b[A-Z]{2}\d{7}\b'),
        # ICD-10 Diagnosis Code
        'ICD-10 Code': re.compile(r'\b[A-Z]\d{2}(?:\.\d{1,4})?\b'),
        # NDC Drug Code (National Drug Code)
        'NDC Code': re.compile(r'\b\d{4,5}-\d{3,4}-\d{1,2}\b'),
    },
    'Insurance Identifiers': {
        # Generic Insurance Policy Number
        'Insurance Policy Number': re.compile(r'\b[A-Z]{2,4}\d{6,12}\b'),
        # Insurance Group Number
        'Insurance Group Number': re.compile(r'\b\d{5,10}\b'),
        # Insurance Claim Number
        'Insurance Claim Number': re.compile(r'\b[A-Z]{1,3}\d{8,15}\b'),
    },
    'Authentication Tokens': {
        # TOTP/OTP (6-8 digit codes)
        'OTP Code': re.compile(r'\b\d{6,8}\b'),
        # Session ID (hex string, 32+ chars)
        'Session ID': re.compile(r'\b[0-9a-f]{32,64}\b'),
        # CSRF Token
        'CSRF Token': re.compile(r'\b[0-9a-zA-Z_-]{32,64}\b'),
        # OAuth Refresh Token
        'Refresh Token': re.compile(r'\b[0-9a-zA-Z_-]{40,}\b'),
    },
    'Social Media Identifiers': {
        # Twitter/X handle
        'Twitter Handle': re.compile(r'(?<!\w)@[A-Za-z_]\w{0,14}\b'),
        # Hashtag (can contain PII in targeted contexts)
        'Hashtag': re.compile(r'(?<!\w)#[A-Za-z]\w{2,49}\b'),
        # Social media numeric user ID
        'Social Media User ID': re.compile(r'\b\d{6,20}\b'),
    },
    'Education Identifiers': {
        # Student ID (typically 7-10 digits)
        'Student ID': re.compile(r'\b\d{7,10}\b'),
        # University Email (common .edu pattern)
        'EDU Email': re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.edu\b', re.IGNORECASE),
        # GPA (0.0-4.0 scale)
        'GPA': re.compile(r'\b[0-4]\.\d{1,2}\b'),
    },
    'Legal Identifiers': {
        # US Federal Case Number (e.g., 1:23-cv-04567)
        'US Federal Case Number': re.compile(r'\b\d:\d{2}-[a-z]{2}-\d{4,5}\b'),
        # State Case/Docket Number
        'Court Docket Number': re.compile(r'\b\d{2,4}-?[A-Z]{1,4}-?\d{4,8}\b'),
        # Bar Number
        'Bar Number': re.compile(r'\b\d{5,8}\b'),
    },
    'Employment Identifiers': {
        # Employee ID (alphanumeric, 5-10 chars)
        'Employee ID': re.compile(r'\b[A-Z]{1,3}\d{4,8}\b'),
        # Work Permit Number
        'Work Permit Number': re.compile(r'\b[A-Z]{2,3}\d{7,10}\b'),
    },
    'Biometric Identifiers': {
        # Fingerprint Hash (SHA-256)
        'Biometric Hash': re.compile(r'\b[0-9a-f]{64}\b'),
        # Facial Recognition Template ID
        'Biometric Template ID': re.compile(r'\b[A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12}\b'),
    },
    'Property Identifiers': {
        # US APN/Parcel Number
        'Parcel Number': re.compile(r'\b\d{3}-\d{3}-\d{3}(?:-\d{3})?\b'),
        # Title/Deed Number
        'Title Deed Number': re.compile(r'\b\d{4,}-?\d{4,}\b'),
    },
}
