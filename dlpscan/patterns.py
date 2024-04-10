import re

# A dictionary to store various regex patterns for matching identification numbers, credit cards, etc.
PATTERNS = {
    'Personal Identification': {
        # Canadian Social Insurance Number pattern with optional spaces or hyphens between the groups (formatted as XXX-XXX-XXX or XXXXXXXXX)
        'Canada SIN': re.compile(r'\b\d{3}[-\s]?\d{3}[-\s]?\d{3}\b'),
        
        # United States Social Security Number pattern with optional spaces or hyphens between the groups (formatted as XXX-XX-XXXX or XXXXXXXXX)
        'USA SSN': re.compile(r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b'),
        
        # UK National Insurance Number pattern formatted as XX999999X
        'UK NIN': re.compile(r'\b[A-Z]{2}\d{6}[A-Z]\b'),
        
        # Singapore National Registration Identity Card pattern formatted as X9999999X
        'Singapore NIRC': re.compile(r'\b[SFTG]\d{7}[A-Z]\b'),
        
        # Australian Tax File Number pattern with 9 consecutive digits
        'Australia TFN': re.compile(r'\b\d{9}\b'),
        
        # Indian Permanent Account Number pattern formatted as XXXXX9999X
        'India PAN': re.compile(r'\b[A-Z]{5}\d{4}[A-Z]\b'),
        
        # German ID pattern with 11 alphanumeric characters without specific format
        'Germany ID': re.compile(r'\b[ABCDEFGHJKLMNPRTUVWXYZ0-9]{11}\b'),
        
        # Brazilian CPF pattern that matches both formatted (XXX.XXX.XXX-XX) and unformatted (XXXXXXXXXXX) numbers
        'Brazil CPF': re.compile(r'\b\d{3}(\.\d{3}){2}-\d{2}\b|\b\d{11}\b'),
        
        # Spain DNI/NIE pattern allowing an optional leading character (X/Y/Z) followed by either 7 or 8 digits and finally a letter
        'Spain DNI/NIE': re.compile(r'\b[XYZ]?\d{7,8}[A-Z]\b'),
    },
    'Credit Card Numbers': {
        # Visa card pattern with optional spaces or hyphens between 4-digit groups (formatted as XXXX XXXX XXXX XXXX)
        'Visa': re.compile(r'4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}'),
        
        # MasterCard pattern with optional spaces or hyphens between 4-digit groups (formatted as 5XXX XXXX XXXX XXXX where X can be 1-5)
        'MasterCard': re.compile(r'5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}'),
        
        # American Express card pattern with optional spaces or hyphens after 4 and 6 digits (formatted as 34XX XXXXXX XXXXX or 37XX XXXXXX XXXXX)
        'Amex': re.compile(r'3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}'),
        
        # Discover card pattern with optional spaces or hyphens between 4-digit groups (formatted as 6011 XXXX XXXX XXXX or 65XX XXXX XXXX XXXX)
        'Discover': re.compile(r'6(?:011|5\d{2})[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}'),
    },
    'Driver Licenses': {
        # Generic driver's license pattern with one or two letters followed by 4 to 9 digits
        'Generic': re.compile(r'\b[A-Z]{1,2}\d{4,9}\b'),  
        
        # California driver's license pattern formatted as a single letter followed by 7 digits
        'California DL': re.compile(r'\b[A-Z]\d{7}\b'),
        
        # New York driver's license pattern with a letter followed by 7 to 18 digits
        'New York DL': re.compile(r'\b[A-Z]\d{7,18}\b'), 
        
        # India driver's license pattern formatted as two letters followed by 13 digits
        'India DL': re.compile(r'\b[A-Z]{2}\d{13}\b'),   
        
        # Ontario driver's license pattern with specific grouping, formatted as X9999-99999-99999
        'Ontario': re.compile(r'\b[A-Z]\d{4}-\d{5}-\d{5}\b'),
        
        # British Columbia driver's license pattern with 7 digits
        'British Columbia': re.compile(r'\b\d{7}\b'),
    },
    'Health Cards': {
        # Ontario health card pattern with 10 consecutive digits
        'Ontario': re.compile(r'\b\d{10}\b'),
        
        # British National Health Service number pattern with 10 consecutive digits
        'British NHS': re.compile(r'\b\d{10}\b'),
        
        # Australian Medicare pattern with 11 consecutive digits
        'Australia Medicare': re.compile(r'\b\d{11}\b'),
    },
    'Passports': {
        # Canadian passport pattern formatted as two letters followed by six digits
        'Canada': re.compile(r'\b[A-Z]{2}\d{6}\b'),
        
        # USA passport pattern with 9 consecutive digits
        'USA Passport': re.compile(r'\b\d{9}\b'),
        
        # EU Emergency Travel Document pattern formatted as three letters followed by six digits
        'EU ETD': re.compile(r'\b[A-Z]{3}\d{6}\b'),
        
        # Japan passport pattern with a specific letter (M/S/R/C) followed by seven digits
        'Japan Passport': re.compile(r'\b[MSRC]\d{7}\b'),
    },
    'Bank Account Numbers': {
        # Generic IBAN pattern with proper grouping and optional spaces, starting with two letters followed by two digits, then up to 31 alphanumeric characters in groups of four
        'IBAN Generic': re.compile(r'\b[A-Z]{2}\d{2}(?: ?\d{4}){3,6}\d{1,3}?\b'),
        
        # USA routing number pattern with 9 consecutive digits
        'USA Routing Number': re.compile(r'\b\d{9}\b'),
        
        # UK sort code pattern formatted as XX-XX-XX with hyphen-separated groups
        'UK Sort Code': re.compile(r'\b\d{2}-\d{2}-\d{2}\b'),
        
        # SWIFT/BIC pattern with standard format including 4-letter bank code, 2-letter country code, 2-alphanumeric location code, and an optional 3-character branch code
        'SWIFT/BIC': re.compile(r'\b[A-Z]{4}[A-Z]{2}[A-Z2-9][A-NP-Z0-9](?:[A-Z\d]{3})?\b'),
    },
    # Additional patterns and categories can be added here...
}
