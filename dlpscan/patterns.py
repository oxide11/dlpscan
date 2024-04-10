import re

PATTERNS = {
    'Personal Identification': {
        'Canada SIN': re.compile(r'\b\d{3}[-\s]?\d{3}[-\s]?\d{3}\b'),
        'USA SSN': re.compile(r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b'),
        'UK NIN': re.compile(r'\b[A-Z]{2}\d{6}[A-Z]{1}\b'),
        'Singapore NIRC': re.compile(r'\b[SFTG]\d{7}[A-Z]\b'),
        # Compile other patterns similarly
    },
    'Credit Card Numbers': {
        'Visa': re.compile(r'4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}'),
        'MasterCard': re.compile(r'5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}'),
        'Amex': re.compile(r'3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}'),
        'Discover': re.compile(r'6(?:011|5\d{2})[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}'),
    },
     'Drivers License Numbers': {
       'Generic': re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'),
        # You can refine these patterns or add more specific ones for Visa, MC, etc.
    },
    'Driver Licenses': {
        'Ontario': re.compile(r'\b[A-Z]\d{4}-\d{5}-\d{5}\b'),
        'British Columbia': re.compile(r'\b\d{7}\b'),
        # Add other provinces as needed
    },
    'Health Cards': {
        'Ontario': re.compile(r'\b\d{10}\b'),
        # Add other provinces as needed
    },
    'Passports': {
        'Canada': re.compile(r'\b[A-Z]{2}\d{6}\b'),
        # Adjust or add other patterns as needed for different countries
    },
    # Add categories for driver's licenses, health cards, passports with corresponding patterns
}
