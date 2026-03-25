import re

# Standard optional delimiter: matches dash, dot, space, or nothing.
_S = r'[-.\s]?'


NORTH_AMERICA_PATTERNS = {
    'North America - United States': {
        # Social Security Number: XXX-XX-XXXX
        'USA SSN': re.compile(rf'\b\d{{3}}{_S}\d{{2}}{_S}\d{{4}}\b'),
        # Individual Taxpayer Identification Number: 9XX-XX-XXXX
        'USA ITIN': re.compile(rf'\b9\d{{2}}{_S}\d{{2}}{_S}\d{{4}}\b'),
        # Employer Identification Number: XX-XXXXXXX
        'USA EIN': re.compile(rf'\b\d{{2}}{_S}\d{{7}}\b'),
        # Passport Book: 9 digits
        'USA Passport': re.compile(r'\b\d{9}\b'),
        # Passport Card: C + 8 digits
        'USA Passport Card': re.compile(r'\bC\d{8}\b'),
        # Routing Number: 9 digits
        'USA Routing Number': re.compile(r'\b\d{9}\b'),
        # DEA Number: 2 letters + 7 digits
        'US DEA Number': re.compile(r'\b[A-Z]{2}\d{7}\b'),
        # NPI: 10 digits starting with 1 or 2
        'US NPI': re.compile(r'\b[12]\d{9}\b'),
        # Medicare Beneficiary Identifier
        'US MBI': re.compile(rf'\b[1-9][A-CEGHJ-NP-RT-Y](?:[0-9]|[A-CEGHJ-NP-RT-Y])[0-9]{_S}[A-CEGHJ-NP-RT-Y](?:[0-9]|[A-CEGHJ-NP-RT-Y])[0-9]{_S}[A-CEGHJ-NP-RT-Y]{{2}}[0-9]{{2}}\b'),
        # DoD/EDIPI: 10 digits
        'US DoD ID': re.compile(r'\b\d{10}\b'),
        # Known Traveler Number (Global Entry/TSA PreCheck): 9 digits
        'US Known Traveler Number': re.compile(r'\b\d{9}\b'),
        # US Phone: (XXX) XXX-XXXX
        'US Phone Number': re.compile(r'(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)'),
        # Alabama DL: 7 digits
        'Alabama DL': re.compile(r'\b\d{7}\b'),
        # Alaska DL: 7 digits
        'Alaska DL': re.compile(r'\b\d{7}\b'),
        # Arizona DL: letter + 8 digits OR 9 digits
        'Arizona DL': re.compile(r'\b(?:[A-Z]\d{8}|\d{9})\b'),
        # Arkansas DL: 8-9 digits
        'Arkansas DL': re.compile(r'\b\d{8,9}\b'),
        # California DL: letter + 7 digits
        'California DL': re.compile(r'\b[A-Z]\d{7}\b'),
        # Colorado DL: 9 digits or letter + 3-6 digits
        'Colorado DL': re.compile(r'\b(?:\d{9}|[A-Z]\d{3,6})\b'),
        # Connecticut DL: 9 digits
        'Connecticut DL': re.compile(r'\b\d{9}\b'),
        # Delaware DL: 1-7 digits
        'Delaware DL': re.compile(r'\b\d{1,7}\b'),
        # DC DL: 7 digits or 9 digits
        'DC DL': re.compile(r'\b(?:\d{7}|\d{9})\b'),
        # Florida DL: letter + 12 digits
        'Florida DL': re.compile(r'\b[A-Z]\d{12}\b'),
        # Georgia DL: 7-9 digits
        'Georgia DL': re.compile(r'\b\d{7,9}\b'),
        # Hawaii DL: letter + 8 digits or 9 digits
        'Hawaii DL': re.compile(r'\b(?:[A-Z]\d{8}|\d{9})\b'),
        # Idaho DL: 2 letters + 6 digits + letter
        'Idaho DL': re.compile(r'\b[A-Z]{2}\d{6}[A-Z]\b'),
        # Illinois DL: letter + 11 digits
        'Illinois DL': re.compile(r'\b[A-Z]\d{11}\b'),
        # Indiana DL: 10 digits or letter + 9 digits
        'Indiana DL': re.compile(r'\b(?:\d{10}|[A-Z]\d{9})\b'),
        # Iowa DL: 3 digits + 2 letters + 4 digits
        'Iowa DL': re.compile(r'\b\d{3}[A-Z]{2}\d{4}\b'),
        # Kansas DL: letter + 8 digits or letter + letter + 7 digits or 9 digits
        'Kansas DL': re.compile(r'\b(?:[A-Z]\d{8}|[A-Z]{2}\d{7}|\d{9})\b'),
        # Kentucky DL: letter + 8 digits
        'Kentucky DL': re.compile(r'\b[A-Z]\d{8}\b'),
        # Louisiana DL: 9 digits
        'Louisiana DL': re.compile(r'\b\d{9}\b'),
        # Maine DL: 7 digits or 7 digits + letter
        'Maine DL': re.compile(r'\b\d{7}[A-Z]?\b'),
        # Maryland DL: letter + 12 digits
        'Maryland DL': re.compile(r'\b[A-Z]\d{12}\b'),
        # Massachusetts DL: letter + 8 digits or 9 digits
        'Massachusetts DL': re.compile(r'\b(?:[A-Z]\d{8}|\d{9})\b'),
        # Michigan DL: letter + 12 digits
        'Michigan DL': re.compile(r'\b[A-Z]\d{12}\b'),
        # Minnesota DL: letter + 12 digits
        'Minnesota DL': re.compile(r'\b[A-Z]\d{12}\b'),
        # Mississippi DL: 9 digits
        'Mississippi DL': re.compile(r'\b\d{9}\b'),
        # Missouri DL: letter + 5-9 digits or 9 digits
        'Missouri DL': re.compile(r'\b(?:[A-Z]\d{5,9}|\d{9})\b'),
        # Montana DL: 13 digits or 9 digits
        'Montana DL': re.compile(r'\b(?:\d{13}|\d{9})\b'),
        # Nebraska DL: letter + 8 digits
        'Nebraska DL': re.compile(r'\b[A-Z]\d{8}\b'),
        # Nevada DL: 10 digits or 12 digits
        'Nevada DL': re.compile(r'\b(?:\d{10}|\d{12})\b'),
        # New Hampshire DL: 2 digits + 3 letters + 5 digits
        'New Hampshire DL': re.compile(r'\b\d{2}[A-Z]{3}\d{5}\b'),
        # New Jersey DL: letter + 14 digits
        'New Jersey DL': re.compile(r'\b[A-Z]\d{14}\b'),
        # New Mexico DL: 9 digits
        'New Mexico DL': re.compile(r'\b\d{9}\b'),
        # New York DL: 9 digits
        'New York DL': re.compile(r'\b\d{9}\b'),
        # North Carolina DL: 1-12 digits
        'North Carolina DL': re.compile(r'\b\d{1,12}\b'),
        # North Dakota DL: 3 letters + 6 digits or 9 digits
        'North Dakota DL': re.compile(r'\b(?:[A-Z]{3}\d{6}|\d{9})\b'),
        # Ohio DL: 2 letters + 6 digits
        'Ohio DL': re.compile(r'\b[A-Z]{2}\d{6}\b'),
        # Oklahoma DL: letter + 9 digits or 9 digits
        'Oklahoma DL': re.compile(r'\b(?:[A-Z]\d{9}|\d{9})\b'),
        # Oregon DL: 1-9 digits
        'Oregon DL': re.compile(r'\b\d{1,9}\b'),
        # Pennsylvania DL: 8 digits
        'Pennsylvania DL': re.compile(r'\b\d{8}\b'),
        # Rhode Island DL: 7 digits or letter + 6 digits
        'Rhode Island DL': re.compile(r'\b(?:\d{7}|[A-Z]\d{6})\b'),
        # South Carolina DL: 5-11 digits
        'South Carolina DL': re.compile(r'\b\d{5,11}\b'),
        # South Dakota DL: 8-10 digits or 12 digits
        'South Dakota DL': re.compile(r'\b(?:\d{8,10}|\d{12})\b'),
        # Tennessee DL: 7-9 digits
        'Tennessee DL': re.compile(r'\b\d{7,9}\b'),
        # Texas DL: 8 digits
        'Texas DL': re.compile(r'\b\d{8}\b'),
        # Utah DL: 4-10 digits
        'Utah DL': re.compile(r'\b\d{4,10}\b'),
        # Vermont DL: 8 digits or 7 digits + letter
        'Vermont DL': re.compile(r'\b(?:\d{8}|\d{7}[A-Z])\b'),
        # Virginia DL: letter + 8-11 digits or 9 digits
        'Virginia DL': re.compile(r'\b(?:[A-Z]\d{8,11}|\d{9})\b'),
        # Washington DL: 1-7 letters + alphanumeric (12 chars)
        'Washington DL': re.compile(r'\b[A-Z]{1,7}[A-Z0-9*]{5,11}\b'),
        # West Virginia DL: 7 digits or letter + 6 digits
        'West Virginia DL': re.compile(r'\b(?:\d{7}|[A-Z]\d{6})\b'),
        # Wisconsin DL: letter + 13 digits
        'Wisconsin DL': re.compile(r'\b[A-Z]\d{13}\b'),
        # Wyoming DL: 9-10 digits
        'Wyoming DL': re.compile(r'\b\d{9,10}\b'),
    },
    'North America - US Generic DL': {
        'Generic US DL': re.compile(r'\b[A-Z]{1,2}\d{4,14}\b'),
    },
    'North America - Canada': {
        # Social Insurance Number: XXX-XXX-XXX
        'Canada SIN': re.compile(rf'\b\d{{3}}{_S}\d{{3}}{_S}\d{{3}}\b'),
        # Business Number: 9 digits + 2 letters + 4 digits
        'Canada BN': re.compile(r'\b\d{9}[A-Z]{2}\d{4}\b'),
        # Passport: 2 letters + 6 digits
        'Canada Passport': re.compile(r'\b[A-Z]{2}\d{6}\b'),
        # Bank transit/institution code: XXXXX-XXX
        'Canada Bank Code': re.compile(rf'\b\d{{5}}{_S}\d{{3}}\b'),
        # Permanent Resident Card: 2 letters + 7-10 digits
        'Canada PR Card': re.compile(r'\b[A-Z]{2}\d{7,10}\b'),
        # NEXUS Card: 9 digits
        'Canada NEXUS': re.compile(r'\b\d{9}\b'),
        # Ontario DL: letter + 4 digits + 5 digits + 5 digits
        'Ontario DL': re.compile(rf'\b[A-Z]\d{{4}}{_S}\d{{5}}{_S}\d{{5}}\b'),
        # Ontario Health (OHIP): 10 digits + 2-letter version code
        'Ontario HC': re.compile(r'\b\d{10}(?:\s?[A-Z]{2})?\b'),
        # Quebec DL: letter + 4 digits + 6 digits + 2 digits
        'Quebec DL': re.compile(rf'\b[A-Z]\d{{4}}{_S}\d{{6}}{_S}\d{{2}}\b'),
        # Quebec Health (RAMQ): 4 letters + 8 digits
        'Quebec HC': re.compile(r'\b[A-Z]{4}\d{8}\b'),
        # British Columbia DL: 7 digits
        'British Columbia DL': re.compile(r'\b\d{7}\b'),
        # BC Health (MSP): 10 digits starting with 9
        'BC HC': re.compile(r'\b9\d{9}\b'),
        # Alberta DL: 6-9 digits
        'Alberta DL': re.compile(r'\b\d{6,9}\b'),
        # Alberta Health (AHCIP): 9 digits
        'Alberta HC': re.compile(r'\b\d{9}\b'),
        # Saskatchewan DL: 8 digits
        'Saskatchewan DL': re.compile(r'\b\d{8}\b'),
        # Saskatchewan Health: 9 digits
        'Saskatchewan HC': re.compile(r'\b\d{9}\b'),
        # Manitoba DL: 6 letters + 6 digits (Soundex-based)
        'Manitoba DL': re.compile(r'\b[A-Z]{6}\d{6}\b'),
        # Manitoba Health (PHIN): 9 digits
        'Manitoba HC': re.compile(r'\b\d{9}\b'),
        # New Brunswick DL: 5-7 digits
        'New Brunswick DL': re.compile(r'\b\d{5,7}\b'),
        # New Brunswick Health: 9 digits
        'New Brunswick HC': re.compile(r'\b\d{9}\b'),
        # Nova Scotia DL: 5 letters + 9 digits (Soundex-based)
        'Nova Scotia DL': re.compile(r'\b[A-Z]{5}\d{9}\b'),
        # Nova Scotia Health (MSI): 10 digits
        'Nova Scotia HC': re.compile(r'\b\d{10}\b'),
        # PEI DL: 1-6 digits
        'PEI DL': re.compile(r'\b\d{1,6}\b'),
        # PEI Health: 8 digits
        'PEI HC': re.compile(r'\b\d{8}\b'),
        # Newfoundland DL: letter + 9-10 digits
        'Newfoundland DL': re.compile(r'\b[A-Z]\d{9,10}\b'),
        # Newfoundland Health (MCP): 12 digits
        'Newfoundland HC': re.compile(r'\b\d{12}\b'),
        # Yukon DL: 6 digits
        'Yukon DL': re.compile(r'\b\d{6}\b'),
        # NWT DL: 6 digits
        'NWT DL': re.compile(r'\b\d{6}\b'),
        # Nunavut DL: 6 digits
        'Nunavut DL': re.compile(r'\b\d{6}\b'),
    },
    'North America - Mexico': {
        # CURP: 18 alphanumeric
        'Mexico CURP': re.compile(r'\b[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d\b'),
        # RFC: 12-13 alphanumeric
        'Mexico RFC': re.compile(r'\b[A-Z&]{3,4}\d{6}[A-Z0-9]{3}\b'),
        # Clave de Elector (INE voter key): 18 chars
        'Mexico Clave Elector': re.compile(r'\b[A-Z]{6}\d{8}[HM]\d{3}\b'),
        # INE CIC: 9 digits
        'Mexico INE CIC': re.compile(r'\b\d{9}\b'),
        # INE OCR: 13 digits
        'Mexico INE OCR': re.compile(r'\b\d{13}\b'),
        # Mexican Passport: letter + 8 digits
        'Mexico Passport': re.compile(r'\b[A-Z]\d{8}\b'),
        # NSS/IMSS (social security): 11 digits
        'Mexico NSS': re.compile(r'\b\d{11}\b'),
    },
}
