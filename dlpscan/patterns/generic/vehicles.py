import re


VEHICLES_PATTERNS = {
    'Vehicle Identification': {
        'VIN': re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'),
    },
}
