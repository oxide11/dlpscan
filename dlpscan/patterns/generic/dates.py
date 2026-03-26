import re

DATES_PATTERNS = {
    'Dates': {
        'Date ISO': re.compile(r'\b\d{4}[-/](?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])\b'),
        'Date US': re.compile(r'\b(?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])[-/]\d{4}\b'),
        'Date EU': re.compile(r'\b(?:0[1-9]|[12]\d|3[01])[-/](?:0[1-9]|1[0-2])[-/]\d{4}\b'),
    },
}
