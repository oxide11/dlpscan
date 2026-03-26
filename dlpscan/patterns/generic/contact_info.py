import re

CONTACT_INFO_PATTERNS = {
    'Contact Information': {
        'Email Address': re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'),
        'E.164 Phone Number': re.compile(r'\+[1-9]\d{6,14}\b'),
        'IPv4 Address': re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'),
        'IPv6 Address': re.compile(r'\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b|\b::(?:[0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4}\b|\b(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}\b'),
        'MAC Address': re.compile(r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b'),
    },
}
