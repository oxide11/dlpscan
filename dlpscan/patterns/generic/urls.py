import re


URLS_PATTERNS = {
    'URLs with Credentials': {
        'URL with Password': re.compile(r'https?://[^:\s]+:[^@\s]+@[^\s]+'),
        'URL with Token': re.compile(r'https?://[^\s]*[?&](?:token|key|api_key|apikey|access_token|secret|password|passwd|pwd)=[^\s&]+', re.IGNORECASE),
    },
}
