import re

CLOUD_PROVIDERS_PATTERNS = {
    'Cloud Provider Secrets': {
        'AWS Access Key': re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
        'AWS Secret Key': re.compile(r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])'),
        'Google API Key': re.compile(r'\bAIza[0-9A-Za-z_\-]{35}\b'),
    },
}
