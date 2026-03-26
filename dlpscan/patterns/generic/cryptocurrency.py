import re

CRYPTOCURRENCY_PATTERNS = {
    'Cryptocurrency': {
        'Bitcoin Address (Legacy)': re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
        'Bitcoin Address (Bech32)': re.compile(r'\bbc1[a-zA-HJ-NP-Za-km-z0-9]{25,89}\b'),
        'Ethereum Address': re.compile(r'\b0x[0-9a-fA-F]{40}\b'),
        'Litecoin Address': re.compile(r'\b[LM][a-km-zA-HJ-NP-Z1-9]{26,33}\b'),
        'Bitcoin Cash Address': re.compile(r'\b(?:bitcoincash:)?[qp][a-z0-9]{41}\b'),
        'Monero Address': re.compile(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'),
        'Ripple Address': re.compile(r'\br[1-9A-HJ-NP-Za-km-z]{24,34}\b'),
    },
}
