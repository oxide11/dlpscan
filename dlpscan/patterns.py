import re

# =============================================================================
# DLP Scan Patterns
#
# Organisation:
#   1. GENERIC PATTERNS    — Universal formats, not tied to a country or vendor
#   2. CUSTOM PATTERNS     — Vendor / service-specific secrets and tokens
#   3. GEOGRAPHIC REGIONS  — Country and region-specific identifiers
#
# The scanner iterates every category → sub-category and applies context
# keyword proximity checks from context_patterns.py.
# =============================================================================

PATTERNS = {

    # #########################################################################
    #  1.  G E N E R I C   P A T T E R N S
    # #########################################################################

    # =========================================================================
    # CREDIT CARD NUMBERS (Luhn-validated at scan time)
    # =========================================================================
    'Credit Card Numbers': {
        # Visa: starts with 4, 16 digits
        'Visa': re.compile(r'\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),

        # MasterCard: starts with 51-55 or 2221-2720, 16 digits
        'MasterCard': re.compile(
            r'\b(?:5[1-5]\d{2}|2(?:2[2-9]\d|2[3-9]\d|[3-6]\d{2}|7[01]\d|720))'
            r'[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'
        ),

        # American Express: starts with 34 or 37, 15 digits
        'Amex': re.compile(r'\b3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}\b'),

        # Discover: starts with 6011, 644-649, or 65
        'Discover': re.compile(r'\b6(?:011|5\d{2}|4[4-9]\d)[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),

        # JCB: starts with 3528-3589, 16 digits
        'JCB': re.compile(r'\b35(?:2[89]|[3-8]\d)[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),

        # Diners Club: starts with 300-305, 36, or 38, 14 digits
        'Diners Club': re.compile(r'\b3(?:0[0-5]|[68]\d)\d[\s-]?\d{6}[\s-]?\d{4}\b'),

        # UnionPay: starts with 62, 16-19 digits
        'UnionPay': re.compile(r'\b62\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}(?:[\s-]?\d{1,3})?\b'),
    },

    # =========================================================================
    # CONTACT INFORMATION
    # =========================================================================
    'Contact Information': {
        # Email addresses (simplified RFC 5322)
        'Email Address': re.compile(
            r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
        ),

        # International E.164: +[country][number] (7-15 digits)
        'E.164 Phone Number': re.compile(r'\+[1-9]\d{6,14}\b'),

        # IPv4 address
        'IPv4 Address': re.compile(
            r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
        ),

        # IPv6 address (common forms)
        'IPv6 Address': re.compile(
            r'\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b'
            r'|'
            r'\b::(?:[0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4}\b'
            r'|'
            r'\b(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}\b'
        ),

        # MAC address: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
        'MAC Address': re.compile(
            r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b'
        ),
    },

    # =========================================================================
    # BANKING & FINANCIAL (international formats)
    # =========================================================================
    'Banking and Financial': {
        # Generic IBAN
        'IBAN Generic': re.compile(
            r'\b[A-Z]{2}\d{2}[\s]?[\dA-Z]{4}(?:[\s]?[\dA-Z]{4}){2,7}(?:[\s]?[\dA-Z]{1,4})?\b'
        ),

        # SWIFT/BIC: 8 or 11 characters
        'SWIFT/BIC': re.compile(
            r'\b[A-Z]{4}[A-Z]{2}[A-Z2-9][A-NP-Z0-9](?:[A-Z\d]{3})?\b'
        ),
    },

    # =========================================================================
    # CRYPTOCURRENCY
    # =========================================================================
    'Cryptocurrency': {
        # Bitcoin Legacy (P2PKH/P2SH): starts with 1 or 3
        'Bitcoin Address (Legacy)': re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),

        # Bitcoin Bech32: starts with bc1
        'Bitcoin Address (Bech32)': re.compile(r'\bbc1[a-zA-HJ-NP-Za-km-z0-9]{25,89}\b'),

        # Ethereum: 0x + 40 hex characters
        'Ethereum Address': re.compile(r'\b0x[0-9a-fA-F]{40}\b'),

        # Litecoin: starts with L or M
        'Litecoin Address': re.compile(r'\b[LM][a-km-zA-HJ-NP-Z1-9]{26,33}\b'),

        # Bitcoin Cash: starts with bitcoincash: or q/p
        'Bitcoin Cash Address': re.compile(r'\b(?:bitcoincash:)?[qp][a-z0-9]{41}\b'),

        # Monero: starts with 4, 95 chars
        'Monero Address': re.compile(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'),

        # Ripple (XRP): starts with r, 25-35 chars
        'Ripple Address': re.compile(r'\br[1-9A-HJ-NP-Za-km-z]{24,34}\b'),
    },

    # =========================================================================
    # VEHICLE IDENTIFICATION
    # =========================================================================
    'Vehicle Identification': {
        # VIN: 17 alphanumeric characters (no I, O, Q)
        'VIN': re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'),
    },

    # =========================================================================
    # DATES (context-gated for DOB detection)
    # =========================================================================
    'Dates': {
        # ISO format: YYYY-MM-DD
        'Date ISO': re.compile(r'\b\d{4}[-/](?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])\b'),

        # US format: MM/DD/YYYY or MM-DD-YYYY
        'Date US': re.compile(r'\b(?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])[-/]\d{4}\b'),

        # EU format: DD/MM/YYYY or DD-MM-YYYY
        'Date EU': re.compile(r'\b(?:0[1-9]|[12]\d|3[01])[-/](?:0[1-9]|1[0-2])[-/]\d{4}\b'),
    },

    # =========================================================================
    # URLS WITH CREDENTIALS
    # =========================================================================
    'URLs with Credentials': {
        # URL with embedded username:password
        'URL with Password': re.compile(r'https?://[^:\s]+:[^@\s]+@[^\s]+'),

        # URL with token/key in query string
        'URL with Token': re.compile(
            r'https?://[^\s]*[?&](?:token|key|api_key|apikey|access_token|secret|password|passwd|pwd)'
            r'=[^\s&]+',
            re.IGNORECASE,
        ),
    },

    # =========================================================================
    # GENERIC SECRETS (format-based, not vendor-specific)
    # =========================================================================
    'Generic Secrets': {
        # Bearer Token in Authorization context
        'Bearer Token': re.compile(r'[Bb]earer\s+[A-Za-z0-9\-._~+/]+=*'),

        # JSON Web Token (JWT): three base64url segments
        'JWT Token': re.compile(
            r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
        ),

        # RSA/SSH/EC Private Key header
        'Private Key': re.compile(
            r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'
        ),

        # Generic API key assignment: api_key=..., api-secret: ..., etc.
        'Generic API Key': re.compile(
            r'(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)'
            r'\s*[=:]\s*["\']?[A-Za-z0-9\-._~+/]{16,}["\']?',
            re.IGNORECASE,
        ),

        # Generic secret/password assignment in config
        'Generic Secret Assignment': re.compile(
            r'(?:password|passwd|pwd|secret|token|credential)'
            r'\s*[=:]\s*["\']?[^\s"\']{8,}["\']?',
            re.IGNORECASE,
        ),

        # Database connection strings with embedded credentials
        'Database Connection String': re.compile(
            r'(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis|mssql)'
            r'://[^:\s]+:[^@\s]+@[^\s]+',
            re.IGNORECASE,
        ),
    },

    # #########################################################################
    #  2.  C U S T O M   P A T T E R N S  (vendor / service-specific)
    # #########################################################################

    # =========================================================================
    # CLOUD PROVIDERS
    # =========================================================================
    'Cloud Provider Secrets': {
        # AWS Access Key ID: starts with AKIA, 20 chars
        'AWS Access Key': re.compile(r'\bAKIA[0-9A-Z]{16}\b'),

        # AWS Secret Access Key: 40 base64-ish characters
        'AWS Secret Key': re.compile(
            r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])'
        ),

        # Google API Key: AIza followed by 35 characters
        'Google API Key': re.compile(r'\bAIza[0-9A-Za-z_\-]{35}\b'),
    },

    # =========================================================================
    # CODE PLATFORMS & DEVTOOLS
    # =========================================================================
    'Code Platform Secrets': {
        # GitHub Personal Access Token (classic): ghp_ prefix
        'GitHub Token (Classic)': re.compile(r'\bghp_[A-Za-z0-9]{36}\b'),

        # GitHub Fine-Grained Token: github_pat_ prefix
        'GitHub Token (Fine-Grained)': re.compile(r'\bgithub_pat_[A-Za-z0-9_]{22,82}\b'),

        # GitHub OAuth Token: gho_ prefix
        'GitHub OAuth Token': re.compile(r'\bgho_[A-Za-z0-9]{36}\b'),

        # NPM Token
        'NPM Token': re.compile(r'\bnpm_[A-Za-z0-9]{36}\b'),

        # PyPI Token
        'PyPI Token': re.compile(r'\bpypi-[A-Za-z0-9_\-]{16,}\b'),
    },

    # =========================================================================
    # PAYMENT SERVICES
    # =========================================================================
    'Payment Service Secrets': {
        # Stripe Secret Key: sk_live_ or sk_test_
        'Stripe Secret Key': re.compile(r'\bsk_(?:live|test)_[A-Za-z0-9]{24,}\b'),

        # Stripe Publishable Key: pk_live_ or pk_test_
        'Stripe Publishable Key': re.compile(r'\bpk_(?:live|test)_[A-Za-z0-9]{24,}\b'),
    },

    # =========================================================================
    # MESSAGING & COMMUNICATION SERVICES
    # =========================================================================
    'Messaging Service Secrets': {
        # Slack Bot Token: xoxb-
        'Slack Bot Token': re.compile(r'\bxoxb-[0-9A-Za-z\-]+\b'),

        # Slack User Token: xoxp-
        'Slack User Token': re.compile(r'\bxoxp-[0-9A-Za-z\-]+\b'),

        # Slack Webhook URL
        'Slack Webhook': re.compile(
            r'https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+'
        ),

        # SendGrid API Key: SG. prefix
        'SendGrid API Key': re.compile(r'\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b'),

        # Twilio API Key: SK + 32 hex
        'Twilio API Key': re.compile(r'\bSK[0-9a-f]{32}\b'),

        # Mailgun API Key
        'Mailgun API Key': re.compile(r'\bkey-[0-9a-zA-Z]{32}\b'),
    },

    # #########################################################################
    #  3.  G E O G R A P H I C   R E G I O N S
    # #########################################################################

    # =========================================================================
    # NORTH AMERICA — United States
    # =========================================================================
    'North America - United States': {
        # Social Security Number: XXX-XX-XXXX
        'USA SSN': re.compile(r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b'),

        # Individual Taxpayer Identification Number: 9XX-XX-XXXX
        'USA ITIN': re.compile(r'\b9\d{2}[-\s]?\d{2}[-\s]?\d{4}\b'),

        # Employer Identification Number: XX-XXXXXXX
        'USA EIN': re.compile(r'\b\d{2}-\d{7}\b'),

        # Passport: 9 digits
        'USA Passport': re.compile(r'\b\d{9}\b'),

        # Routing Number: 9 digits
        'USA Routing Number': re.compile(r'\b\d{9}\b'),

        # DEA Number: 2 letters + 7 digits
        'US DEA Number': re.compile(r'\b[A-Z]{2}\d{7}\b'),

        # NPI (National Provider Identifier): 10 digits, starts with 1 or 2
        'US NPI': re.compile(r'\b[12]\d{9}\b'),

        # Medicare Beneficiary Identifier (MBI)
        'US MBI': re.compile(
            r'\b[1-9][A-Z](?:[0-9]|[A-Z])[0-9]-?[A-Z](?:[0-9]|[A-Z])[0-9]-?[A-Z]{2}[0-9]{2}\b'
        ),

        # US/Canada phone: (555) 123-4567, 555-123-4567, +1-555-123-4567
        'US Phone Number': re.compile(
            r'(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)'
        ),

        # California driver's license: letter + 7 digits
        'California DL': re.compile(r'\b[A-Z]\d{7}\b'),

        # New York driver's license: letter + 7-18 digits
        'New York DL': re.compile(r'\b[A-Z]\d{7,18}\b'),

        # Generic US driver's license: 1-2 letters + 4-9 digits
        'Generic DL': re.compile(r'\b[A-Z]{1,2}\d{4,9}\b'),
    },

    # =========================================================================
    # NORTH AMERICA — Canada
    # =========================================================================
    'North America - Canada': {
        # Social Insurance Number: XXX-XXX-XXX
        'Canada SIN': re.compile(r'\b\d{3}[-\s]?\d{3}[-\s]?\d{3}\b'),

        # Business Number: 9 digits + 2 letters + 4 digits
        'Canada BN': re.compile(r'\b\d{9}[A-Z]{2}\d{4}\b'),

        # Passport: 2 letters + 6 digits
        'Canada Passport': re.compile(r'\b[A-Z]{2}\d{6}\b'),

        # Bank transit/institution code: XXXXX-XXX
        'Canada Bank Code': re.compile(r'\b\d{5}-\d{3}\b'),

        # Ontario driver's license: X9999-99999-99999
        'Ontario DL': re.compile(r'\b[A-Z]\d{4}-\d{5}-\d{5}\b'),

        # Ontario health card (OHIP): 10 digits
        'Ontario HC': re.compile(r'\b\d{10}\b'),

        # British Columbia driver's license: 7 digits
        'British Columbia DL': re.compile(r'\b\d{7}\b'),

        # Alberta driver's license: letter + 4-9 digits
        'Alberta DL': re.compile(r'\b[A-Z]\d{4,9}\b'),

        # Alberta health card: X9999-99999
        'Alberta HC': re.compile(r'\b[A-Z]\d{4}-\d{5}\b'),

        # Quebec driver's license: 2 letters + 4-9 digits
        'Quebec DL': re.compile(r'\b[A-Z]{2}\d{4,9}\b'),

        # Quebec health card (RAMQ): 12 digits
        'Quebec HC': re.compile(r'\b\d{12}\b'),

        # Nova Scotia driver's license: 2 letters + 4-9 digits
        'Nova Scotia DL': re.compile(r'\b[A-Z]{2}\d{4,9}\b'),

        # Nova Scotia health card: 10 digits
        'Nova Scotia HC': re.compile(r'\b\d{10}\b'),
    },

    # =========================================================================
    # NORTH AMERICA — Mexico
    # =========================================================================
    'North America - Mexico': {
        # CURP: 18 alphanumeric characters
        'Mexico CURP': re.compile(
            r'\b[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d\b'
        ),

        # RFC (tax ID): 12 or 13 alphanumeric characters
        'Mexico RFC': re.compile(r'\b[A-Z&]{3,4}\d{6}[A-Z0-9]{3}\b'),
    },

    # =========================================================================
    # EUROPE — United Kingdom
    # =========================================================================
    'Europe - United Kingdom': {
        # National Insurance Number: XX999999X (HMRC-compliant letter restrictions)
        'UK NIN': re.compile(r'\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b'),

        # Unique Taxpayer Reference: 10 digits
        'UK UTR': re.compile(r'\b\d{10}\b'),

        # Passport: 9 digits
        'UK Passport': re.compile(r'\b\d{9}\b'),

        # Sort code: XX-XX-XX
        'UK Sort Code': re.compile(r'\b\d{2}-\d{2}-\d{2}\b'),

        # NHS Number: 10 digits
        'British NHS': re.compile(r'\b\d{10}\b'),

        # UK phone: +44 7911 123456, 07911 123456
        'UK Phone Number': re.compile(
            r'(?:\+44[-.\s]?|0)(?:\d[-.\s]?){9,10}(?!\d)'
        ),
    },

    # =========================================================================
    # EUROPE — Germany
    # =========================================================================
    'Europe - Germany': {
        # National ID: 9 alphanumeric (new format, excludes I/O/S)
        'Germany ID': re.compile(r'\b[CFGHJKLMNPRTVWXYZ0-9]{9}\b'),

        # Passport: C + 8 alphanumeric
        'Germany Passport': re.compile(r'\bC[A-Z0-9]{8}\b'),
    },

    # =========================================================================
    # EUROPE — France
    # =========================================================================
    'Europe - France': {
        # INSEE/NIR (Social Security): 13 digits + 2-digit key
        'France NIR': re.compile(r'\b[12]\d{2}(?:0[1-9]|1[0-2])\d{2}\d{3}\d{3}\d{2}\b'),

        # Passport: 2 digits + 2 letters + 5 digits
        'France Passport': re.compile(r'\b\d{2}[A-Z]{2}\d{5}\b'),
    },

    # =========================================================================
    # EUROPE — Italy
    # =========================================================================
    'Europe - Italy': {
        # Codice Fiscale: 6 letters, 2 digits, 1 letter, 2 digits, 1 letter, 3 digits, 1 letter
        'Italy Codice Fiscale': re.compile(
            r'\b[A-Z]{6}\d{2}[A-EHLMPR-T]\d{2}[A-Z]\d{3}[A-Z]\b'
        ),
    },

    # =========================================================================
    # EUROPE — Netherlands
    # =========================================================================
    'Europe - Netherlands': {
        # BSN (Burgerservicenummer): 8 or 9 digits
        'Netherlands BSN': re.compile(r'\b\d{8,9}\b'),
    },

    # =========================================================================
    # EUROPE — Spain
    # =========================================================================
    'Europe - Spain': {
        # DNI/NIE: optional X/Y/Z prefix, 7-8 digits, trailing letter
        'Spain DNI/NIE': re.compile(r'\b[XYZ]?\d{7,8}[A-Z]\b'),
    },

    # =========================================================================
    # EUROPE — Poland
    # =========================================================================
    'Europe - Poland': {
        # PESEL: 11 digits
        'Poland PESEL': re.compile(r'\b\d{11}\b'),
    },

    # =========================================================================
    # EUROPE — Sweden
    # =========================================================================
    'Europe - Sweden': {
        # Personal Identity Number: YYMMDD-XXXX
        'Sweden PIN': re.compile(r'\b\d{6}[-+]?\d{4}\b'),
    },

    # =========================================================================
    # EUROPE — Portugal
    # =========================================================================
    'Europe - Portugal': {
        # NIF: 9 digits
        'Portugal NIF': re.compile(r'\b\d{9}\b'),
    },

    # =========================================================================
    # EUROPE — Switzerland
    # =========================================================================
    'Europe - Switzerland': {
        # AHV/AVS Number: 756.XXXX.XXXX.XX
        'Switzerland AHV': re.compile(r'\b756\.\d{4}\.\d{4}\.\d{2}\b'),
    },

    # =========================================================================
    # EUROPE — Turkey
    # =========================================================================
    'Europe - Turkey': {
        # TC Kimlik: 11 digits starting with non-zero
        'Turkey TC Kimlik': re.compile(r'\b[1-9]\d{10}\b'),
    },

    # =========================================================================
    # EUROPE — EU (multi-country)
    # =========================================================================
    'Europe - EU': {
        # EU Emergency Travel Document: 3 letters + 6 digits
        'EU ETD': re.compile(r'\b[A-Z]{3}\d{6}\b'),
    },

    # =========================================================================
    # ASIA-PACIFIC — India
    # =========================================================================
    'Asia-Pacific - India': {
        # PAN: XXXXX9999X (5 letters, 4 digits, 1 letter)
        'India PAN': re.compile(r'\b[A-Z]{5}\d{4}[A-Z]\b'),

        # Aadhaar Number: 12 digits with optional spaces/hyphens
        'India Aadhaar': re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),

        # Passport: letter + 7 digits
        'India Passport': re.compile(r'\b[A-Z]\d{7}\b'),

        # Driver's license: 2 letters + 13 digits
        'India DL': re.compile(r'\b[A-Z]{2}\d{13}\b'),
    },

    # =========================================================================
    # ASIA-PACIFIC — Singapore
    # =========================================================================
    'Asia-Pacific - Singapore': {
        # NRIC: [STFGM]XXXXXXX[A-Z]
        'Singapore NIRC': re.compile(r'\b[STFGM]\d{7}[A-Z]\b'),
    },

    # =========================================================================
    # ASIA-PACIFIC — Australia
    # =========================================================================
    'Asia-Pacific - Australia': {
        # Tax File Number: 8 or 9 digits
        'Australia TFN': re.compile(r'\b\d{8,9}\b'),

        # Medicare: 11 digits
        'Australia Medicare': re.compile(r'\b\d{11}\b'),

        # Passport: letter + 7 digits
        'Australia Passport': re.compile(r'\b[A-Z]\d{7}\b'),
    },

    # =========================================================================
    # ASIA-PACIFIC — Japan
    # =========================================================================
    'Asia-Pacific - Japan': {
        # My Number (Individual Number): 12 digits
        'Japan My Number': re.compile(r'\b\d{12}\b'),

        # Passport: M/S/R/C + 7 digits
        'Japan Passport': re.compile(r'\b[MSRC]\d{7}\b'),
    },

    # =========================================================================
    # ASIA-PACIFIC — South Korea
    # =========================================================================
    'Asia-Pacific - South Korea': {
        # Resident Registration Number: XXXXXX-XXXXXXX
        'South Korea RRN': re.compile(r'\b\d{6}[-\s]?\d{7}\b'),
    },

    # =========================================================================
    # ASIA-PACIFIC — China
    # =========================================================================
    'Asia-Pacific - China': {
        # Resident Identity Card: 18 digits (last may be X)
        'China Resident ID': re.compile(r'\b\d{17}[\dX]\b'),

        # Passport: E or G + 8 digits
        'China Passport': re.compile(r'\b[EG]\d{8}\b'),
    },

    # =========================================================================
    # SOUTH AMERICA — Brazil
    # =========================================================================
    'South America - Brazil': {
        # CPF: XXX.XXX.XXX-XX or XXXXXXXXXXX
        'Brazil CPF': re.compile(r'\b\d{3}\.\d{3}\.\d{3}-\d{2}\b|\b\d{11}\b'),

        # Passport: 2 letters + 6 digits
        'Brazil Passport': re.compile(r'\b[A-Z]{2}\d{6}\b'),
    },

    # =========================================================================
    # AFRICA — South Africa
    # =========================================================================
    'Africa - South Africa': {
        # National ID: 13 digits
        'South Africa ID': re.compile(r'\b\d{13}\b'),
    },
}
