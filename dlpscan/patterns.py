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
        'US MBI': re.compile(r'\b[1-9][A-CEGHJ-NP-RT-Y](?:[0-9]|[A-CEGHJ-NP-RT-Y])[0-9]-?[A-CEGHJ-NP-RT-Y](?:[0-9]|[A-CEGHJ-NP-RT-Y])[0-9]-?[A-CEGHJ-NP-RT-Y]{2}[0-9]{2}\b'),
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

    # =========================================================================
    # NORTH AMERICA — US Generic DL (fallback catch-all)
    # =========================================================================
    'North America - US Generic DL': {
        # Generic US driver's license: catches common L + digits formats
        'Generic US DL': re.compile(r'\b[A-Z]{1,2}\d{4,14}\b'),
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
        # Permanent Resident Card: 2 letters + 7-10 digits
        'Canada PR Card': re.compile(r'\b[A-Z]{2}\d{7,10}\b'),
        # NEXUS Card: 9 digits
        'Canada NEXUS': re.compile(r'\b\d{9}\b'),
        # Ontario DL: letter + 4 digits + dash + 5 digits + dash + 5 digits
        'Ontario DL': re.compile(r'\b[A-Z]\d{4}-\d{5}-\d{5}\b'),
        # Ontario Health (OHIP): 10 digits + 2-letter version code
        'Ontario HC': re.compile(r'\b\d{10}(?:\s?[A-Z]{2})?\b'),
        # Quebec DL: letter + 4 digits + dash + 6 digits + dash + 2 digits
        'Quebec DL': re.compile(r'\b[A-Z]\d{4}-\d{6}-\d{2}\b'),
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

    # =========================================================================
    # NORTH AMERICA — Mexico
    # =========================================================================
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
        # PAN: ABCDE1234F — 5 upper letters, 4 digits, 1 upper letter.
        # 4th char encodes holder type (P=individual, C=company, etc.).
        # Example (fake): BNZAA2318J
        'India PAN': re.compile(r'\b[A-Z]{5}\d{4}[A-Z]\b'),

        # Aadhaar: 12 digits, first digit 2-9 (0/1 reserved), Verhoeff check digit.
        # Commonly formatted as XXXX XXXX XXXX or XXXX-XXXX-XXXX.
        # Example (fake): 2345 6789 0123
        'India Aadhaar': re.compile(r'\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b'),

        # Passport: 1 uppercase letter + 7 digits (2nd digit 1-9, last digit 1-9).
        # Common series letters: J, K, L, M, N, P, R, S, T, U.
        # Example (fake): K1234567
        'India Passport': re.compile(r'\b[A-Z][1-9]\d{5}[1-9]\b'),

        # Driving Licence: SS-RR-YYYY-NNNNNNN or SSRR YYYYNNNNNNN.
        # SS=state code (2 letters), RR=RTO code (2 digits),
        # YYYY=year of issue, NNNNNNN=7-digit serial.
        # Example (fake): HR-06-1985-0034761
        'India DL': re.compile(
            r'\b[A-Z]{2}[-\s]?\d{2}[-\s]?(?:19|20)\d{2}[-\s]?\d{7}\b'
        ),

        # Voter ID (EPIC): 3 uppercase letters + 7 digits.
        # Issued by Election Commission of India.
        # Example (fake): ABC1234567
        'India Voter ID': re.compile(r'\b[A-Z]{3}\d{7}\b'),

        # Ration Card: 10-digit standardised format (One Nation One Ration Card).
        # First 2 digits = state code, remaining 8 = running number.
        # Example (fake): 2712345678
        'India Ration Card': re.compile(r'\b\d{2}[\s-]?\d{8}\b'),
    },

    # =========================================================================
    # ASIA-PACIFIC — China (incl. Hong Kong, Macau, Taiwan)
    # =========================================================================
    'Asia-Pacific - China': {
        # Resident Identity Card (居民身份证): 18 chars.
        # Format: RRRRRR-YYYYMMDD-SSS-C where C may be 0-9 or X.
        # 6-digit region code, 8-digit DOB, 3-digit sequence, 1 check digit.
        # Check digit via ISO 7064 MOD 11-2.
        # Example (fake): 110101199003074518
        'China Resident ID': re.compile(
            r'\b\d{6}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])'
            r'(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b'
        ),

        # China Passport: E/G/D prefix + 8 digits, or EA-EZ series (letter + 7 digits).
        # E = e-passport (since 2012), G = older ordinary, D = diplomatic.
        # Example (fake): E12345678, G23456789
        'China Passport': re.compile(r'\b[EGD][A-Z]?\d{7,8}\b'),

        # Hong Kong Identity Card (HKID): 1-2 letters + 6 digits + (check digit).
        # Check digit is 0-9 or A, usually in parentheses.
        # Example (fake): A123456(7), AB987654(A)
        'Hong Kong ID': re.compile(
            r'\b[A-Z]{1,2}\d{6}\s?\(?[0-9A]\)?\b'
        ),

        # Macau BIR (Resident Identity Card): 7 digits + check digit in parens.
        # First digit: 1 (post-1992), 5 (Portuguese BI), 7 (PSP card).
        # Example (fake): 1234567(8)
        'Macau ID': re.compile(
            r'\b[1578]\d{6}\s?\(?[0-9]\)?\b'
        ),

        # Taiwan National ID: 1 letter (region) + 9 digits.
        # 2nd digit: 1=male, 2=female (citizen); 8=male, 9=female (new UI).
        # Check digit via weighted mod-10 algorithm.
        # Example (fake): A123456789
        'Taiwan National ID': re.compile(r'\b[A-Z][12489]\d{8}\b'),
    },

    # =========================================================================
    # ASIA-PACIFIC — Japan
    # =========================================================================
    'Asia-Pacific - Japan': {
        # My Number (個人番号): 12 digits, last digit is check digit.
        # Check: mod-11 with weights (2,3,4,5,6,7,2,3,4,5,6) from right.
        # Example (fake): 123456789012
        'Japan My Number': re.compile(r'\b\d{12}\b'),

        # Passport: 2 uppercase letters + 7 digits.
        # Series: TZ, MZ, TK, etc.
        # Example (fake): TZ1234567
        'Japan Passport': re.compile(r'\b[A-Z]{2}\d{7}\b'),

        # Driving Licence: 12 consecutive digits.
        # Digits 1-2: prefecture code, 3-4: year of first qualification,
        # 5-10: serial, 11: check digit, 12: reissue count.
        # Example (fake): 432019654321
        'Japan DL': re.compile(r'\b\d{12}\b'),

        # Juminhyo Code (Resident Registration Network code): 11 digits.
        # Used in Basic Resident Registry.
        # Example (fake): 12345678901
        'Japan Juminhyo Code': re.compile(r'\b\d{11}\b'),

        # Health Insurance Insurer Number (保険者番号): 6 or 8 digits.
        # 8-digit: 2 legal-class + 2 prefecture + 3 insurer + 1 check.
        # Example (fake): 06130012
        'Japan Health Insurance': re.compile(r'\b\d{8}\b'),

        # Residence Card (Zairyu Card): 2 letters + 8 digits + 2 letters.
        # Example (fake): AB12345678CD
        'Japan Residence Card': re.compile(r'\b[A-Z]{2}\d{8}[A-Z]{2}\b'),
    },

    # =========================================================================
    # ASIA-PACIFIC — South Korea
    # =========================================================================
    'Asia-Pacific - South Korea': {
        # Resident Registration Number (RRN): YYMMDD-SBBBBAC.
        # First 6 = DOB, 7th = gender/century (1-4,9,0), then area/serial/check.
        # Check digit via weighted mod formula.
        # Example (fake): 850102-1234567
        'South Korea RRN': re.compile(
            r'\b\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])[-\s]?[1-8]\d{6}\b'
        ),

        # Passport: M (multi-entry) or S (single-entry) or R/O/D + 8 digits.
        # Example (fake): M12345678
        'South Korea Passport': re.compile(r'\b[MSROD]\d{8}\b'),

        # Driving Licence: AA-BB-CCCCCC-DE (12 digits with hyphens).
        # AA=region, BB=year, CCCCCC=serial, D=check, E=reissue count.
        # Example (fake): 11-22-333333-44
        'South Korea DL': re.compile(
            r'\b\d{2}[-\s]?\d{2}[-\s]?\d{6}[-\s]?\d{2}\b'
        ),
    },

    # =========================================================================
    # ASIA-PACIFIC — Singapore
    # =========================================================================
    'Asia-Pacific - Singapore': {
        # NRIC: [S|T]NNNNNNN[A-Z] (citizens/PRs).
        # S = born before 2000, T = born 2000+. Check letter via mod-11.
        # Example (fake): S1234567D
        'Singapore NRIC': re.compile(r'\b[ST]\d{7}[A-Z]\b'),

        # FIN (Foreign Identification Number): [F|G|M]NNNNNNN[A-Z].
        # F = pre-2000, G = 2000-2021, M = 2022+.
        # Example (fake): G1234567X
        'Singapore FIN': re.compile(r'\b[FGM]\d{7}[A-Z]\b'),

        # Passport: 1 letter (typically E for biometric) + 7 digits + 1 letter.
        # Example (fake): E1234567A
        'Singapore Passport': re.compile(r'\b[A-Z]\d{7}[A-Z]\b'),

        # Driving Licence: same format as NRIC/FIN (NRIC is used as DL number).
        # Example (fake): S1234567D
        'Singapore DL': re.compile(r'\b[STFGM]\d{7}[A-Z]\b'),
    },

    # =========================================================================
    # ASIA-PACIFIC — Australia
    # =========================================================================
    'Asia-Pacific - Australia': {
        # Tax File Number (TFN): 8 or 9 digits.
        # 9-digit: 8-digit identifier + 1 check digit.
        # Check: weights [1,4,3,7,5,8,6,9,10], sum mod 11 == 0.
        # Example (fake): 123456782
        'Australia TFN': re.compile(r'\b\d{3}[\s]?\d{3}[\s]?\d{2,3}\b'),

        # Medicare: 10-11 digits, first digit 2-6.
        # Digits 1-8: card ID, 9: check digit (weighted mod-10), 10: issue, 11: IRN.
        # Example (fake): 2123 45670 1 1
        'Australia Medicare': re.compile(r'\b[2-6]\d{3}[\s]?\d{5}[\s]?\d[\s]?\d?\b'),

        # Passport: 1-2 letters + 7 digits.
        # Example (fake): PA1234567
        'Australia Passport': re.compile(r'\b[A-Z]{1,2}\d{7}\b'),

        # Driving Licence — formats vary by state/territory
        # NSW: 8 digits.                   Example: 12345678
        'Australia DL NSW': re.compile(r'\b\d{8}\b'),
        # VIC: 8-10 digits.                Example: 123456789
        'Australia DL VIC': re.compile(r'\b\d{8,10}\b'),
        # QLD: 8-9 digits.                 Example: 12345678
        'Australia DL QLD': re.compile(r'\b\d{8,9}\b'),
        # WA: 7 digits.                    Example: 1234567
        'Australia DL WA': re.compile(r'\b\d{7}\b'),
        # SA: 1 letter + 5-6 digits or 6 digits.  Example: T52682
        'Australia DL SA': re.compile(r'\b[A-Z]?\d{5,6}\b'),
        # TAS: 1 letter + 5-6 digits.      Example: A12345
        'Australia DL TAS': re.compile(r'\b[A-Z]\d{5,6}\b'),
        # ACT: 6-10 digits.                Example: 12345678
        'Australia DL ACT': re.compile(r'\b\d{6,10}\b'),
        # NT: 5-7 digits.                  Example: 123456
        'Australia DL NT': re.compile(r'\b\d{5,7}\b'),
    },

    # =========================================================================
    # ASIA-PACIFIC — New Zealand
    # =========================================================================
    'Asia-Pacific - New Zealand': {
        # IRD Number: 8 or 9 digits (8-digit numbers get a leading zero).
        # Check digit via mod-11 with weights [3,2,7,6,5,4,3,2].
        # Example (fake): 12345678, 012345678
        'New Zealand IRD': re.compile(r'\b\d{8,9}\b'),

        # Passport: 2 letters + 6 digits (e.g., RA series since 2021).
        # Example (fake): LA123456
        'New Zealand Passport': re.compile(r'\b[A-Z]{2}\d{6}\b'),

        # NHI (National Health Index): 3 letters (excl. I, O) + 4 digits.
        # Check digit via weighted mod-11 on letter ordinals.
        # Example (fake): ZAC5361
        'New Zealand NHI': re.compile(r'\b[A-HJ-NP-Z]{3}\d{4}\b'),

        # Driving Licence: 2 letters + 6 digits.
        # Example (fake): BQ739482
        'New Zealand DL': re.compile(r'\b[A-Z]{2}\d{6}\b'),
    },

    # =========================================================================
    # ASIA-PACIFIC — Philippines
    # =========================================================================
    'Asia-Pacific - Philippines': {
        # PhilSys National ID (PSN): 12-digit randomly generated number.
        # Example (fake): 1234-5678-9012
        'Philippines PhilSys': re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),

        # TIN: 9 digits (+ optional 3-digit branch code = 12 digits).
        # Format: ###-###-### or ###-###-###-###.
        # 1st digit: 0=corp, 1-9=individual.
        # Example (fake): 123-456-789, 123-456-789-001
        'Philippines TIN': re.compile(
            r'\b\d{3}-?\d{3}-?\d{3}(?:-?\d{3})?\b'
        ),

        # SSS: 10 digits, format ##-#######-#.
        # Example (fake): 34-1234567-8
        'Philippines SSS': re.compile(r'\b\d{2}-?\d{7}-?\d\b'),

        # PhilHealth: 12 digits, format ##-#########-# (2-9-1).
        # Last digit is mod-11 check digit.
        # Example (fake): 12-123456789-0
        'Philippines PhilHealth': re.compile(r'\b\d{2}-?\d{9}-?\d\b'),

        # Passport: current e-passport (post-Aug 2016): L#######L.
        # Older: LL###### or LL#######.
        # Example (fake): P1234567A
        'Philippines Passport': re.compile(
            r'\b[A-Z]{1,2}\d{6,7}[A-Z]?\b'
        ),

        # UMID (CRN): 12 digits, format ####-#######-#.
        # Example (fake): 0012-3456789-0
        'Philippines UMID': re.compile(r'\b\d{4}-?\d{7}-?\d\b'),
    },

    # =========================================================================
    # ASIA-PACIFIC — Thailand
    # =========================================================================
    'Asia-Pacific - Thailand': {
        # National ID: 13 digits, format X-XXXX-XXXXX-XX-X.
        # 1st digit: citizen category. Last digit: check digit.
        # Example (fake): 1-1234-56789-01-2
        'Thailand National ID': re.compile(
            r'\b\d[-\s]?\d{4}[-\s]?\d{5}[-\s]?\d{2}[-\s]?\d\b'
        ),

        # Passport: 2 letters + 7 digits.
        # Example (fake): AA1234567
        'Thailand Passport': re.compile(r'\b[A-Z]{2}\d{7}\b'),

        # Driving Licence: for Thai citizens, same as 13-digit National ID.
        # Example (fake): 1123456789012
        'Thailand DL': re.compile(r'\b\d{13}\b'),

        # Tax ID: 13 digits (same as National ID for individuals).
        # Example (fake): 1234567890123
        'Thailand Tax ID': re.compile(r'\b\d{13}\b'),
    },

    # =========================================================================
    # ASIA-PACIFIC — Malaysia
    # =========================================================================
    'Asia-Pacific - Malaysia': {
        # MyKad (IC Number): YYMMDD-PB-####, 12 digits with or without hyphens.
        # PB = place-of-birth code (2 digits), last digit odd=male/even=female.
        # Example (fake): 850916-14-5023
        'Malaysia MyKad': re.compile(
            r'\b\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])[-\s]?'
            r'\d{2}[-\s]?\d{4}\b'
        ),

        # Passport: 1 letter (A=Peninsula, H=Sabah, K=Sarawak) + 8 digits.
        # Example (fake): A12345678
        'Malaysia Passport': re.compile(r'\b[A-Z]\d{8}\b'),
    },

    # =========================================================================
    # ASIA-PACIFIC — Indonesia
    # =========================================================================
    'Asia-Pacific - Indonesia': {
        # NIK (Nomor Induk Kependudukan): 16 digits.
        # Format: 6 region + 6 DOB (females +40 on day) + 4 serial.
        # Example (fake): 3204012345670001
        'Indonesia NIK': re.compile(r'\b\d{16}\b'),

        # NPWP (Tax): old 15-digit format XX.XXX.XXX.X-XXX.XXX.
        # Example (fake): 01.234.567.8-123.456
        'Indonesia NPWP': re.compile(
            r'\b\d{2}\.?\d{3}\.?\d{3}\.?\d[-.]?\d{3}\.?\d{3}\b'
        ),

        # Passport: 1-2 letters + 6-7 digits (9 chars total).
        # Example (fake): A1234567
        'Indonesia Passport': re.compile(r'\b[A-Z]{1,2}\d{6,7}\b'),
    },

    # =========================================================================
    # ASIA-PACIFIC — Vietnam
    # =========================================================================
    'Asia-Pacific - Vietnam': {
        # CCCD (Citizen Identification): 12 digits.
        # Format: 3 province + 1 gender/century + 2 birth year + 6 random.
        # Example (fake): 001099012345
        'Vietnam CCCD': re.compile(r'\b\d{12}\b'),

        # Passport: 1 letter (B/C for ordinary) + 8 digits.
        # Example (fake): B12345678
        'Vietnam Passport': re.compile(r'\b[A-Z]\d{8}\b'),

        # Tax Code (MST): 10 digits, optionally + hyphen + 3-digit branch.
        # Example (fake): 0123456789, 0123456789-001
        'Vietnam Tax Code': re.compile(r'\b\d{10}(?:-\d{3})?\b'),
    },

    # =========================================================================
    # ASIA-PACIFIC — Pakistan
    # =========================================================================
    'Asia-Pacific - Pakistan': {
        # CNIC: 13 digits in 5-7-1 format (XXXXX-XXXXXXX-X).
        # 1st digit: province (1=KP,3=Punjab,4=Sindh,5=Baloch,6=ISB,7=GB).
        # Last digit: odd=male, even=female.
        # Example (fake): 61101-1234567-1
        'Pakistan CNIC': re.compile(
            r'\b\d{5}[-\s]?\d{7}[-\s]?\d\b'
        ),

        # NICOP: same 13-digit format as CNIC (for overseas Pakistanis).
        # Example (fake): 42201-7654321-2
        'Pakistan NICOP': re.compile(
            r'\b\d{5}[-\s]?\d{7}[-\s]?\d\b'
        ),

        # Passport: 2 letters + 7 digits.
        # Example (fake): AB1234567
        'Pakistan Passport': re.compile(r'\b[A-Z]{2}\d{7}\b'),
    },

    # =========================================================================
    # ASIA-PACIFIC — Bangladesh
    # =========================================================================
    'Asia-Pacific - Bangladesh': {
        # NID: 10 digits (smart card) or 17 digits (old with birth year prefix).
        # 10-digit: 9 random + 1 check. 17-digit: birth year + codes + serial.
        # Example (fake): 1234567890, 19751234567890123
        'Bangladesh NID': re.compile(r'\b(?:\d{10}|\d{17})\b'),

        # Passport: 2 letters + 7 digits (ICAO MRP format).
        # Example (fake): AB1234567
        'Bangladesh Passport': re.compile(r'\b[A-Z]{2}\d{7}\b'),

        # TIN: 12 digits, issued by National Board of Revenue.
        # Example (fake): 123456789012
        'Bangladesh TIN': re.compile(r'\b\d{12}\b'),
    },

    # =========================================================================
    # ASIA-PACIFIC — Sri Lanka
    # =========================================================================
    'Asia-Pacific - Sri Lanka': {
        # NIC Old: 9 digits + V or X (e.g., 722441524V).
        # First 2 = birth year, next 3 = day-of-year (females +500).
        'Sri Lanka NIC Old': re.compile(r'\b\d{9}[VXvx]\b'),

        # NIC New: 12 digits (since 2016).
        # 4-digit birth year + 3-digit day + 4-digit serial + 1 check.
        # Example (fake): 200125302976
        'Sri Lanka NIC New': re.compile(r'\b\d{12}\b'),

        # Passport: 1 letter (N/M/P series) + 7 digits.
        # Example (fake): N1234567
        'Sri Lanka Passport': re.compile(r'\b[A-Z]\d{7}\b'),
    },

    # #########################################################################
    #  L A T I N   A M E R I C A
    # #########################################################################

    # =========================================================================
    # LATIN AMERICA — Brazil
    # =========================================================================
    'Latin America - Brazil': {
        # CPF (Cadastro de Pessoas Físicas): XXX.XXX.XXX-XX (11 digits)
        # Last 2 digits are check digits calculated from the first 9
        'Brazil CPF': re.compile(
            r'\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b'
        ),

        # CNPJ (Cadastro Nacional da Pessoa Jurídica): XX.XXX.XXX/XXXX-XX (14 digits)
        # 8-digit company ID + 4-digit branch + 2 check digits
        'Brazil CNPJ': re.compile(
            r'\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b'
        ),

        # RG (Registro Geral / Identity Card): 7-10 digits, optional check digit (digit or X)
        # Format varies by state; common display: XX.XXX.XXX-X
        'Brazil RG': re.compile(
            r'\b\d{1,2}\.?\d{3}\.?\d{3}-?[\dXx]\b'
        ),

        # CNH (Carteira Nacional de Habilitação / Driving Licence): 11 digits
        'Brazil CNH': re.compile(r'\b\d{11}\b'),

        # SUS Card / CNS (Cartão Nacional de Saúde): 15 digits
        # Starts with 1 or 2 (beneficiary) or 7, 8, 9 (professional)
        'Brazil SUS Card': re.compile(
            r'\b[1-2]\d{10}00[01]\d\b'
            r'|'
            r'\b[789]\d{14}\b'
        ),

        # Passport: 2 uppercase letters + 6 digits
        'Brazil Passport': re.compile(r'\b[A-Z]{2}\d{6}\b'),
    },

    # =========================================================================
    # LATIN AMERICA — Argentina
    # =========================================================================
    'Latin America - Argentina': {
        # DNI (Documento Nacional de Identidad): 7-8 digits
        'Argentina DNI': re.compile(r'\b\d{7,8}\b'),

        # CUIL/CUIT (tax ID): XX-XXXXXXXX-X (11 digits)
        # Prefix: 20 (male), 27 (female), 23-26 (either), 30/33 (legal entity)
        # Middle 8 digits = DNI (zero-padded); last digit = check digit
        'Argentina CUIL/CUIT': re.compile(
            r'\b(?:20|2[3-7]|30|33)-?\d{8}-?\d\b'
        ),

        # Passport: letter + 6-7 digits (older: 8 digits + letter)
        'Argentina Passport': re.compile(
            r'\b[A-Z]{3}\d{6}\b'
        ),
    },

    # =========================================================================
    # LATIN AMERICA — Colombia
    # =========================================================================
    'Latin America - Colombia': {
        # Cédula de Ciudadanía (CC): 6-10 digits
        'Colombia Cedula': re.compile(r'\b\d{6,10}\b'),

        # NIT (Número de Identificación Tributaria): NNN.NNN.NNN-N (9 digits + 1 check digit)
        'Colombia NIT': re.compile(
            r'\b\d{3}\.?\d{3}\.?\d{3}-?\d\b'
        ),

        # NUIP (Número Único de Identificación Personal): same as Cédula, up to 10 digits
        'Colombia NUIP': re.compile(r'\b\d{6,10}\b'),

        # Passport: alphanumeric, typically 2 letters + 6-7 digits
        'Colombia Passport': re.compile(r'\b[A-Z]{2}\d{6,7}\b'),
    },

    # =========================================================================
    # LATIN AMERICA — Chile
    # =========================================================================
    'Latin America - Chile': {
        # RUN/RUT: XX.XXX.XXX-X (7-8 digit base + check digit 0-9 or K)
        # Check digit uses Modulo 11 algorithm
        'Chile RUN/RUT': re.compile(
            r'\b\d{1,2}\.?\d{3}\.?\d{3}-?[\dkK]\b'
        ),

        # Passport: 9 alphanumeric characters
        'Chile Passport': re.compile(r'\b[A-Z]?\d{7,8}\b'),
    },

    # =========================================================================
    # LATIN AMERICA — Peru
    # =========================================================================
    'Latin America - Peru': {
        # DNI (Documento Nacional de Identidad): exactly 8 digits
        'Peru DNI': re.compile(r'\b\d{8}\b'),

        # RUC (Registro Único de Contribuyentes): 11 digits
        # Starts with 10 (individual w/ DNI), 15 (individual other), 17 (diplomatic), 20 (legal entity)
        'Peru RUC': re.compile(r'\b(?:10|15|17|20)\d{9}\b'),

        # Carnet de Extranjería: 9-12 digits
        'Peru Carnet Extranjeria': re.compile(r'\b\d{9,12}\b'),

        # Passport: alphanumeric, up to 9 characters
        'Peru Passport': re.compile(r'\b[A-Z]{2}\d{6,7}\b'),
    },

    # =========================================================================
    # LATIN AMERICA — Venezuela
    # =========================================================================
    'Latin America - Venezuela': {
        # Cédula de Identidad: V or E prefix + 6-9 digits
        # V = Venezuelan citizen, E = foreign resident (Extranjero)
        'Venezuela Cedula': re.compile(
            r'\b[VvEe]-?\d{6,9}\b'
        ),

        # RIF (Registro de Información Fiscal): letter + 8 digits + check digit
        # Prefix: V (citizen), E (foreign), J (legal entity), G (government)
        'Venezuela RIF': re.compile(
            r'\b[VEJGvejg]-?\d{8}-?\d\b'
        ),

        # Passport: alphanumeric, typically letter + 7-8 digits
        'Venezuela Passport': re.compile(r'\b[A-Z]\d{7,8}\b'),
    },

    # =========================================================================
    # LATIN AMERICA — Ecuador
    # =========================================================================
    'Latin America - Ecuador': {
        # Cédula: 10 digits (first 2 = province code)
        'Ecuador Cedula': re.compile(r'\b\d{10}\b'),

        # RUC: 13 digits (cédula + 001 suffix for individuals)
        'Ecuador RUC': re.compile(r'\b\d{13}\b'),

        # Passport: 8-9 alphanumeric characters
        'Ecuador Passport': re.compile(r'\b[A-Z]\d{7,8}\b'),
    },

    # =========================================================================
    # LATIN AMERICA — Uruguay
    # =========================================================================
    'Latin America - Uruguay': {
        # Cédula de Identidad: X.XXX.XXX-X (7 digits + 1 check digit)
        # Check digit via dot-product with weights 8,1,2,3,4,7,6 mod 10
        'Uruguay Cedula': re.compile(
            r'\b\d{1}\.?\d{3}\.?\d{3}-?\d\b'
        ),

        # RUT (Registro Único Tributario): 12 digits
        # Format: 2-digit series + 6-digit number + 001 + check digit
        'Uruguay RUT': re.compile(r'\b\d{12}\b'),

        # Passport: alphanumeric, up to 9 characters
        'Uruguay Passport': re.compile(r'\b[A-Z]\d{6,8}\b'),
    },

    # =========================================================================
    # LATIN AMERICA — Paraguay
    # =========================================================================
    'Latin America - Paraguay': {
        # Cédula de Identidad: up to 7 digits
        'Paraguay Cedula': re.compile(r'\b\d{5,7}\b'),

        # RUC: 6-8 digits + hyphen + check digit (Modulo 11)
        'Paraguay RUC': re.compile(r'\b\d{6,8}-?\d\b'),

        # Passport: up to 9 alphanumeric (ICAO standard)
        'Paraguay Passport': re.compile(r'\b[A-Z]\d{6,8}\b'),
    },

    # =========================================================================
    # LATIN AMERICA — Costa Rica
    # =========================================================================
    'Latin America - Costa Rica': {
        # Cédula de Identidad: 9 digits (X-XXXX-XXXX)
        'Costa Rica Cedula': re.compile(
            r'\b\d{1}-?\d{4}-?\d{4}\b'
        ),

        # DIMEX (Documento de Identidad Migratorio para Extranjeros): 11-12 digits
        'Costa Rica DIMEX': re.compile(r'\b\d{11,12}\b'),

        # Passport: 9 alphanumeric characters
        'Costa Rica Passport': re.compile(r'\b[A-Z]\d{8}\b'),
    },

    # #########################################################################
    #  M I D D L E   E A S T
    # #########################################################################

    # =========================================================================
    # MIDDLE EAST — Saudi Arabia
    # =========================================================================
    'Middle East - Saudi Arabia': {
        # National ID / Iqama: 10 digits
        # Starts with 1 (Saudi citizen) or 2 (resident/Iqama)
        # Validated with Luhn algorithm
        'Saudi Arabia National ID': re.compile(r'\b[12]\d{9}\b'),

        # Passport: alphanumeric, typically letter + 7-8 digits
        'Saudi Arabia Passport': re.compile(r'\b[A-Z]\d{7,8}\b'),
    },

    # =========================================================================
    # MIDDLE EAST — United Arab Emirates
    # =========================================================================
    'Middle East - UAE': {
        # Emirates ID: 15 digits starting with 784 (UAE ISO 3166 country code)
        # Format: 784-YYYY-NNNNNNN-C (country + birth year + serial + check digit)
        'UAE Emirates ID': re.compile(
            r'\b784-?\d{4}-?\d{7}-?\d\b'
        ),

        # Visa Number: 14 digits (emirate code + year + serial)
        # Emirate codes: 101=Abu Dhabi, 201=Dubai, 301=Sharjah, etc.
        'UAE Visa Number': re.compile(
            r'\b[1-7]01/?(?:19|20)\d{2}/?\d{7}\b'
        ),

        # Passport: alphanumeric, typically 9 characters
        'UAE Passport': re.compile(r'\b[A-Z]?\d{7,9}\b'),
    },

    # =========================================================================
    # MIDDLE EAST — Israel
    # =========================================================================
    'Middle East - Israel': {
        # Teudat Zehut (Identity Number): 9 digits with Luhn check digit
        # May be left-padded with zeros; 1 prefix digit + 7 digits + 1 check digit
        'Israel Teudat Zehut': re.compile(r'\b\d{9}\b'),

        # Passport: alphanumeric, typically 7-8 digits
        'Israel Passport': re.compile(r'\b\d{7,8}\b'),
    },

    # =========================================================================
    # MIDDLE EAST — Qatar
    # =========================================================================
    'Middle East - Qatar': {
        # QID (Qatar ID): 11 digits
        # Digit 1: century of birth (2=1900s, 3=2000s)
        # Digits 2-3: birth year; Digits 4-6: ISO country code; Digits 7-11: sequence
        'Qatar QID': re.compile(r'\b[23]\d{10}\b'),

        # Passport: alphanumeric, typically letter + 7 digits
        'Qatar Passport': re.compile(r'\b[A-Z]\d{7}\b'),
    },

    # =========================================================================
    # MIDDLE EAST — Kuwait
    # =========================================================================
    'Middle East - Kuwait': {
        # Civil ID: 12 digits
        # Format: N(century) + YYMMDD(DOB) + NNNN(serial) + C(check digit)
        'Kuwait Civil ID': re.compile(r'\b[1-3]\d{11}\b'),

        # Passport: alphanumeric, up to 9 characters
        'Kuwait Passport': re.compile(r'\b[A-Z]?\d{7,9}\b'),
    },

    # =========================================================================
    # MIDDLE EAST — Bahrain
    # =========================================================================
    'Middle East - Bahrain': {
        # CPR (Central Population Registration): 9 digits
        # Format: YYMM(birth) + NNNN(random) + C(check)
        'Bahrain CPR': re.compile(r'\b\d{9}\b'),

        # Passport: alphanumeric, up to 9 characters
        'Bahrain Passport': re.compile(r'\b\d{7,9}\b'),
    },

    # =========================================================================
    # MIDDLE EAST — Jordan
    # =========================================================================
    'Middle East - Jordan': {
        # National ID Number: 10 digits
        # First digit indicates gender (1=male, 2=female)
        'Jordan National ID': re.compile(r'\b\d{10}\b'),

        # Passport: alphanumeric, typically letter + 7 digits
        'Jordan Passport': re.compile(r'\b[A-Z]\d{7}\b'),
    },

    # =========================================================================
    # MIDDLE EAST — Lebanon
    # =========================================================================
    'Middle East - Lebanon': {
        # National ID: up to 12-digit serial number
        'Lebanon ID': re.compile(r'\b\d{7,12}\b'),

        # Passport: RL or LR prefix + 6-7 digits
        'Lebanon Passport': re.compile(r'\b(?:RL|LR)\d{6,7}\b'),
    },

    # =========================================================================
    # MIDDLE EAST — Iraq
    # =========================================================================
    'Middle East - Iraq': {
        # National Card Number: 12 digits
        'Iraq National ID': re.compile(r'\b\d{12}\b'),

        # Passport: 9 alphanumeric characters (restricted letter set: no I, O, B, D, E, etc.)
        'Iraq Passport': re.compile(r'\b[A-HJ-NP-Z0-9]{9}\b'),
    },

    # =========================================================================
    # MIDDLE EAST — Iran
    # =========================================================================
    'Middle East - Iran': {
        # Melli Code (Shomareh Melli / National ID): 10 digits
        # First 3 digits = state code; next 6 = random; last = check digit
        'Iran Melli Code': re.compile(r'\b\d{10}\b'),

        # Passport: letter + 8 digits
        'Iran Passport': re.compile(r'\b[A-Z]\d{8}\b'),
    },

    # #########################################################################
    #  A F R I C A
    # #########################################################################

    # =========================================================================
    # AFRICA — South Africa
    # =========================================================================
    'Africa - South Africa': {
        # National ID: 13 digits (YYMMDDSSSSCAZ)
        # DOB(6) + gender(4) + citizenship(1) + race(1, always 8) + Luhn check digit(1)
        'South Africa ID': re.compile(r'\b\d{13}\b'),

        # Passport: up to 9 alphanumeric (may start with letter)
        'South Africa Passport': re.compile(r'\b[A-Z]?\d{8,9}\b'),

        # Driving Licence Number: 10 digits + 2 letters
        'South Africa DL': re.compile(r'\b\d{10}[A-Z]{2}\b'),
    },

    # =========================================================================
    # AFRICA — Nigeria
    # =========================================================================
    'Africa - Nigeria': {
        # NIN (National Identification Number): 11 digits
        # Validated with Verhoeff checksum
        'Nigeria NIN': re.compile(r'\b\d{11}\b'),

        # BVN (Bank Verification Number): 11 digits
        'Nigeria BVN': re.compile(r'\b\d{11}\b'),

        # TIN (Tax Identification Number): 12-13 digits
        'Nigeria TIN': re.compile(r'\b\d{12,13}\b'),

        # Voter's Card (VIN): 19 alphanumeric characters
        'Nigeria Voter Card': re.compile(r'\b[0-9A-Z]{19}\b'),

        # Driver's Licence: 3 letters (state code) + 5-9 digits + optional trailing alpha
        'Nigeria Driver Licence': re.compile(
            r'\b[A-Z]{3}\d{5,9}[A-Z]{0,2}\d{0,2}\b'
        ),

        # Passport: letter + 8 digits
        'Nigeria Passport': re.compile(r'\b[A-Z]\d{8}\b'),
    },

    # =========================================================================
    # AFRICA — Kenya
    # =========================================================================
    'Africa - Kenya': {
        # National ID: 7-8 digits (legacy); 9 digits under Maisha Namba
        'Kenya National ID': re.compile(r'\b\d{7,8}\b'),

        # KRA PIN: letter + 9 digits + letter (11 chars total, e.g. P051099232D)
        'Kenya KRA PIN': re.compile(r'\b[A-Z]\d{9}[A-Z]\b'),

        # NHIF Number: numeric, typically 6-9 digits
        'Kenya NHIF': re.compile(r'\b\d{6,9}\b'),

        # Passport: alphanumeric, up to 9 characters
        'Kenya Passport': re.compile(r'\b[A-Z]\d{7,8}\b'),
    },

    # =========================================================================
    # AFRICA — Egypt
    # =========================================================================
    'Africa - Egypt': {
        # National ID: 14 digits
        # Century(1) + YYMMDD(6) + governorate(2) + unique(4) + check(1)
        # Century digit: 2=1900s, 3=2000s
        'Egypt National ID': re.compile(
            r'\b[23]\d{13}\b'
        ),

        # Tax ID: 9 digits (3 groups of 3)
        'Egypt Tax ID': re.compile(r'\b\d{3}-?\d{3}-?\d{3}\b'),

        # Passport: alphanumeric, typically letter + 7 digits or 8 digits
        'Egypt Passport': re.compile(r'\b[A-Z]?\d{7,8}\b'),
    },

    # =========================================================================
    # AFRICA — Ghana
    # =========================================================================
    'Africa - Ghana': {
        # Ghana Card: GHA-XXXXXXXXX-X (GHA + 9 digits + check digit)
        # Non-citizens use different 3-letter prefix
        'Ghana Card': re.compile(
            r'\b(?:GHA|[A-Z]{3})-\d{9}-\d\b'
        ),

        # TIN: Ghana Card PIN is used as TIN for individuals since April 2021
        # Organisational TIN: letter prefix (C, G, Q, V) + 10 digits
        'Ghana TIN': re.compile(r'\b[CGQV]\d{10}\b'),

        # NHIS: linked to Ghana Card PIN
        'Ghana NHIS': re.compile(
            r'\b(?:GHA|[A-Z]{3})-\d{9}-\d\b'
        ),

        # Passport: alphanumeric, letter + 7 digits
        'Ghana Passport': re.compile(r'\b[A-Z]\d{7}\b'),
    },

    # =========================================================================
    # AFRICA — Ethiopia
    # =========================================================================
    'Africa - Ethiopia': {
        # Fayda National ID: 12 digits (new digital ID system)
        'Ethiopia National ID': re.compile(r'\b\d{12}\b'),

        # TIN: 10 digits (state code region + unique + check digit)
        'Ethiopia TIN': re.compile(r'\b\d{10}\b'),

        # Passport: alphanumeric, typically letter + 7 digits
        'Ethiopia Passport': re.compile(r'\b[A-Z]{2}\d{7}\b'),
    },

    # =========================================================================
    # AFRICA — Tanzania
    # =========================================================================
    'Africa - Tanzania': {
        # NIDA National ID (NIN): 20 digits
        'Tanzania NIDA': re.compile(r'\b\d{20}\b'),

        # TIN (Business): 9 digits
        'Tanzania TIN': re.compile(r'\b\d{9}\b'),

        # Passport: alphanumeric, letter + 7-8 digits
        'Tanzania Passport': re.compile(r'\b[A-Z]{2}\d{7}\b'),
    },

    # =========================================================================
    # AFRICA — Morocco
    # =========================================================================
    'Africa - Morocco': {
        # CIN/CNIE (Carte Nationale d'Identité Electronique): alphanumeric
        # Format: 1-2 letters + 5-6 digits (e.g. AB123456)
        'Morocco CIN': re.compile(r'\b[A-Z]{1,2}\d{5,6}\b'),

        # Identifiant Fiscal (Tax ID): 8 digits
        'Morocco Tax ID': re.compile(r'\b\d{8}\b'),

        # Passport: alphanumeric, typically 2 letters + 7 digits
        'Morocco Passport': re.compile(r'\b[A-Z]{2}\d{7}\b'),
    },

    # =========================================================================
    # AFRICA — Tunisia
    # =========================================================================
    'Africa - Tunisia': {
        # CIN (Carte d'Identité Nationale): 8 digits
        'Tunisia CIN': re.compile(r'\b\d{8}\b'),

        # Passport: letter + 6 digits (e.g. X123456)
        'Tunisia Passport': re.compile(r'\b[A-Z]\d{6}\b'),
    },

    # =========================================================================
    # AFRICA — Uganda
    # =========================================================================
    'Africa - Uganda': {
        # NIN: 14 alphanumeric characters
        # Format: CM/CF + YY(birth year) + NNNNNN(unique) + XXXX(random alphanumeric)
        'Uganda NIN': re.compile(
            r'\bC[MF]\d{8}[A-Z0-9]{4}\b'
        ),

        # Passport: alphanumeric, up to 9 characters
        'Uganda Passport': re.compile(r'\b[A-Z]\d{7,8}\b'),
    },
}
