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
        # -----------------------------------------------------------------
        # FEDERAL IDENTIFIERS
        # -----------------------------------------------------------------

        # Social Security Number: XXX-XX-XXXX
        'USA SSN': re.compile(r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b'),

        # Individual Taxpayer Identification Number: 9XX-XX-XXXX
        'USA ITIN': re.compile(r'\b9\d{2}[-\s]?\d{2}[-\s]?\d{4}\b'),

        # Employer Identification Number: XX-XXXXXXX
        'USA EIN': re.compile(r'\b\d{2}-\d{7}\b'),

        # US Passport Book — legacy 9-digit or Next-Gen (letter + 8 digits)
        # Example: 123456789  or  A12345678
        'USA Passport Book': re.compile(r'\b(?:[A-Z]\d{8}|\d{9})\b'),

        # US Passport Card — C + 8 digits  (e.g. C12345678)
        'USA Passport Card': re.compile(r'\b[Cc]\d{8}\b'),

        # Routing Number: 9 digits
        'USA Routing Number': re.compile(r'\b\d{9}\b'),

        # DEA Number: 2 letters + 7 digits
        'US DEA Number': re.compile(r'\b[A-Z]{2}\d{7}\b'),

        # NPI (National Provider Identifier): 10 digits, starts with 1 or 2
        'US NPI': re.compile(r'\b[12]\d{9}\b'),

        # Medicare Beneficiary Identifier (MBI) — CMS 11-char format
        # Pos: C(1-9) A(letter*) AN(digit-or-letter*) N(0-9) …
        # *letter = [AC-HJKMNP-RT-Y] (excludes S,L,O,I,B,Z)
        # Example: 1EG4-TE5-MK73  (hyphens optional, for display only)
        'US MBI': re.compile(
            r'\b[1-9][AC-HJKMNP-RT-Y][0-9AC-HJKMNP-RT-Y][0-9]'
            r'-?[AC-HJKMNP-RT-Y][0-9AC-HJKMNP-RT-Y][0-9]'
            r'-?[AC-HJKMNP-RT-Y]{2}[0-9]{2}\b'
        ),

        # DoD ID Number (EDIPI) — 10-digit military identifier on CAC cards
        # Example: 1234567890
        'US DoD ID': re.compile(r'\b\d{10}\b'),

        # Known Traveler Number — Global Entry / NEXUS / SENTRI PASS ID
        # 9 digits, typically starts with 10,13,14,15,16,50,70,80,95,98,99
        # Example: 100123456
        'US Known Traveler Number': re.compile(r'\b\d{9}\b'),

        # Known Traveler Number — TSA PreCheck enrollment prefix variants
        # TT (IDEMIA), TE (Telos), AC (CLEAR) + 7-9 digits
        # Example: TT1234567
        'US TSA PreCheck KTN': re.compile(r'\b(?:TT|TE|AC)\d{7,9}\b'),

        # US/Canada phone: (555) 123-4567, 555-123-4567, +1-555-123-4567
        'US Phone Number': re.compile(
            r'(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)'
        ),

        # -----------------------------------------------------------------
        # STATE DRIVER'S LICENSES — all 50 states + DC
        # Sources: NTSI, FMCSA, Milyli Blackout reference
        # -----------------------------------------------------------------

        # Alabama: 1-8 digits (typically 7)  — example: 6996164
        'Alabama DL': re.compile(r'\b\d{1,8}\b'),

        # Alaska: 1-7 digits  — example: 1234567
        'Alaska DL': re.compile(r'\b\d{1,7}\b'),

        # Arizona: L + 1-8 digits | LL + 2-5 digits | 9 digits
        'Arizona DL': re.compile(
            r'\b(?:[A-Z]\d{1,8}|[A-Z]{2}\d{2,5}|\d{9})\b'
        ),

        # Arkansas: 4-9 digits  — example: 999999999
        'Arkansas DL': re.compile(r'\b\d{4,9}\b'),

        # California: L + 7 digits  — example: A0002144
        'California DL': re.compile(r'\b[A-Z]\d{7}\b'),

        # Colorado: 9 digits | L + 3-6 digits | LL + 2-5 digits
        'Colorado DL': re.compile(
            r'\b(?:\d{9}|[A-Z]\d{3,6}|[A-Z]{2}\d{2,5})\b'
        ),

        # Connecticut: 9 digits  — example: 123456789
        'Connecticut DL': re.compile(r'\b\d{9}\b'),

        # Delaware: 1-7 digits  — example: 1234567
        'Delaware DL': re.compile(r'\b\d{1,7}\b'),

        # District of Columbia: 7 or 9 digits
        'DC DL': re.compile(r'\b(?:\d{7}|\d{9})\b'),

        # Florida: L + 12 digits  — example: G544-061-73-925-0
        'Florida DL': re.compile(r'\b[A-Z]\d{3}-?\d{3}-?\d{2}-?\d{3}-?\d\b'),

        # Georgia: 7-9 digits  — example: 123456789
        'Georgia DL': re.compile(r'\b\d{7,9}\b'),

        # Hawaii: L + 8 digits | 9 digits
        'Hawaii DL': re.compile(r'\b(?:[A-Z]\d{8}|\d{9})\b'),

        # Idaho: LL + 6 digits + L | 9 digits  — example: AA123456Z
        'Idaho DL': re.compile(r'\b(?:[A-Z]{2}\d{6}[A-Z]|\d{9})\b'),

        # Illinois: L + 11 digits (L###-####-####)  — example: D400-7836-0001
        'Illinois DL': re.compile(r'\b[A-Z]\d{3}-?\d{4}-?\d{4}\b'),

        # Indiana: L + 9 digits | 9-10 digits  — example: 0299-11-6078
        'Indiana DL': re.compile(r'\b(?:[A-Z]\d{9}|\d{9,10})\b'),

        # Iowa: 9 digits | 3 digits + 2 letters + 4 digits
        'Iowa DL': re.compile(r'\b(?:\d{9}|\d{3}[A-Z]{2}\d{4})\b'),

        # Kansas: LNLNL | L + 8 digits | 9 digits  — example: K00-09-7443
        'Kansas DL': re.compile(
            r'\b(?:[A-Z]\d[A-Z]\d[A-Z]|[A-Z]\d{2}-?\d{2}-?\d{4}|\d{9})\b'
        ),

        # Kentucky: L + 8-9 digits | 9 digits  — example: V12-345-678
        'Kentucky DL': re.compile(r'\b(?:[A-Z]\d{8,9}|\d{9})\b'),

        # Louisiana: 1-9 digits (typically 9)  — example: 007000100
        'Louisiana DL': re.compile(r'\b\d{1,9}\b'),

        # Maine: 7 digits | 7 digits + L | 8 digits  — example: 0015000
        'Maine DL': re.compile(r'\b(?:\d{7}[A-Z]?|\d{8})\b'),

        # Maryland: L + 12 digits  — example: S514778616977
        'Maryland DL': re.compile(r'\b[A-Z]\d{12}\b'),

        # Massachusetts: L + 8 digits | 9 digits  — example: S99988880
        'Massachusetts DL': re.compile(r'\b(?:[A-Z]\d{8}|\d{9})\b'),

        # Michigan: L + 10-12 digits  — example: P800000224322
        'Michigan DL': re.compile(r'\b[A-Z]\d{10,12}\b'),

        # Minnesota: L + 12 digits  — example: A123456789012
        'Minnesota DL': re.compile(r'\b[A-Z]\d{12}\b'),

        # Mississippi: 9 digits  — example: 123456789
        'Mississippi DL': re.compile(r'\b\d{9}\b'),

        # Missouri: L + 5-9 digits | L + 6 digits + R |
        #           8 digits + 2 letters | 9 digits + L | 9 digits
        'Missouri DL': re.compile(
            r'\b(?:[A-Z]\d{5,9}|[A-Z]\d{6}R|\d{8}[A-Z]{2}|\d{9}[A-Z]|\d{9})\b'
        ),

        # Montana: L + 8 digits | 9 digits | 13-14 digits
        'Montana DL': re.compile(
            r'\b(?:[A-Z]\d{8}|\d{9}|\d{13,14})\b'
        ),

        # Nebraska: L + 8 digits | 1-7 digits  — example: A20600249
        'Nebraska DL': re.compile(r'\b(?:[A-Z]\d{8}|\d{1,7})\b'),

        # Nevada: 9-12 digits | X + 8 digits  — example: 0002102201
        'Nevada DL': re.compile(r'\b(?:\d{9,12}|X\d{8})\b'),

        # New Hampshire: 2 digits + 3 letters + 5 digits
        # (month-of-birth + name letters + year/day + dup code)
        'New Hampshire DL': re.compile(r'\b\d{2}[A-Z]{3}\d{5}\b'),

        # New Jersey: L + 14 digits (L####-#####-#####)
        'New Jersey DL': re.compile(r'\b[A-Z]\d{4}-?\d{5}-?\d{5}\b'),

        # New Mexico: 8-9 digits  — example: 013696424
        'New Mexico DL': re.compile(r'\b\d{8,9}\b'),

        # New York: 9 digits (### ### ###)  — example: 123 456 789
        'New York DL': re.compile(r'\b\d{3}\s?\d{3}\s?\d{3}\b'),

        # North Carolina: 1-12 digits  — example: 801330315912
        'North Carolina DL': re.compile(r'\b\d{1,12}\b'),

        # North Dakota: LLL + 6 digits | 9 digits
        # first 3 letters of surname + DOB-based digits
        'North Dakota DL': re.compile(r'\b(?:[A-Z]{3}\d{6}|\d{9})\b'),

        # Ohio: LL + 6 digits | L + 4-8 digits | 8 digits — example: TL545796
        'Ohio DL': re.compile(
            r'\b(?:[A-Z]{2}\d{6}|[A-Z]\d{4,8}|\d{8})\b'
        ),

        # Oklahoma: L + 9 digits | 9 digits  — example: B000062835
        'Oklahoma DL': re.compile(r'\b(?:[A-Z]\d{9}|\d{9})\b'),

        # Oregon: 1-9 digits (typically 7)  — example: 6110033
        'Oregon DL': re.compile(r'\b\d{1,9}\b'),

        # Pennsylvania: 8 digits (## ### ###)  — example: 17 600 550
        'Pennsylvania DL': re.compile(r'\b\d{2}\s?\d{3}\s?\d{3}\b'),

        # Rhode Island: 7 digits | V + 6 digits
        'Rhode Island DL': re.compile(r'\b(?:\d{7}|V\d{6})\b'),

        # South Carolina: 5-11 digits  — example: 123456789
        'South Carolina DL': re.compile(r'\b\d{5,11}\b'),

        # South Dakota: 6-10 digits | 12 digits
        'South Dakota DL': re.compile(r'\b(?:\d{6,10}|\d{12})\b'),

        # Tennessee: 7-9 digits  — example: 12345678
        'Tennessee DL': re.compile(r'\b\d{7,9}\b'),

        # Texas: 8 digits  — example: 17600550
        'Texas DL': re.compile(r'\b\d{8}\b'),

        # Utah: 4-10 digits  — example: 123456789
        'Utah DL': re.compile(r'\b\d{4,10}\b'),

        # Vermont: 8 digits | 7 digits + L  — example: 17600550 or 8205059A
        'Vermont DL': re.compile(r'\b(?:\d{8}|\d{7}[A-Z])\b'),

        # Virginia: L + 8-11 digits | 9 digits
        'Virginia DL': re.compile(r'\b(?:[A-Z]\d{8,11}|\d{9})\b'),

        # Washington: 1-7 letters + alphanumeric/asterisk mix, 12 chars total
        'Washington DL': re.compile(r'\b[A-Z]{1,7}[A-Z0-9*]{5,11}\b'),

        # West Virginia: 7 digits | 1-2 letters + 5-6 digits
        'West Virginia DL': re.compile(
            r'\b(?:\d{7}|[A-Z]{1,2}\d{5,6})\b'
        ),

        # Wisconsin: L + 13 digits (L###-####-####-##)  — example: M123-4567-8901-23
        'Wisconsin DL': re.compile(r'\b[A-Z]\d{3}-?\d{4}-?\d{4}-?\d{2}\b'),

        # Wyoming: 9-10 digits (######-### or ######-####)  — example: 050070-003
        'Wyoming DL': re.compile(r'\b\d{6}-?\d{3,4}\b'),
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
        # -----------------------------------------------------------------
        # FEDERAL IDENTIFIERS
        # -----------------------------------------------------------------

        # Social Insurance Number: XXX-XXX-XXX (Luhn-validated at scan time)
        'Canada SIN': re.compile(r'\b\d{3}[-\s]?\d{3}[-\s]?\d{3}\b'),

        # Business Number: 9 digits + 2 letters + 4 digits (e.g. 123456789RC0001)
        'Canada BN': re.compile(r'\b\d{9}[A-Z]{2}\d{4}\b'),

        # Canadian Passport: 2 letters + 6 digits (e.g. GA123456)
        'Canada Passport': re.compile(r'\b[A-Z]{2}\d{6}\b'),

        # Permanent Resident Card Number: 2 letters + 7-10 digits
        # e.g. PA0123456 (9 chars) or RA0302123456 (12 chars)
        'Canada PR Card': re.compile(r'\b[A-Z]{2}\d{7,10}\b'),

        # NEXUS Card (PASS ID): 9 digits
        # Typically starts with 10, 13, 14, 15, 16, 50, 70, 80, 95, 98, or 99
        'Canada NEXUS': re.compile(r'\b\d{9}\b'),

        # Bank transit/institution code: XXXXX-XXX
        'Canada Bank Code': re.compile(r'\b\d{5}-\d{3}\b'),

        # -----------------------------------------------------------------
        # PROVINCIAL DRIVER'S LICENCES
        # -----------------------------------------------------------------

        # Ontario: L + 4 digits + 5 digits + 5 digits (L####-#####-#####)
        # Example: A1234-56789-01234
        'Ontario DL': re.compile(r'\b[A-Z]\d{4}-?\d{5}-?\d{5}\b'),

        # Quebec: L + 12 digits  — example: M123456789012
        'Quebec DL': re.compile(r'\b[A-Z]\d{12}\b'),

        # British Columbia: 7 digits  — example: 1234567
        'British Columbia DL': re.compile(r'\b\d{7}\b'),

        # Alberta: 6 digits-3 digits | 5-9 digits  — example: 123456-789
        'Alberta DL': re.compile(r'\b(?:\d{6}-\d{3}|\d{5,9})\b'),

        # Saskatchewan: 8 digits  — example: 12345678
        'Saskatchewan DL': re.compile(r'\b\d{8}\b'),

        # Manitoba: encoded name+DOB — pattern LL-LL-LL-LNNNLL
        # Example: AB-CD-EF-G123HJ
        'Manitoba DL': re.compile(
            r'\b[A-Z]{2}-?[A-Z]{2}-?[A-Z]{2}-?[A-Z]\d{3}[A-Z]{2}\b'
        ),

        # New Brunswick: 5-7 digits  — example: 1234567
        'New Brunswick DL': re.compile(r'\b\d{5,7}\b'),

        # Nova Scotia: 5 letters + 9 digits (LLLLL-NNN-NNN-NNN)
        # First 5 letters of surname + encoded DOB
        # Example: SMITH-301-106-789
        'Nova Scotia DL': re.compile(
            r'\b[A-Z]{5}-?\d{3}-?\d{3}-?\d{3}\b'
        ),

        # Prince Edward Island: 5-6 digits  — example: 12345
        'PEI DL': re.compile(r'\b\d{5,6}\b'),

        # Newfoundland & Labrador: L + 9 digits  — example: A123456789
        'Newfoundland DL': re.compile(r'\b[A-Z]\d{9}\b'),

        # Yukon: 1-6 digits  — example: 123456
        'Yukon DL': re.compile(r'\b\d{1,6}\b'),

        # Northwest Territories: 6 digits  — example: 123456
        'NWT DL': re.compile(r'\b\d{6}\b'),

        # Nunavut: 6 digits (similar to NWT)  — example: 123456
        'Nunavut DL': re.compile(r'\b\d{6}\b'),

        # -----------------------------------------------------------------
        # PROVINCIAL HEALTH CARDS
        # -----------------------------------------------------------------

        # Ontario OHIP: 10 digits + optional 2-char version code
        # Example: 1234567890 or 1234567890 AB
        'Ontario OHIP': re.compile(r'\b\d{10}(?:\s?[A-Z]{2})?\b'),

        # Quebec RAMQ: 4 letters (surname + first initial) + 8 digits
        # Example: SMIJ12345678
        'Quebec RAMQ': re.compile(r'\b[A-Z]{4}\d{8}\b'),

        # British Columbia MSP: 10 digits starting with 9
        # Example: 9123456789
        'BC MSP': re.compile(r'\b9\d{9}\b'),

        # Alberta AHCIP (PHN): 9 digits
        # Example: 123456789
        'Alberta AHCIP': re.compile(r'\b\d{9}\b'),

        # Saskatchewan Health: 9 digits  — example: 123456789
        'Saskatchewan HC': re.compile(r'\b\d{9}\b'),

        # Manitoba PHIN: 9 digits  — example: 123456789
        'Manitoba PHIN': re.compile(r'\b\d{9}\b'),

        # New Brunswick Medicare: 9 digits  — example: 123456789
        'New Brunswick HC': re.compile(r'\b\d{9}\b'),

        # Nova Scotia MSI: 10 digits  — example: 1234567890
        'Nova Scotia MSI': re.compile(r'\b\d{10}\b'),

        # PEI Health Card: 8 digits  — example: 12345678
        'PEI HC': re.compile(r'\b\d{8}\b'),

        # Newfoundland MCP: 12 digits  — example: 123456789012
        'Newfoundland MCP': re.compile(r'\b\d{12}\b'),
    },

    # =========================================================================
    # NORTH AMERICA — Mexico
    # =========================================================================
    'North America - Mexico': {
        # CURP: 4 letters + 6 digits + H/M + 5 letters + alphanum + digit
        # Example: GARC850101HDFRRL09
        'Mexico CURP': re.compile(
            r'\b[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d\b'
        ),

        # RFC (tax ID): 3-4 letters/& + 6 digits + 3 alphanumeric
        # Persona moral (12): ABC060101AB1  |  Persona fisica (13): GARC850101AB1
        'Mexico RFC': re.compile(r'\b[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3}\b'),

        # INE/IFE Voter Credential — Clave de Elector: 18 characters
        # 6 consonants + YYMMDD + state-code(2) + H/M + 3 digits
        # Example: GRCRRL850101H001
        'Mexico Clave Elector': re.compile(
            r'\b[A-Z]{6}\d{2}[01]\d[0-3]\d[0-3]\d[HM]\d{3}\b'
        ),

        # INE/IFE — CIC (Credential Identification Code): 9 digits
        # Example: 123456789
        'Mexico INE CIC': re.compile(r'\b\d{9}\b'),

        # INE/IFE — OCR code: 13 digits (unique per physical card)
        # Example: 1234567890123
        'Mexico INE OCR': re.compile(r'\b\d{13}\b'),

        # Mexican Passport: 1 letter + 8 digits (currently G or N series)
        # Example: G12345678
        'Mexico Passport': re.compile(r'\b[A-Z]\d{8}\b'),

        # IMSS NSS (Numero de Seguro Social): 11 digits
        # subdelegation(2) + reg-year(2) + birth-year(2) + consecutive(4) + check(1)
        # Example: 12345678901
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
