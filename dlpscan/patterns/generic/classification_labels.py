import re

CLASSIFICATION_LABELS_PATTERNS = {
    # ── Regulatory & Supervisory Classification ─────────────────────
    'Supervisory Information': {
        # Supervisory Controlled Information
        'Supervisory Controlled': re.compile(r'\b[Ss]upervisory\s+[Cc]ontrolled\s+[Ii]nformation\b'),
        # Supervisory Confidential
        'Supervisory Confidential': re.compile(r'\b[Ss]upervisory\s+[Cc]onfidential\b'),
        # Confidential Supervisory Information (CSI) — used by OCC, Fed, FDIC
        'CSI': re.compile(r'\b(?:[Cc]onfidential\s+[Ss]upervisory\s+[Ii]nformation|CSI)\b'),
        # Non-Public Supervisory Information
        'Non-Public Supervisory': re.compile(r'\b[Nn]on-?[Pp]ublic\s+[Ss]upervisory\s+[Ii]nformation\b'),
        # Restricted Supervisory Information
        'Restricted Supervisory': re.compile(r'\b[Rr]estricted\s+[Ss]upervisory\s+[Ii]nformation\b'),
        # Examination Report / MRA / MRIA
        'Examination Findings': re.compile(r'\b(?:MRA|MRIA|[Mm]atter[s]?\s+[Rr]equiring\s+(?:[Ii]mmediate\s+)?[Aa]ttention)\b'),
    },
    # ── Privileged Information ──────────────────────────────────────
    'Privileged Information': {
        # Attorney-Client Privilege
        'Attorney-Client Privilege': re.compile(r'\b[Aa]ttorney[-\s][Cc]lient\s+[Pp]rivileged?\b'),
        # Privileged and Confidential
        'Privileged and Confidential': re.compile(r'\b[Pp]rivileged\s+(?:and|&)\s+[Cc]onfidential\b'),
        # Work Product Doctrine
        'Work Product': re.compile(r'\b[Ww]ork\s+[Pp]roduct(?:\s+[Dd]octrine)?\b'),
        # Privileged Information (generic)
        'Privileged Information': re.compile(r'\b[Pp]rivileged\s+[Ii]nformation\b'),
        # Legal Privilege
        'Legal Privilege': re.compile(r'\b[Ll]egal(?:ly)?\s+[Pp]rivileged\b'),
        # Litigation Hold / Legal Hold
        'Litigation Hold': re.compile(r'\b(?:[Ll]itigation|[Ll]egal)\s+[Hh]old\b'),
        # Protected by Privilege
        'Protected by Privilege': re.compile(r'\b[Pp]rotected\s+(?:by|under)\s+[Pp]rivilege\b'),
    },
    # ── Data Classification Labels ──────────────────────────────────
    'Data Classification Labels': {
        # Top Secret / Secret / Confidential (government style)
        'Top Secret': re.compile(r'\b(?:TOP\s+SECRET|TS//SCI|TS//SI)\b'),
        'Secret Classification': re.compile(r'\b(?:SECRET(?://NOFORN)?|CLASSIFIED\s+SECRET)\b'),
        'Confidential Classification': re.compile(r'\bCLASSIFIED\s+CONFIDENTIAL\b'),
        # FOUO - For Official Use Only
        'FOUO': re.compile(r'\b(?:FOUO|[Ff]or\s+[Oo]fficial\s+[Uu]se\s+[Oo]nly)\b'),
        # Controlled Unclassified Information (CUI)
        'CUI': re.compile(r'\b(?:CUI|[Cc]ontrolled\s+[Uu]nclassified\s+[Ii]nformation)\b'),
        # Sensitive But Unclassified (SBU)
        'SBU': re.compile(r'\b(?:SBU|[Ss]ensitive\s+[Bb]ut\s+[Uu]nclassified)\b'),
        # Law Enforcement Sensitive (LES)
        'LES': re.compile(r'\b(?:LES|[Ll]aw\s+[Ee]nforcement\s+[Ss]ensitive)\b'),
        # NOFORN - Not Releasable to Foreign Nationals
        'NOFORN': re.compile(r'\bNOFORN\b'),
    },
    # ── Corporate/Enterprise Classification ─────────────────────────
    'Corporate Classification': {
        # Internal Only / Internal Use Only
        'Internal Only': re.compile(r'\b[Ii]nternal\s+(?:[Uu]se\s+)?[Oo]nly\b'),
        # Restricted (corporate data label)
        'Restricted': re.compile(r'\b(?:RESTRICTED|[Rr]estricted\s+[Dd]ata|[Rr]estricted\s+[Ii]nformation)\b'),
        # Confidential (corporate)
        'Corporate Confidential': re.compile(r'\b(?:[Cc]ompany\s+[Cc]onfidential|[Cc]orporate\s+[Cc]onfidential|[Ss]trictly\s+[Cc]onfidential)\b'),
        # Highly Confidential
        'Highly Confidential': re.compile(r'\b[Hh]ighly\s+[Cc]onfidential\b'),
        # Not for Distribution / Do Not Distribute
        'Do Not Distribute': re.compile(r'\b(?:[Nn]ot\s+[Ff]or\s+[Dd]istribution|[Dd]o\s+[Nn]ot\s+[Dd]istribute|[Nn]o\s+[Dd]istribution)\b'),
        # Need to Know
        'Need to Know': re.compile(r'\b[Nn]eed\s+[Tt]o\s+[Kk]now(?:\s+[Bb]asis)?\b'),
        # Eyes Only
        'Eyes Only': re.compile(r'\b[Ee]yes\s+[Oo]nly\b'),
        # Proprietary
        'Proprietary': re.compile(r'\b(?:[Pp]roprietary\s+(?:[Ii]nformation|[Dd]ata|[Mm]aterial)|[Tt]rade\s+[Ss]ecret)\b'),
        # Embargoed
        'Embargoed': re.compile(r'\b[Ee]mbargoed?\s+(?:[Ii]nformation|[Dd]ata|[Uu]ntil|[Mm]aterial)\b'),
    },
    # ── Financial Regulatory Labels ─────────────────────────────────
    'Financial Regulatory Labels': {
        # Material Non-Public Information (MNPI)
        'MNPI': re.compile(r'\b(?:MNPI|[Mm]aterial\s+[Nn]on-?[Pp]ublic\s+[Ii]nformation)\b'),
        # Inside Information
        'Inside Information': re.compile(r'\b[Ii]nside(?:r)?\s+[Ii]nformation\b'),
        # Pre-Decisional
        'Pre-Decisional': re.compile(r'\b[Pp]re-?[Dd]ecisional\b'),
        # Draft - Not for Circulation
        'Draft Not for Circulation': re.compile(r'\b[Dd]raft\s*[-–—]\s*[Nn]ot\s+[Ff]or\s+[Cc]irculation\b'),
        # Market Sensitive
        'Market Sensitive': re.compile(r'\b[Mm]arket\s+[Ss]ensitive\b'),
        # Information Barrier / Chinese Wall
        'Information Barrier': re.compile(r'\b(?:[Ii]nformation\s+[Bb]arrier|[Cc]hinese\s+[Ww]all)\b'),
        # Investment Recommendation - Restricted
        'Investment Restricted': re.compile(r'\b[Rr]estricted\s+[Ll]ist\b'),
    },
    # ── Privacy & Data Protection Labels ────────────────────────────
    'Privacy Classification': {
        # PII / Personally Identifiable Information
        'PII Label': re.compile(r'\b(?:PII|[Pp]ersonally\s+[Ii]dentifiable\s+[Ii]nformation)\b'),
        # PHI / Protected Health Information
        'PHI Label': re.compile(r'\b(?:PHI|[Pp]rotected\s+[Hh]ealth\s+[Ii]nformation)\b'),
        # HIPAA
        'HIPAA': re.compile(r'\bHIPAA\b'),
        # GDPR Personal Data
        'GDPR Personal Data': re.compile(r'\b(?:GDPR|[Pp]ersonal\s+[Dd]ata\s+(?:under|per|pursuant))\b'),
        # PCI-DSS / Cardholder Data
        'PCI-DSS': re.compile(r'\b(?:PCI[-\s]?DSS|[Cc]ardholder\s+[Dd]ata\s+[Ee]nvironment|CDE)\b'),
        # FERPA / Education Records
        'FERPA': re.compile(r'\b(?:FERPA|[Ff]amily\s+[Ee]ducational\s+[Rr]ights)\b'),
        # GLBA / Financial Privacy
        'GLBA': re.compile(r'\b(?:GLBA|[Gg]ramm[-\s][Ll]each[-\s][Bb]liley)\b'),
        # CCPA / CPRA
        'CCPA/CPRA': re.compile(r'\b(?:CCPA|CPRA|[Cc]alifornia\s+[Cc]onsumer\s+[Pp]rivacy)\b'),
        # SOX / Sarbanes-Oxley
        'SOX': re.compile(r'\b(?:SOX|[Ss]arbanes[-\s][Oo]xley)\b'),
        # NPI (Non-Public Personal Information under GLBA)
        'NPI': re.compile(r'\b(?:NPI|[Nn]on-?[Pp]ublic\s+[Pp]ersonal\s+[Ii]nformation)\b'),
    },
}
