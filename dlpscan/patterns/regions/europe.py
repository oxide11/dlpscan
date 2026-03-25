import re


EUROPE_PATTERNS = {
    # ── United Kingdom ──────────────────────────────────────────────
    'Europe - United Kingdom': {
        'UK NIN': re.compile(r'\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b'),
        'UK UTR': re.compile(r'\b\d{5}\s?\d{5}\b'),
        'UK Passport': re.compile(r'\b\d{9}\b'),
        'UK Sort Code': re.compile(r'\b\d{2}-\d{2}-\d{2}\b'),
        'British NHS': re.compile(r'\b\d{3}\s?\d{3}\s?\d{4}\b'),
        'UK Phone Number': re.compile(r'(?:\+44[-.\s]?|0)(?:\d[-.\s]?){9,10}(?!\d)'),
        'UK DL': re.compile(r'\b[A-Z]{5}\d{6}[A-Z0-9]{5}\b'),
    },
    # ── Germany ─────────────────────────────────────────────────────
    'Europe - Germany': {
        'Germany ID': re.compile(r'\b[CFGHJKLMNPRTVWXYZ0-9]{9}\b'),
        'Germany Passport': re.compile(r'\bC[A-Z0-9]{8}\b'),
        'Germany Tax ID': re.compile(r'\b\d{11}\b'),
        'Germany Social Insurance': re.compile(r'\b\d{2}[0-3]\d[01]\d{2}\d[A-Z]\d{3}\b'),
        'Germany DL': re.compile(r'\b[A-Z0-9]{11}\b'),
        'Germany IBAN': re.compile(r'\bDE\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{2}\b', re.IGNORECASE),
    },
    # ── France ──────────────────────────────────────────────────────
    'Europe - France': {
        'France NIR': re.compile(r'\b[12]\d{2}(?:0[1-9]|1[0-2])(?:\d{2}|2[AB])\d{3}\d{3}\d{2}\b'),
        'France Passport': re.compile(r'\b\d{2}[A-Z]{2}\d{5}\b'),
        'France CNI': re.compile(r'\b[A-Z0-9]{12}\b'),
        'France DL': re.compile(r'\b\d{2}[A-Z]{2}\d{5}\b'),
        'France IBAN': re.compile(r'\bFR\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{3}\b', re.IGNORECASE),
    },
    # ── Italy ───────────────────────────────────────────────────────
    'Europe - Italy': {
        'Italy Codice Fiscale': re.compile(r'\b[A-Z]{6}\d{2}[A-EHLMPR-T]\d{2}[A-Z]\d{3}[A-Z]\b'),
        'Italy Passport': re.compile(r'\b[A-Z]{2}\d{7}\b'),
        'Italy DL': re.compile(r'\b[A-Z]{2}\d{7}[A-Z]\b'),
        'Italy SSN': re.compile(r'\b[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]\b'),
        'Italy Partita IVA': re.compile(r'\b\d{11}\b'),
    },
    # ── Netherlands ─────────────────────────────────────────────────
    'Europe - Netherlands': {
        'Netherlands BSN': re.compile(r'\b\d{9}\b'),
        'Netherlands Passport': re.compile(r'\b[A-Z]{2}[A-Z0-9]{6}\d\b'),
        'Netherlands DL': re.compile(r'\b\d{10}\b'),
        'Netherlands IBAN': re.compile(r'\bNL\d{2}\s?[A-Z]{4}\s?\d{4}\s?\d{4}\s?\d{2}\b', re.IGNORECASE),
    },
    # ── Spain ───────────────────────────────────────────────────────
    'Europe - Spain': {
        'Spain DNI': re.compile(r'\b\d{8}[A-Z]\b'),
        'Spain NIE': re.compile(r'\b[XYZ]\d{7}[A-Z]\b'),
        'Spain Passport': re.compile(r'\b[A-Z]{3}\d{6}\b'),
        'Spain NSS': re.compile(r'\b\d{2}[-/]?\d{8}[-/]?\d{2}\b'),
        'Spain DL': re.compile(r'\b\d{8}[A-Z]\b'),
    },
    # ── Poland ──────────────────────────────────────────────────────
    'Europe - Poland': {
        'Poland PESEL': re.compile(r'\b\d{11}\b'),
        'Poland NIP': re.compile(r'\b\d{3}-?\d{3}-?\d{2}-?\d{2}\b'),
        'Poland REGON': re.compile(r'\b\d{9}(?:\d{5})?\b'),
        'Poland ID Card': re.compile(r'\b[A-Z]{3}\d{6}\b'),
        'Poland Passport': re.compile(r'\b[A-Z]{2}\d{7}\b'),
        'Poland DL': re.compile(r'\b\d{5}/\d{2}/\d{4}\b'),
    },
    # ── Sweden ──────────────────────────────────────────────────────
    'Europe - Sweden': {
        'Sweden PIN': re.compile(r'\b\d{6}[-+]?\d{4}\b'),
        'Sweden Passport': re.compile(r'\b\d{8}\b'),
        'Sweden DL': re.compile(r'\b\d{6}[-]?\d{4}\b'),
        'Sweden Organisation Number': re.compile(r'\b\d{6}-\d{4}\b'),
    },
    # ── Portugal ────────────────────────────────────────────────────
    'Europe - Portugal': {
        'Portugal NIF': re.compile(r'\b[12356789]\d{8}\b'),
        'Portugal CC': re.compile(r'\b\d{8}\s?\d\s?[A-Z]{2}\d\b'),
        'Portugal Passport': re.compile(r'\b[A-Z]{1,2}\d{6}\b'),
        'Portugal NISS': re.compile(r'\b\d{11}\b'),
    },
    # ── Switzerland ─────────────────────────────────────────────────
    'Europe - Switzerland': {
        'Switzerland AHV': re.compile(r'\b756\.\d{4}\.\d{4}\.\d{2}\b'),
        'Switzerland Passport': re.compile(r'\b[A-Z]\d{7}\b'),
        'Switzerland DL': re.compile(r'\b\d{6,7}\b'),
        'Switzerland UID': re.compile(r'\bCHE-?\d{3}\.\d{3}\.\d{3}\b'),
    },
    # ── Turkey ──────────────────────────────────────────────────────
    'Europe - Turkey': {
        'Turkey TC Kimlik': re.compile(r'\b[1-9]\d{10}\b'),
        'Turkey Passport': re.compile(r'\b[A-Z]\d{7}\b'),
        'Turkey DL': re.compile(r'\b\d{6}\b'),
        'Turkey Tax ID': re.compile(r'\b\d{10}\b'),
    },
    # ── Austria ─────────────────────────────────────────────────────
    'Europe - Austria': {
        'Austria SVN': re.compile(r'\b\d{4}[-\s]?\d{6}\b'),
        'Austria Passport': re.compile(r'\b[A-Z]\d{7}\b'),
        'Austria ID Card': re.compile(r'\b\d{8}\b'),
        'Austria DL': re.compile(r'\b\d{8}\b'),
        'Austria Tax Number': re.compile(r'\b\d{2}-?\d{3}/?\d{4}\b'),
    },
    # ── Belgium ─────────────────────────────────────────────────────
    'Europe - Belgium': {
        'Belgium NRN': re.compile(r'\b\d{2}[.\s]?\d{2}[.\s]?\d{2}[-.\s]?\d{3}[.\s]?\d{2}\b'),
        'Belgium Passport': re.compile(r'\b[A-Z]{2}\d{6}\b'),
        'Belgium DL': re.compile(r'\b\d{10}\b'),
        'Belgium VAT': re.compile(r'\bBE\s?0?\d{3}\.?\d{3}\.?\d{3}\b', re.IGNORECASE),
    },
    # ── Ireland ─────────────────────────────────────────────────────
    'Europe - Ireland': {
        'Ireland PPS': re.compile(r'\b\d{7}[A-Z]{1,2}\b'),
        'Ireland Passport': re.compile(r'\b[A-Z]{2}\d{7}\b'),
        'Ireland DL': re.compile(r'\b\d{3}-?\d{3}-?\d{3}\b'),
        'Ireland Eircode': re.compile(r'\b[A-Z]\d{2}\s?[A-Z0-9]{4}\b'),
    },
    # ── Denmark ─────────────────────────────────────────────────────
    'Europe - Denmark': {
        'Denmark CPR': re.compile(r'\b[0-3]\d[01]\d{3}[-]?\d{4}\b'),
        'Denmark Passport': re.compile(r'\b\d{9}\b'),
        'Denmark DL': re.compile(r'\b\d{8}\b'),
    },
    # ── Finland ─────────────────────────────────────────────────────
    'Europe - Finland': {
        'Finland HETU': re.compile(r'\b[0-3]\d[01]\d{3}[-+A]\d{3}[A-Z0-9]\b'),
        'Finland Passport': re.compile(r'\b[A-Z]{2}\d{7}\b'),
        'Finland DL': re.compile(r'\b\d{8,10}\b'),
    },
    # ── Norway ──────────────────────────────────────────────────────
    'Europe - Norway': {
        'Norway FNR': re.compile(r'\b[0-3]\d[01]\d{3}\d{5}\b'),
        'Norway D-Number': re.compile(r'\b[4-7]\d[01]\d{3}\d{5}\b'),
        'Norway Passport': re.compile(r'\b\d{8}\b'),
        'Norway DL': re.compile(r'\b\d{11}\b'),
    },
    # ── Czech Republic ──────────────────────────────────────────────
    'Europe - Czech Republic': {
        'Czech Birth Number': re.compile(r'\b\d{2}[0-7]\d[0-3]\d/?-?\d{3,4}\b'),
        'Czech Passport': re.compile(r'\b\d{8}\b'),
        'Czech DL': re.compile(r'\b[A-Z]{2}\d{6}\b'),
        'Czech ICO': re.compile(r'\b\d{8}\b'),
    },
    # ── Hungary ─────────────────────────────────────────────────────
    'Europe - Hungary': {
        'Hungary Personal ID': re.compile(r'\b\d[-]?\d{6}[-]?\d{4}\b'),
        'Hungary TAJ': re.compile(r'\b\d{3}\s?\d{3}\s?\d{3}\b'),
        'Hungary Tax Number': re.compile(r'\b\d{10}\b'),
        'Hungary Passport': re.compile(r'\b[A-Z]{2}\d{6,7}\b'),
        'Hungary DL': re.compile(r'\b[A-Z]{2}\d{6}\b'),
    },
    # ── Romania ─────────────────────────────────────────────────────
    'Europe - Romania': {
        'Romania CNP': re.compile(r'\b[1-8]\d{12}\b'),
        'Romania CIF': re.compile(r'\b\d{2,10}\b'),
        'Romania Passport': re.compile(r'\b\d{8,9}\b'),
        'Romania DL': re.compile(r'\b\d{9}\b'),
    },
    # ── Greece ──────────────────────────────────────────────────────
    'Europe - Greece': {
        'Greece AFM': re.compile(r'\b\d{9}\b'),
        'Greece AMKA': re.compile(r'\b[0-3]\d[01]\d{3}\d{5}\b'),
        'Greece ID Card': re.compile(r'\b[A-Z]{2}\d{6}\b'),
        'Greece Passport': re.compile(r'\b[A-Z]{2}\d{7}\b'),
        'Greece DL': re.compile(r'\b[A-Z]{2}\d{6}\b'),
    },
    # ── Croatia ─────────────────────────────────────────────────────
    'Europe - Croatia': {
        'Croatia OIB': re.compile(r'\b\d{11}\b'),
        'Croatia Passport': re.compile(r'\b\d{9}\b'),
        'Croatia ID Card': re.compile(r'\b\d{9}\b'),
        'Croatia DL': re.compile(r'\b\d{8,9}\b'),
    },
    # ── Bulgaria ────────────────────────────────────────────────────
    'Europe - Bulgaria': {
        'Bulgaria EGN': re.compile(r'\b\d{10}\b'),
        'Bulgaria LNC': re.compile(r'\b\d{10}\b'),
        'Bulgaria ID Card': re.compile(r'\b\d{9}\b'),
        'Bulgaria Passport': re.compile(r'\b\d{9}\b'),
    },
    # ── Slovakia ────────────────────────────────────────────────────
    'Europe - Slovakia': {
        'Slovakia Birth Number': re.compile(r'\b\d{2}[0-7]\d[0-3]\d/?-?\d{3,4}\b'),
        'Slovakia Passport': re.compile(r'\b[A-Z]{2}\d{6}\b'),
        'Slovakia DL': re.compile(r'\b[A-Z]{2}\d{6}\b'),
    },
    # ── Lithuania ───────────────────────────────────────────────────
    'Europe - Lithuania': {
        'Lithuania Asmens Kodas': re.compile(r'\b[3-6]\d{2}[01]\d[0-3]\d{5}\b'),
        'Lithuania Passport': re.compile(r'\b\d{8}\b'),
        'Lithuania DL': re.compile(r'\b\d{8}\b'),
    },
    # ── Latvia ──────────────────────────────────────────────────────
    'Europe - Latvia': {
        'Latvia Personas Kods': re.compile(r'\b[0-3]\d[01]\d{3}[-]?\d{5}\b'),
        'Latvia Passport': re.compile(r'\b[A-Z]{2}\d{7}\b'),
        'Latvia DL': re.compile(r'\b[A-Z]{2}\d{6}\b'),
    },
    # ── Estonia ─────────────────────────────────────────────────────
    'Europe - Estonia': {
        'Estonia Isikukood': re.compile(r'\b[1-6]\d{2}[01]\d[0-3]\d{5}\b'),
        'Estonia Passport': re.compile(r'\b[A-Z]{2}\d{7}\b'),
        'Estonia DL': re.compile(r'\b[A-Z]{2}\d{6}\b'),
    },
    # ── Slovenia ────────────────────────────────────────────────────
    'Europe - Slovenia': {
        'Slovenia EMSO': re.compile(r'\b[0-3]\d[01]\d{3}\d{6}\d\b'),
        'Slovenia Tax Number': re.compile(r'\b\d{8}\b'),
        'Slovenia Passport': re.compile(r'\b[A-Z]{2}\d{7}\b'),
        'Slovenia DL': re.compile(r'\b\d{8}\b'),
    },
    # ── Luxembourg ──────────────────────────────────────────────────
    'Europe - Luxembourg': {
        'Luxembourg NIN': re.compile(r'\b\d{4}[01]\d[0-3]\d\d{5}\b'),
        'Luxembourg Passport': re.compile(r'\b[A-Z]{2}\d{6}\b'),
        'Luxembourg DL': re.compile(r'\b\d{6}\b'),
    },
    # ── Malta ───────────────────────────────────────────────────────
    'Europe - Malta': {
        'Malta ID Card': re.compile(r'\b\d{3,7}[A-Z]\b'),
        'Malta Passport': re.compile(r'\b\d{7}\b'),
        'Malta TIN': re.compile(r'\b\d{3,9}[A-Z]?\b'),
    },
    # ── Cyprus ──────────────────────────────────────────────────────
    'Europe - Cyprus': {
        'Cyprus ID Card': re.compile(r'\b\d{7,8}\b'),
        'Cyprus Passport': re.compile(r'\b[A-Z]\d{7,8}\b'),
        'Cyprus TIN': re.compile(r'\b\d{8}[A-Z]\b'),
    },
    # ── Iceland ─────────────────────────────────────────────────────
    'Europe - Iceland': {
        'Iceland Kennitala': re.compile(r'\b[0-3]\d[01]\d{3}[-]?\d{4}\b'),
        'Iceland Passport': re.compile(r'\b[A-Z]\d{7}\b'),
    },
    # ── Liechtenstein ───────────────────────────────────────────────
    'Europe - Liechtenstein': {
        'Liechtenstein PIN': re.compile(r'\b\d{12}\b'),
        'Liechtenstein Passport': re.compile(r'\b[A-Z]\d{5}\b'),
    },
    # ── EU-wide ─────────────────────────────────────────────────────
    'Europe - EU': {
        'EU ETD': re.compile(r'\b[A-Z]{3}\d{6}\b'),
        'EU VAT Generic': re.compile(r'\b(?:AT|BE|BG|CY|CZ|DE|DK|EE|EL|ES|FI|FR|HR|HU|IE|IT|LT|LU|LV|MT|NL|PL|PT|RO|SE|SI|SK)[A-Z0-9]{8,12}\b'),
    },
}
