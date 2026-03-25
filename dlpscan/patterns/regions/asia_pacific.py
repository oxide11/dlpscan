import re

# Standard optional delimiter: matches dash, dot, space, or nothing.
_S = r'[-.\s/\\_\u2013\u2014\u00a0]?'


ASIA_PACIFIC_PATTERNS = {
    'Asia-Pacific - India': {
        'India PAN': re.compile(r'\b[A-Z]{5}\d{4}[A-Z]\b'),
        'India Aadhaar': re.compile(r'\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b'),
        'India Passport': re.compile(r'\b[A-Z][1-9]\d{5}[1-9]\b'),
        'India DL': re.compile(r'\b[A-Z]{2}[-\s]?\d{2}[-\s]?(?:19|20)\d{2}[-\s]?\d{7}\b'),
        'India Voter ID': re.compile(r'\b[A-Z]{3}\d{7}\b'),
        'India Ration Card': re.compile(r'\b\d{2}[\s-]?\d{8}\b'),
    },
    'Asia-Pacific - China': {
        'China Resident ID': re.compile(r'\b\d{6}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b'),
        'China Passport': re.compile(r'\b[EGD][A-Z]?\d{7,8}\b'),
        'Hong Kong ID': re.compile(r'\b[A-Z]{1,2}\d{6}\s?\(?[0-9A]\)?\b'),
        'Macau ID': re.compile(r'\b[1578]\d{6}\s?\(?[0-9]\)?\b'),
        'Taiwan National ID': re.compile(r'\b[A-Z][12489]\d{8}\b'),
    },
    'Asia-Pacific - Japan': {
        'Japan My Number': re.compile(r'\b\d{12}\b'),
        'Japan Passport': re.compile(r'\b[A-Z]{2}\d{7}\b'),
        'Japan DL': re.compile(r'\b\d{12}\b'),
        'Japan Juminhyo Code': re.compile(r'\b\d{11}\b'),
        'Japan Health Insurance': re.compile(r'\b\d{8}\b'),
        'Japan Residence Card': re.compile(r'\b[A-Z]{2}\d{8}[A-Z]{2}\b'),
    },
    'Asia-Pacific - South Korea': {
        'South Korea RRN': re.compile(r'\b\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])[-\s]?[1-8]\d{6}\b'),
        'South Korea Passport': re.compile(r'\b[MSROD]\d{8}\b'),
        'South Korea DL': re.compile(r'\b\d{2}[-\s]?\d{2}[-\s]?\d{6}[-\s]?\d{2}\b'),
    },
    'Asia-Pacific - Singapore': {
        'Singapore NRIC': re.compile(r'\b[ST]\d{7}[A-Z]\b'),
        'Singapore FIN': re.compile(r'\b[FGM]\d{7}[A-Z]\b'),
        'Singapore Passport': re.compile(r'\b[A-Z]\d{7}[A-Z]\b'),
        'Singapore DL': re.compile(r'\b[STFGM]\d{7}[A-Z]\b'),
    },
    'Asia-Pacific - Australia': {
        'Australia TFN': re.compile(r'\b\d{3}[\s]?\d{3}[\s]?\d{2,3}\b'),
        'Australia Medicare': re.compile(r'\b[2-6]\d{3}[\s]?\d{5}[\s]?\d[\s]?\d?\b'),
        'Australia Passport': re.compile(r'\b[A-Z]{1,2}\d{7}\b'),
        'Australia DL NSW': re.compile(r'\b\d{8}\b'),
        'Australia DL VIC': re.compile(r'\b\d{8,10}\b'),
        'Australia DL QLD': re.compile(r'\b\d{8,9}\b'),
        'Australia DL WA': re.compile(r'\b\d{7}\b'),
        'Australia DL SA': re.compile(r'\b[A-Z]?\d{5,6}\b'),
        'Australia DL TAS': re.compile(r'\b[A-Z]\d{5,6}\b'),
        'Australia DL ACT': re.compile(r'\b\d{6,10}\b'),
        'Australia DL NT': re.compile(r'\b\d{5,7}\b'),
    },
    'Asia-Pacific - New Zealand': {
        'New Zealand IRD': re.compile(r'\b\d{8,9}\b'),
        'New Zealand Passport': re.compile(r'\b[A-Z]{2}\d{6}\b'),
        'New Zealand NHI': re.compile(r'\b[A-HJ-NP-Z]{3}\d{4}\b'),
        'New Zealand DL': re.compile(r'\b[A-Z]{2}\d{6}\b'),
    },
    'Asia-Pacific - Philippines': {
        'Philippines PhilSys': re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),
        'Philippines TIN': re.compile(rf'\b\d{{3}}{_S}\d{{3}}{_S}\d{{3}}(?:{_S}\d{{3}})?\b'),
        'Philippines SSS': re.compile(rf'\b\d{{2}}{_S}\d{{7}}{_S}\d\b'),
        'Philippines PhilHealth': re.compile(rf'\b\d{{2}}{_S}\d{{9}}{_S}\d\b'),
        'Philippines Passport': re.compile(r'\b[A-Z]{1,2}\d{6,7}[A-Z]?\b'),
        'Philippines UMID': re.compile(rf'\b\d{{4}}{_S}\d{{7}}{_S}\d\b'),
    },
    'Asia-Pacific - Thailand': {
        'Thailand National ID': re.compile(r'\b\d[-\s]?\d{4}[-\s]?\d{5}[-\s]?\d{2}[-\s]?\d\b'),
        'Thailand Passport': re.compile(r'\b[A-Z]{2}\d{7}\b'),
        'Thailand DL': re.compile(r'\b\d{13}\b'),
        'Thailand Tax ID': re.compile(r'\b\d{13}\b'),
    },
    'Asia-Pacific - Malaysia': {
        'Malaysia MyKad': re.compile(r'\b\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])[-\s]?\d{2}[-\s]?\d{4}\b'),
        'Malaysia Passport': re.compile(r'\b[A-Z]\d{8}\b'),
    },
    'Asia-Pacific - Indonesia': {
        'Indonesia NIK': re.compile(r'\b\d{16}\b'),
        'Indonesia NPWP': re.compile(r'\b\d{2}\.?\d{3}\.?\d{3}\.?\d[-.]?\d{3}\.?\d{3}\b'),
        'Indonesia Passport': re.compile(r'\b[A-Z]{1,2}\d{6,7}\b'),
    },
    'Asia-Pacific - Vietnam': {
        'Vietnam CCCD': re.compile(r'\b\d{12}\b'),
        'Vietnam Passport': re.compile(r'\b[A-Z]\d{8}\b'),
        'Vietnam Tax Code': re.compile(r'\b\d{10}(?:-\d{3})?\b'),
    },
    'Asia-Pacific - Pakistan': {
        'Pakistan CNIC': re.compile(r'\b\d{5}[-\s]?\d{7}[-\s]?\d\b'),
        'Pakistan NICOP': re.compile(r'\b\d{5}[-\s]?\d{7}[-\s]?\d\b'),
        'Pakistan Passport': re.compile(r'\b[A-Z]{2}\d{7}\b'),
    },
    'Asia-Pacific - Bangladesh': {
        'Bangladesh NID': re.compile(r'\b(?:\d{10}|\d{17})\b'),
        'Bangladesh Passport': re.compile(r'\b[A-Z]{2}\d{7}\b'),
        'Bangladesh TIN': re.compile(r'\b\d{12}\b'),
    },
    'Asia-Pacific - Sri Lanka': {
        'Sri Lanka NIC Old': re.compile(r'\b\d{9}[VXvx]\b'),
        'Sri Lanka NIC New': re.compile(r'\b\d{12}\b'),
        'Sri Lanka Passport': re.compile(r'\b[A-Z]\d{7}\b'),
    },
}
