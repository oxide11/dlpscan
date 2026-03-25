import re

# Standard optional delimiter: matches dash, dot, space, or nothing.
_S = r'[-.\s/\\_\u2013\u2014\u00a0]?'


LATIN_AMERICA_PATTERNS = {
    'Latin America - Brazil': {
        'Brazil CPF': re.compile(rf'\b\d{{3}}{_S}\d{{3}}{_S}\d{{3}}{_S}\d{{2}}\b'),
        'Brazil CNPJ': re.compile(rf'\b\d{{2}}{_S}\d{{3}}{_S}\d{{3}}{_S}\d{{4}}{_S}\d{{2}}\b'),
        'Brazil RG': re.compile(rf'\b\d{{1,2}}{_S}\d{{3}}{_S}\d{{3}}{_S}[\dXx]\b'),
        'Brazil CNH': re.compile(r'\b\d{11}\b'),
        'Brazil SUS Card': re.compile(r'\b[1-2]\d{10}00[01]\d\b|\b[789]\d{14}\b'),
        'Brazil Passport': re.compile(r'\b[A-Z]{2}\d{6}\b'),
    },
    'Latin America - Argentina': {
        'Argentina DNI': re.compile(r'\b\d{7,8}\b'),
        'Argentina CUIL/CUIT': re.compile(rf'\b(?:20|2[3-7]|30|33){_S}\d{{8}}{_S}\d\b'),
        'Argentina Passport': re.compile(r'\b[A-Z]{3}\d{6}\b'),
    },
    'Latin America - Colombia': {
        'Colombia Cedula': re.compile(r'\b\d{6,10}\b'),
        'Colombia NIT': re.compile(rf'\b\d{{3}}{_S}\d{{3}}{_S}\d{{3}}{_S}\d\b'),
        'Colombia NUIP': re.compile(r'\b\d{6,10}\b'),
        'Colombia Passport': re.compile(r'\b[A-Z]{2}\d{6,7}\b'),
    },
    'Latin America - Chile': {
        'Chile RUN/RUT': re.compile(rf'\b\d{{1,2}}{_S}\d{{3}}{_S}\d{{3}}{_S}[\dkK]\b'),
        'Chile Passport': re.compile(r'\b[A-Z]?\d{7,8}\b'),
    },
    'Latin America - Peru': {
        'Peru DNI': re.compile(r'\b\d{8}\b'),
        'Peru RUC': re.compile(r'\b(?:10|15|17|20)\d{9}\b'),
        'Peru Carnet Extranjeria': re.compile(r'\b\d{9,12}\b'),
        'Peru Passport': re.compile(r'\b[A-Z]{2}\d{6,7}\b'),
    },
    'Latin America - Venezuela': {
        'Venezuela Cedula': re.compile(rf'\b[VvEe]{_S}\d{{6,9}}\b'),
        'Venezuela RIF': re.compile(rf'\b[VEJGvejg]{_S}\d{{8}}{_S}\d\b'),
        'Venezuela Passport': re.compile(r'\b[A-Z]\d{7,8}\b'),
    },
    'Latin America - Ecuador': {
        'Ecuador Cedula': re.compile(r'\b\d{10}\b'),
        'Ecuador RUC': re.compile(r'\b\d{13}\b'),
        'Ecuador Passport': re.compile(r'\b[A-Z]\d{7,8}\b'),
    },
    'Latin America - Uruguay': {
        'Uruguay Cedula': re.compile(rf'\b\d{{1}}{_S}\d{{3}}{_S}\d{{3}}{_S}\d\b'),
        'Uruguay RUT': re.compile(r'\b\d{12}\b'),
        'Uruguay Passport': re.compile(r'\b[A-Z]\d{6,8}\b'),
    },
    'Latin America - Paraguay': {
        'Paraguay Cedula': re.compile(r'\b\d{5,7}\b'),
        'Paraguay RUC': re.compile(rf'\b\d{{6,8}}{_S}\d\b'),
        'Paraguay Passport': re.compile(r'\b[A-Z]\d{6,8}\b'),
    },
    'Latin America - Costa Rica': {
        'Costa Rica Cedula': re.compile(rf'\b\d{{1}}{_S}\d{{4}}{_S}\d{{4}}\b'),
        'Costa Rica DIMEX': re.compile(r'\b\d{11,12}\b'),
        'Costa Rica Passport': re.compile(r'\b[A-Z]\d{8}\b'),
    },
}
