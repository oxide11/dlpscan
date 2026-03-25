import re


LATIN_AMERICA_PATTERNS = {
    'Latin America - Brazil': {
        'Brazil CPF': re.compile(r'\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b'),
        'Brazil CNPJ': re.compile(r'\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b'),
        'Brazil RG': re.compile(r'\b\d{1,2}\.?\d{3}\.?\d{3}-?[\dXx]\b'),
        'Brazil CNH': re.compile(r'\b\d{11}\b'),
        'Brazil SUS Card': re.compile(r'\b[1-2]\d{10}00[01]\d\b|\b[789]\d{14}\b'),
        'Brazil Passport': re.compile(r'\b[A-Z]{2}\d{6}\b'),
    },
    'Latin America - Argentina': {
        'Argentina DNI': re.compile(r'\b\d{7,8}\b'),
        'Argentina CUIL/CUIT': re.compile(r'\b(?:20|2[3-7]|30|33)-?\d{8}-?\d\b'),
        'Argentina Passport': re.compile(r'\b[A-Z]{3}\d{6}\b'),
    },
    'Latin America - Colombia': {
        'Colombia Cedula': re.compile(r'\b\d{6,10}\b'),
        'Colombia NIT': re.compile(r'\b\d{3}\.?\d{3}\.?\d{3}-?\d\b'),
        'Colombia NUIP': re.compile(r'\b\d{6,10}\b'),
        'Colombia Passport': re.compile(r'\b[A-Z]{2}\d{6,7}\b'),
    },
    'Latin America - Chile': {
        'Chile RUN/RUT': re.compile(r'\b\d{1,2}\.?\d{3}\.?\d{3}-?[\dkK]\b'),
        'Chile Passport': re.compile(r'\b[A-Z]?\d{7,8}\b'),
    },
    'Latin America - Peru': {
        'Peru DNI': re.compile(r'\b\d{8}\b'),
        'Peru RUC': re.compile(r'\b(?:10|15|17|20)\d{9}\b'),
        'Peru Carnet Extranjeria': re.compile(r'\b\d{9,12}\b'),
        'Peru Passport': re.compile(r'\b[A-Z]{2}\d{6,7}\b'),
    },
    'Latin America - Venezuela': {
        'Venezuela Cedula': re.compile(r'\b[VvEe]-?\d{6,9}\b'),
        'Venezuela RIF': re.compile(r'\b[VEJGvejg]-?\d{8}-?\d\b'),
        'Venezuela Passport': re.compile(r'\b[A-Z]\d{7,8}\b'),
    },
    'Latin America - Ecuador': {
        'Ecuador Cedula': re.compile(r'\b\d{10}\b'),
        'Ecuador RUC': re.compile(r'\b\d{13}\b'),
        'Ecuador Passport': re.compile(r'\b[A-Z]\d{7,8}\b'),
    },
    'Latin America - Uruguay': {
        'Uruguay Cedula': re.compile(r'\b\d{1}\.?\d{3}\.?\d{3}-?\d\b'),
        'Uruguay RUT': re.compile(r'\b\d{12}\b'),
        'Uruguay Passport': re.compile(r'\b[A-Z]\d{6,8}\b'),
    },
    'Latin America - Paraguay': {
        'Paraguay Cedula': re.compile(r'\b\d{5,7}\b'),
        'Paraguay RUC': re.compile(r'\b\d{6,8}-?\d\b'),
        'Paraguay Passport': re.compile(r'\b[A-Z]\d{6,8}\b'),
    },
    'Latin America - Costa Rica': {
        'Costa Rica Cedula': re.compile(r'\b\d{1}-?\d{4}-?\d{4}\b'),
        'Costa Rica DIMEX': re.compile(r'\b\d{11,12}\b'),
        'Costa Rica Passport': re.compile(r'\b[A-Z]\d{8}\b'),
    },
}
