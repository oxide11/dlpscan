


PII_IDENTIFIERS_CONTEXT = {
    'Personal Identifiers': {
        'Identifiers': {
            'Date of Birth': ['date of birth', 'dob', 'born on', 'birth date', 'birthday', 'birthdate', 'd.o.b'],
            'Gender Marker': ['gender', 'sex', 'identified as', 'gender identity', 'biological sex'],
        },
        'distance': 30,
    },
    'Geolocation': {
        'Identifiers': {
            'GPS Coordinates': ['latitude', 'longitude', 'lat', 'lng', 'lon', 'coordinates', 'gps', 'geolocation', 'location', 'coord'],
            'GPS DMS': ['latitude', 'longitude', 'coordinates', 'gps', 'dms', 'degrees minutes seconds'],
            'Geohash': ['geohash', 'geo hash', 'location hash'],
        },
        'distance': 50,
    },
    'Postal Codes': {
        'Identifiers': {
            'US ZIP+4 Code': ['zip', 'zip code', 'zipcode', 'postal code', 'mailing address', 'zip+4'],
            'UK Postcode': ['postcode', 'post code', 'postal code', 'uk address'],
            'Canada Postal Code': ['postal code', 'code postal', 'canadian address'],
            'Japan Postal Code': ['postal code', 'yubin bangou', 'japanese address'],
            'Brazil CEP': ['cep', 'codigo postal', 'brazilian address'],
        },
        'distance': 50,
    },
    'Device Identifiers': {
        'Identifiers': {
            'IMEI': ['imei', 'international mobile equipment identity', 'device imei', 'handset id', 'phone imei', 'equipment identity'],
            'IMEISV': ['imeisv', 'imei software version', 'imei sv', 'software version number'],
            'MEID': ['meid', 'mobile equipment identifier', 'cdma device', 'equipment id'],
            'ICCID': ['iccid', 'sim card number', 'sim number', 'integrated circuit card', 'sim id', 'sim serial'],
            'IDFA/IDFV': ['idfa', 'idfv', 'advertising identifier', 'identifier for advertisers', 'vendor identifier', 'apple device id'],
        },
        'distance': 50,
    },
    'Medical Identifiers': {
        'Identifiers': {
            'Health Plan ID': ['health plan', 'insurance id', 'beneficiary', 'member id', 'subscriber id'],
            'DEA Number': ['dea', 'dea number', 'drug enforcement', 'prescriber', 'controlled substance'],
            'ICD-10 Code': ['icd', 'icd-10', 'diagnosis code', 'diagnostic code', 'condition code', 'icd code'],
            'NDC Code': ['ndc', 'national drug code', 'drug code', 'medication code', 'pharmaceutical'],
        },
        'distance': 50,
    },
    'Insurance Identifiers': {
        'Identifiers': {
            'Insurance Policy Number': ['policy number', 'policy no', 'insurance policy', 'policy id', 'coverage number', 'policy#'],
            'Insurance Claim Number': ['claim number', 'claim no', 'claim id', 'claim#', 'claims reference', 'incident number'],
        },
        'distance': 50,
    },
    'Authentication Tokens': {
        'Identifiers': {
            'Session ID': ['session id', 'session_id', 'sessionid', 'sess_id', 'session token', 'phpsessid', 'jsessionid', 'asp.net_sessionid'],
        },
        'distance': 50,
    },
    'Social Media Identifiers': {
        'Identifiers': {
            'Twitter Handle': ['twitter', 'tweet', 'x.com', 'twitter handle', 'twitter username', 'follow'],
            'Hashtag': ['hashtag', 'tagged', 'trending', 'topic'],
        },
        'distance': 50,
    },
    'Education Identifiers': {
        'Identifiers': {
            'EDU Email': ['student email', 'edu email', 'university email', 'academic email', 'school email', 'college email'],
        },
        'distance': 50,
    },
    'Legal Identifiers': {
        'Identifiers': {
            'US Federal Case Number': ['case number', 'case no', 'docket', 'civil action', 'case#', 'filing number'],
            'Court Docket Number': ['docket number', 'docket no', 'court case', 'case file', 'case reference', 'court number'],
        },
        'distance': 50,
    },
    'Employment Identifiers': {
        'Identifiers': {
            'Employee ID': ['employee id', 'employee number', 'emp id', 'staff id', 'personnel number', 'emp no', 'worker id', 'badge number'],
            'Work Permit Number': ['work permit', 'work visa', 'employment authorization', 'ead', 'labor permit', 'work authorization'],
        },
        'distance': 50,
    },
    'Biometric Identifiers': {
        'Identifiers': {
            'Biometric Hash': ['biometric', 'fingerprint hash', 'fingerprint', 'facial recognition', 'iris scan', 'palm print', 'voiceprint', 'retina scan'],
            'Biometric Template ID': ['biometric template', 'facial template', 'fingerprint template', 'enrollment id', 'biometric id'],
        },
        'distance': 50,
    },
    'Property Identifiers': {
        'Identifiers': {
            'Parcel Number': ['parcel number', 'apn', 'assessor parcel', 'parcel id', 'lot number', 'property id'],
            'Title Deed Number': ['title number', 'deed number', 'deed of trust', 'title deed', 'land title', 'property title'],
        },
        'distance': 50,
    },
}
