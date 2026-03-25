

PII_IDENTIFIERS_CONTEXT = {
    'Personal Identifiers': {
        'Identifiers': {
            'Date of Birth': ['date of birth', 'dob', 'born on', 'birth date', 'birthday', 'birthdate', 'd.o.b'],
            'Age Value': ['age', 'years old', 'yr old', 'yrs old', 'aged', 'age group'],
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
            'US ZIP Code': ['zip', 'zip code', 'zipcode', 'postal code', 'mailing address', 'zip+4'],
            'UK Postcode': ['postcode', 'post code', 'postal code', 'uk address'],
            'Canada Postal Code': ['postal code', 'code postal', 'canadian address'],
            'Australia Postcode': ['postcode', 'post code', 'australian address'],
            'Germany PLZ': ['plz', 'postleitzahl', 'postal code', 'german address'],
            'Japan Postal Code': ['postal code', 'yubin bangou', 'japanese address'],
            'India PIN Code': ['pin code', 'pincode', 'postal index number', 'indian address'],
            'Brazil CEP': ['cep', 'codigo postal', 'brazilian address'],
        },
        'distance': 50,
    },
    'Device Identifiers': {
        'Identifiers': {
            'IMEI': ['imei', 'international mobile equipment identity', 'device imei', 'handset id', 'phone imei'],
            'IMSI': ['imsi', 'international mobile subscriber', 'subscriber identity', 'sim id'],
            'Android Device ID': ['android id', 'device id', 'android device', 'ssaid'],
            'IDFA/IDFV': ['idfa', 'idfv', 'advertising identifier', 'identifier for advertisers', 'vendor identifier', 'apple device id'],
            'Device Serial Number': ['serial number', 'serial no', 'sn', 'device serial', 'hardware serial', 'serial#'],
        },
        'distance': 50,
    },
    'Medical Identifiers': {
        'Identifiers': {
            'Medical Record Number': ['mrn', 'medical record', 'patient id', 'patient number', 'chart number', 'medical id', 'health record'],
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
            'Insurance Group Number': ['group number', 'group no', 'group id', 'plan group', 'insurance group', 'grp'],
            'Insurance Claim Number': ['claim number', 'claim no', 'claim id', 'claim#', 'claims reference', 'incident number'],
        },
        'distance': 50,
    },
    'Authentication Tokens': {
        'Identifiers': {
            'OTP Code': ['otp', 'one-time password', 'one time password', 'verification code', 'two-factor', '2fa', 'mfa code', 'authenticator code', 'totp'],
            'Session ID': ['session id', 'session_id', 'sessionid', 'sess_id', 'session token', 'phpsessid', 'jsessionid', 'asp.net_sessionid'],
            'CSRF Token': ['csrf', 'csrf_token', 'xsrf', 'anti-forgery', 'request token', 'authenticity_token', '_token'],
            'Refresh Token': ['refresh_token', 'refresh token', 'rt_token', 'oauth refresh'],
        },
        'distance': 50,
    },
    'Social Media Identifiers': {
        'Identifiers': {
            'Twitter Handle': ['twitter', 'tweet', '@', 'x.com', 'twitter handle', 'twitter username', 'follow'],
            'Hashtag': ['hashtag', 'tagged', 'trending', 'topic'],
            'Social Media User ID': ['user id', 'user_id', 'userid', 'profile id', 'account id', 'facebook id', 'instagram id', 'tiktok id'],
        },
        'distance': 50,
    },
    'Education Identifiers': {
        'Identifiers': {
            'Student ID': ['student id', 'student number', 'student no', 'enrollment number', 'matriculation', 'university id', 'school id'],
            'EDU Email': ['student email', 'edu email', 'university email', 'academic email', 'school email', 'college email'],
            'GPA': ['gpa', 'grade point average', 'cumulative gpa', 'cgpa', 'academic standing', 'grades'],
        },
        'distance': 50,
    },
    'Legal Identifiers': {
        'Identifiers': {
            'US Federal Case Number': ['case number', 'case no', 'docket', 'civil action', 'case#', 'filing number'],
            'Court Docket Number': ['docket number', 'docket no', 'court case', 'case file', 'case reference', 'court number'],
            'Bar Number': ['bar number', 'bar no', 'attorney number', 'bar id', 'bar license', 'attorney id'],
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
