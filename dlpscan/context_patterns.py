CONTEXT_KEYWORDS = {
    'Personal Identification': {
        'Identifiers': {
            'Canada SIN': ['social insurance number', 'sin'],
            'USA SSN': ['social security number', 'ssn'],
            'UK NIN': ['national insurance number', 'nin'],
            'Singapore NIRC': ['national registration identity card', 'nric'],
            'Australia TFN': ['tax file number', 'tfn'],
            'India PAN': ['permanent account number', 'pan'],
            'Germany ID': ['identification number'],
            'Brazil CPF': ['cpf'],
            'Spain DNI/NIE': ['dni', 'nie'],
        },
        'distance': 20,
    },
    'Credit Card Numbers': {
        'Identifiers': {
            'Visa': ['visa', 'cc', 'credit card'],
            'MasterCard': ['mastercard', 'mc', 'credit card'],
            'Amex': ['amex', 'american express', 'credit card'],
            'Discover': ['discover', 'credit card'],
        },
        'distance': 30,
    },
    'Driver Licenses': {
        'Identifiers': {
            'Generic': ['driver\'s license number', 'dl number', 'driving license', 'license id'],
            'California DL': ['california driver\'s license'],
            'New York DL': ['new york driver\'s license'],
            'India DL': ['india driver\'s license'],
            'Ontario': ['ontario driver\'s license'],
            'British Columbia': ['british columbia driver\'s license'],
            'Alberta DL': ['alberta driver\'s license'],
            'Quebec DL': ['quebec driver\'s license'],
            'Nova Scotia DL': ['nova scotia driver\'s license'],
        },
        'distance': 20,
    },
    'Passports': {
        'Identifiers': {
            'Canada': ['canadian passport'],
            'USA Passport': ['us passport'],
            'EU ETD': ['eu emergency travel document'],
            'Japan Passport': ['japanese passport'],
        },
        'distance': 20,
    },
    'Health Cards': {
        'Identifiers': {
            'Ontario': ['ontario health card', 'on health', 'on health card'],
            'British NHS': ['british nhs number'],
            'Australia Medicare': ['australian medicare'],
            'Alberta HC': ['alberta health card', 'alberta hc', 'ab health', 'ab health card'],
            'Quebec HC': ['quebec health card'],
            'Nova Scotia HC': ['nova scotia health card'],
        },
        'distance': 20,
    },
    'Bank Account Numbers': {
        'Identifiers': {
            'IBAN Generic': ['iban', 'international bank account number'],
            'USA Routing Number': ['us routing number'],
            'UK Sort Code': ['uk sort code'],
            'SWIFT/BIC': ['swift', 'bic', 'bank identifier code'],
        },
        'distance': 30,
    },
}