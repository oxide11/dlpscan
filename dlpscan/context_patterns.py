CONTEXT_KEYWORDS = {
    # The 'Personal Identification' category for sensitive personal information
    'Personal Identification': {
        # A list of keywords associated with personal identification
        'keywords': [
            'social insurance number', 'sin', 'social security number', 'ssn',
            'national insurance', 'nin', 'tax file number', 'tfn', 'permanent account number',
            'pan', 'citizen id', 'identification number', 'passport number', 'driver\'s license',
            'health insurance', 'medicare', 'cpf', 'nirc', 'dni', 'nie'
        ],
        # Proximity distance for detecting surrounding relevant text
        'distance': 20,
    },
    # The 'Credit Card' category for sensitive credit card information
    'Credit Card': {
        # A list of keywords associated with credit card information
        'keywords': [
            'cc', 'visa', 'mc', 'amex', 'mastercard', 'credit card', 'card number', 
            'cvv', 'cvc', 'card verification', 'expiry date', 'expiration date', 'credit',
            'debit card', 'charge card', 'bank card', 'account number', 'card holder'
        ],
        # Larger search range for proximity to credit card number contexts
        'distance': 30,  # This comment clarifies why the distance is set to 30 characters
    },
    # A new category for driver license related keywords
    'Driver Licenses': {
        # Keywords specifically related to driver's licenses
        'keywords': [
            'driver\'s license number', 'dl number', 'driving license', 'license id',
            'vehicle registration', 'driver license', 'licence number'
        ],
        # The specified proximity to utilize for this category
        'distance': 20,
    },
    # Another new category for passport related keywords
    'Passports': {
        # Keywords that are typically associated with passports
        'keywords': [
            'passport number', 'passport id', 'travel document number', 
            'document number', 'passport code'
        ],
        # Proximity measure for passport information detection
        'distance': 20,
    },
    # Category aimed at health card and medical identification numbers
    'Health Cards': {
        # Keywords indicating various forms of health identification
        'keywords': [
            'health card number', 'health number', 'medical card', 'insurance number', 
            'patient id', 'nhs number', 'medicare number', 'policy number'
        ],
        # Distance parameter for contextually relevant text close to health numbers
        'distance': 20,
    },
    # Category focusing on bank account numbers and related information
    'Bank Account Numbers': {
        # Keywords commonly found near or with bank account details
        'keywords': [
            'iban', 'routing number', 'sort code', 'swift', 'bic', 'bank account',
            'account number', 'beneficiary account', 'transit number', 'aba'
        ],
        # Increased search range due to the structured nature of banking details
        'distance': 30,  # Explains why a larger context is considered for bank accounts
    },
    # Placeholder for additional categories to extend the context keyword list
}
