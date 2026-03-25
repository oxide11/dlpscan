CONTEXT_KEYWORDS = {

    # #########################################################################
    #  1.  G E N E R I C   P A T T E R N S
    # #########################################################################

    'Credit Card Numbers': {
        'Identifiers': {
            'Visa': ['visa', 'cc', 'credit card', 'card number', 'card no'],
            'MasterCard': ['mastercard', 'mc', 'credit card', 'card number', 'card no'],
            'Amex': ['amex', 'american express', 'credit card', 'card number'],
            'Discover': ['discover', 'credit card', 'card number'],
            'JCB': ['jcb', 'credit card', 'card number'],
            'Diners Club': ['diners club', 'diners', 'credit card', 'card number'],
            'UnionPay': ['unionpay', 'union pay', 'credit card', 'card number'],
        },
        'distance': 50,
    },
    'Contact Information': {
        'Identifiers': {
            'Email Address': ['email', 'e-mail', 'email address', 'mail to', 'contact'],
            'E.164 Phone Number': ['phone', 'telephone', 'tel', 'mobile', 'contact number'],
            'IPv4 Address': ['ip address', 'ip', 'server', 'host', 'network'],
            'IPv6 Address': ['ip address', 'ipv6', 'server', 'host', 'network'],
            'MAC Address': ['mac address', 'hardware address', 'physical address', 'mac'],
        },
        'distance': 50,
    },
    'Banking and Financial': {
        'Identifiers': {
            'IBAN Generic': ['iban', 'international bank account number'],
            'SWIFT/BIC': ['swift', 'bic', 'bank identifier code', 'swift code'],
        },
        'distance': 50,
    },
    'Cryptocurrency': {
        'Identifiers': {
            'Bitcoin Address (Legacy)': ['bitcoin', 'btc', 'wallet', 'crypto'],
            'Bitcoin Address (Bech32)': ['bitcoin', 'btc', 'segwit', 'wallet'],
            'Ethereum Address': ['ethereum', 'eth', 'ether', 'wallet', 'crypto'],
            'Litecoin Address': ['litecoin', 'ltc', 'wallet'],
            'Bitcoin Cash Address': ['bitcoin cash', 'bch', 'wallet'],
            'Monero Address': ['monero', 'xmr', 'wallet'],
            'Ripple Address': ['ripple', 'xrp', 'wallet'],
        },
        'distance': 50,
    },
    'Vehicle Identification': {
        'Identifiers': {
            'VIN': ['vin', 'vehicle identification', 'vehicle id', 'chassis number',
                    'vehicle number'],
        },
        'distance': 50,
    },
    'Dates': {
        'Identifiers': {
            'Date ISO': ['date of birth', 'dob', 'birth date', 'birthday', 'born on',
                         'born', 'birthdate'],
            'Date US': ['date of birth', 'dob', 'birth date', 'birthday', 'born on',
                        'born', 'birthdate'],
            'Date EU': ['date of birth', 'dob', 'birth date', 'birthday', 'born on',
                        'born', 'birthdate'],
        },
        'distance': 50,
    },
    'URLs with Credentials': {
        'Identifiers': {
            'URL with Password': ['url', 'link', 'endpoint', 'connection', 'connect'],
            'URL with Token': ['url', 'link', 'endpoint', 'api', 'callback'],
        },
        'distance': 80,
    },
    'Generic Secrets': {
        'Identifiers': {
            'Bearer Token': ['authorization', 'bearer', 'auth token'],
            'JWT Token': ['jwt', 'json web token', 'auth', 'token'],
            'Private Key': ['private key', 'rsa', 'ssh key', 'pem'],
            'Generic API Key': ['api key', 'api_key', 'apikey', 'api secret'],
            'Generic Secret Assignment': ['password', 'secret', 'credential', 'passwd'],
            'Database Connection String': ['database', 'db connection', 'connection string',
                                           'mongodb', 'postgres', 'mysql', 'redis'],
        },
        'distance': 80,
    },

    # #########################################################################
    #  2.  C U S T O M   P A T T E R N S
    # #########################################################################

    'Cloud Provider Secrets': {
        'Identifiers': {
            'AWS Access Key': ['aws', 'amazon', 'access key', 'aws key'],
            'AWS Secret Key': ['aws secret', 'secret access key', 'aws_secret'],
            'Google API Key': ['google', 'gcp', 'google api', 'google cloud'],
        },
        'distance': 80,
    },
    'Code Platform Secrets': {
        'Identifiers': {
            'GitHub Token (Classic)': ['github', 'gh token', 'personal access token'],
            'GitHub Token (Fine-Grained)': ['github', 'fine-grained', 'pat'],
            'GitHub OAuth Token': ['github oauth', 'oauth token'],
            'NPM Token': ['npm', 'node package', 'npm token'],
            'PyPI Token': ['pypi', 'python package', 'pip'],
        },
        'distance': 80,
    },
    'Payment Service Secrets': {
        'Identifiers': {
            'Stripe Secret Key': ['stripe', 'payment', 'stripe secret'],
            'Stripe Publishable Key': ['stripe', 'publishable', 'stripe key'],
        },
        'distance': 80,
    },
    'Messaging Service Secrets': {
        'Identifiers': {
            'Slack Bot Token': ['slack', 'bot token', 'slack bot'],
            'Slack User Token': ['slack', 'user token', 'slack user'],
            'Slack Webhook': ['slack', 'webhook', 'incoming webhook'],
            'SendGrid API Key': ['sendgrid', 'email api'],
            'Twilio API Key': ['twilio', 'sms', 'messaging'],
            'Mailgun API Key': ['mailgun', 'email'],
        },
        'distance': 80,
    },

    # #########################################################################
    #  3.  G E O G R A P H I C   R E G I O N S
    # #########################################################################

    # --- North America ---
    'North America - United States': {
        'Identifiers': {
            'USA SSN': ['social security number', 'ssn', 'social security no'],
            'USA ITIN': ['individual taxpayer', 'itin', 'taxpayer identification'],
            'USA EIN': ['employer identification', 'ein', 'federal tax id', 'fein'],
            'USA Passport': ['us passport', 'usa passport', 'american passport', 'passport number'],
            'USA Routing Number': ['routing number', 'aba routing', 'routing transit'],
            'US DEA Number': ['dea number', 'dea registration', 'dea no', 'drug enforcement'],
            'US NPI': ['npi', 'national provider identifier', 'provider number'],
            'US MBI': ['mbi', 'medicare beneficiary', 'beneficiary identifier'],
            'US Phone Number': ['phone', 'telephone', 'tel', 'cell', 'mobile', 'call', 'fax'],
            'California DL': ["california driver's license", 'california dl'],
            'New York DL': ["new york driver's license", 'new york dl', 'ny dl'],
            'Generic DL': ["driver's license", 'dl number', 'driving license', 'license id',
                           'driver license', 'drivers license', 'licence number'],
        },
        'distance': 50,
    },
    'North America - Canada': {
        'Identifiers': {
            'Canada SIN': ['social insurance number', 'sin', 'social insurance no'],
            'Canada BN': ['business number', 'canada bn', 'cra business'],
            'Canada Passport': ['canadian passport', 'canada passport', 'passport canada'],
            'Canada Bank Code': ['transit number', 'institution number', 'bank transit'],
            'Ontario DL': ["ontario driver's license", 'ontario dl'],
            'Ontario HC': ['ontario health card', 'on health', 'on health card', 'ohip'],
            'British Columbia DL': ["british columbia driver's license", 'bc dl'],
            'Alberta DL': ["alberta driver's license", 'alberta dl'],
            'Alberta HC': ['alberta health card', 'alberta hc', 'ab health', 'ab health card', 'ahcip'],
            'Quebec DL': ["quebec driver's license", 'quebec dl'],
            'Quebec HC': ['quebec health card', 'ramq', 'carte soleil'],
            'Nova Scotia DL': ["nova scotia driver's license", 'nova scotia dl'],
            'Nova Scotia HC': ['nova scotia health card', 'msi number', 'msi card'],
        },
        'distance': 50,
    },
    'North America - Mexico': {
        'Identifiers': {
            'Mexico CURP': ['curp', 'clave unica', 'population registry'],
            'Mexico RFC': ['rfc', 'registro federal', 'federal taxpayer'],
        },
        'distance': 50,
    },

    # --- Europe ---
    'Europe - United Kingdom': {
        'Identifiers': {
            'UK NIN': ['national insurance number', 'nin', 'national insurance no'],
            'UK UTR': ['unique taxpayer reference', 'utr', 'tax reference'],
            'UK Passport': ['uk passport', 'british passport', 'united kingdom passport'],
            'UK Sort Code': ['sort code', 'uk sort', 'bank sort'],
            'British NHS': ['british nhs number', 'nhs number', 'nhs no', 'national health service'],
            'UK Phone Number': ['phone', 'telephone', 'tel', 'mobile', 'uk phone'],
        },
        'distance': 50,
    },
    'Europe - Germany': {
        'Identifiers': {
            'Germany ID': ['identification number', 'personalausweis', 'german id'],
            'Germany Passport': ['german passport', 'germany passport', 'reisepass'],
        },
        'distance': 50,
    },
    'Europe - France': {
        'Identifiers': {
            'France NIR': ['insee', 'nir', 'french social security', 'securite sociale'],
            'France Passport': ['french passport', 'france passport', 'passeport'],
        },
        'distance': 50,
    },
    'Europe - Italy': {
        'Identifiers': {
            'Italy Codice Fiscale': ['codice fiscale', 'fiscal code', 'italian tax'],
        },
        'distance': 50,
    },
    'Europe - Netherlands': {
        'Identifiers': {
            'Netherlands BSN': ['burgerservicenummer', 'bsn', 'citizen service number'],
        },
        'distance': 50,
    },
    'Europe - Spain': {
        'Identifiers': {
            'Spain DNI/NIE': ['dni', 'nie', 'documento nacional'],
        },
        'distance': 50,
    },
    'Europe - Poland': {
        'Identifiers': {
            'Poland PESEL': ['pesel', 'polish id', 'personal identification number'],
        },
        'distance': 50,
    },
    'Europe - Sweden': {
        'Identifiers': {
            'Sweden PIN': ['personnummer', 'swedish id', 'personal identity number'],
        },
        'distance': 50,
    },
    'Europe - Portugal': {
        'Identifiers': {
            'Portugal NIF': ['nif', 'contribuinte', 'tax identification'],
        },
        'distance': 50,
    },
    'Europe - Switzerland': {
        'Identifiers': {
            'Switzerland AHV': ['ahv', 'avs', 'swiss social security'],
        },
        'distance': 50,
    },
    'Europe - Turkey': {
        'Identifiers': {
            'Turkey TC Kimlik': ['tc kimlik', 'turkish id', 'kimlik numarasi'],
        },
        'distance': 50,
    },
    'Europe - EU': {
        'Identifiers': {
            'EU ETD': ['eu emergency travel document', 'etd', 'emergency travel'],
        },
        'distance': 50,
    },

    # --- Asia-Pacific ---
    'Asia-Pacific - India': {
        'Identifiers': {
            'India PAN': ['permanent account number', 'pan', 'pan card'],
            'India Aadhaar': ['aadhaar', 'aadhar', 'aadhaar number', 'uid number'],
            'India Passport': ['indian passport', 'india passport'],
            'India DL': ["india driver's license", 'indian dl', 'driving licence india'],
        },
        'distance': 50,
    },
    'Asia-Pacific - Singapore': {
        'Identifiers': {
            'Singapore NIRC': ['national registration identity card', 'nric'],
        },
        'distance': 50,
    },
    'Asia-Pacific - Australia': {
        'Identifiers': {
            'Australia TFN': ['tax file number', 'tfn'],
            'Australia Medicare': ['australian medicare', 'medicare number', 'medicare card'],
            'Australia Passport': ['australian passport', 'australia passport'],
        },
        'distance': 50,
    },
    'Asia-Pacific - Japan': {
        'Identifiers': {
            'Japan My Number': ['my number', 'individual number', 'kojin bango'],
            'Japan Passport': ['japanese passport', 'japan passport'],
        },
        'distance': 50,
    },
    'Asia-Pacific - South Korea': {
        'Identifiers': {
            'South Korea RRN': ['resident registration', 'rrn', 'jumin deungnok'],
        },
        'distance': 50,
    },
    'Asia-Pacific - China': {
        'Identifiers': {
            'China Resident ID': ['resident id', 'identity card', 'shenfenzheng'],
            'China Passport': ['chinese passport', 'china passport'],
        },
        'distance': 50,
    },

    # --- South America ---
    'South America - Brazil': {
        'Identifiers': {
            'Brazil CPF': ['cpf', 'cadastro de pessoas fisicas'],
            'Brazil Passport': ['brazilian passport', 'brazil passport'],
        },
        'distance': 50,
    },

    # --- Africa ---
    'Africa - South Africa': {
        'Identifiers': {
            'South Africa ID': ['south african id', 'sa id', 'identity number'],
        },
        'distance': 50,
    },
}
