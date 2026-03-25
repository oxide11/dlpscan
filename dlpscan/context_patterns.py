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

    # --- North America: United States ---
    'North America - United States': {
        'Identifiers': {
            # Federal identifiers
            'USA SSN': ['social security number', 'ssn', 'social security no'],
            'USA ITIN': ['individual taxpayer', 'itin', 'taxpayer identification'],
            'USA EIN': ['employer identification', 'ein', 'federal tax id', 'fein'],
            'USA Passport Book': ['us passport', 'usa passport', 'american passport',
                                  'passport number', 'passport book'],
            'USA Passport Card': ['passport card', 'us passport card', 'usa passport card'],
            'USA Routing Number': ['routing number', 'aba routing', 'routing transit'],
            'US DEA Number': ['dea number', 'dea registration', 'dea no', 'drug enforcement'],
            'US NPI': ['npi', 'national provider identifier', 'provider number'],
            'US MBI': ['mbi', 'medicare beneficiary', 'beneficiary identifier',
                       'medicare number', 'medicare id'],
            'US DoD ID': ['dod id', 'military id', 'edipi', 'cac card',
                          'common access card', 'department of defense'],
            'US Known Traveler Number': ['known traveler', 'ktn', 'global entry',
                                         'trusted traveler', 'pass id', 'nexus', 'sentri'],
            'US TSA PreCheck KTN': ['tsa precheck', 'tsa pre', 'precheck number',
                                     'known traveler'],
            'US Phone Number': ['phone', 'telephone', 'tel', 'cell', 'mobile', 'call', 'fax'],

            # State driver's licenses — all 50 + DC
            'Alabama DL': ["alabama driver's license", 'alabama dl', 'al dl'],
            'Alaska DL': ["alaska driver's license", 'alaska dl', 'ak dl'],
            'Arizona DL': ["arizona driver's license", 'arizona dl', 'az dl'],
            'Arkansas DL': ["arkansas driver's license", 'arkansas dl', 'ar dl'],
            'California DL': ["california driver's license", 'california dl', 'ca dl'],
            'Colorado DL': ["colorado driver's license", 'colorado dl', 'co dl'],
            'Connecticut DL': ["connecticut driver's license", 'connecticut dl', 'ct dl'],
            'Delaware DL': ["delaware driver's license", 'delaware dl', 'de dl'],
            'DC DL': ["dc driver's license", 'district of columbia dl', 'dc dl'],
            'Florida DL': ["florida driver's license", 'florida dl', 'fl dl'],
            'Georgia DL': ["georgia driver's license", 'georgia dl', 'ga dl'],
            'Hawaii DL': ["hawaii driver's license", 'hawaii dl', 'hi dl'],
            'Idaho DL': ["idaho driver's license", 'idaho dl', 'id dl'],
            'Illinois DL': ["illinois driver's license", 'illinois dl', 'il dl'],
            'Indiana DL': ["indiana driver's license", 'indiana dl', 'in dl'],
            'Iowa DL': ["iowa driver's license", 'iowa dl', 'ia dl'],
            'Kansas DL': ["kansas driver's license", 'kansas dl', 'ks dl'],
            'Kentucky DL': ["kentucky driver's license", 'kentucky dl', 'ky dl'],
            'Louisiana DL': ["louisiana driver's license", 'louisiana dl', 'la dl'],
            'Maine DL': ["maine driver's license", 'maine dl', 'me dl'],
            'Maryland DL': ["maryland driver's license", 'maryland dl', 'md dl'],
            'Massachusetts DL': ["massachusetts driver's license", 'massachusetts dl', 'ma dl'],
            'Michigan DL': ["michigan driver's license", 'michigan dl', 'mi dl'],
            'Minnesota DL': ["minnesota driver's license", 'minnesota dl', 'mn dl'],
            'Mississippi DL': ["mississippi driver's license", 'mississippi dl', 'ms dl'],
            'Missouri DL': ["missouri driver's license", 'missouri dl', 'mo dl'],
            'Montana DL': ["montana driver's license", 'montana dl', 'mt dl'],
            'Nebraska DL': ["nebraska driver's license", 'nebraska dl', 'ne dl'],
            'Nevada DL': ["nevada driver's license", 'nevada dl', 'nv dl'],
            'New Hampshire DL': ["new hampshire driver's license", 'new hampshire dl', 'nh dl'],
            'New Jersey DL': ["new jersey driver's license", 'new jersey dl', 'nj dl'],
            'New Mexico DL': ["new mexico driver's license", 'new mexico dl', 'nm dl'],
            'New York DL': ["new york driver's license", 'new york dl', 'ny dl'],
            'North Carolina DL': ["north carolina driver's license", 'north carolina dl', 'nc dl'],
            'North Dakota DL': ["north dakota driver's license", 'north dakota dl', 'nd dl'],
            'Ohio DL': ["ohio driver's license", 'ohio dl', 'oh dl'],
            'Oklahoma DL': ["oklahoma driver's license", 'oklahoma dl', 'ok dl'],
            'Oregon DL': ["oregon driver's license", 'oregon dl', 'or dl'],
            'Pennsylvania DL': ["pennsylvania driver's license", 'pennsylvania dl', 'pa dl'],
            'Rhode Island DL': ["rhode island driver's license", 'rhode island dl', 'ri dl'],
            'South Carolina DL': ["south carolina driver's license", 'south carolina dl', 'sc dl'],
            'South Dakota DL': ["south dakota driver's license", 'south dakota dl', 'sd dl'],
            'Tennessee DL': ["tennessee driver's license", 'tennessee dl', 'tn dl'],
            'Texas DL': ["texas driver's license", 'texas dl', 'tx dl'],
            'Utah DL': ["utah driver's license", 'utah dl', 'ut dl'],
            'Vermont DL': ["vermont driver's license", 'vermont dl', 'vt dl'],
            'Virginia DL': ["virginia driver's license", 'virginia dl', 'va dl'],
            'Washington DL': ["washington driver's license", 'washington dl', 'wa dl'],
            'West Virginia DL': ["west virginia driver's license", 'west virginia dl', 'wv dl'],
            'Wisconsin DL': ["wisconsin driver's license", 'wisconsin dl', 'wi dl'],
            'Wyoming DL': ["wyoming driver's license", 'wyoming dl', 'wy dl'],
        },
        'distance': 50,
    },
    'North America - US Generic DL': {
        'Identifiers': {
            'Generic US DL': ["driver's license", 'dl number', 'driving license', 'license id',
                              'driver license', 'drivers license', 'licence number',
                              'license number', 'dl no'],
        },
        'distance': 50,
    },

    # --- North America: Canada ---
    'North America - Canada': {
        'Identifiers': {
            # Federal identifiers
            'Canada SIN': ['social insurance number', 'sin', 'social insurance no'],
            'Canada BN': ['business number', 'canada bn', 'cra business'],
            'Canada Passport': ['canadian passport', 'canada passport', 'passport canada'],
            'Canada PR Card': ['permanent resident', 'pr card', 'permanent resident card',
                               'immigration', 'landed immigrant'],
            'Canada NEXUS': ['nexus', 'nexus card', 'pass id', 'trusted traveler',
                             'nexus number', 'cbp pass'],
            'Canada Bank Code': ['transit number', 'institution number', 'bank transit'],

            # Provincial driver's licences
            'Ontario DL': ["ontario driver's licence", 'ontario dl', 'on dl'],
            'Quebec DL': ["quebec driver's licence", 'quebec dl', 'qc dl',
                          'permis de conduire'],
            'British Columbia DL': ["british columbia driver's licence", 'bc dl',
                                    "bc driver's licence"],
            'Alberta DL': ["alberta driver's licence", 'alberta dl', 'ab dl'],
            'Saskatchewan DL': ["saskatchewan driver's licence", 'saskatchewan dl', 'sk dl'],
            'Manitoba DL': ["manitoba driver's licence", 'manitoba dl', 'mb dl'],
            'New Brunswick DL': ["new brunswick driver's licence", 'new brunswick dl', 'nb dl'],
            'Nova Scotia DL': ["nova scotia driver's licence", 'nova scotia dl', 'ns dl'],
            'PEI DL': ["pei driver's licence", 'prince edward island dl', 'pe dl'],
            'Newfoundland DL': ["newfoundland driver's licence", 'newfoundland dl', 'nl dl',
                                'labrador dl'],
            'Yukon DL': ["yukon driver's licence", 'yukon dl', 'yt dl'],
            'NWT DL': ["northwest territories driver's licence", 'nwt dl', 'nt dl'],
            'Nunavut DL': ["nunavut driver's licence", 'nunavut dl', 'nu dl'],

            # Provincial health cards
            'Ontario OHIP': ['ohip', 'ontario health card', 'ontario health insurance',
                             'health card number', 'ohip number'],
            'Quebec RAMQ': ['ramq', 'carte soleil', 'quebec health card',
                            'regie assurance maladie', 'health insurance quebec'],
            'BC MSP': ['bc msp', 'medical services plan', 'bc health card',
                       'bc phn', 'personal health number'],
            'Alberta AHCIP': ['ahcip', 'alberta health card', 'alberta phn',
                              'alberta health care insurance', 'ab health'],
            'Saskatchewan HC': ['saskatchewan health card', 'sk health', 'sk phn',
                                'saskatchewan health number'],
            'Manitoba PHIN': ['manitoba phin', 'manitoba health card', 'mb health',
                              'personal health identification number'],
            'New Brunswick HC': ['new brunswick health card', 'nb medicare',
                                 'nb health', 'new brunswick medicare'],
            'Nova Scotia MSI': ['nova scotia msi', 'msi card', 'msi number',
                                'nova scotia health card', 'ns health'],
            'PEI HC': ['pei health card', 'prince edward island health',
                       'pe health card'],
            'Newfoundland MCP': ['newfoundland mcp', 'mcp card', 'mcp number',
                                 'medical care plan', 'nl health card'],
        },
        'distance': 50,
    },

    # --- North America: Mexico ---
    'North America - Mexico': {
        'Identifiers': {
            'Mexico CURP': ['curp', 'clave unica', 'clave unica de registro',
                            'registro de poblacion', 'population registry'],
            'Mexico RFC': ['rfc', 'registro federal', 'registro federal de contribuyentes',
                           'federal taxpayer', 'tax id mexico'],
            'Mexico Clave Elector': ['clave de elector', 'credencial para votar',
                                     'credencial elector', 'ine', 'ife',
                                     'voter credential'],
            'Mexico INE CIC': ['cic', 'codigo de identificacion', 'ine cic',
                               'credential identification code'],
            'Mexico INE OCR': ['ocr', 'ine ocr', 'optical character recognition',
                               'credencial ocr'],
            'Mexico Passport': ['pasaporte mexicano', 'mexico passport',
                                'mexican passport', 'pasaporte'],
            'Mexico NSS': ['nss', 'numero de seguro social', 'imss',
                           'seguro social', 'instituto mexicano del seguro social'],
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

    # #########################################################################
    #  L A T I N   A M E R I C A
    # #########################################################################

    'Latin America - Brazil': {
        'Identifiers': {
            'Brazil CPF': ['cpf', 'cadastro de pessoas fisicas', 'cadastro pessoa fisica',
                           'contribuinte', 'receita federal'],
            'Brazil CNPJ': ['cnpj', 'cadastro nacional', 'pessoa juridica', 'empresa',
                            'razao social'],
            'Brazil RG': ['rg', 'registro geral', 'identidade', 'carteira de identidade',
                          'documento de identidade'],
            'Brazil CNH': ['cnh', 'carteira de habilitacao', 'habilitacao', 'driving licence',
                           'carteira nacional'],
            'Brazil SUS Card': ['sus', 'cartao nacional de saude', 'cns', 'saude',
                                'cartao sus'],
            'Brazil Passport': ['passaporte', 'brazilian passport', 'brazil passport',
                                'passport number'],
        },
        'distance': 50,
    },
    'Latin America - Argentina': {
        'Identifiers': {
            'Argentina DNI': ['dni', 'documento nacional de identidad', 'documento nacional',
                              'identidad', 'renaper'],
            'Argentina CUIL/CUIT': ['cuil', 'cuit', 'clave unica', 'identificacion tributaria',
                                    'afip'],
            'Argentina Passport': ['pasaporte', 'argentinian passport', 'argentina passport',
                                   'passport number'],
        },
        'distance': 50,
    },
    'Latin America - Colombia': {
        'Identifiers': {
            'Colombia Cedula': ['cedula', 'cedula de ciudadania', 'cc', 'documento identidad',
                                'registraduria'],
            'Colombia NIT': ['nit', 'numero de identificacion tributaria', 'dian',
                             'contribuyente', 'tax id'],
            'Colombia NUIP': ['nuip', 'numero unico de identificacion personal',
                              'identificacion personal', 'tarjeta identidad'],
            'Colombia Passport': ['pasaporte', 'colombian passport', 'colombia passport',
                                  'passport number'],
        },
        'distance': 50,
    },
    'Latin America - Chile': {
        'Identifiers': {
            'Chile RUN/RUT': ['rut', 'run', 'rol unico tributario', 'rol unico nacional',
                              'cedula identidad'],
            'Chile Passport': ['pasaporte', 'chilean passport', 'chile passport',
                               'passport number'],
        },
        'distance': 50,
    },
    'Latin America - Peru': {
        'Identifiers': {
            'Peru DNI': ['dni', 'documento nacional de identidad', 'reniec', 'identidad',
                         'documento identidad'],
            'Peru RUC': ['ruc', 'registro unico de contribuyentes', 'sunat', 'contribuyente',
                         'tax id'],
            'Peru Carnet Extranjeria': ['carnet de extranjeria', 'carnet extranjeria', 'ce',
                                        'migraciones', 'extranjero'],
            'Peru Passport': ['pasaporte', 'peruvian passport', 'peru passport',
                              'passport number'],
        },
        'distance': 50,
    },
    'Latin America - Venezuela': {
        'Identifiers': {
            'Venezuela Cedula': ['cedula', 'cedula de identidad', 'ci', 'saime',
                                 'venezolano'],
            'Venezuela RIF': ['rif', 'registro de informacion fiscal', 'seniat', 'fiscal',
                              'contribuyente'],
            'Venezuela Passport': ['pasaporte', 'venezuelan passport', 'venezuela passport',
                                   'passport number'],
        },
        'distance': 50,
    },
    'Latin America - Ecuador': {
        'Identifiers': {
            'Ecuador Cedula': ['cedula', 'cedula de identidad', 'cedula ciudadania',
                               'registro civil', 'identidad'],
            'Ecuador RUC': ['ruc', 'registro unico de contribuyentes', 'sri',
                            'contribuyente', 'tax id'],
            'Ecuador Passport': ['pasaporte', 'ecuadorian passport', 'ecuador passport',
                                 'passport number'],
        },
        'distance': 50,
    },
    'Latin America - Uruguay': {
        'Identifiers': {
            'Uruguay Cedula': ['cedula', 'cedula de identidad', 'documento identidad',
                               'identidad', 'dnic'],
            'Uruguay RUT': ['rut', 'registro unico tributario', 'dgi', 'contribuyente',
                            'tax id'],
            'Uruguay Passport': ['pasaporte', 'uruguayan passport', 'uruguay passport',
                                 'passport number'],
        },
        'distance': 50,
    },
    'Latin America - Paraguay': {
        'Identifiers': {
            'Paraguay Cedula': ['cedula', 'cedula de identidad', 'identidad civil',
                                'documento identidad', 'policia nacional'],
            'Paraguay RUC': ['ruc', 'registro unico de contribuyentes', 'set', 'dnit',
                             'contribuyente'],
            'Paraguay Passport': ['pasaporte', 'paraguayan passport', 'paraguay passport',
                                  'passport number'],
        },
        'distance': 50,
    },
    'Latin America - Costa Rica': {
        'Identifiers': {
            'Costa Rica Cedula': ['cedula', 'cedula de identidad', 'tse', 'costarricense',
                                  'tribunal supremo'],
            'Costa Rica DIMEX': ['dimex', 'documento migratorio', 'extranjero',
                                 'migracion', 'residencia'],
            'Costa Rica Passport': ['pasaporte', 'costa rican passport', 'costa rica passport',
                                    'passport number'],
        },
        'distance': 50,
    },

    # #########################################################################
    #  M I D D L E   E A S T
    # #########################################################################

    'Middle East - Saudi Arabia': {
        'Identifiers': {
            'Saudi Arabia National ID': ['national id', 'iqama', 'saudi id', 'huwiyya',
                                         'ministry of interior'],
            'Saudi Arabia Passport': ['saudi passport', 'saudi arabia passport', 'jawaz safar',
                                      'passport number'],
        },
        'distance': 50,
    },
    'Middle East - UAE': {
        'Identifiers': {
            'UAE Emirates ID': ['emirates id', 'eid', 'uae id', 'identity card',
                                'federal authority'],
            'UAE Visa Number': ['visa number', 'entry permit', 'uae visa', 'residence visa',
                                'visa file'],
            'UAE Passport': ['uae passport', 'emirati passport', 'passport number',
                             'passport'],
        },
        'distance': 50,
    },
    'Middle East - Israel': {
        'Identifiers': {
            'Israel Teudat Zehut': ['teudat zehut', 'mispar zehut', 'identity number',
                                    'israeli id', 'zehut'],
            'Israel Passport': ['israeli passport', 'israel passport', 'darkon',
                                'passport number'],
        },
        'distance': 50,
    },
    'Middle East - Qatar': {
        'Identifiers': {
            'Qatar QID': ['qid', 'qatar id', 'resident permit', 'moi qatar',
                          'identity card'],
            'Qatar Passport': ['qatar passport', 'qatari passport', 'passport number',
                               'jawaz'],
        },
        'distance': 50,
    },
    'Middle East - Kuwait': {
        'Identifiers': {
            'Kuwait Civil ID': ['civil id', 'paci', 'kuwait id', 'civil information',
                                'identity card'],
            'Kuwait Passport': ['kuwaiti passport', 'kuwait passport', 'passport number',
                                'passport'],
        },
        'distance': 50,
    },
    'Middle East - Bahrain': {
        'Identifiers': {
            'Bahrain CPR': ['cpr', 'central population registration', 'bahrain id',
                            'personal number', 'identity card'],
            'Bahrain Passport': ['bahraini passport', 'bahrain passport', 'passport number',
                                 'passport'],
        },
        'distance': 50,
    },
    'Middle East - Jordan': {
        'Identifiers': {
            'Jordan National ID': ['national number', 'raqam watani', 'jordanian id',
                                   'civil status', 'identity card'],
            'Jordan Passport': ['jordanian passport', 'jordan passport', 'passport number',
                                'passport'],
        },
        'distance': 50,
    },
    'Middle East - Lebanon': {
        'Identifiers': {
            'Lebanon ID': ['lebanese id', 'national id', 'identity card', 'hawiyya',
                           'interior ministry'],
            'Lebanon Passport': ['lebanese passport', 'lebanon passport', 'passport number',
                                 'general security'],
        },
        'distance': 50,
    },
    'Middle East - Iraq': {
        'Identifiers': {
            'Iraq National ID': ['national card', 'bitaqa wataniya', 'iraqi id',
                                 'civil status', 'identity card'],
            'Iraq Passport': ['iraqi passport', 'iraq passport', 'passport number',
                              'passport'],
        },
        'distance': 50,
    },
    'Middle East - Iran': {
        'Identifiers': {
            'Iran Melli Code': ['melli code', 'shomareh melli', 'kart melli', 'national code',
                                'iranian id'],
            'Iran Passport': ['iranian passport', 'iran passport', 'passport number',
                              'gozarnameh'],
        },
        'distance': 50,
    },

    # #########################################################################
    #  A F R I C A
    # #########################################################################

    'Africa - South Africa': {
        'Identifiers': {
            'South Africa ID': ['south african id', 'sa id', 'identity number', 'id number',
                                'home affairs'],
            'South Africa Passport': ['south african passport', 'sa passport',
                                      'passport number', 'home affairs'],
            'South Africa DL': ["driver's licence", 'driving licence', 'south african dl',
                                'licence number', 'traffic department'],
        },
        'distance': 50,
    },
    'Africa - Nigeria': {
        'Identifiers': {
            'Nigeria NIN': ['nin', 'national identification number', 'nimc', 'national identity',
                            'identity number'],
            'Nigeria BVN': ['bvn', 'bank verification number', 'bank verification', 'nibss',
                            'cbn'],
            'Nigeria TIN': ['tin', 'tax identification number', 'firs', 'tax id',
                            'joint tax board'],
            'Nigeria Voter Card': ['voter card', 'pvc', 'voter identification', 'inec',
                                   'permanent voter'],
            'Nigeria Driver Licence': ["driver's licence", 'driving licence', 'frsc',
                                       'licence number', 'ndl'],
            'Nigeria Passport': ['nigerian passport', 'nigeria passport', 'passport number',
                                 'immigration'],
        },
        'distance': 50,
    },
    'Africa - Kenya': {
        'Identifiers': {
            'Kenya National ID': ['national id', 'kenyan id', 'identity card', 'huduma namba',
                                  'maisha namba'],
            'Kenya KRA PIN': ['kra pin', 'kra', 'kenya revenue', 'tax pin', 'itax'],
            'Kenya NHIF': ['nhif', 'national hospital insurance', 'health insurance',
                           'nhif number'],
            'Kenya Passport': ['kenyan passport', 'kenya passport', 'passport number',
                               'immigration'],
        },
        'distance': 50,
    },
    'Africa - Egypt': {
        'Identifiers': {
            'Egypt National ID': ['national id', 'raqam qawmi', 'egyptian id',
                                  'identity card', 'civil registry'],
            'Egypt Tax ID': ['tax id', 'tax registration', 'maslahat al-darayeb',
                             'tax number', 'eta'],
            'Egypt Passport': ['egyptian passport', 'egypt passport', 'passport number',
                               'jawaz safar'],
        },
        'distance': 50,
    },
    'Africa - Ghana': {
        'Identifiers': {
            'Ghana Card': ['ghana card', 'nia', 'national identification', 'identity card',
                           'ghana id'],
            'Ghana TIN': ['tin', 'tax identification', 'gra', 'taxpayer', 'tax number'],
            'Ghana NHIS': ['nhis', 'national health insurance', 'health insurance',
                           'nhia', 'health card'],
            'Ghana Passport': ['ghanaian passport', 'ghana passport', 'passport number',
                               'immigration'],
        },
        'distance': 50,
    },
    'Africa - Ethiopia': {
        'Identifiers': {
            'Ethiopia National ID': ['fayda', 'national id', 'ethiopian id', 'identity number',
                                     'fayda id'],
            'Ethiopia TIN': ['tin', 'tax identification', 'erca', 'ministry of revenue',
                             'tax number'],
            'Ethiopia Passport': ['ethiopian passport', 'ethiopia passport', 'passport number',
                                  'immigration'],
        },
        'distance': 50,
    },
    'Africa - Tanzania': {
        'Identifiers': {
            'Tanzania NIDA': ['nida', 'national id', 'tanzanian id', 'nin',
                              'national identification'],
            'Tanzania TIN': ['tin', 'tax identification', 'tra', 'tanzania revenue',
                             'tax number'],
            'Tanzania Passport': ['tanzanian passport', 'tanzania passport', 'passport number',
                                  'immigration'],
        },
        'distance': 50,
    },
    'Africa - Morocco': {
        'Identifiers': {
            'Morocco CIN': ['cin', 'cnie', 'carte nationale', 'carte identite',
                            'identite nationale'],
            'Morocco Tax ID': ['identifiant fiscal', 'if', 'dgi', 'tax id',
                               'impots'],
            'Morocco Passport': ['moroccan passport', 'morocco passport', 'passeport',
                                 'passport number'],
        },
        'distance': 50,
    },
    'Africa - Tunisia': {
        'Identifiers': {
            'Tunisia CIN': ['cin', 'carte identite nationale', 'carte identite',
                            'tunisian id', 'identity card'],
            'Tunisia Passport': ['tunisian passport', 'tunisia passport', 'passeport',
                                 'passport number'],
        },
        'distance': 50,
    },
    'Africa - Uganda': {
        'Identifiers': {
            'Uganda NIN': ['nin', 'national identification number', 'nira', 'national id',
                           'ugandan id'],
            'Uganda Passport': ['ugandan passport', 'uganda passport', 'passport number',
                                'immigration'],
        },
        'distance': 50,
    },
}
