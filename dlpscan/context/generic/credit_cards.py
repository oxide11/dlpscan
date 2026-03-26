


CREDIT_CARDS_CONTEXT = {
    'Credit Card Numbers': {
        'Identifiers': {
            'Visa': ['visa', 'credit card', 'card number', 'card no', 'pan', 'primary account'],
            'MasterCard': ['mastercard', 'credit card', 'card number', 'card no', 'pan', 'primary account'],
            'Amex': ['amex', 'american express', 'credit card', 'card number', 'pan', 'primary account'],
            'Discover': ['discover', 'credit card', 'card number', 'pan', 'primary account'],
            'JCB': ['jcb', 'credit card', 'card number', 'pan', 'primary account'],
            'Diners Club': ['diners club', 'diners', 'credit card', 'card number', 'pan', 'primary account'],
            'UnionPay': ['unionpay', 'union pay', 'credit card', 'card number', 'pan', 'primary account'],
        },
        'distance': 50,
    },
    'Primary Account Numbers': {
        'Identifiers': {
            'PAN': ['pan', 'primary account number', 'account number', 'card number', 'cardholder number', 'full card'],
            'Masked PAN': ['masked pan', 'truncated pan', 'masked card', 'truncated card', 'last four', 'first six'],
        },
        'distance': 50,
    },
    'Card Track Data': {
        'Identifiers': {
            'Track 1 Data': ['track 1', 'track1', 'magnetic stripe', 'magstripe', 'swipe data', 'card track'],
            'Track 2 Data': ['track 2', 'track2', 'magnetic stripe', 'magstripe', 'swipe data', 'card track'],
        },
        'distance': 50,
    },
    'Card Expiration Dates': {
        'Identifiers': {
            'Card Expiry': ['expiry', 'expiration', 'exp date', 'exp', 'valid thru', 'valid through', 'good thru', 'card expires', 'mm/yy'],
        },
        'distance': 30,
    },
}
