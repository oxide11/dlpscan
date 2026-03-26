import re

PAYMENT_SERVICES_PATTERNS = {
    'Payment Service Secrets': {
        'Stripe Secret Key': re.compile(r'\bsk_(?:live|test)_[A-Za-z0-9]{24,}\b'),
        'Stripe Publishable Key': re.compile(r'\bpk_(?:live|test)_[A-Za-z0-9]{24,}\b'),
    },
}
