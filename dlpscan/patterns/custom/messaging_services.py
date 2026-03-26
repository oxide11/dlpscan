import re

MESSAGING_SERVICES_PATTERNS = {
    'Messaging Service Secrets': {
        'Slack Bot Token': re.compile(r'\bxoxb-[0-9A-Za-z\-]+\b'),
        'Slack User Token': re.compile(r'\bxoxp-[0-9A-Za-z\-]+\b'),
        'Slack Webhook': re.compile(r'https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+'),
        'SendGrid API Key': re.compile(r'\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b'),
        'Twilio API Key': re.compile(r'\bSK[0-9a-f]{32}\b'),
        'Mailgun API Key': re.compile(r'\bkey-[0-9a-zA-Z]{32}\b'),
    },
}
