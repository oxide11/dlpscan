import re

SECRETS_PATTERNS = {
    'Generic Secrets': {
        'Bearer Token': re.compile(r'[Bb]earer\s+[A-Za-z0-9\-._~+/]+=*'),
        'JWT Token': re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
        'Private Key': re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
        'Generic API Key': re.compile(r'(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[=:]\s*["\']?[A-Za-z0-9\-._~+/]{16,}["\']?', re.IGNORECASE),
        'Generic Secret Assignment': re.compile(r'(?:password|passwd|pwd|secret|token|credential)\s*[=:]\s*["\']?[^\s"\']{8,}["\']?', re.IGNORECASE),
        'Database Connection String': re.compile(r'(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis|mssql)://[^:\s]+:[^@\s]+@[^\s]+', re.IGNORECASE),
    },
}
