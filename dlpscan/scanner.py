import re
# Assume PATTERNS and CONTEXT_KEYWORDS are modules properly defined elsewhere.
from .patterns import PATTERNS
from .context_patterns import CONTEXT_KEYWORDS


def redact_sensitive_info(match):
    """Redacts sensitive information, leaving the last four digits visible."""
    return "X" * (len(match) - 4) + match[-4:]


def is_luhn_valid(card_number):
    """Check if the card number is valid according to the Luhn algorithm."""
    num_sum = sum(int(digit) if idx % 2 else int(digit) * 2 - 9 if int(digit) * 2 > 9 
                  else int(digit) * 2 for idx, digit in enumerate(card_number[-1::-1]))
    return num_sum % 10 == 0


def scan_for_context(text, start_index, category):
    """Scan for contextual keywords around a found pattern."""
    keywords = CONTEXT_KEYWORDS[category]['keywords']
    distance = CONTEXT_KEYWORDS[category]['distance']
    pre_text = text[max(0, start_index - distance):start_index]
    post_text = text[start_index:start_index + distance]
    return any(keyword in pre_text or keyword in post_text for keyword in keywords)


# The scan_text function will be the primary interface for scanning texts.
def enhanced_scan_text(text):
    """Scans the text for sensitive information and also checks for contextual keywords."""
    findings = []
    for category, patterns in PATTERNS.items():
        for label, pattern in patterns.items():
            for match in re.finditer(pattern, text):
                has_context = False
                if category in CONTEXT_KEYWORDS:
                    has_context = scan_for_context(text, match.start(), category)
                findings.append((match.group(), label, has_context))
    return findings
