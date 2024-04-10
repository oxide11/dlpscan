import re
from collections import defaultdict
from .patterns import PATTERNS
from .context_patterns import CONTEXT_KEYWORDS

def redact_sensitive_info(match):
    """Redacts sensitive information, leaving the last four digits visible."""
    return "X" * (len(match) - 4) + match[-4:]

def is_luhn_valid(card_number):
    """Check if the card number is valid according to the Luhn algorithm."""
    num_sum = 0
    num_digits = len(card_number)
    oddeven = num_digits % 2
    
    for count in range(num_digits):
        digit = int(card_number[count])
        
        if not ((count & 1) ^ oddeven):
            digit = digit * 2
        if digit > 9:
            digit = digit - 9
            
        num_sum += digit
        
    return (num_sum % 10) == 0

def scan_for_context(text, start_index, category):
    """Scan for contextual keywords around a found pattern."""
    keywords = CONTEXT_KEYWORDS[category]['keywords']
    distance = CONTEXT_KEYWORDS[category]['distance']
    pre_text = text[max(0, start_index - distance):start_index]
    post_text = text[start_index:start_index + distance]
    for keyword in keywords:
        if keyword in pre_text or keyword in post_text:
            return True
    return False

# The scan_text function will be the primary interface for scanning texts.
def enhanced_scan_text(text):
    """Scans the text for sensitive information and also checks for contextual keywords."""
    findings = []
    for category, patterns in PATTERNS.items():
        for label, pattern in patterns.items():
            for match in pattern.finditer(text):
                has_context = False
                if category in CONTEXT_KEYWORDS:
                    has_context = scan_for_context(text, match.start(), category)
                findings.append((match.group(), label, has_context))
                return findings