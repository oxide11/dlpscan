import re

# Assuming these imports are correct and used elsewhere in the wider context.
from patterns import PATTERNS  # Relative imports removed, assuming patterns is on the Python path
from context_patterns import CONTEXT_KEYWORDS

# Compile word patterns only if keywords are available for a category.
compiled_context_patterns = {
    category: re.compile(r'\b(' + '|'.join(map(re.escape, details.get('keywords', []))) + r')\b', re.IGNORECASE)
    for category, details in CONTEXT_KEYWORDS.items() if details.get('keywords')
}

def redact_sensitive_info(match, redaction_char='X'):
    if not match:
        raise ValueError("Input string cannot be None or Empty.")

    match_printable = "".join(filter(str.isprintable, match))

    if len(match_printable) < 4:
        raise ValueError("Input string must have at least 4 printable characters.")
    
    return redaction_char * (len(match_printable) - 4) + match_printable[-4:]

def is_luhn_valid(card_number: str) -> bool:
    # Remove non-numeric non-space/hyphen characters first to handle edge cases
    sanitized_card_number = ''.join(filter(lambda x: x.isdigit() or x.isspace() or x == '-', card_number))
    # Remove spaces and hyphens next
    sanitized_card_number = ''.join(filter(str.isdigit, sanitized_card_number))

    if not sanitized_card_number:
        raise ValueError("Card number must not be empty after sanitization.")

    # Optimization with pre-calculated array for doubling digits.
    luhn_double = [sum(divmod(int(digit) * 2, 10)) for digit in '0123456789']
    num_sum = sum((int(digit) if idx % 2 else luhn_double[int(digit)])
                  for idx, digit in enumerate(reversed(sanitized_card_number)))

    return num_sum % 10 == 0

def scan_for_context(text: str, start_index: int, category: str) -> bool:
    distance_config = CONTEXT_KEYWORDS.get(category, {})
    distance = distance_config.get('distance', 0)

    pre_text = text[max(0, start_index - distance):start_index]
    post_text = text[start_index:min(len(text), start_index + distance)]

    context_pattern = compiled_context_patterns.get(category)

    if not context_pattern:
        return False

    return context_pattern.search(pre_text) or context_pattern.search(post_text)

def enhanced_scan_text(text: str):
    # Reuse the pre-compiled patterns
    compiled_patterns = compiled_context_patterns

    for category, context_pattern in compiled_patterns.items():
        for match in context_pattern.finditer(text):
            label = "Unknown"  # Assuming there is no direct way to retrieve label from this pattern
            has_context = scan_for_context(text, match.start(), category)
            yield (match.group(), label, has_context)
