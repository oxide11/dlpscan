import re

# Assuming these imports are necessary and used elsewhere in the code.
from .patterns import PATTERNS
from .context_patterns import CONTEXT_KEYWORDS

# Optimization: compile word pattern once per category outside of scan_for_context to avoid re-compiling for every call.
compiled_context_patterns = {
    category: re.compile(r'\b(' + '|'.join(map(re.escape, details.get('keywords', []))) + r')\b', re.IGNORECASE)
    for category, details in CONTEXT_KEYWORDS.items()
}

def redact_sensitive_info(match, redaction_char='X'):
    if not match:
        raise ValueError("Input string cannot be None or Empty.")

    # Check for non-printable characters in input more efficiently.
    clean_match_length = sum(1 for c in match if c.isprintable())
    
    if clean_match_length < 4:
        raise ValueError("Input string must have at least 4 printable characters.")
    
    return redaction_char * (clean_match_length - 4) + match[-4:]


def is_luhn_valid(card_number: str) -> bool:
    sanitized_card_number = ''.join(filter(str.isdigit, card_number))

    if not sanitized_card_number:
        raise ValueError("Card number must not be empty after removing spaces and hyphens.")

    # Optimize Luhn's algorithm by using a pre-calculated array for doubling digits.
    luhn_double = [sum(divmod(int(digit) * 2, 10)) for digit in '0123456789']
    num_sum = sum((int(digit) if idx % 2 else luhn_double[int(digit)]) 
                  for idx, digit in enumerate(reversed(sanitized_card_number)))

    return num_sum % 10 == 0


def scan_for_context(text: str, start_index: int, category: str) -> bool:
    distance_config = CONTEXT_KEYWORDS.get(category, {})
    distance = distance_config.get('distance', 0)

    pre_text = text[max(0, start_index - distance):start_index]
    post_text = text[start_index:start_index + distance]

    # Use pre-compiled patterns from the dictionary.
    context_pattern = compiled_context_patterns.get(category)

    # If there's no pattern for the category, return False directly.
    if not context_pattern:
        return False

    # Search within the pre and post text.
    return context_pattern.search(pre_text) or context_pattern.search(post_text)


def enhanced_scan_text(text: str):
    compiled_patterns = {
        category: {label: re.compile(pattern) for label, pattern in patterns.items()}
        for category, patterns in PATTERNS.items()
    }

    for category, patterns in compiled_patterns.items():
        for label, compiled_pattern in patterns.items():
            for match in compiled_pattern.finditer(text):
                has_context = scan_for_context(text, match.start(), category) if category in CONTEXT_KEYWORDS else False
                yield (match.group(), label, has_context)
