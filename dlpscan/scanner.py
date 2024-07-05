import re

# Assuming these imports are correct and used elsewhere in the wider context.
from .patterns import PATTERNS  # Relative imports removed, assuming patterns is on the Python path
from .context_patterns import CONTEXT_KEYWORDS
from .exceptions import EmptyInputError, ShortInputError, InvalidCardNumberError, SubCategoryNotFoundError

# Compile word patterns only if keywords are available for a category.
compiled_context_patterns = {
    (category, sub_category): re.compile(r'\b(' + '|'.join(map(re.escape, keywords)) + r')\b', re.IGNORECASE)
    for category, details in CONTEXT_KEYWORDS.items()
    for sub_category, keywords in details['Identifiers'].items()
}

def redact_sensitive_info(match, redaction_char='X'):
    if not match:
        raise EmptyInputError("Input string cannot be None or Empty.")

    match_printable = "".join(filter(str.isprintable, match))
    if len(match_printable) < 4:
        raise ShortInputError("Input string must have at least 4 printable characters.")
    
    redacted_word = "".join(redaction_char if c not in ['-', ' '] else c for c in match_printable)
    return redacted_word

def redact_sensitive_info_with_patterns(text, category, sub_category):
    if category not in PATTERNS or sub_category not in PATTERNS[category]:
        raise SubCategoryNotFoundError(f"Sub-Category '{sub_category}' not found in PATTERNS for category '{category}'.")

    pattern = PATTERNS[category][sub_category]
    redacted_text = text
    has_matches = False

    for match in pattern.finditer(text):
        has_matches = True
        redacted_match = redact_sensitive_info(match.group())
        redacted_text = redacted_text.replace(match.group(), redacted_match)
    
    if not has_matches:
        return text

    return redacted_text

def is_luhn_valid(card_number: str) -> bool:
    sanitized_card_number = ''.join(filter(lambda x: x.isdigit() or x.isspace() or x == '-', card_number))
    sanitized_card_number = ''.join(filter(str.isdigit, sanitized_card_number))

    if not sanitized_card_number:
        raise InvalidCardNumberError("Card number must not be empty after sanitization.")

    luhn_double = [sum(divmod(int(digit) * 2, 10)) for digit in '0123456789']
    num_sum = sum((int(digit) if idx % 2 else luhn_double[int(digit)])
                  for idx, digit in enumerate(reversed(sanitized_card_number)))

    return num_sum % 10 == 0

def scan_for_context(text: str, start_index: int, category: str, sub_category: str) -> bool:
    distance_config = CONTEXT_KEYWORDS.get(category, {})
    distance = distance_config.get('distance', 0)
    print(f"Length: {len(text)} Distance: {distance} Category: {category} | Subcategory: {sub_category} | Start Index: {start_index}")
    pre_text = text[max(0, start_index - distance):start_index]
    post_text = text[start_index:min(len(text), start_index + distance)]
    print(f"Pre Text: {pre_text} | Post Text: {post_text}")
    context_pattern = compiled_context_patterns.get((category, sub_category))
    print(f"Context Pattern: {context_pattern}")

    if not context_pattern:
        return False

    pre_check = context_pattern.search(pre_text)
    post_check = context_pattern.search(post_text)
    print(f"Pre Check: {pre_check} | Post Check: {post_check}")
    return context_pattern.search(pre_text) or context_pattern.search(post_text)

def enhanced_scan_text(text: str):
    compiled_patterns = compiled_context_patterns

    for (category, sub_category), context_pattern in compiled_patterns.items():
        for match in context_pattern.finditer(text):
            label = "Unknown"
            has_context = scan_for_context(text, match.start(), category, sub_category)
            yield (match.group(), label, has_context, category, sub_category)
