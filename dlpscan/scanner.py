import re
from typing import Generator, Tuple

from .patterns import PATTERNS
from .context_patterns import CONTEXT_KEYWORDS
from .exceptions import (
    EmptyInputError,
    ShortInputError,
    InvalidCardNumberError,
    SubCategoryNotFoundError,
)

# Pre-compile context keyword patterns for proximity matching.
compiled_context_patterns = {
    (category, sub_category): re.compile(
        r'\b(' + '|'.join(map(re.escape, keywords)) + r')\b', re.IGNORECASE
    )
    for category, details in CONTEXT_KEYWORDS.items()
    for sub_category, keywords in details['Identifiers'].items()
}


def redact_sensitive_info(match: str, redaction_char: str = 'X') -> str:
    """Replace printable characters in *match* with *redaction_char*, preserving separators."""
    if not match:
        raise EmptyInputError("Input string cannot be None or empty.")

    match_printable = ''.join(filter(str.isprintable, match))
    if len(match_printable) < 4:
        raise ShortInputError("Input string must have at least 4 printable characters.")

    return ''.join(
        redaction_char if c not in ('-', ' ', '.') else c
        for c in match_printable
    )


def redact_sensitive_info_with_patterns(text: str, category: str, sub_category: str) -> str:
    """Redact all occurrences of *sub_category* pattern within *category* in *text*."""
    if category not in PATTERNS or sub_category not in PATTERNS[category]:
        raise SubCategoryNotFoundError(
            f"Sub-Category '{sub_category}' not found in PATTERNS for category '{category}'."
        )

    pattern = PATTERNS[category][sub_category]
    redacted_text = text

    for match in pattern.finditer(text):
        redacted_text = redacted_text.replace(match.group(), redact_sensitive_info(match.group()))

    return redacted_text


def is_luhn_valid(card_number: str) -> bool:
    """Validate a credit-card number using the Luhn algorithm."""
    sanitized = ''.join(c for c in card_number if c.isdigit())

    if not sanitized:
        raise InvalidCardNumberError("Card number must not be empty after sanitization.")

    # Standard Luhn: double every second digit from the right.
    total = 0
    for idx, digit in enumerate(reversed(sanitized)):
        n = int(digit)
        if idx % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n

    return total % 10 == 0


def scan_for_context(text: str, start_index: int, end_index: int,
                     category: str, sub_category: str) -> bool:
    """Check whether contextual keywords appear near the match span."""
    distance_config = CONTEXT_KEYWORDS.get(category, {})
    distance = distance_config.get('distance', 50)

    pre_text = text[max(0, start_index - distance):start_index]
    post_text = text[end_index:min(len(text), end_index + distance)]

    context_pattern = compiled_context_patterns.get((category, sub_category))
    if not context_pattern:
        return False

    return bool(context_pattern.search(pre_text) or context_pattern.search(post_text))


def enhanced_scan_text(text: str) -> Generator[Tuple[str, str, bool, str, str], None, None]:
    """Scan *text* for sensitive data using PATTERNS, with optional context verification.

    Yields tuples of (matched_text, sub_category, has_context, category, sub_category).
    """
    for category, sub_categories in PATTERNS.items():
        for sub_category, pattern in sub_categories.items():
            for match in pattern.finditer(text):
                # For credit cards, apply Luhn validation.
                if category == 'Credit Card Numbers':
                    try:
                        if not is_luhn_valid(match.group()):
                            continue
                    except InvalidCardNumberError:
                        continue

                has_context = scan_for_context(
                    text, match.start(), match.end(), category, sub_category
                )
                yield (match.group(), sub_category, has_context, category, sub_category)
