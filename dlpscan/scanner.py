import re

# Import custom modules containing patterns and context keywords.
from .patterns import PATTERNS
from .context_patterns import CONTEXT_KEYWORDS


def redact_sensitive_info(match, redaction_char='X'):
    # Make sure the match string is not None or Empty
    if not match:
        raise ValueError("Input string cannot be None or Empty.")

    # Check for non-printable characters in the input
    if any(not c.isprintable() for c in match):
        raise ValueError("Input contains non-printable characters.")
    
    cleaned_match = ''.join(c for c in match if c.isprintable())
    
    if len(cleaned_match) < 4:
        raise ValueError("Input string must have at least 4 printable characters.")
    
    return redaction_char * (len(cleaned_match) - 4) + cleaned_match[-4:]


def is_luhn_valid(card_number: str) -> bool:
    # Check for non-digit characters
    if not all(char.isdigit() or char in " -" for char in card_number):
        raise ValueError("Card number must contain only digits, spaces, or hyphens.")

    # Remove any non-digit characters like spaces or hyphens
    sanitized_card_number = ''.join(filter(str.isdigit, card_number))
    
    # Check that the sanitized card number is not just an empty string.
    if not sanitized_card_number:
        raise ValueError("Card number must not be empty after removing spaces and hyphens.")
    
    num_sum = sum(int(digit) if (idx + 1) % 2 else (int(digit) * 2 - 9) if (int(digit) * 2 > 9)
                  else int(digit) * 2 for idx, digit in enumerate(reversed(sanitized_card_number)))

    return num_sum % 10 == 0



def scan_for_context(text: str, start_index: int, category: str) -> bool:
    """
    Scans for contextual keywords around a found pattern within a specified distance considering word boundaries.
    
    Parameters:
        text (str): The text to be scanned.
        start_index (int): The index where the pattern was found.
        category (str): The category of the pattern that determines which keywords to look for.

    Returns:
        bool: True if any contextual keyword is found near the pattern, False otherwise.
    """
    keywords = CONTEXT_KEYWORDS.get(category, {}).get('keywords', [])
    distance = CONTEXT_KEYWORDS.get(category, {}).get('distance', 0)
    pre_text = text[max(0, start_index - distance):start_index]
    post_text = text[start_index:start_index + distance]

    # Create a pattern to match whole words only
    word_pattern = r'\b(' + '|'.join(map(re.escape, keywords)) + r')\b'

    # Search within the pre and post text
    return re.search(word_pattern, pre_text, re.IGNORECASE) or re.search(word_pattern, post_text, re.IGNORECASE)


def enhanced_scan_text(text: str):
    """
    Scans the provided text for sensitive information according to defined patterns
    and also checks for the presence of contextual keywords.
    
    Parameters:
        text (str): The text to scan for sensitive information.
    
    Returns:
        Iterable of tuples: Each tuple contains the matched string, its label, and a flag indicating context relevance.
    """
    # Pre-compile regex patterns for performance improvement
    compiled_patterns = {
        category: {label: re.compile(pattern) for label, pattern in patterns.items()}
        for category, patterns in PATTERNS.items()
    }

    # Iterate over the categories and their associated pre-compiled patterns.
    for category, patterns in compiled_patterns.items():
        # Iterate over the labels and regex patterns within each category.
        for label, compiled_pattern in patterns.items():
            # Find all matches of the pattern in the text using regular expressions.
            for match in compiled_pattern.finditer(text):
                has_context = False
                # If the category has associated context keywords, check for their presence.
                if category in CONTEXT_KEYWORDS:
                    has_context = scan_for_context(text, match.start(), category)
                # Yield the matching info as a tuple.
                yield (match.group(), label, has_context)

