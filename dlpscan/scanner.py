import re

# Import custom modules containing patterns and context keywords.
from .patterns import PATTERNS
from .context_patterns import CONTEXT_KEYWORDS


def redact_sensitive_info(match, redaction_char='X'):
    """
    Redacts sensitive information from a matched string by replacing all but the last four characters with a specified character.
    
    Parameters:
        match (str): The string containing sensitive information to be redacted.
        redaction_char (str): The character used for redaction.

    Returns:
        str: A redacted string with only the last four characters visible.
    """
    if len(match) < 4:
        raise ValueError("Input string must have at least 4 characters.")
    return redaction_char * (len(match) - 4) + match[-4:]


def is_luhn_valid(card_number: str) -> bool:
    """
    Validates a credit card number using the Luhn algorithm.
    
    Parameters:
        card_number (str): The credit card number as a string.

    Returns:
        bool: True if the credit card number is valid, False otherwise.
    """
    num_sum = sum(int(digit) if (idx + 1) % 2 else int(digit) * 2 - 9 if int(digit) * 2 > 9
                  else int(digit) * 2 for idx, digit in enumerate(reversed(card_number)))
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

