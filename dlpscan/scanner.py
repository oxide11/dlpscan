import re
import signal
from typing import Generator, Tuple, Optional, Set

from .patterns import PATTERNS
from .context import CONTEXT_KEYWORDS
from .exceptions import (
    EmptyInputError,
    ShortInputError,
    InvalidCardNumberError,
    SubCategoryNotFoundError,
)

# Maximum input size to prevent resource exhaustion (10 MB).
MAX_INPUT_SIZE = 10 * 1024 * 1024

# Timeout in seconds for individual regex operations (0 = no timeout).
REGEX_TIMEOUT_SECONDS = 5

# Pre-compile context keyword patterns for proximity matching.
compiled_context_patterns: dict = {}
for _category, _details in CONTEXT_KEYWORDS.items():
    _identifiers = _details.get('Identifiers', {})
    for _sub_category, _keywords in _identifiers.items():
        if _keywords:
            compiled_context_patterns[(_category, _sub_category)] = re.compile(
                r'\b(' + '|'.join(map(re.escape, _keywords)) + r')\b',
                re.IGNORECASE,
            )


class _RegexTimeout(Exception):
    """Raised when a regex operation exceeds the time limit."""


def _timeout_handler(signum, frame):
    raise _RegexTimeout("Regex operation timed out")


def _safe_finditer(pattern: re.Pattern, text: str, timeout: int = REGEX_TIMEOUT_SECONDS):
    """Yield regex matches with an optional per-pattern timeout guard.

    Falls back to unguarded matching on platforms that lack SIGALRM (Windows).
    """
    if timeout <= 0 or not hasattr(signal, 'SIGALRM'):
        yield from pattern.finditer(text)
        return

    old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
    signal.alarm(timeout)
    try:
        for m in pattern.finditer(text):
            yield m
    except _RegexTimeout:
        pass  # Skip this pattern — likely ReDoS or pathological input
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)


def _validate_text_input(text) -> str:
    """Validate and sanitize scanner input text."""
    if text is None:
        raise EmptyInputError("Input text cannot be None.")
    if not isinstance(text, str):
        raise TypeError(f"Expected str, got {type(text).__name__}.")
    if len(text) == 0:
        raise EmptyInputError("Input text cannot be empty.")
    if len(text) > MAX_INPUT_SIZE:
        raise ValueError(
            f"Input text exceeds maximum size of {MAX_INPUT_SIZE:,} bytes "
            f"({len(text):,} bytes provided)."
        )
    return text


def redact_sensitive_info(match: str, redaction_char: str = 'X') -> str:
    """Replace printable characters in *match* with *redaction_char*, preserving separators."""
    if not match:
        raise EmptyInputError("Input string cannot be None or empty.")

    if len(redaction_char) != 1:
        raise ValueError("redaction_char must be a single character.")

    match_printable = ''.join(filter(str.isprintable, match))
    if len(match_printable) < 4:
        raise ShortInputError("Input string must have at least 4 printable characters.")

    # Preserve common delimiters in redacted output for readability.
    _PRESERVED_DELIMITERS = frozenset('-. /\\_\u2013\u2014\u00a0')
    return ''.join(
        redaction_char if c not in _PRESERVED_DELIMITERS else c
        for c in match_printable
    )


def redact_sensitive_info_with_patterns(text: str, category: str, sub_category: str) -> str:
    """Redact all occurrences of *sub_category* pattern within *category* in *text*.

    Uses regex substitution (not string replace) to only redact actual
    pattern matches, avoiding false replacements of identical substrings
    that appear in non-sensitive positions.
    """
    text = _validate_text_input(text)

    if category not in PATTERNS or sub_category not in PATTERNS[category]:
        raise SubCategoryNotFoundError(
            f"Sub-Category '{sub_category}' not found in PATTERNS for category '{category}'."
        )

    pattern = PATTERNS[category][sub_category]

    def _redact_match(m):
        matched = m.group()
        try:
            return redact_sensitive_info(matched)
        except (EmptyInputError, ShortInputError):
            return matched  # Leave short/empty matches untouched

    return pattern.sub(_redact_match, text)


def is_luhn_valid(card_number: str) -> bool:
    """Validate a credit-card number using the Luhn algorithm."""
    if not isinstance(card_number, str):
        raise InvalidCardNumberError("Card number must be a string.")

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
    """Check whether contextual keywords appear near the match span.

    Returns True if any keyword is found within the configured distance,
    False otherwise. Returns False if no context keywords are configured
    for the given category/sub_category pair.
    """
    distance_config = CONTEXT_KEYWORDS.get(category, {})
    distance = distance_config.get('distance', 50)

    # Clamp indices to valid range.
    pre_start = max(0, start_index - distance)
    post_end = min(len(text), end_index + distance)

    pre_text = text[pre_start:start_index]
    post_text = text[end_index:post_end]

    context_pattern = compiled_context_patterns.get((category, sub_category))
    if not context_pattern:
        return False

    return bool(context_pattern.search(pre_text) or context_pattern.search(post_text))


def enhanced_scan_text(
    text: str,
    categories: Optional[Set[str]] = None,
    require_context: bool = False,
) -> Generator[Tuple[str, str, bool, str, str], None, None]:
    """Scan *text* for sensitive data using PATTERNS, with optional context verification.

    Args:
        text: The input text to scan.
        categories: Optional set of category names to scan. If None, scans all.
        require_context: If True, only yield matches that have contextual keyword support.

    Yields:
        Tuples of (matched_text, sub_category, has_context, category, sub_category).
    """
    text = _validate_text_input(text)

    patterns_to_scan = PATTERNS
    if categories:
        patterns_to_scan = {k: v for k, v in PATTERNS.items() if k in categories}

    for category, sub_categories in patterns_to_scan.items():
        for sub_category, pattern in sub_categories.items():
            for match in _safe_finditer(pattern, text):
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

                if require_context and not has_context:
                    continue

                yield (match.group(), sub_category, has_context, category, sub_category)
