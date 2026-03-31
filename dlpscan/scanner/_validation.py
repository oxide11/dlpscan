"""Input validation, normalization, and card validation."""

from ..exceptions import EmptyInputError, InvalidCardNumberError
from ..unicode_normalize import normalize_text

# Maximum input size to prevent resource exhaustion (10 MB).
MAX_INPUT_SIZE = 10 * 1024 * 1024


def _validate_text_input(text: object) -> str:
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


def _normalize_text(text: str) -> tuple:
    """Normalize text to defeat Unicode evasion (zero-width chars, homoglyphs).

    Returns (normalized_text, offset_map) where offset_map maps each position
    in normalized_text back to its original position.
    """
    normalized, offset_map = normalize_text(text)
    return normalized, offset_map


def is_luhn_valid(card_number: str) -> bool:
    """Validate a credit-card number using the Luhn algorithm."""
    if not isinstance(card_number, str):
        raise InvalidCardNumberError("Card number must be a string.")

    sanitized = ''.join(c for c in card_number if c.isdigit())

    if not sanitized:
        raise InvalidCardNumberError("Card number must not be empty after sanitization.")

    total = 0
    for idx, digit in enumerate(reversed(sanitized)):
        n = int(digit)
        if idx % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n

    return total % 10 == 0
