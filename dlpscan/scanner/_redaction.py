"""Redaction functions for masking sensitive data."""

from ..exceptions import EmptyInputError, ShortInputError, SubCategoryNotFoundError
from ._config import _get_all_patterns
from ._validation import _normalize_text, _validate_text_input


def redact_sensitive_info(match: str, redaction_char: str = 'X') -> str:
    """Replace printable characters in *match* with *redaction_char*, preserving separators."""
    if match is None:
        raise EmptyInputError("Input string cannot be None or empty.")
    if not isinstance(match, str):
        raise TypeError(f"Expected str, got {type(match).__name__}.")
    if len(match) == 0:
        raise EmptyInputError("Input string cannot be None or empty.")

    if not isinstance(redaction_char, str) or len(redaction_char) != 1:
        raise ValueError("redaction_char must be a single character.")

    match_printable = ''.join(filter(str.isprintable, match))
    if len(match_printable) < 4:
        raise ShortInputError("Input string must have at least 4 printable characters.")

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
    original_text = _validate_text_input(text)
    normalized, offset_map = _normalize_text(original_text)

    all_patterns = _get_all_patterns()

    if category not in all_patterns or sub_category not in all_patterns[category]:
        raise SubCategoryNotFoundError(
            f"Sub-Category '{sub_category}' not found in PATTERNS for category '{category}'."
        )

    pattern = all_patterns[category][sub_category]

    redact_spans: list[tuple[int, int]] = []
    for m in pattern.finditer(normalized):
        ns, ne = m.start(), m.end()
        if offset_map:
            os_ = offset_map[ns] if ns < len(offset_map) else len(original_text)
            oe = (offset_map[ne - 1] + 1) if ne <= len(offset_map) and ne > 0 else len(original_text)
        else:
            os_, oe = ns, ne
        redact_spans.append((os_, oe))

    if not redact_spans:
        return original_text

    result = list(original_text)
    _PRESERVED_DELIMITERS = frozenset('-. /\\_\u2013\u2014\u00a0')
    for start, end in redact_spans:
        for i in range(start, end):
            if result[i] not in _PRESERVED_DELIMITERS and result[i].isprintable():
                result[i] = 'X'
    return ''.join(result)
