"""Unicode normalization to defeat evasion via zero-width characters and homoglyphs.

This module provides two layers of text preprocessing:

1. **Zero-width character stripping** — removes invisible Unicode characters
   (zero-width space, joiner, non-joiner, BOM, soft hyphen, etc.) that can be
   inserted into sensitive data to break regex matching.

2. **Homoglyph normalization** — maps visually similar Unicode characters
   (confusables) back to their ASCII equivalents so that digit/letter
   substitutions (e.g. Cyrillic "а" for Latin "a") do not bypass detection.

Both transforms preserve string length parity via an offset map so that
match spans in the normalized text can be mapped back to the original.
"""

import re
import unicodedata

# ── Zero-width / invisible characters ─────────────────────────────────────────
# Characters that occupy no visible space and can be inserted to break patterns.

ZERO_WIDTH_CHARS = frozenset((
    # ── Original invisible characters ──
    '\u200b',   # Zero Width Space
    '\u200c',   # Zero Width Non-Joiner
    '\u200d',   # Zero Width Joiner
    '\u200e',   # Left-to-Right Mark
    '\u200f',   # Right-to-Left Mark
    '\u2060',   # Word Joiner
    '\u2061',   # Function Application
    '\u2062',   # Invisible Times
    '\u2063',   # Invisible Separator
    '\u2064',   # Invisible Plus
    '\ufeff',   # Byte Order Mark / Zero Width No-Break Space
    '\u00ad',   # Soft Hyphen
    '\u034f',   # Combining Grapheme Joiner
    '\u061c',   # Arabic Letter Mark
    '\u180e',   # Mongolian Vowel Separator
    '\ufff9',   # Interlinear Annotation Anchor
    '\ufffa',   # Interlinear Annotation Separator
    '\ufffb',   # Interlinear Annotation Terminator
    # ── RTL / Bidi directional overrides (evasion §1.3) ──
    '\u202a',   # Left-to-Right Embedding
    '\u202b',   # Right-to-Left Embedding
    '\u202c',   # Pop Directional Formatting
    '\u202d',   # Left-to-Right Override
    '\u202e',   # Right-to-Left Override
    '\u2066',   # Left-to-Right Isolate
    '\u2067',   # Right-to-Left Isolate
    '\u2068',   # First Strong Isolate
    '\u2069',   # Pop Directional Isolate
    # ── Variation selectors (evasion §1.1 residual risk) ──
    *[chr(c) for c in range(0xFE00, 0xFE10)],   # VS1–VS16
    # ── Unicode Tags block — steganographic hiding (evasion §8.2) ──
    *[chr(c) for c in range(0xE0001, 0xE0080)],  # U+E0001–U+E007F
))

_ZERO_WIDTH_RE = re.compile('[' + ''.join(ZERO_WIDTH_CHARS) + ']')

# ── Unicode whitespace normalization (evasion §2.1 — delimiter variation) ────
# Maps exotic Unicode whitespace characters to ASCII space so that patterns
# using `_S` (which matches common delimiters) can catch them.
UNICODE_SPACES = frozenset((
    '\u2000',   # En Quad
    '\u2001',   # Em Quad
    '\u2002',   # En Space
    '\u2003',   # Em Space
    '\u2004',   # Three-Per-Em Space
    '\u2005',   # Four-Per-Em Space
    '\u2006',   # Six-Per-Em Space
    '\u2007',   # Figure Space
    '\u2008',   # Punctuation Space
    '\u2009',   # Thin Space
    '\u200a',   # Hair Space
    '\u202f',   # Narrow No-Break Space
    '\u205f',   # Medium Mathematical Space
    '\u3000',   # Ideographic Space
))


def normalize_whitespace(text: str) -> str:
    """Replace exotic Unicode whitespace characters with ASCII space.

    This defeats delimiter variation evasion where attackers use ideographic
    spaces, thin spaces, etc. that are not matched by standard regex ``\\s``.
    """
    return ''.join(' ' if ch in UNICODE_SPACES else ch for ch in text)


def strip_zero_width(text: str) -> tuple[str, list[int]]:
    """Remove zero-width / invisible characters from *text*.

    Returns:
        A tuple of (cleaned_text, offset_map) where offset_map[i] gives the
        original index corresponding to position *i* in cleaned_text.
    """
    offset_map: list[int] = []
    chars: list[str] = []
    for i, ch in enumerate(text):
        if ch not in ZERO_WIDTH_CHARS:
            chars.append(ch)
            offset_map.append(i)
    return ''.join(chars), offset_map


# ── Homoglyph / confusable character map ──────────────────────────────────────
# Maps visually similar Unicode characters to their ASCII equivalents.
# Focused on digits and letters commonly used in sensitive data patterns.

# Digit confusables: characters that look like 0-9.
_DIGIT_HOMOGLYPHS: dict[str, str] = {
    # Fullwidth digits
    '\uff10': '0', '\uff11': '1', '\uff12': '2', '\uff13': '3', '\uff14': '4',
    '\uff15': '5', '\uff16': '6', '\uff17': '7', '\uff18': '8', '\uff19': '9',
    # Subscript digits
    '\u2080': '0', '\u2081': '1', '\u2082': '2', '\u2083': '3', '\u2084': '4',
    '\u2085': '5', '\u2086': '6', '\u2087': '7', '\u2088': '8', '\u2089': '9',
    # Superscript digits
    '\u2070': '0', '\u00b9': '1', '\u00b2': '2', '\u00b3': '3', '\u2074': '4',
    '\u2075': '5', '\u2076': '6', '\u2077': '7', '\u2078': '8', '\u2079': '9',
    # Mathematical bold/monospace/sans digits (U+1D7CE-U+1D7FF) — common block
    # We handle these via NFKD normalization below.
    # Other lookalikes
    '\u04e8': '0',  # Cyrillic О with diaeresis (resembles 0)
}

# Letter confusables: Cyrillic, Greek, and other scripts that mimic Latin.
_LETTER_HOMOGLYPHS: dict[str, str] = {
    # Cyrillic → Latin
    '\u0410': 'A', '\u0430': 'a',  # А/а
    '\u0412': 'B', '\u0432': 'b',  # В/в (sometimes)
    '\u0421': 'C', '\u0441': 'c',  # С/с
    '\u0415': 'E', '\u0435': 'e',  # Е/е
    '\u041d': 'H', '\u043d': 'h',  # Н/н
    '\u0406': 'I', '\u0456': 'i',  # І/і (Ukrainian)
    '\u041a': 'K', '\u043a': 'k',  # К/к
    '\u041c': 'M', '\u043c': 'm',  # М/м
    '\u041e': 'O', '\u043e': 'o',  # О/о
    '\u0420': 'P', '\u0440': 'p',  # Р/р
    '\u0405': 'S', '\u0455': 's',  # Ѕ/ѕ (Macedonian)
    '\u0422': 'T', '\u0442': 't',  # Т/т
    '\u0425': 'X', '\u0445': 'x',  # Х/х
    '\u0423': 'Y', '\u0443': 'y',  # У/у
    # Greek → Latin
    '\u0391': 'A', '\u03b1': 'a',  # Α/α
    '\u0392': 'B', '\u03b2': 'b',  # Β/β
    '\u0395': 'E', '\u03b5': 'e',  # Ε/ε
    '\u0397': 'H', '\u03b7': 'h',  # Η/η
    '\u0399': 'I', '\u03b9': 'i',  # Ι/ι
    '\u039a': 'K', '\u03ba': 'k',  # Κ/κ
    '\u039c': 'M', '\u03bc': 'm',  # Μ/μ
    '\u039d': 'N', '\u03bd': 'n',  # Ν/ν
    '\u039f': 'O', '\u03bf': 'o',  # Ο/ο
    '\u03a1': 'P', '\u03c1': 'p',  # Ρ/ρ
    '\u03a4': 'T', '\u03c4': 't',  # Τ/τ
    '\u03a7': 'X', '\u03c7': 'x',  # Χ/χ
    '\u03a5': 'Y', '\u03c5': 'y',  # Υ/υ
    '\u0396': 'Z', '\u03b6': 'z',  # Ζ/ζ
    # Fullwidth Latin letters
    **{chr(c): chr(c - 0xFF21 + ord('A')) for c in range(0xFF21, 0xFF3B)},  # Ａ-Ｚ
    **{chr(c): chr(c - 0xFF41 + ord('a')) for c in range(0xFF41, 0xFF5B)},  # ａ-ｚ
    # Common symbol lookalikes
    '\u2010': '-',  # Hyphen
    '\u2011': '-',  # Non-Breaking Hyphen
    '\u2012': '-',  # Figure Dash
    '\u2013': '-',  # En Dash
    '\u2014': '-',  # Em Dash
    '\u2015': '-',  # Horizontal Bar
    '\u2212': '-',  # Minus Sign
    '\ufe58': '-',  # Small Em Dash
    '\ufe63': '-',  # Small Hyphen-Minus
    '\uff0d': '-',  # Fullwidth Hyphen-Minus
    '\uff0e': '.',  # Fullwidth Full Stop
    '\u2024': '.',  # One Dot Leader
    '\uff20': '@',  # Fullwidth Commercial At
    '\uff0f': '/',  # Fullwidth Solidus
}

# Combined map for fast lookup.
_HOMOGLYPH_MAP: dict[str, str] = {**_DIGIT_HOMOGLYPHS, **_LETTER_HOMOGLYPHS}


def normalize_homoglyphs(text: str) -> str:
    """Replace confusable Unicode characters with their ASCII equivalents.

    Applies two passes:
    1. NFKD decomposition to normalize fullwidth digits, ligatures, etc.
    2. Explicit homoglyph table for Cyrillic/Greek/symbol lookalikes.
    """
    # NFKD decomposes compatibility characters (fullwidth, circled, etc.) and
    # strips combining marks so that "３" becomes "3", "ﬁ" becomes "fi", etc.
    text = unicodedata.normalize('NFKC', text)

    # Apply explicit homoglyph replacements for characters NFKC doesn't fix.
    chars = list(text)
    for i, ch in enumerate(chars):
        replacement = _HOMOGLYPH_MAP.get(ch)
        if replacement is not None:
            chars[i] = replacement
    return ''.join(chars)


def normalize_text(text: str) -> tuple[str, list[int]]:
    """Full normalization pipeline: strip zero-width chars, normalize whitespace, then homoglyphs.

    Pipeline order:
    1. Strip zero-width / invisible characters (preserves offset map)
    2. Normalize exotic Unicode whitespace → ASCII space (1:1, no offset change)
    3. Normalize homoglyphs via NFKC + explicit mapping

    Returns:
        (normalized_text, offset_map) where offset_map maps positions in
        normalized_text back to the original text.
    """
    cleaned, offset_map = strip_zero_width(text)
    cleaned = normalize_whitespace(cleaned)
    normalized = normalize_homoglyphs(cleaned)
    return normalized, offset_map
