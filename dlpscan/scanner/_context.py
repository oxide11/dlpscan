"""Context keyword matching: exact, fuzzy (Levenshtein), and l33tspeak."""

import re
from typing import Optional

from ..ahocorasick import ContextHitIndex
from ..context import CONTEXT_KEYWORDS
from ..unicode_normalize import normalize_leet
from ._config import _custom_context, compiled_context_patterns

# Minimum edit distance for fuzzy matching (higher = more false positives).
FUZZY_MAX_DISTANCE = 2

# Minimum keyword length for fuzzy matching (short keywords produce too many
# false positives with edit distance > 0).
FUZZY_MIN_KEYWORD_LENGTH = 5


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings.

    Uses a single-row dynamic programming approach for O(min(m,n)) space.
    """
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if not s2:
        return len(s1)

    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            curr_row.append(min(
                curr_row[j] + 1,        # insertion
                prev_row[j + 1] + 1,    # deletion
                prev_row[j] + cost,      # substitution
            ))
        prev_row = curr_row

    return prev_row[-1]


def _fuzzy_keyword_match(text_window: str, keywords: list[str],
                         max_distance: int = FUZZY_MAX_DISTANCE) -> bool:
    """Check if any keyword appears in text_window with fuzzy matching.

    Handles both single-word and multi-word keywords by generating
    n-grams from the text window.
    """
    text_lower = text_window.lower()
    words = re.findall(r'\b\w+\b', text_lower)

    for keyword in keywords:
        kw_lower = keyword.lower()
        if len(kw_lower) < FUZZY_MIN_KEYWORD_LENGTH:
            continue

        kw_word_count = len(kw_lower.split())

        if kw_word_count == 1:
            for word in words:
                if abs(len(word) - len(kw_lower)) > max_distance:
                    continue
                if _levenshtein_distance(word, kw_lower) <= max_distance:
                    return True
        else:
            for i in range(len(words) - kw_word_count + 1):
                ngram = ' '.join(words[i:i + kw_word_count])
                if abs(len(ngram) - len(kw_lower)) > max_distance:
                    continue
                if _levenshtein_distance(ngram, kw_lower) <= max_distance:
                    return True
    return False


def scan_for_context(text: str, start_index: int, end_index: int,
                     category: str, sub_category: str) -> bool:
    """Check whether contextual keywords appear near the match span.

    Uses three-pass matching:
    1. Exact regex match against compiled keyword patterns (fast path).
    2. Fuzzy Levenshtein match (edit distance <= 2) for keywords >= 5 chars.
    3. L33tspeak-normalized re-check for obfuscated keywords.
    """
    if not isinstance(text, str):
        raise TypeError(f"Expected str for text, got {type(text).__name__}.")
    if not isinstance(start_index, int) or not isinstance(end_index, int):
        raise TypeError("start_index and end_index must be integers.")
    if start_index < 0 or end_index < 0:
        raise ValueError("start_index and end_index must be non-negative.")
    if end_index > len(text):
        raise ValueError("end_index exceeds text length.")
    if start_index > end_index:
        raise ValueError("start_index must not exceed end_index.")

    distance_config = CONTEXT_KEYWORDS.get(category, _custom_context.get(category, {}))
    distance = distance_config.get('distance', 50)

    pre_start = max(0, start_index - distance)
    post_end = min(len(text), end_index + distance)

    pre_text = text[pre_start:start_index]
    post_text = text[end_index:post_end]

    context_pattern = compiled_context_patterns.get((category, sub_category))
    if not context_pattern:
        return False

    # Fast path: exact regex match.
    if context_pattern.search(pre_text) or context_pattern.search(post_text):
        return True

    # Slow path: fuzzy matching for typos/misspellings.
    raw_keywords = _get_raw_keywords(category, sub_category)
    if raw_keywords:
        context_window = pre_text + ' ' + post_text
        if _fuzzy_keyword_match(context_window, raw_keywords):
            return True

        # L33tspeak path: normalize the context window and re-check.
        leet_window = normalize_leet(context_window)
        if leet_window != context_window:
            if context_pattern.search(normalize_leet(pre_text)) or \
               context_pattern.search(normalize_leet(post_text)):
                return True

    return False


def _get_raw_keywords(category: str, sub_category: str) -> list[str]:
    """Retrieve the raw keyword list for a given category/sub_category."""
    for source in (CONTEXT_KEYWORDS, _custom_context):
        cat_data = source.get(category, {})
        identifiers = cat_data.get('Identifiers', {})
        keywords = identifiers.get(sub_category, [])
        if keywords:
            return keywords
    return []


def _check_context(text: str, start: int, end: int,
                    category: str, sub_category: str,
                    ac_hit_index: Optional[ContextHitIndex] = None) -> bool:
    """Dispatch context check to the appropriate backend.

    When Aho-Corasick hit index is provided, uses fast positional lookup.
    Otherwise falls back to the regex-based scan_for_context.
    """
    if ac_hit_index is not None:
        distance_config = CONTEXT_KEYWORDS.get(category, _custom_context.get(category, {}))
        distance = distance_config.get('distance', 50)
        result = ac_hit_index.has_hit_in_range(
            category, sub_category,
            max(0, start - distance), end + distance,
        )
        if result:
            return True
        # Fall through to fuzzy matching (Aho-Corasick is exact only).
        raw_keywords = _get_raw_keywords(category, sub_category)
        if raw_keywords:
            pre_start = max(0, start - distance)
            post_end = min(len(text), end + distance)
            pre_text = text[pre_start:start]
            post_text = text[end:post_end]
            context_window = pre_text + ' ' + post_text
            if _fuzzy_keyword_match(context_window, raw_keywords):
                return True
            # L33tspeak path: normalize and re-check via AC index.
            leet_window = normalize_leet(context_window)
            if leet_window != context_window:
                context_pattern = compiled_context_patterns.get(
                    (category, sub_category))
                if context_pattern and (
                    context_pattern.search(normalize_leet(pre_text)) or
                    context_pattern.search(normalize_leet(post_text))
                ):
                    return True
        return False
    return scan_for_context(text, start, end, category, sub_category)
