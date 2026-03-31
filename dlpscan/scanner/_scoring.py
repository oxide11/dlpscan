"""Confidence scoring and overlap deduplication."""

from typing import List

from ..models import DEFAULT_SPECIFICITY, PATTERN_SPECIFICITY, Match


def _compute_confidence(sub_category: str, has_context: bool, context_required: bool) -> float:
    """Compute a 0.0-1.0 confidence score for a match.

    Factors:
    - Base specificity of the pattern (how unique the regex is)
    - Context keyword presence (boosts score)
    - Context required but missing (caps at low score)
    """
    base = PATTERN_SPECIFICITY.get(sub_category, DEFAULT_SPECIFICITY)

    if has_context:
        confidence = min(1.0, base + 0.20)
    elif context_required:
        confidence = base * 0.3
    else:
        confidence = base

    return round(confidence, 2)


def _deduplicate_overlapping(matches: List[Match]) -> List[Match]:
    """Remove overlapping matches, keeping the highest-confidence one.

    When two matches overlap in character span, keep the one with higher
    confidence. If tied, prefer the longer match.
    """
    if not matches:
        return matches

    sorted_matches = sorted(matches, key=lambda m: (m.span[0], -(m.span[1] - m.span[0])))

    result = []
    last_end = -1

    for m in sorted_matches:
        if m.span[0] >= last_end:
            result.append(m)
            last_end = m.span[1]
        else:
            prev = result[-1]
            if m.confidence > prev.confidence:
                result[-1] = m
                last_end = m.span[1]
            elif m.confidence == prev.confidence and (m.span[1] - m.span[0]) > (prev.span[1] - prev.span[0]):
                result[-1] = m
                last_end = m.span[1]

    return result
