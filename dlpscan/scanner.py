import fnmatch
import io
import logging
import os
import re
import signal
import threading
from typing import Generator, List, Optional, Set, Tuple

from .ahocorasick import (
    CONTEXT_BACKEND_AHOCORASICK,
    DEFAULT_CONTEXT_BACKEND,
    VALID_BACKENDS,
    ContextHitIndex,
    get_matcher,
    rebuild_matcher,
)
from .context import CONTEXT_KEYWORDS
from .exceptions import (
    EmptyInputError,
    InvalidCardNumberError,
    ShortInputError,
    SubCategoryNotFoundError,
)
from .metrics import MetricsCollector
from .models import (
    CONTEXT_REQUIRED_PATTERNS,
    DEFAULT_SPECIFICITY,
    PATTERN_SPECIFICITY,
    Match,
)
from .patterns import PATTERNS
from .plugins import run_post_processors, run_validators
from .unicode_normalize import normalize_text

logger = logging.getLogger(__name__)

# Maximum input size to prevent resource exhaustion (10 MB).
MAX_INPUT_SIZE = 10 * 1024 * 1024

# Timeout in seconds for individual regex operations (0 = no timeout).
REGEX_TIMEOUT_SECONDS = 5

# Maximum number of matches returned by a single scan to prevent memory exhaustion.
MAX_MATCHES = 50_000

# Maximum total scan time in seconds across all patterns (0 = no limit).
MAX_SCAN_SECONDS = 120

# -- Context backend setting --
_context_backend: str = DEFAULT_CONTEXT_BACKEND


def set_context_backend(backend: str) -> None:
    """Set the context keyword matching backend.

    Args:
        backend: ``"regex"`` (default, compiled alternation patterns) or
                 ``"ahocorasick"`` (single-pass trie-based matching).
    """
    global _context_backend
    backend = backend.strip().lower()
    if backend not in VALID_BACKENDS:
        raise ValueError(f"Invalid context backend {backend!r}. "
                         f"Valid options: {sorted(VALID_BACKENDS)}")
    _context_backend = backend
    if backend == CONTEXT_BACKEND_AHOCORASICK:
        # Eagerly build the automaton so first scan isn't slow.
        rebuild_matcher(custom_context=_custom_context if _custom_context else None)
    logger.info("Context backend set to %r", backend)


def get_context_backend() -> str:
    """Return the current context keyword matching backend."""
    return _context_backend


# -- Custom pattern registry (protected by _registry_lock) --
_registry_lock = threading.Lock()
_custom_patterns: dict = {}
_custom_context: dict = {}
_custom_specificity_keys: dict = {}  # category -> set of keys added to PATTERN_SPECIFICITY
_custom_context_required_keys: dict = {}  # category -> set of keys added

# Pre-compile context keyword patterns for proximity matching.
compiled_context_patterns: dict = {}


def _rebuild_context_patterns():
    """Rebuild compiled context patterns from CONTEXT_KEYWORDS + custom context."""
    compiled_context_patterns.clear()
    for source in (CONTEXT_KEYWORDS, _custom_context):
        for _category, _details in source.items():
            _identifiers = _details.get('Identifiers', {})
            for _sub_category, _keywords in _identifiers.items():
                if _keywords:
                    compiled_context_patterns[(_category, _sub_category)] = re.compile(
                        r'\b(' + '|'.join(map(re.escape, _keywords)) + r')\b',
                        re.IGNORECASE,
                    )


_rebuild_context_patterns()


# -- Custom pattern registration API --

def register_patterns(category: str, patterns: dict, context: Optional[dict] = None,
                      specificity: Optional[dict] = None,
                      context_required: Optional[set] = None):
    """Register custom patterns at runtime.

    Args:
        category: Category name (e.g., 'My Custom Patterns').
        patterns: Dict of {sub_category: compiled_regex_pattern}.
        context: Optional context keywords dict with 'Identifiers' and 'distance'.
        specificity: Optional dict of {sub_category: float} specificity scores.
        context_required: Optional set of sub_category names that require context.

    Example::

        import re
        from dlpscan import register_patterns

        register_patterns(
            category='Internal IDs',
            patterns={
                'Project Code': re.compile(r'\\bPRJ-\\d{6}\\b'),
                'Employee Badge': re.compile(r'\\bEMP\\d{5}\\b'),
            },
            context={
                'Identifiers': {
                    'Project Code': ['project', 'project id', 'project code'],
                    'Employee Badge': ['badge', 'employee', 'badge number'],
                },
                'distance': 50,
            },
            specificity={
                'Project Code': 0.80,
                'Employee Badge': 0.70,
            },
        )
    """
    if not isinstance(category, str) or not category:
        raise ValueError("category must be a non-empty string.")
    if not isinstance(patterns, dict) or not patterns:
        raise ValueError("patterns must be a non-empty dict of {name: compiled_regex}.")

    with _registry_lock:
        _custom_patterns[category] = patterns

        if context:
            _custom_context[category] = context
            _rebuild_context_patterns()
            if _context_backend == CONTEXT_BACKEND_AHOCORASICK:
                rebuild_matcher(custom_context=_custom_context)

        if specificity:
            PATTERN_SPECIFICITY.update(specificity)
            _custom_specificity_keys[category] = set(specificity.keys())

        if context_required:
            global CONTEXT_REQUIRED_PATTERNS
            _custom_context_required_keys[category] = set(context_required)
            CONTEXT_REQUIRED_PATTERNS = CONTEXT_REQUIRED_PATTERNS | frozenset(context_required)


def unregister_patterns(category: str):
    """Remove previously registered custom patterns and associated metadata."""
    with _registry_lock:
        _custom_patterns.pop(category, None)

        if category in _custom_context:
            _custom_context.pop(category)
            _rebuild_context_patterns()
            if _context_backend == CONTEXT_BACKEND_AHOCORASICK:
                rebuild_matcher(custom_context=_custom_context if _custom_context else None)

        # Clean up specificity entries added by this category.
        removed_keys = _custom_specificity_keys.pop(category, set())
        for key in removed_keys:
            PATTERN_SPECIFICITY.pop(key, None)

        # Clean up context_required entries added by this category.
        removed_ctx = _custom_context_required_keys.pop(category, set())
        if removed_ctx:
            global CONTEXT_REQUIRED_PATTERNS
            CONTEXT_REQUIRED_PATTERNS = CONTEXT_REQUIRED_PATTERNS - frozenset(removed_ctx)


def _get_all_patterns() -> dict:
    """Return merged built-in + custom patterns."""
    merged = dict(PATTERNS)
    merged.update(_custom_patterns)
    return merged


# -- Internal helpers --

class _RegexTimeout(Exception):
    """Raised when a regex operation exceeds the time limit."""


def _timeout_handler(signum, frame):
    raise _RegexTimeout("Regex operation timed out")


def _can_use_sigalrm() -> bool:
    """Check if SIGALRM is available and we are in the main thread."""
    return (
        hasattr(signal, 'SIGALRM')
        and threading.current_thread() is threading.main_thread()
    )


class _ThreadTimeout:
    """Cross-platform timeout using threading.Timer for non-Unix/non-main-thread.

    Sets a flag that the scan loop checks periodically. Unlike SIGALRM this
    cannot interrupt a blocking regex mid-execution, but it prevents runaway
    scans from consuming unbounded time across pattern iterations.
    """

    def __init__(self, seconds: int):
        self._seconds = seconds
        self._expired = False
        self._timer: Optional[threading.Timer] = None

    def start(self) -> None:
        if self._seconds <= 0:
            return
        self._expired = False
        self._timer = threading.Timer(self._seconds, self._expire)
        self._timer.daemon = True
        self._timer.start()

    def _expire(self) -> None:
        self._expired = True

    @property
    def expired(self) -> bool:
        return self._expired

    def cancel(self) -> None:
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None


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


# -- Confidence scoring --

def _compute_confidence(sub_category: str, has_context: bool, context_required: bool) -> float:
    """Compute a 0.0-1.0 confidence score for a match.

    Factors:
    - Base specificity of the pattern (how unique the regex is)
    - Context keyword presence (boosts score)
    - Context required but missing (caps at low score)
    """
    base = PATTERN_SPECIFICITY.get(sub_category, DEFAULT_SPECIFICITY)

    if has_context:
        # Context keywords found — boost confidence.
        confidence = min(1.0, base + 0.20)
    elif context_required:
        # Pattern is broad AND no context found — very low confidence.
        confidence = base * 0.3
    else:
        # No context but pattern is specific enough to stand alone.
        confidence = base

    return round(confidence, 2)


# -- Overlap deduplication --

def _deduplicate_overlapping(matches: List[Match]) -> List[Match]:
    """Remove overlapping matches, keeping the highest-confidence one.

    When two matches overlap in character span, keep the one with higher
    confidence. If tied, prefer the longer match.
    """
    if not matches:
        return matches

    # Sort by span start, then by span length descending.
    sorted_matches = sorted(matches, key=lambda m: (m.span[0], -(m.span[1] - m.span[0])))

    result = []
    last_end = -1

    for m in sorted_matches:
        if m.span[0] >= last_end:
            # No overlap — add directly.
            result.append(m)
            last_end = m.span[1]
        else:
            # Overlaps with previous — keep higher confidence.
            prev = result[-1]
            if m.confidence > prev.confidence:
                result[-1] = m
                last_end = m.span[1]
            elif m.confidence == prev.confidence and (m.span[1] - m.span[0]) > (prev.span[1] - prev.span[0]):
                result[-1] = m
                last_end = m.span[1]

    return result


# -- Public API --

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

    Text is normalized (zero-width chars stripped, homoglyphs mapped) before
    pattern matching so that Unicode evasion techniques are ineffective.
    Redaction is applied to the original text at the mapped-back positions.
    """
    original_text = _validate_text_input(text)
    normalized, offset_map = _normalize_text(original_text)

    all_patterns = _get_all_patterns()

    if category not in all_patterns or sub_category not in all_patterns[category]:
        raise SubCategoryNotFoundError(
            f"Sub-Category '{sub_category}' not found in PATTERNS for category '{category}'."
        )

    pattern = all_patterns[category][sub_category]

    # Collect spans in original text that need redacting.
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

    # Build redacted string from original text.
    result = list(original_text)
    _PRESERVED_DELIMITERS = frozenset('-. /\\_\u2013\u2014\u00a0')
    for start, end in redact_spans:
        for i in range(start, end):
            if result[i] not in _PRESERVED_DELIMITERS and result[i].isprintable():
                result[i] = 'X'
    return ''.join(result)


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
            # Cost is 0 if characters match, 1 otherwise.
            cost = 0 if c1 == c2 else 1
            curr_row.append(min(
                curr_row[j] + 1,        # insertion
                prev_row[j + 1] + 1,    # deletion
                prev_row[j] + cost,     # substitution
            ))
        prev_row = curr_row
    return prev_row[-1]


# Maximum edit distance for fuzzy context keyword matching.
FUZZY_MAX_DISTANCE = 2

# Minimum keyword length for fuzzy matching (short keywords produce too many
# false positives with edit distance > 0).
FUZZY_MIN_KEYWORD_LENGTH = 5


def _fuzzy_keyword_match(text_window: str, keywords: list[str],
                         max_distance: int = FUZZY_MAX_DISTANCE) -> bool:
    """Check if any keyword appears in text_window with fuzzy matching.

    Handles both single-word and multi-word keywords by generating
    n-grams from the text window. Compares each n-gram against each
    keyword using Levenshtein edit distance.
    """
    text_lower = text_window.lower()
    words = re.findall(r'\b\w+\b', text_lower)

    for keyword in keywords:
        kw_lower = keyword.lower()
        # Skip short keywords for fuzzy matching — too many false positives.
        if len(kw_lower) < FUZZY_MIN_KEYWORD_LENGTH:
            continue

        kw_word_count = len(kw_lower.split())

        if kw_word_count == 1:
            # Single-word keyword: compare against individual words.
            for word in words:
                if abs(len(word) - len(kw_lower)) > max_distance:
                    continue
                if _levenshtein_distance(word, kw_lower) <= max_distance:
                    return True
        else:
            # Multi-word keyword: generate n-grams of matching word count
            # and compare the joined n-gram against the keyword.
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

    Uses two-pass matching:
    1. Exact regex match against compiled keyword patterns (fast path).
    2. Fuzzy Levenshtein match (edit distance ≤ 2) for keywords ≥ 5 chars,
       catching typos, abbreviations, and close misspellings.

    Returns True if any keyword is found within the configured distance,
    False otherwise. Returns False if no context keywords are configured
    for the given category/sub_category pair.
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

    # Check built-in context, then custom context.
    distance_config = CONTEXT_KEYWORDS.get(category, _custom_context.get(category, {}))
    distance = distance_config.get('distance', 50)

    # Clamp indices to valid range.
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
    # Retrieve the raw keyword list for this sub_category.
    raw_keywords = _get_raw_keywords(category, sub_category)
    if raw_keywords:
        context_window = pre_text + ' ' + post_text
        if _fuzzy_keyword_match(context_window, raw_keywords):
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
        # Look up context distance config.
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
            context_window = text[pre_start:start] + ' ' + text[end:post_end]
            if _fuzzy_keyword_match(context_window, raw_keywords):
                return True
        return False
    return scan_for_context(text, start, end, category, sub_category)


def enhanced_scan_text(
    text: str,
    categories: Optional[Set[str]] = None,
    require_context: bool = False,
    max_matches: int = MAX_MATCHES,
    deduplicate: bool = True,
) -> Generator[Match, None, None]:
    """Scan *text* for sensitive data using PATTERNS, with optional context verification.

    Args:
        text: The input text to scan.
        categories: Optional set of category names to scan. If None, scans all.
        require_context: If True, only yield matches that have contextual keyword support.
        max_matches: Maximum number of matches to return (default MAX_MATCHES).
        deduplicate: If True (default), remove overlapping matches keeping highest confidence.

    Yields:
        Match objects with text, category, sub_category, has_context, confidence, span.
        Match objects support tuple unpacking for backward compatibility:
        ``text, sub_category, has_context, category = match``

    Note:
        Uses SIGALRM on Unix main thread for hard timeout, with a
        threading.Timer fallback on all other platforms/threads.
    """
    original_text = _validate_text_input(text)

    # Normalize to defeat zero-width character and homoglyph evasion.
    text, offset_map = _normalize_text(original_text)

    all_patterns = _get_all_patterns()

    patterns_to_scan = all_patterns
    if categories is not None:
        patterns_to_scan = {k: v for k, v in all_patterns.items() if k in categories}

    raw_matches: List[Match] = []
    scan_timed_out = False
    patterns_timed_out = 0

    with MetricsCollector() as metrics:
        metrics.bytes_scanned = len(original_text)
        metrics.categories_scanned = len(patterns_to_scan)

        # Set up global scan timeout: prefer SIGALRM, fall back to threading.Timer.
        _global_old_handler = None
        _thread_timeout: Optional[_ThreadTimeout] = None
        use_sigalrm = MAX_SCAN_SECONDS > 0 and _can_use_sigalrm()

        if use_sigalrm:
            _global_old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
            signal.alarm(MAX_SCAN_SECONDS)
        elif MAX_SCAN_SECONDS > 0:
            # Cross-platform fallback: threading.Timer sets a flag checked in the loop.
            _thread_timeout = _ThreadTimeout(MAX_SCAN_SECONDS)
            _thread_timeout.start()

        # Pre-compute Aho-Corasick hit index if using that backend.
        _ac_hit_index: Optional[ContextHitIndex] = None
        if _context_backend == CONTEXT_BACKEND_AHOCORASICK:
            try:
                matcher = get_matcher()
                _ac_hit_index = matcher.search(text)
            except Exception:
                logger.warning("Aho-Corasick search failed; falling back to regex")
                _ac_hit_index = None

        try:
            for category, sub_categories in patterns_to_scan.items():
                if scan_timed_out or len(raw_matches) >= max_matches:
                    break
                # Check thread-based timeout between categories.
                if _thread_timeout and _thread_timeout.expired:
                    scan_timed_out = True
                    metrics.scan_truncated = True
                    logger.warning(
                        "Thread-based scan timeout (%ds) reached. Scan truncated.",
                        MAX_SCAN_SECONDS,
                    )
                    break

                for sub_category, pattern in sub_categories.items():
                    if scan_timed_out or len(raw_matches) >= max_matches:
                        break
                    # Check thread-based timeout between sub-categories.
                    if _thread_timeout and _thread_timeout.expired:
                        scan_timed_out = True
                        metrics.scan_truncated = True
                        logger.warning(
                            "Thread-based scan timeout (%ds) reached. Scan truncated.",
                            MAX_SCAN_SECONDS,
                        )
                        break

                    is_ctx_required = sub_category in CONTEXT_REQUIRED_PATTERNS

                    try:
                        for match in pattern.finditer(text):
                            # For credit cards, apply Luhn validation.
                            if category == 'Credit Card Numbers':
                                try:
                                    if not is_luhn_valid(match.group()):
                                        continue
                                except InvalidCardNumberError:
                                    continue

                            has_context = _check_context(
                                text, match.start(), match.end(),
                                category, sub_category, _ac_hit_index
                            )

                            # Context-required patterns are silently skipped without context.
                            if is_ctx_required and not has_context:
                                continue

                            # User-requested require_context filter.
                            if require_context and not has_context:
                                continue

                            confidence = _compute_confidence(sub_category, has_context, is_ctx_required)

                            # Map span back to original text positions.
                            norm_start, norm_end = match.start(), match.end()
                            if offset_map:
                                orig_start = offset_map[norm_start] if norm_start < len(offset_map) else len(original_text)
                                orig_end = (offset_map[norm_end - 1] + 1) if norm_end <= len(offset_map) and norm_end > 0 else len(original_text)
                            else:
                                orig_start, orig_end = norm_start, norm_end

                            # Use the original text slice for the match text so
                            # callers see the actual content (including any
                            # zero-width chars that were present).
                            original_match_text = original_text[orig_start:orig_end]

                            m = Match(
                                text=original_match_text,
                                category=category,
                                sub_category=sub_category,
                                has_context=has_context,
                                confidence=confidence,
                                span=(orig_start, orig_end),
                                context_required=is_ctx_required,
                            )

                            # Run plugin validators — discard match if any validator rejects.
                            if not run_validators(m):
                                continue

                            raw_matches.append(m)

                            if len(raw_matches) >= max_matches:
                                logger.warning(
                                    "Match limit reached (%d). Scan truncated.", max_matches
                                )
                                metrics.scan_truncated = True
                                break
                    except _RegexTimeout:
                        patterns_timed_out += 1
                        if _global_old_handler is not None:
                            scan_timed_out = True
                            metrics.scan_truncated = True
                            logger.warning(
                                "Global scan timeout (%ds) reached. Scan truncated.",
                                MAX_SCAN_SECONDS,
                            )
                        else:
                            logger.warning(
                                "Regex timeout: pattern %r skipped.", pattern.pattern
                            )
        finally:
            if _global_old_handler is not None:
                signal.signal(signal.SIGALRM, _global_old_handler)
                signal.alarm(0)
            if _thread_timeout is not None:
                _thread_timeout.cancel()

        if deduplicate:
            raw_matches = _deduplicate_overlapping(raw_matches)

        # Run plugin post-processors on the full match list.
        raw_matches = run_post_processors(raw_matches)

        metrics.match_count = len(raw_matches)
        metrics.patterns_timed_out = patterns_timed_out

    yield from raw_matches


# -- File / stream scanning --

def _scan_chunks(
    read_fn,
    categories: Optional[Set[str]],
    require_context: bool,
    max_matches: int,
    deduplicate: bool,
    chunk_size: int,
    chunk_overlap: int,
) -> Generator[Match, None, None]:
    """Shared chunked scanning logic for files and streams.

    Args:
        read_fn: Callable that reads up to N characters (e.g., file.read).
        categories: Optional set of category names to scan.
        require_context: If True, only yield matches with context.
        max_matches: Maximum total matches to return.
        deduplicate: If True, deduplicate overlapping matches per chunk.
        chunk_size: Characters per chunk.
        chunk_overlap: Overlap between chunks.

    Yields:
        Match objects with span offsets relative to the full input.
    """
    total_yielded = 0
    offset = 0
    prev_tail = ''
    # Track yielded spans to avoid duplicates from the overlap region.
    seen_spans: set = set()

    while True:
        raw = read_fn(chunk_size)
        if not raw:
            break

        # Prepend overlap from previous chunk to catch boundary matches.
        chunk = prev_tail + raw
        chunk_offset = offset - len(prev_tail)

        try:
            for m in enhanced_scan_text(
                chunk,
                categories=categories,
                require_context=require_context,
                max_matches=max_matches - total_yielded,
                deduplicate=deduplicate,
            ):
                # Adjust span to be relative to the full input.
                abs_span = (m.span[0] + chunk_offset, m.span[1] + chunk_offset)

                # Skip matches already yielded from a previous chunk's overlap.
                if abs_span in seen_spans:
                    continue
                seen_spans.add(abs_span)

                adjusted = Match(
                    text=m.text,
                    category=m.category,
                    sub_category=m.sub_category,
                    has_context=m.has_context,
                    confidence=m.confidence,
                    span=abs_span,
                    context_required=m.context_required,
                )
                yield adjusted
                total_yielded += 1

                if total_yielded >= max_matches:
                    return
        except EmptyInputError:
            pass  # Chunk was empty after preprocessing — expected for sparse files.
        except ValueError as exc:
            logger.debug("Chunk skipped (offset %d): %s", chunk_offset, exc)

        # Keep tail for overlap with next chunk.
        prev_tail = raw[-chunk_overlap:] if len(raw) >= chunk_overlap else raw
        offset += len(raw)

        # Prune seen_spans — only need to track spans that could appear in the
        # next chunk's overlap region.  Anything before (offset - chunk_overlap)
        # can't be duplicated.
        cutoff = offset - chunk_overlap
        seen_spans = {s for s in seen_spans if s[1] > cutoff}


def scan_file(
    file_path: str,
    categories: Optional[Set[str]] = None,
    require_context: bool = False,
    max_matches: int = MAX_MATCHES,
    deduplicate: bool = True,
    encoding: str = 'utf-8',
    chunk_size: int = 1024 * 1024,
    chunk_overlap: int = 1024,
) -> Generator[Match, None, None]:
    """Scan a file for sensitive data, processing in chunks for memory efficiency.

    Args:
        file_path: Path to the file to scan.
        categories: Optional set of category names to scan.
        require_context: If True, only yield matches with context.
        max_matches: Maximum total matches to return.
        deduplicate: If True, deduplicate overlapping matches per chunk.
        encoding: File encoding (default 'utf-8').
        chunk_size: Size of each chunk in bytes (default 1 MB).
        chunk_overlap: Overlap between chunks to catch matches at boundaries (default 1 KB).

    Yields:
        Match objects with span offsets relative to the full file.
    """
    try:
        file_size = os.path.getsize(file_path)
    except OSError:
        raise FileNotFoundError(f"File not found: {file_path}")

    if file_size == 0:
        return

    with open(file_path, 'r', encoding=encoding, errors='replace') as f:
        yield from _scan_chunks(
            f.read, categories, require_context, max_matches,
            deduplicate, chunk_size, chunk_overlap,
        )


def scan_stream(
    stream: io.TextIOBase,
    categories: Optional[Set[str]] = None,
    require_context: bool = False,
    max_matches: int = MAX_MATCHES,
    deduplicate: bool = True,
    chunk_size: int = 1024 * 1024,
    chunk_overlap: int = 1024,
) -> Generator[Match, None, None]:
    """Scan a text stream for sensitive data.

    Works like scan_file but accepts any text stream (StringIO, stdin, etc.).

    Args:
        stream: A readable text stream.
        categories: Optional set of category names to scan.
        require_context: If True, only yield matches with context.
        max_matches: Maximum total matches to return.
        deduplicate: If True, deduplicate overlapping matches per chunk.
        chunk_size: Characters to read per chunk (default 1M).
        chunk_overlap: Overlap between chunks (default 1K).

    Yields:
        Match objects with span offsets relative to stream start.
    """
    yield from _scan_chunks(
        stream.read, categories, require_context, max_matches,
        deduplicate, chunk_size, chunk_overlap,
    )


# Default directories and file extensions to skip during directory scanning.
_SKIP_DIRS = frozenset({
    '.git', '.hg', '.svn', '__pycache__', 'node_modules', '.tox',
    '.mypy_cache', '.ruff_cache', '.pytest_cache', 'venv', '.venv',
    'env', '.env', 'dist', 'build', '.eggs', '*.egg-info',
})

_BINARY_EXTENSIONS = frozenset({
    '.pyc', '.pyo', '.so', '.dylib', '.dll', '.exe', '.bin',
    '.gif', '.ico',
    '.mp3', '.mp4', '.avi', '.mov', '.mkv', '.wav', '.flac',
    '.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.sqlite', '.db', '.pickle', '.pkl',
})

# Extensions that require extractors (not raw text reading).
# scan_directory delegates these to the extraction pipeline.
_EXTRACTOR_EXTENSIONS = frozenset({
    '.png', '.jpg', '.jpeg', '.bmp', '.tiff', '.tif', '.webp',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
})


def _has_extractor(path: str) -> bool:
    """Check if a file has a registered extractor (e.g. images, Office docs)."""
    _, ext = os.path.splitext(path)
    return ext.lower() in _EXTRACTOR_EXTENSIONS


def _is_binary_file(path: str) -> bool:
    """Quick heuristic to detect binary files."""
    _, ext = os.path.splitext(path)
    ext_lower = ext.lower()
    if ext_lower in _BINARY_EXTENSIONS:
        return True
    # Files with extractors are handled separately, not as binary.
    if ext_lower in _EXTRACTOR_EXTENSIONS:
        return False
    # Check first 8KB for null bytes
    try:
        with open(path, 'rb') as f:
            chunk = f.read(8192)
            return b'\x00' in chunk
    except OSError:
        return True


def scan_directory(
    dir_path: str,
    categories: Optional[Set[str]] = None,
    require_context: bool = False,
    max_matches: int = MAX_MATCHES,
    deduplicate: bool = True,
    encoding: str = 'utf-8',
    skip_paths: Optional[List[str]] = None,
) -> Generator[Tuple[str, Match], None, None]:
    """Recursively scan all text files in a directory.

    Args:
        dir_path: Path to the directory to scan.
        categories: Optional set of category names to scan.
        require_context: If True, only yield matches with context.
        max_matches: Maximum total matches across all files.
        deduplicate: If True, deduplicate overlapping matches per file.
        encoding: File encoding (default 'utf-8').
        skip_paths: Optional list of glob patterns for paths to skip.

    Yields:
        (file_path, match) tuples where match is a Match object.
    """
    if not os.path.isdir(dir_path):
        raise FileNotFoundError(f"Directory not found: {dir_path}")

    total_yielded = 0
    skip_globs = skip_paths or []

    for root, dirs, files in os.walk(dir_path):
        # Prune skipped directories in-place.
        dirs[:] = [
            d for d in dirs
            if d not in _SKIP_DIRS
            and not any(fnmatch.fnmatch(d, p) for p in _SKIP_DIRS if '*' in p)
        ]

        for filename in sorted(files):
            if total_yielded >= max_matches:
                return

            file_path = os.path.join(root, filename)
            rel_path = os.path.relpath(file_path, dir_path)

            # Skip paths matching ignore globs.
            if any(fnmatch.fnmatch(rel_path, g) for g in skip_globs):
                continue

            # Skip binary files.
            if _is_binary_file(file_path):
                continue

            try:
                # Files with registered extractors (images, Office docs, PDFs)
                # are processed via text extraction first.
                if _has_extractor(file_path):
                    try:
                        from .extractors import extract_text as _extract
                        result = _extract(file_path)
                        if result.text:
                            for m in enhanced_scan_text(
                                result.text,
                                categories=categories,
                                require_context=require_context,
                                max_matches=max_matches - total_yielded,
                                deduplicate=deduplicate,
                            ):
                                yield (rel_path, m)
                                total_yielded += 1
                                if total_yielded >= max_matches:
                                    return
                    except ImportError as exc:
                        logger.debug("Extractor dependency missing for %s: %s", file_path, exc)
                    except (FileNotFoundError, OSError) as exc:
                        logger.warning("Extractor I/O error for %s: %s", file_path, exc)
                    except Exception as exc:
                        logger.warning("Extractor failed for %s: %s", file_path, exc)
                    continue

                for m in scan_file(
                    file_path,
                    categories=categories,
                    require_context=require_context,
                    max_matches=max_matches - total_yielded,
                    deduplicate=deduplicate,
                    encoding=encoding,
                ):
                    yield (rel_path, m)
                    total_yielded += 1

                    if total_yielded >= max_matches:
                        return
            except (FileNotFoundError, UnicodeDecodeError, OSError) as exc:
                logger.debug("Skipping %s: %s", file_path, exc)
                continue
