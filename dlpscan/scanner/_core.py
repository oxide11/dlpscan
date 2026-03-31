"""Core scanning engine: enhanced_scan_text."""

import logging
import signal
from typing import Generator, List, Optional, Set

from .. import models as _models
from ..ahocorasick import CONTEXT_BACKEND_AHOCORASICK, ContextHitIndex, get_matcher
from ..exceptions import InvalidCardNumberError
from ..metrics import MetricsCollector
from ..models import Match
from ..plugins import run_post_processors, run_validators
from ._config import _context_backend, _get_all_patterns
from ._context import _check_context
from ._scoring import _compute_confidence, _deduplicate_overlapping
from ._timeout import _can_use_sigalrm, _RegexTimeout, _ThreadTimeout, _timeout_handler
from ._validation import _normalize_text, _validate_text_input, is_luhn_valid

# Timeout in seconds for individual regex operations (0 = no timeout).
REGEX_TIMEOUT_SECONDS = 5

# Maximum number of matches returned by a single scan to prevent memory exhaustion.
MAX_MATCHES = 50_000

# Maximum total scan time in seconds across all patterns (0 = no limit).
MAX_SCAN_SECONDS = 120

logger = logging.getLogger(__name__)


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
                    if _thread_timeout and _thread_timeout.expired:
                        scan_timed_out = True
                        metrics.scan_truncated = True
                        logger.warning(
                            "Thread-based scan timeout (%ds) reached. Scan truncated.",
                            MAX_SCAN_SECONDS,
                        )
                        break

                    is_ctx_required = sub_category in _models.CONTEXT_REQUIRED_PATTERNS

                    try:
                        for match in pattern.finditer(text):
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

                            if is_ctx_required and not has_context:
                                continue

                            if require_context and not has_context:
                                continue

                            confidence = _compute_confidence(sub_category, has_context, is_ctx_required)

                            norm_start, norm_end = match.start(), match.end()
                            if offset_map:
                                orig_start = offset_map[norm_start] if norm_start < len(offset_map) else len(original_text)
                                orig_end = (offset_map[norm_end - 1] + 1) if norm_end <= len(offset_map) and norm_end > 0 else len(original_text)
                            else:
                                orig_start, orig_end = norm_start, norm_end

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

        raw_matches = run_post_processors(raw_matches)

        metrics.match_count = len(raw_matches)
        metrics.patterns_timed_out = patterns_timed_out

    yield from raw_matches
