"""Scanner configuration: backend selection, custom pattern registry."""

import logging
import re
import threading
from typing import Optional

from .. import models as _models
from ..ahocorasick import (
    CONTEXT_BACKEND_AHOCORASICK,
    DEFAULT_CONTEXT_BACKEND,
    VALID_BACKENDS,
    rebuild_matcher,
)
from ..context import CONTEXT_KEYWORDS
from ..models import PATTERN_SPECIFICITY
from ..patterns import PATTERNS

logger = logging.getLogger(__name__)

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
        rebuild_matcher(custom_context=_custom_context if _custom_context else None)
    logger.info("Context backend set to %r", backend)


def get_context_backend() -> str:
    """Return the current context keyword matching backend."""
    return _context_backend


# -- Custom pattern registry (protected by _registry_lock) --
_registry_lock = threading.Lock()
_custom_patterns: dict = {}
_custom_context: dict = {}
_custom_specificity_keys: dict = {}
_custom_context_required_keys: dict = {}

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
            _custom_context_required_keys[category] = set(context_required)
            _models.CONTEXT_REQUIRED_PATTERNS = _models.CONTEXT_REQUIRED_PATTERNS | frozenset(context_required)


def unregister_patterns(category: str):
    """Remove previously registered custom patterns and associated metadata."""
    with _registry_lock:
        _custom_patterns.pop(category, None)

        if category in _custom_context:
            _custom_context.pop(category)
            _rebuild_context_patterns()
            if _context_backend == CONTEXT_BACKEND_AHOCORASICK:
                rebuild_matcher(custom_context=_custom_context if _custom_context else None)

        removed_keys = _custom_specificity_keys.pop(category, set())
        for key in removed_keys:
            PATTERN_SPECIFICITY.pop(key, None)

        removed_ctx = _custom_context_required_keys.pop(category, set())
        if removed_ctx:
            _models.CONTEXT_REQUIRED_PATTERNS = _models.CONTEXT_REQUIRED_PATTERNS - frozenset(removed_ctx)


def _get_all_patterns() -> dict:
    """Return merged built-in + custom patterns."""
    merged = dict(PATTERNS)
    merged.update(_custom_patterns)
    return merged
