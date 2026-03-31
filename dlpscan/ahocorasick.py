"""Aho-Corasick based context keyword matching engine.

Provides a single-pass O(n) alternative to the default regex alternation
approach for context keyword matching. Instead of running 560+ separate
regex patterns, this module builds a single automaton from all 2,500+
context keywords and scans the text once.

The automaton emits ``(position, keyword, category, sub_category)`` hits
which are indexed by position for fast proximity lookups.

Usage::

    from dlpscan.ahocorasick import AhoCorasickMatcher

    matcher = AhoCorasickMatcher()
    matcher.build()  # builds from CONTEXT_KEYWORDS

    # Single-pass scan
    hits = matcher.search(text)

    # Check context near a match span
    has_ctx = matcher.has_context_near(hits, start, end, category, sub_cat, distance=50)

Configuration:

    The matcher is opt-in. Enable via:
    - Environment variable: ``DLPSCAN_CONTEXT_BACKEND=ahocorasick``
    - Config file: ``context_backend = "ahocorasick"``
    - Programmatic: ``InputGuard(context_backend="ahocorasick")``

    Default is ``"regex"`` (the original compiled alternation patterns).
"""

import bisect
import logging
import threading
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Backend enum
# ---------------------------------------------------------------------------

CONTEXT_BACKEND_REGEX = "regex"
CONTEXT_BACKEND_AHOCORASICK = "ahocorasick"
VALID_BACKENDS = frozenset({CONTEXT_BACKEND_REGEX, CONTEXT_BACKEND_AHOCORASICK})

# Default backend — regex for backward compatibility.
DEFAULT_CONTEXT_BACKEND = CONTEXT_BACKEND_REGEX

# ---------------------------------------------------------------------------
# Hit data structure
# ---------------------------------------------------------------------------

class ContextHit:
    """A single keyword hit from the Aho-Corasick automaton."""
    __slots__ = ('position', 'keyword', 'category', 'sub_category')

    def __init__(self, position: int, keyword: str, category: str, sub_category: str):
        self.position = position
        self.keyword = keyword
        self.category = category
        self.sub_category = sub_category

    def __repr__(self) -> str:
        return (f"ContextHit(pos={self.position}, kw={self.keyword!r}, "
                f"cat={self.category!r}, sub={self.sub_category!r})")


class ContextHitIndex:
    """Positional index over Aho-Corasick hits for fast proximity queries.

    Hits are stored sorted by position per (category, sub_category) pair,
    enabling O(log n) range queries via binary search.
    """

    def __init__(self, hits: List[ContextHit]):
        # Map (cat, sub) -> sorted list of positions
        self._positions: Dict[Tuple[str, str], List[int]] = defaultdict(list)
        for h in hits:
            self._positions[(h.category, h.sub_category)].append(h.position)
        # Sort each list for binary search
        for key in self._positions:
            self._positions[key].sort()

    def has_hit_in_range(self, category: str, sub_category: str,
                         range_start: int, range_end: int) -> bool:
        """Check if any keyword hit for (category, sub_category) falls in [range_start, range_end).

        Uses binary search for O(log n) per query.
        """
        positions = self._positions.get((category, sub_category))
        if not positions:
            return False
        idx = bisect.bisect_left(positions, range_start)
        return idx < len(positions) and positions[idx] < range_end

    @property
    def empty(self) -> bool:
        return not self._positions


# ---------------------------------------------------------------------------
# Aho-Corasick Matcher
# ---------------------------------------------------------------------------

class AhoCorasickMatcher:
    """Single-pass multi-keyword matcher using the Aho-Corasick algorithm.

    Wraps the ``pyahocorasick`` C extension for native-speed trie traversal.
    Falls back to a pure-Python implementation if the C extension is unavailable.

    Thread-safe: the automaton is built once and then read-only.
    """

    def __init__(self):
        self._automaton = None
        self._built = False
        self._lock = threading.Lock()
        self._keyword_count = 0
        self._use_c_extension = False

    def build(self, context_keywords: Optional[dict] = None,
              custom_context: Optional[dict] = None) -> None:
        """Build the automaton from context keyword dictionaries.

        Args:
            context_keywords: The CONTEXT_KEYWORDS dict (category -> {Identifiers: {sub: [kws]}}).
                             If None, imports from dlpscan.context.
            custom_context: Optional custom context dict (same structure).
        """
        with self._lock:
            if context_keywords is None:
                from .context import CONTEXT_KEYWORDS
                context_keywords = CONTEXT_KEYWORDS

            # Try the C extension first.
            try:
                import ahocorasick
                self._automaton = ahocorasick.Automaton()
                self._use_c_extension = True
            except ImportError:
                logger.info("pyahocorasick not installed; using pure-Python fallback")
                self._automaton = _PurePythonAutomaton()
                self._use_c_extension = False

            count = 0
            for source in (context_keywords, custom_context):
                if source is None:
                    continue
                for category, details in source.items():
                    identifiers = details.get('Identifiers', {})
                    for sub_category, keywords in identifiers.items():
                        for kw in keywords:
                            kw_lower = kw.lower()
                            # Store (keyword, category, sub_category) as value.
                            # For the C extension, key collisions overwrite,
                            # so we use a list to support multiple mappings.
                            if self._use_c_extension:
                                existing = self._automaton.get(kw_lower, [])
                                existing.append((kw, category, sub_category))
                                self._automaton.add_word(kw_lower, existing)
                            else:
                                self._automaton.add_word(kw_lower, (kw, category, sub_category))
                            count += 1

            if self._use_c_extension:
                self._automaton.make_automaton()

            self._keyword_count = count
            self._built = True
            logger.debug("Aho-Corasick automaton built with %d keyword entries", count)

    @property
    def is_built(self) -> bool:
        return self._built

    @property
    def keyword_count(self) -> int:
        return self._keyword_count

    def search(self, text: str) -> ContextHitIndex:
        """Scan text in a single O(n) pass and return a positional hit index.

        Args:
            text: The text to search (will be lowercased internally).

        Returns:
            ContextHitIndex for fast proximity queries.
        """
        if not self._built:
            raise RuntimeError("Automaton not built. Call build() first.")

        text_lower = text.lower()
        hits: List[ContextHit] = []

        if self._use_c_extension:
            for end_pos, values in self._automaton.iter(text_lower):
                for kw, category, sub_category in values:
                    # end_pos is the index of the last char of the match
                    start_pos = end_pos - len(kw) + 1
                    hits.append(ContextHit(start_pos, kw, category, sub_category))
        else:
            for start_pos, values in self._automaton.iter(text_lower):
                for kw, category, sub_category in values:
                    hits.append(ContextHit(start_pos, kw, category, sub_category))

        return ContextHitIndex(hits)

    def has_context_near(self, hit_index: ContextHitIndex,
                         match_start: int, match_end: int,
                         category: str, sub_category: str,
                         distance: int = 50) -> bool:
        """Check if any context keyword is within distance of the match span.

        Args:
            hit_index: Pre-computed hit index from search().
            match_start: Start of the pattern match in text.
            match_end: End of the pattern match in text.
            category: Pattern category.
            sub_category: Pattern sub-category.
            distance: Maximum character distance for context window.

        Returns:
            True if a context keyword hit falls within the window.
        """
        range_start = max(0, match_start - distance)
        range_end = match_end + distance
        return hit_index.has_hit_in_range(category, sub_category, range_start, range_end)


# ---------------------------------------------------------------------------
# Pure-Python fallback automaton
# ---------------------------------------------------------------------------

class _TrieNode:
    """Node in the Aho-Corasick trie."""
    __slots__ = ('children', 'fail', 'output', 'depth')

    def __init__(self):
        self.children: Dict[str, '_TrieNode'] = {}
        self.fail: Optional['_TrieNode'] = None
        self.output: List[tuple] = []  # list of (keyword, category, sub_category)
        self.depth: int = 0


class _PurePythonAutomaton:
    """Pure-Python Aho-Corasick automaton.

    Builds a trie with failure links for linear-time multi-pattern matching.
    Used as fallback when pyahocorasick C extension is not available.
    """

    def __init__(self):
        self._root = _TrieNode()
        self._built = False

    def add_word(self, keyword: str, value: tuple) -> None:
        """Add a keyword and its associated value to the trie."""
        node = self._root
        for ch in keyword:
            if ch not in node.children:
                child = _TrieNode()
                child.depth = node.depth + 1
                node.children[ch] = child
            node = node.children[ch]
        node.output.append(value)

    def make_automaton(self) -> None:
        """Build failure links using BFS (standard Aho-Corasick construction)."""
        from collections import deque
        queue = deque()

        # Initialize depth-1 nodes: their fail links point to root.
        for ch, child in self._root.children.items():
            child.fail = self._root
            queue.append(child)

        # BFS to build failure links for deeper nodes.
        while queue:
            current = queue.popleft()
            for ch, child in current.children.items():
                queue.append(child)

                # Walk failure links to find longest proper suffix that is a prefix.
                fail = current.fail
                while fail is not None and ch not in fail.children:
                    fail = fail.fail
                child.fail = fail.children[ch] if fail is not None else self._root
                if child.fail is child:
                    child.fail = self._root

                # Merge output from fail node (dictionary suffix links).
                child.output = child.output + child.fail.output

        self._built = True

    def iter(self, text: str):
        """Iterate over all matches in text.

        Yields (start_position, values_list) for each match.
        """
        if not self._built:
            self.make_automaton()

        node = self._root
        for i, ch in enumerate(text):
            while node is not self._root and ch not in node.children:
                node = node.fail if node.fail is not None else self._root
            if ch in node.children:
                node = node.children[ch]
            else:
                node = self._root

            if node.output:
                for value in node.output:
                    kw = value[0]  # keyword string
                    start_pos = i - len(kw) + 1
                    yield start_pos, [value]


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_global_matcher: Optional[AhoCorasickMatcher] = None
_global_lock = threading.Lock()


def get_matcher() -> AhoCorasickMatcher:
    """Get or create the global Aho-Corasick matcher singleton.

    The automaton is built lazily on first access.
    """
    global _global_matcher
    if _global_matcher is not None and _global_matcher.is_built:
        return _global_matcher
    with _global_lock:
        if _global_matcher is None or not _global_matcher.is_built:
            _global_matcher = AhoCorasickMatcher()
            _global_matcher.build()
    return _global_matcher


def rebuild_matcher(custom_context: Optional[dict] = None) -> None:
    """Rebuild the global matcher (e.g. after registering custom patterns)."""
    global _global_matcher
    with _global_lock:
        _global_matcher = AhoCorasickMatcher()
        _global_matcher.build(custom_context=custom_context)
