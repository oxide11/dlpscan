"""LRU scan result cache with TTL eviction."""

from __future__ import annotations

import hashlib
import threading
import time
from collections import OrderedDict
from typing import Optional

from .guard.core import ScanResult

_CacheEntry = tuple  # (ScanResult, float timestamp)


class ScanCache:
    """Thread-safe LRU cache for scan results, keyed by SHA-256 of text."""

    def __init__(self, max_size: int = 1000, ttl_seconds: float = 300) -> None:
        self._max_size = max_size
        self._ttl_seconds = ttl_seconds
        self._store: OrderedDict[str, _CacheEntry] = OrderedDict()
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0

    @staticmethod
    def _key(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def get(self, text: str) -> Optional[ScanResult]:
        """Return cached result or None. Evicts expired entries lazily."""
        key = self._key(text)
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                self._misses += 1
                return None
            result, ts = entry
            if time.monotonic() - ts > self._ttl_seconds:
                del self._store[key]
                self._misses += 1
                return None
            # Move to end (most recently used)
            self._store.move_to_end(key)
            self._hits += 1
            return result

    def put(self, text: str, result: ScanResult) -> None:
        """Store a scan result, evicting LRU entry if at capacity."""
        key = self._key(text)
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
                self._store[key] = (result, time.monotonic())
                return
            if len(self._store) >= self._max_size:
                self._store.popitem(last=False)
            self._store[key] = (result, time.monotonic())

    def invalidate(self, text: str) -> None:
        """Remove a specific entry by text content."""
        key = self._key(text)
        with self._lock:
            self._store.pop(key, None)

    def clear(self) -> None:
        """Remove all cached entries."""
        with self._lock:
            self._store.clear()
            self._hits = 0
            self._misses = 0

    @property
    def stats(self) -> dict:
        """Return cache statistics."""
        with self._lock:
            return {
                "hits": self._hits,
                "misses": self._misses,
                "size": len(self._store),
            }


# ---------------------------------------------------------------------------
# Module-level default cache
# ---------------------------------------------------------------------------

_default_cache: Optional[ScanCache] = None
_default_cache_lock = threading.Lock()


def get_default_cache() -> Optional[ScanCache]:
    """Return the module-level default cache (may be None)."""
    with _default_cache_lock:
        return _default_cache


def set_default_cache(cache: Optional[ScanCache]) -> None:
    """Set (or clear) the module-level default cache."""
    global _default_cache
    with _default_cache_lock:
        _default_cache = cache
