"""Count-Min Sketch — probabilistic frequency estimation.

Space-efficient data structure for counting item frequencies in streams.
Answers "how many times has X been seen?" using constant memory regardless
of how many distinct items pass through.

Usage::

    from dlpscan.countmin import CountMinSketch

    cms = CountMinSketch(width=10000, depth=7)
    cms.increment("user:123:ssn")
    cms.increment("user:123:ssn")
    print(cms.estimate("user:123:ssn"))  # 2 (may overcount, never undercount)

DLP Use Case:

    Threshold-based alerting — "flag any channel where >50 SSNs have
    passed in the last hour." Uses ~280 KB regardless of volume.
"""

import hashlib
import struct
from typing import List


class CountMinSketch:
    """Count-Min Sketch for frequency estimation.

    Uses *depth* independent hash functions and a *width* x *depth* counter
    grid. ``increment(key)`` increments one counter per row. ``estimate(key)``
    returns the minimum across all rows — this is guaranteed to be ≥ the true
    count (never undercounts) but may overcount due to hash collisions.

    Error bounds:
        - Overcount ≤ total_count / width  (with probability 1 - (1/e)^depth)
        - width=10000, depth=7 → 99.9% of estimates within 0.01% of total count

    Args:
        width: Number of counters per row. More = less overcount.
        depth: Number of hash functions / rows. More = higher confidence.

    Memory: width × depth × 4 bytes (32-bit counters).
    """

    def __init__(self, width: int = 10000, depth: int = 7):
        if width <= 0 or depth <= 0:
            raise ValueError("width and depth must be positive integers")
        self._width = width
        self._depth = depth
        self._table: List[List[int]] = [[0] * width for _ in range(depth)]
        self._total = 0

    def _hashes(self, key: str) -> List[int]:
        """Compute *depth* independent hash indices for *key*."""
        key_bytes = key.encode('utf-8')
        indices = []
        for i in range(self._depth):
            h = hashlib.md5(key_bytes + struct.pack('<I', i)).digest()
            idx = struct.unpack('<I', h[:4])[0] % self._width
            indices.append(idx)
        return indices

    def increment(self, key: str, count: int = 1) -> None:
        """Increment the count for *key* by *count*."""
        for row, idx in enumerate(self._hashes(key)):
            self._table[row][idx] += count
        self._total += count

    def estimate(self, key: str) -> int:
        """Estimate the count for *key*.

        Returns the minimum counter across all rows — guaranteed ≥ true count.
        """
        return min(
            self._table[row][idx]
            for row, idx in enumerate(self._hashes(key))
        )

    @property
    def total(self) -> int:
        """Total number of increments across all keys."""
        return self._total

    @property
    def width(self) -> int:
        return self._width

    @property
    def depth(self) -> int:
        return self._depth

    def clear(self) -> None:
        """Reset all counters to zero."""
        for row in self._table:
            for i in range(len(row)):
                row[i] = 0
        self._total = 0

    def merge(self, other: 'CountMinSketch') -> None:
        """Merge another sketch into this one (element-wise addition).

        Both sketches must have the same dimensions.
        """
        if self._width != other._width or self._depth != other._depth:
            raise ValueError("Cannot merge sketches with different dimensions")
        for row in range(self._depth):
            for col in range(self._width):
                self._table[row][col] += other._table[row][col]
        self._total += other._total
