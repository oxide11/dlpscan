"""Cuckoo Filter — space-efficient probabilistic set with deletion support.

Like a Bloom filter but supports deletion. Stores tiny fingerprints in
buckets, using cuckoo hashing to resolve collisions.

Usage::

    from dlpscan.cuckoo import CuckooFilter

    cf = CuckooFilter(capacity=100000)
    cf.insert("secret-value-hash")
    cf.contains("secret-value-hash")   # True
    cf.delete("secret-value-hash")     # True (removed)
    cf.contains("secret-value-hash")   # False

DLP Use Case:

    Memory-efficient alternative to Python set() for EDM hash lookups.
    100K items in ~150 KB vs ~6.4 MB for a Python set of 64-char hex strings.
    Supports dynamic add/remove without rebuilding.
"""

import hashlib
import struct


class CuckooFilter:
    """Cuckoo Filter with configurable fingerprint size and bucket capacity.

    Args:
        capacity: Expected number of items. Actual table size is rounded up.
        bucket_size: Items per bucket (default 4). More = higher load factor.
        fingerprint_bits: Bits per fingerprint (default 16). More = lower FP rate.
        max_kicks: Maximum cuckoo displacements before declaring full (default 500).

    False positive rate: approximately 2 * bucket_size / 2^fingerprint_bits
        - fingerprint_bits=8,  bucket_size=4: ~3.1%
        - fingerprint_bits=12, bucket_size=4: ~0.19%
        - fingerprint_bits=16, bucket_size=4: ~0.012%

    Memory: capacity × fingerprint_bits / 8 bytes (approximately).
    """

    def __init__(self, capacity: int = 100000, bucket_size: int = 4,
                 fingerprint_bits: int = 16, max_kicks: int = 500):
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        if fingerprint_bits not in (8, 12, 16, 32):
            raise ValueError("fingerprint_bits must be 8, 12, 16, or 32")

        self._bucket_size = bucket_size
        self._fp_bits = fingerprint_bits
        self._fp_mask = (1 << fingerprint_bits) - 1
        self._max_kicks = max_kicks

        # Number of buckets (round up to power of 2 for fast modulo)
        num_buckets = max(1, capacity // bucket_size)
        self._num_buckets = 1
        while self._num_buckets < num_buckets:
            self._num_buckets <<= 1
        self._bucket_mask = self._num_buckets - 1

        # Bucket storage: list of lists (each bucket holds up to bucket_size fingerprints)
        self._buckets = [[] for _ in range(self._num_buckets)]
        self._count = 0

    def _hash(self, item: str) -> int:
        """Hash item to a 64-bit integer."""
        h = hashlib.sha256(item.encode('utf-8')).digest()
        return struct.unpack('<Q', h[:8])[0]

    def _fingerprint(self, item: str) -> int:
        """Compute fingerprint for item (non-zero)."""
        h = hashlib.md5(item.encode('utf-8')).digest()
        fp = struct.unpack('<I', h[:4])[0] & self._fp_mask
        return fp if fp != 0 else 1  # Fingerprint must be non-zero

    def _index1(self, item: str) -> int:
        """Primary bucket index."""
        return self._hash(item) & self._bucket_mask

    def _index2(self, i1: int, fingerprint: int) -> int:
        """Alternate bucket index via XOR with fingerprint hash."""
        fp_hash = hashlib.md5(struct.pack('<I', fingerprint)).digest()
        fp_idx = struct.unpack('<I', fp_hash[:4])[0]
        return (i1 ^ fp_idx) & self._bucket_mask

    def insert(self, item: str) -> bool:
        """Insert an item into the filter.

        Returns True if successful, False if the filter is full.
        """
        fp = self._fingerprint(item)
        i1 = self._index1(item)
        i2 = self._index2(i1, fp)

        # Try primary bucket
        if len(self._buckets[i1]) < self._bucket_size:
            self._buckets[i1].append(fp)
            self._count += 1
            return True

        # Try alternate bucket
        if len(self._buckets[i2]) < self._bucket_size:
            self._buckets[i2].append(fp)
            self._count += 1
            return True

        # Both full — cuckoo displacement
        import random
        rng = random.Random(fp)
        idx = rng.choice([i1, i2])

        for _ in range(self._max_kicks):
            # Pick a random entry to evict
            evict_pos = rng.randrange(len(self._buckets[idx]))
            evicted_fp = self._buckets[idx][evict_pos]
            self._buckets[idx][evict_pos] = fp

            # Find alternate bucket for evicted entry
            fp = evicted_fp
            idx = self._index2(idx, fp)

            if len(self._buckets[idx]) < self._bucket_size:
                self._buckets[idx].append(fp)
                self._count += 1
                return True

        # Filter is too full
        return False

    def contains(self, item: str) -> bool:
        """Check if an item might be in the filter.

        Returns True if the item is probably present (small FP rate),
        False if definitely not present.
        """
        fp = self._fingerprint(item)
        i1 = self._index1(item)
        i2 = self._index2(i1, fp)
        return fp in self._buckets[i1] or fp in self._buckets[i2]

    def delete(self, item: str) -> bool:
        """Delete an item from the filter.

        Returns True if the item was found and removed.
        Only delete items that were actually inserted — deleting
        non-existent items can cause false negatives.
        """
        fp = self._fingerprint(item)
        i1 = self._index1(item)
        i2 = self._index2(i1, fp)

        if fp in self._buckets[i1]:
            self._buckets[i1].remove(fp)
            self._count -= 1
            return True
        if fp in self._buckets[i2]:
            self._buckets[i2].remove(fp)
            self._count -= 1
            return True
        return False

    @property
    def count(self) -> int:
        """Number of items currently in the filter."""
        return self._count

    @property
    def capacity(self) -> int:
        """Maximum number of items the filter can hold."""
        return self._num_buckets * self._bucket_size

    @property
    def load_factor(self) -> float:
        """Current load factor (0.0 to 1.0)."""
        return self._count / self.capacity if self.capacity else 0.0

    @property
    def memory_bytes(self) -> int:
        """Approximate memory usage in bytes."""
        return self._num_buckets * self._bucket_size * (self._fp_bits // 8 + 1)

    def clear(self) -> None:
        """Remove all items."""
        for bucket in self._buckets:
            bucket.clear()
        self._count = 0
