"""HyperLogLog — probabilistic cardinality estimation.

Estimates the number of *unique* items in a stream using ~1.5 KB of memory,
regardless of how many items pass through (even billions).

Usage::

    from dlpscan.hyperloglog import HyperLogLog

    hll = HyperLogLog(precision=14)  # 2^14 = 16K registers ≈ 1.5 KB
    for record in stream:
        hll.add(record)
    print(f"Approximately {hll.count()} unique records seen")

DLP Use Case:

    Detect mass exfiltration — if 10,000 unique confidential file signatures
    pass through the firewall in an hour, trigger lockdown. All using <2 KB.
"""

import hashlib
import math
import struct


class HyperLogLog:
    """HyperLogLog cardinality estimator.

    Uses *2^precision* registers to estimate the number of distinct items
    added via ``add()``. The ``count()`` method returns the estimate.

    Standard error: 1.04 / sqrt(2^precision)
        - precision=10: ±3.25% error, 1 KB memory
        - precision=12: ±1.63% error, 4 KB memory
        - precision=14: ±0.81% error, 16 KB memory (default)
        - precision=16: ±0.41% error, 64 KB memory

    Args:
        precision: Number of bits for register indexing (4-16).
                   Higher = more accurate but more memory.
    """

    def __init__(self, precision: int = 14):
        if not 4 <= precision <= 16:
            raise ValueError(f"precision must be 4-16, got {precision}")
        self._p = precision
        self._m = 1 << precision  # number of registers
        self._registers = bytearray(self._m)
        self._count_added = 0

        # Alpha constant for bias correction
        if self._m == 16:
            self._alpha = 0.673
        elif self._m == 32:
            self._alpha = 0.697
        elif self._m == 64:
            self._alpha = 0.709
        else:
            self._alpha = 0.7213 / (1 + 1.079 / self._m)

    def _hash(self, value: str) -> int:
        """Hash value to a 64-bit integer."""
        h = hashlib.sha256(value.encode('utf-8')).digest()
        return struct.unpack('<Q', h[:8])[0]

    @staticmethod
    def _leading_zeros(value: int, max_bits: int) -> int:
        """Count leading zeros in the binary representation."""
        if value == 0:
            return max_bits
        count = 0
        for i in range(max_bits - 1, -1, -1):
            if value & (1 << i):
                break
            count += 1
        return count

    def add(self, value: str) -> None:
        """Add an item to the estimator."""
        h = self._hash(value)
        # Use first p bits as register index
        idx = h & (self._m - 1)
        # Remaining bits for leading zero count
        remaining = h >> self._p
        rho = self._leading_zeros(remaining, 64 - self._p) + 1
        self._registers[idx] = max(self._registers[idx], rho)
        self._count_added += 1

    def count(self) -> int:
        """Estimate the number of distinct items added.

        Uses the HyperLogLog algorithm with bias correction for small
        and large cardinalities.
        """
        # Raw HLL estimate
        indicator = sum(2.0 ** (-r) for r in self._registers)
        estimate = self._alpha * self._m * self._m / indicator

        # Small range correction (linear counting)
        if estimate <= 2.5 * self._m:
            zeros = self._registers.count(0)
            if zeros > 0:
                estimate = self._m * math.log(self._m / zeros)

        # Large range correction (for 64-bit hashes, rarely needed)
        if estimate > (1 << 32) / 30:
            estimate = -(1 << 64) * math.log(1 - estimate / (1 << 64))

        return int(estimate + 0.5)

    @property
    def precision(self) -> int:
        return self._p

    @property
    def memory_bytes(self) -> int:
        """Approximate memory usage in bytes."""
        return self._m

    @property
    def standard_error(self) -> float:
        """Theoretical standard error of the estimate."""
        return 1.04 / math.sqrt(self._m)

    def merge(self, other: 'HyperLogLog') -> None:
        """Merge another HLL into this one (element-wise max).

        Both HLLs must have the same precision.
        """
        if self._p != other._p:
            raise ValueError("Cannot merge HLLs with different precision")
        for i in range(self._m):
            self._registers[i] = max(self._registers[i], other._registers[i])

    def clear(self) -> None:
        """Reset all registers."""
        for i in range(self._m):
            self._registers[i] = 0
        self._count_added = 0
