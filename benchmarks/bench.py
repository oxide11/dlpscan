#!/usr/bin/env python3
"""Performance benchmarks for dlpscan.

Run:
    python -m benchmarks.bench

Measures scan throughput (MB/s) across different input sizes,
category counts, and deduplication settings.
"""

import io
import time
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dlpscan import enhanced_scan_text, scan_stream, PATTERNS


def _generate_mixed_text(size_bytes: int) -> str:
    """Generate a realistic text with embedded sensitive data."""
    block = (
        "The quick brown fox jumps over the lazy dog. "
        "Contact us at test@example.com for details. "
        "My SSN is 123-45-6789 and credit card is 4532015112830366. "
        "IBAN: DE89370400440532013000. SWIFT: DEUTDEFF500. "
        "AWS key: AKIAIOSFODNN7EXAMPLE. "
        "This is normal text with no sensitive data at all. "
        "The meeting is scheduled for tomorrow at noon. "
        "Please review the attached document before Friday. "
    )
    repeats = max(1, size_bytes // len(block))
    return (block * repeats)[:size_bytes]


def _generate_clean_text(size_bytes: int) -> str:
    """Generate text with no sensitive data."""
    block = (
        "The quick brown fox jumps over the lazy dog. "
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
        "This is a perfectly normal sentence with no secrets. "
    )
    repeats = max(1, size_bytes // len(block))
    return (block * repeats)[:size_bytes]


def bench_scan_speed():
    """Benchmark scan throughput at different input sizes."""
    sizes = [
        ('1 KB', 1024),
        ('10 KB', 10 * 1024),
        ('100 KB', 100 * 1024),
        ('1 MB', 1024 * 1024),
        ('5 MB', 5 * 1024 * 1024),
    ]

    print("=" * 65)
    print(f"{'Input Size':<12} {'Matches':>8} {'Time (ms)':>10} {'Throughput':>12}")
    print("=" * 65)

    for label, size in sizes:
        text = _generate_mixed_text(size)

        start = time.perf_counter()
        results = list(enhanced_scan_text(text))
        elapsed = time.perf_counter() - start

        mb = len(text) / (1024 * 1024)
        throughput = mb / elapsed if elapsed > 0 else float('inf')

        print(f"{label:<12} {len(results):>8} {elapsed*1000:>10.1f} {throughput:>9.1f} MB/s")

    print()


def bench_clean_text():
    """Benchmark scanning text with no matches (worst case — all patterns tried)."""
    text = _generate_clean_text(1024 * 1024)

    print("Clean text (1 MB, no matches):")
    start = time.perf_counter()
    results = list(enhanced_scan_text(text))
    elapsed = time.perf_counter() - start
    mb = len(text) / (1024 * 1024)
    print(f"  {len(results)} matches, {elapsed*1000:.1f} ms, {mb/elapsed:.1f} MB/s")
    print()


def bench_category_filter():
    """Benchmark scanning with category filtering vs full scan."""
    text = _generate_mixed_text(100 * 1024)

    print("Category filtering (100 KB):")

    start = time.perf_counter()
    all_results = list(enhanced_scan_text(text))
    t_all = time.perf_counter() - start

    start = time.perf_counter()
    cc_results = list(enhanced_scan_text(text, categories={'Credit Card Numbers'}))
    t_cc = time.perf_counter() - start

    print(f"  All categories: {len(all_results)} matches, {t_all*1000:.1f} ms")
    print(f"  Credit Cards only: {len(cc_results)} matches, {t_cc*1000:.1f} ms")
    print(f"  Speedup: {t_all/t_cc:.1f}x")
    print()


def bench_deduplication():
    """Benchmark deduplication overhead."""
    text = _generate_mixed_text(100 * 1024)

    print("Deduplication overhead (100 KB):")

    start = time.perf_counter()
    dedup = list(enhanced_scan_text(text, deduplicate=True))
    t_dedup = time.perf_counter() - start

    start = time.perf_counter()
    raw = list(enhanced_scan_text(text, deduplicate=False))
    t_raw = time.perf_counter() - start

    print(f"  With dedup: {len(dedup)} matches, {t_dedup*1000:.1f} ms")
    print(f"  Without dedup: {len(raw)} matches, {t_raw*1000:.1f} ms")
    print(f"  Matches removed by dedup: {len(raw) - len(dedup)}")
    print()


def bench_stream():
    """Benchmark stream scanning."""
    text = _generate_mixed_text(1024 * 1024)

    print("Stream scanning (1 MB):")

    start = time.perf_counter()
    stream = io.StringIO(text)
    results = list(scan_stream(stream))
    elapsed = time.perf_counter() - start

    mb = len(text) / (1024 * 1024)
    print(f"  {len(results)} matches, {elapsed*1000:.1f} ms, {mb/elapsed:.1f} MB/s")
    print()


def main():
    total_patterns = sum(len(subs) for subs in PATTERNS.values())
    print(f"\ndlpscan Performance Benchmarks")
    print(f"Patterns: {total_patterns} across {len(PATTERNS)} categories\n")

    bench_scan_speed()
    bench_clean_text()
    bench_category_filter()
    bench_deduplication()
    bench_stream()

    print("Done.")


if __name__ == '__main__':
    main()
