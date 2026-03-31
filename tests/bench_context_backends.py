#!/usr/bin/env python3
"""Benchmark: Regex vs Aho-Corasick context matching backends.

Compares the two context keyword matching backends across multiple dimensions:

1. **Throughput** — ops/sec and MB/s at 1KB, 10KB, 100KB, 1MB text sizes
2. **Match accuracy** — verifies both backends produce identical findings
3. **Context match counts** — confirms context detection is equivalent
4. **Scaling** — how performance changes with text size and match density

Run::

    python tests/bench_context_backends.py
    python tests/bench_context_backends.py --json  # machine-readable output
"""

import json
import os
import random
import sys
import time
from collections import Counter
from datetime import datetime, timezone

_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from dlpscan.scanner import (  # noqa: E402
    enhanced_scan_text,
    get_context_backend,
    set_context_backend,
)

# ---------------------------------------------------------------------------
# Test data generation
# ---------------------------------------------------------------------------

_FILLER = [
    "The quarterly report shows revenue growth of twelve percent. ",
    "Please schedule a meeting with the engineering team for Tuesday. ",
    "Our new product launch is expected to generate significant interest. ",
    "The server migration was completed successfully over the weekend. ",
    "Customer feedback has been overwhelmingly positive this quarter. ",
    "We need to review the security audit findings before the deadline. ",
    "The marketing campaign reached over two million impressions. ",
    "Development velocity has improved since adopting the new framework. ",
    "All compliance training modules must be completed by end of month. ",
    "The data center upgrade will improve latency by thirty percent. ",
]

# Sensitive data WITH context keywords nearby (should trigger context match)
_SENSITIVE_WITH_CONTEXT = [
    "My credit card number is 4532015112830366 and expires 12/28.",
    "Please verify SSN 123-45-6789 for the employee records.",
    "Send payment to IBAN GB29 NWBK 6016 1331 9268 19 immediately.",
    "Contact email address: john.doe@example.org for the report.",
    "The patient medical record number MRN-12345678 is on file.",
    "API key for production: AKIAIOSFODNN7EXAMPLE must be rotated.",
    "GitHub personal access token ghp_ABCDEfghij1234567890abcdefgh1234 leaked.",
    "Bitcoin payment address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa confirmed.",
    "Driver's license number DL-A1234567 on the insurance form.",
    "Passport number AB1234567 for the visa application.",
]

# Sensitive data WITHOUT context (bare patterns)
_SENSITIVE_NO_CONTEXT = [
    "Here is the number 4111111111111111 in the document.",
    "Also reference 987-65-4321 which was mentioned earlier.",
    "Please note GB82 WEST 1234 5698 7654 32 in the ledger.",
    "The token ghp_XYZabc123def456ghi789jkl012mno345pqr is here.",
]


def _build_text(target_bytes, sensitive_interval=4096, context_ratio=0.7):
    """Build text with controlled sensitive data density.

    Args:
        target_bytes: Approximate text size in bytes.
        sensitive_interval: Bytes between sensitive data injections.
        context_ratio: Fraction of injections that include context keywords.
    """
    rng = random.Random(42)
    chunks = []
    current_size = 0
    next_insert = sensitive_interval

    while current_size < target_bytes:
        sentence = rng.choice(_FILLER)
        chunks.append(sentence)
        current_size += len(sentence)
        if current_size >= next_insert:
            if rng.random() < context_ratio:
                token = rng.choice(_SENSITIVE_WITH_CONTEXT)
            else:
                token = rng.choice(_SENSITIVE_NO_CONTEXT)
            chunks.append(" " + token + " ")
            current_size += len(token) + 2
            next_insert += sensitive_interval

    text = "".join(chunks)
    if len(text) > target_bytes:
        text = text[:target_bytes]
    return text


def _build_dense_text(target_bytes):
    """Build text with HIGH sensitive data density (every ~500 bytes)."""
    return _build_text(target_bytes, sensitive_interval=500, context_ratio=0.8)


# ---------------------------------------------------------------------------
# Benchmark runner
# ---------------------------------------------------------------------------

class BenchResult:
    def __init__(self, name, backend, iterations, total_secs, data_bytes,
                 match_count=0, context_matches=0, categories=None):
        self.name = name
        self.backend = backend
        self.iterations = iterations
        self.total_secs = total_secs
        self.data_bytes = data_bytes
        self.match_count = match_count
        self.context_matches = context_matches
        self.categories = categories or {}

    @property
    def avg_ms(self):
        return (self.total_secs / self.iterations * 1000) if self.iterations else 0

    @property
    def ops_sec(self):
        return self.iterations / self.total_secs if self.total_secs else 0

    @property
    def throughput_mb_s(self):
        if not self.total_secs or not self.data_bytes:
            return 0
        return (self.data_bytes * self.iterations / 1024 / 1024) / self.total_secs


def _bench_backend(name, text, backend, iterations):
    """Benchmark a specific backend on given text."""
    original = get_context_backend()
    try:
        set_context_backend(backend)

        # Warmup
        matches = list(enhanced_scan_text(text))
        match_count = len(matches)
        context_matches = sum(1 for m in matches if m.has_context)
        cats = Counter(m.category for m in matches)

        start = time.perf_counter()
        for _ in range(iterations):
            list(enhanced_scan_text(text))
        elapsed = time.perf_counter() - start

        return BenchResult(
            name=name,
            backend=backend,
            iterations=iterations,
            total_secs=elapsed,
            data_bytes=len(text.encode('utf-8')),
            match_count=match_count,
            context_matches=context_matches,
            categories=dict(cats),
        )
    finally:
        set_context_backend(original)


# ---------------------------------------------------------------------------
# Accuracy comparison
# ---------------------------------------------------------------------------

def compare_accuracy(text, label=""):
    """Compare match results between regex and Aho-Corasick backends.

    Returns (matches_identical, regex_matches, ac_matches, diffs).
    """
    original = get_context_backend()
    try:
        set_context_backend('regex')
        regex_matches = list(enhanced_scan_text(text))

        set_context_backend('ahocorasick')
        ac_matches = list(enhanced_scan_text(text))
    finally:
        set_context_backend(original)

    # Compare by (text, category, sub_category, has_context)
    def match_key(m):
        return (m.text, m.category, m.sub_category, m.has_context, m.span)

    regex_set = set(match_key(m) for m in regex_matches)
    ac_set = set(match_key(m) for m in ac_matches)

    only_regex = regex_set - ac_set
    only_ac = ac_set - regex_set

    identical = (only_regex == set() and only_ac == set())

    return {
        'label': label,
        'identical': identical,
        'regex_count': len(regex_matches),
        'ac_count': len(ac_matches),
        'regex_context': sum(1 for m in regex_matches if m.has_context),
        'ac_context': sum(1 for m in ac_matches if m.has_context),
        'only_in_regex': len(only_regex),
        'only_in_ac': len(only_ac),
        'only_regex_samples': list(only_regex)[:5],
        'only_ac_samples': list(only_ac)[:5],
    }


# ---------------------------------------------------------------------------
# Print helpers
# ---------------------------------------------------------------------------

_SEP = "  " + "-" * 100
_HDR = "  {:<30s} {:>10s} {:>10s} {:>10s} {:>10s} {:>10s} {:>10s}"
_ROW = "  {:<30s} {:>10s} {:>10s} {:>10s} {:>10s} {:>10s} {:>10s}"


def _print_comparison(results_regex, results_ac):
    """Print side-by-side comparison table."""
    print()
    print("  === Regex vs Aho-Corasick: Performance Comparison ===")
    print(_SEP)
    print(_HDR.format("Benchmark", "Backend", "Avg (ms)", "Ops/sec",
                      "MB/s", "Matches", "w/ Context"))
    print(_SEP)

    for r_regex, r_ac in zip(results_regex, results_ac):
        print(_ROW.format(
            r_regex.name, "regex",
            f"{r_regex.avg_ms:.1f}", f"{r_regex.ops_sec:.1f}",
            f"{r_regex.throughput_mb_s:.2f}",
            str(r_regex.match_count), str(r_regex.context_matches),
        ))
        print(_ROW.format(
            "", "ahocorasick",
            f"{r_ac.avg_ms:.1f}", f"{r_ac.ops_sec:.1f}",
            f"{r_ac.throughput_mb_s:.2f}",
            str(r_ac.match_count), str(r_ac.context_matches),
        ))
        # Speedup
        if r_regex.avg_ms > 0:
            speedup = r_regex.avg_ms / r_ac.avg_ms if r_ac.avg_ms > 0 else float('inf')
            winner = "AC" if speedup > 1.0 else "Regex"
            print(f"  {'':30s} {'Speedup:':>10s} {speedup:>10.2f}x   ({winner} faster)")
        print(_SEP)


def _print_accuracy(comparisons):
    """Print accuracy comparison table."""
    print()
    print("  === Match Accuracy Comparison ===")
    print(_SEP)
    print(f"  {'Text':30s} {'Identical?':>12s} {'Regex':>8s} {'AC':>8s} "
          f"{'R-Ctx':>8s} {'AC-Ctx':>8s} {'Only-R':>8s} {'Only-AC':>8s}")
    print(_SEP)

    all_identical = True
    for c in comparisons:
        status = "YES" if c['identical'] else "DIFF"
        if not c['identical']:
            all_identical = False
        print(f"  {c['label']:30s} {status:>12s} {c['regex_count']:>8d} "
              f"{c['ac_count']:>8d} {c['regex_context']:>8d} "
              f"{c['ac_context']:>8d} {c['only_in_regex']:>8d} "
              f"{c['only_in_ac']:>8d}")

    print(_SEP)

    if all_identical:
        print("\n  ACCURACY: IDENTICAL — Both backends produce the same matches.")
    else:
        print("\n  ACCURACY: DIFFERENCES FOUND — See details below.")
        for c in comparisons:
            if not c['identical']:
                print(f"\n  {c['label']}:")
                if c['only_regex_samples']:
                    print(f"    Only in regex ({c['only_in_regex']} total):")
                    for s in c['only_regex_samples']:
                        print(f"      {s}")
                if c['only_ac_samples']:
                    print(f"    Only in Aho-Corasick ({c['only_in_ac']} total):")
                    for s in c['only_ac_samples']:
                        print(f"      {s}")

    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    json_output = '--json' in sys.argv

    print()
    print("=" * 104)
    print("  dlpscan Context Backend Benchmark: Regex vs Aho-Corasick")
    print(f"  Python {sys.version.split()[0]}  |  PID {os.getpid()}")
    print("=" * 104)

    # ---- 1. Build test texts ----
    sizes = [
        ("1 KB (normal)",    1 * 1024,  _build_text,       50),
        ("10 KB (normal)",   10 * 1024, _build_text,       30),
        ("100 KB (normal)",  100 * 1024, _build_text,      10),
        ("1 MB (normal)",    1024 * 1024, _build_text,      3),
        ("10 KB (dense)",    10 * 1024, _build_dense_text,  30),
        ("100 KB (dense)",   100 * 1024, _build_dense_text, 10),
    ]

    texts = {}
    for label, size, builder, _ in sizes:
        texts[label] = builder(size)

    # ---- 2. Performance benchmarks ----
    print("\n  Running performance benchmarks ...")
    results_regex = []
    results_ac = []

    for label, size, builder, iters in sizes:
        text = texts[label]
        print(f"    {label} ({len(text):,} chars, {iters} iterations) ...")
        r_regex = _bench_backend(label, text, 'regex', iters)
        r_ac = _bench_backend(label, text, 'ahocorasick', iters)
        results_regex.append(r_regex)
        results_ac.append(r_ac)

    _print_comparison(results_regex, results_ac)

    # ---- 3. Accuracy comparison ----
    print("  Running accuracy comparison ...")
    accuracy_labels = [
        ("1 KB (normal)", texts["1 KB (normal)"]),
        ("10 KB (normal)", texts["10 KB (normal)"]),
        ("100 KB (normal)", texts["100 KB (normal)"]),
        ("10 KB (dense)", texts["10 KB (dense)"]),
    ]

    comparisons = []
    for label, text in accuracy_labels:
        print(f"    {label} ...")
        c = compare_accuracy(text, label)
        comparisons.append(c)

    _print_accuracy(comparisons)

    # ---- 4. Tradeoff summary ----
    print("  === Tradeoff Analysis ===")
    print(_SEP)
    print("""
  REGEX BACKEND (default):
    + Zero external dependencies
    + Proven, battle-tested regex engine (Python re module, C-backed)
    + Supports fuzzy matching (Levenshtein) on context keywords
    + Two-pass matching: exact regex fast path + fuzzy slow path
    - Creates 560 compiled regex alternation patterns at module load
    - Each context check runs a separate regex search per (category, sub_category)
    - O(K) per context check where K = number of keyword patterns for that pair

  AHO-CORASICK BACKEND (opt-in):
    + Single O(n) pass over text finds ALL 2,500+ keywords simultaneously
    + O(log n) proximity lookup via sorted position index + binary search
    + Pre-computed hit index shared across all pattern matches in a scan
    + Biggest win on texts with many matches (each match needs context check)
    - Requires pyahocorasick C extension for best performance (optional dep)
    - Pure-Python fallback is slower than C extension
    - Still falls through to fuzzy Levenshtein matching (not accelerated)
    - Automaton rebuild needed when custom patterns change (rare operation)
    - Exact keyword matching only (no regex features like word boundaries)
      — compensated by checking token boundaries during search

  WHEN TO USE EACH:
    regex:        Default. Best for small-to-medium texts, few matches,
                  or when avoiding external dependencies.
    ahocorasick:  Large documents, high match density, batch processing,
                  or when scanning many files in sequence.
""")
    print(_SEP)

    # ---- 5. JSON output ----
    if json_output:
        summary = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'benchmarks': [
                {
                    'name': r.name,
                    'backend': r.backend,
                    'avg_ms': round(r.avg_ms, 2),
                    'ops_sec': round(r.ops_sec, 2),
                    'throughput_mb_s': round(r.throughput_mb_s, 4),
                    'match_count': r.match_count,
                    'context_matches': r.context_matches,
                }
                for r in results_regex + results_ac
            ],
            'accuracy': comparisons,
        }
        path = os.path.join(os.getcwd(), 'benchmark-context-backends.json')
        with open(path, 'w') as f:
            json.dump(summary, f, indent=2, default=str)
        print(f"  JSON results written to {path}")

    return 0


if __name__ == '__main__':
    sys.exit(main())
