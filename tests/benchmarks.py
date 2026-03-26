#!/usr/bin/env python3
"""Performance benchmarks for dlpscan.

Measures scanning speed against various input sizes and establishes baseline
performance expectations.  Uses only the standard library ``time`` module --
no third-party benchmark frameworks required.

Run::

    python tests/benchmarks.py
"""

import os
import random
import sys
import tempfile
import time

# ---------------------------------------------------------------------------
# Ensure the project root is importable when run as a standalone script.
# ---------------------------------------------------------------------------
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from dlpscan import enhanced_scan_text, scan_file
from dlpscan.guard import InputGuard, Preset
from dlpscan.guard.enums import Action
from dlpscan.pipeline import Pipeline

# ---------------------------------------------------------------------------
# Test data generation
# ---------------------------------------------------------------------------

# Realistic filler text fragments.  These are intentionally mundane so that
# the scanner does not match every line -- only the explicitly injected
# sensitive tokens trigger findings.
_FILLER_SENTENCES = [
    "The quarterly report shows revenue growth of 12 percent year over year. ",
    "Please schedule a meeting with the engineering team for next Tuesday. ",
    "Our new product launch is expected to generate significant interest. ",
    "The server migration was completed successfully over the weekend. ",
    "Customer feedback has been overwhelmingly positive this quarter. ",
    "We need to review the security audit findings before the deadline. ",
    "The marketing campaign reached over two million impressions last week. ",
    "Development velocity has improved since adopting the new framework. ",
    "All compliance training modules must be completed by end of month. ",
    "The data center upgrade will improve latency by approximately thirty percent. ",
    "Budget forecasts indicate a healthy surplus for the current fiscal year. ",
    "Cross-functional collaboration remains a priority for the leadership team. ",
    "The onboarding process has been streamlined to reduce ramp-up time. ",
    "Automated testing coverage has reached ninety percent across core modules. ",
    "The architecture review board approved the proposed microservice split. ",
]

# Sensitive data samples injected at controlled intervals.
_SENSITIVE_SAMPLES = [
    "My credit card number is 4532015112830366.",
    "SSN: 123-45-6789",
    "Contact me at john.doe@example.org",
    "AWS secret key: AKIAIOSFODNN7EXAMPLE",
    "ghp_ABCDEfghij1234567890abcdefgh1234",
    "IBAN: GB29 NWBK 6016 1331 9268 19",
    "Bitcoin address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
]


def _build_text(target_bytes: int, sensitive_interval: int = 8192) -> str:
    """Generate a text payload of approximately *target_bytes* bytes.

    Realistic filler text is repeated and sensitive tokens are inserted at
    random positions roughly every *sensitive_interval* bytes so that the
    scanner has real work to do without hitting the match limit on larger
    inputs.
    """
    rng = random.Random(42)  # Deterministic for reproducibility.
    chunks: list[str] = []
    current_size = 0
    next_insert = sensitive_interval

    while current_size < target_bytes:
        sentence = rng.choice(_FILLER_SENTENCES)
        chunks.append(sentence)
        current_size += len(sentence.encode("utf-8"))
        if current_size >= next_insert:
            token = rng.choice(_SENSITIVE_SAMPLES)
            chunks.append(" " + token + " ")
            current_size += len(token.encode("utf-8")) + 2
            next_insert += sensitive_interval

    text = "".join(chunks)
    # Trim to exact target size (on a character boundary).
    if len(text.encode("utf-8")) > target_bytes:
        encoded = text.encode("utf-8")[:target_bytes]
        text = encoded.decode("utf-8", errors="ignore")
    return text


def _write_temp_file(text: str, suffix: str = ".txt") -> str:
    """Write *text* to a temporary file and return its path."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


# ---------------------------------------------------------------------------
# Benchmark infrastructure
# ---------------------------------------------------------------------------

class BenchmarkResult:
    """Container for a single benchmark measurement."""

    def __init__(self, name: str, iterations: int, total_seconds: float,
                 data_bytes: int = 0):
        self.name = name
        self.iterations = iterations
        self.total_seconds = total_seconds
        self.data_bytes = data_bytes

    @property
    def avg_seconds(self) -> float:
        return self.total_seconds / self.iterations if self.iterations else 0.0

    @property
    def ops_per_sec(self) -> float:
        return self.iterations / self.total_seconds if self.total_seconds else 0.0

    @property
    def throughput_mb_s(self) -> float:
        if self.total_seconds == 0 or self.data_bytes == 0:
            return 0.0
        total_mb = (self.data_bytes * self.iterations) / (1024 * 1024)
        return total_mb / self.total_seconds


def _run_bench(name: str, func, iterations: int,
               data_bytes: int = 0) -> BenchmarkResult:
    """Run *func* for *iterations*, returning a :class:`BenchmarkResult`.

    A single warm-up invocation is performed before measurement begins.
    """
    # Warm-up pass (excluded from timing).
    func()

    start = time.perf_counter()
    for _ in range(iterations):
        func()
    elapsed = time.perf_counter() - start

    return BenchmarkResult(name, iterations, elapsed, data_bytes)


# ---------------------------------------------------------------------------
# Table formatting helpers
# ---------------------------------------------------------------------------

_HEADER_FMT = "  {:<44s} {:>8s} {:>12s} {:>12s} {:>12s}"
_ROW_FMT    = "  {:<44s} {:>8d} {:>12s} {:>12s} {:>12s}"
_SECTION_SEP = "  " + "-" * 94


def _print_table(title: str, results: list[BenchmarkResult]) -> None:
    """Print a formatted results table to stdout."""
    print()
    print(f"  === {title} ===")
    print(_SECTION_SEP)
    print(_HEADER_FMT.format("Benchmark", "Iters", "Avg (ms)", "Ops/sec", "MB/s"))
    print(_SECTION_SEP)
    for r in results:
        avg_ms = r.avg_seconds * 1000
        throughput = f"{r.throughput_mb_s:.2f}" if r.data_bytes else "n/a"
        print(_ROW_FMT.format(
            r.name,
            r.iterations,
            f"{avg_ms:.3f}",
            f"{r.ops_per_sec:.1f}",
            throughput,
        ))
    print(_SECTION_SEP)


# ---------------------------------------------------------------------------
# 1. Text scanning benchmarks
# ---------------------------------------------------------------------------

def bench_text_scanning() -> list[BenchmarkResult]:
    """Benchmark enhanced_scan_text at different input sizes.

    Sizes: 1 KB (1000 iters), 100 KB (100 iters), 1 MB (10 iters),
    10 MB (3 iters).  Measures ops/sec, avg time, and throughput (MB/s).
    """
    configs = [
        ("Small (1 KB)",       1 * 1024,        1000),
        ("Medium (100 KB)",    100 * 1024,       100),
        ("Large (1 MB)",       1 * 1024 * 1024,  10),
        ("Very large (10 MB)", 10 * 1024 * 1024,  3),
    ]

    results: list[BenchmarkResult] = []
    for label, size, iters in configs:
        text = _build_text(size)
        actual_bytes = len(text.encode("utf-8"))

        def scan(t=text):
            list(enhanced_scan_text(t))

        res = _run_bench(label, scan, iters, actual_bytes)
        results.append(res)

    return results


# ---------------------------------------------------------------------------
# 2. File scanning benchmarks
# ---------------------------------------------------------------------------

def bench_file_scanning() -> list[BenchmarkResult]:
    """Benchmark scan_file with temporary files of various sizes.

    Measures time per file and throughput (MB/s).
    """
    sizes = [
        ("File 1 KB",   1 * 1024,        200),
        ("File 100 KB", 100 * 1024,       50),
        ("File 1 MB",   1 * 1024 * 1024,  10),
    ]

    results: list[BenchmarkResult] = []
    temp_paths: list[str] = []

    try:
        for label, size, iters in sizes:
            text = _build_text(size)
            path = _write_temp_file(text)
            temp_paths.append(path)
            actual_bytes = os.path.getsize(path)

            def scan(p=path):
                list(scan_file(p))

            res = _run_bench(label, scan, iters, actual_bytes)
            results.append(res)
    finally:
        for p in temp_paths:
            try:
                os.unlink(p)
            except OSError:
                pass

    return results


# ---------------------------------------------------------------------------
# 3. Pipeline benchmarks
# ---------------------------------------------------------------------------

def bench_pipeline() -> list[BenchmarkResult]:
    """Benchmark Pipeline.process_files with N files (10, 50, 100) and
    varying worker counts (1, 4, 8).

    Measures total time and files/sec.
    """
    file_text = _build_text(4 * 1024)  # 4 KB per file -- small, to isolate overhead
    file_counts = [10, 50, 100]
    worker_configs = [1, 4, 8]

    temp_paths: list[str] = []
    results: list[BenchmarkResult] = []

    try:
        max_files = max(file_counts)
        for _ in range(max_files):
            path = _write_temp_file(file_text)
            temp_paths.append(path)

        for n_files in file_counts:
            paths = temp_paths[:n_files]
            for workers in worker_configs:
                label = f"Pipeline {n_files} files / {workers} workers"

                start = time.perf_counter()
                with Pipeline(max_workers=workers) as pipe:
                    pipe.process_files(paths)
                elapsed = time.perf_counter() - start

                res = BenchmarkResult(label, n_files, elapsed,
                                      len(file_text.encode("utf-8")))
                results.append(res)
    finally:
        for p in temp_paths:
            try:
                os.unlink(p)
            except OSError:
                pass

    return results


# ---------------------------------------------------------------------------
# 4. InputGuard benchmarks
# ---------------------------------------------------------------------------

def bench_input_guard() -> list[BenchmarkResult]:
    """Benchmark InputGuard check / scan / sanitize latency across
    different preset combinations.
    """
    text_clean = "This is a perfectly normal business document with no sensitive data."
    text_dirty = (
        "Please process payment for card 4532015112830366 "
        "and SSN 123-45-6789. Contact me at user@example.com."
    )

    iterations = 500

    preset_combos = [
        ("PCI_DSS only",    [Preset.PCI_DSS]),
        ("PII",             [Preset.PII]),
        ("CREDENTIALS",     [Preset.CREDENTIALS]),
        ("PCI + SSN + PII", [Preset.PCI_DSS, Preset.SSN_SIN, Preset.PII]),
        ("FINANCIAL",       [Preset.FINANCIAL]),
    ]

    results: list[BenchmarkResult] = []

    for combo_label, presets in preset_combos:
        guard_flag = InputGuard(presets=presets, action=Action.FLAG)
        guard_redact = InputGuard(presets=presets, action=Action.REDACT)

        # -- check() latency --
        def do_check(g=guard_flag, t=text_dirty):
            g.check(t)
        res = _run_bench(f"guard.check    [{combo_label}]", do_check, iterations)
        results.append(res)

        # -- scan() latency --
        def do_scan(g=guard_flag, t=text_dirty):
            g.scan(t)
        res = _run_bench(f"guard.scan     [{combo_label}]", do_scan, iterations)
        results.append(res)

        # -- sanitize() latency --
        def do_sanitize(g=guard_redact, t=text_dirty):
            g.sanitize(t)
        res = _run_bench(f"guard.sanitize [{combo_label}]", do_sanitize, iterations)
        results.append(res)

    # Clean-text baseline with broad preset coverage.
    guard_all = InputGuard(
        presets=[Preset.PCI_DSS, Preset.PII, Preset.CREDENTIALS],
        action=Action.FLAG,
    )

    def do_check_clean(g=guard_all, t=text_clean):
        g.check(t)
    res = _run_bench("guard.check    [clean input, broad presets]",
                     do_check_clean, iterations)
    results.append(res)

    return results


# ---------------------------------------------------------------------------
# 5. Pattern matching benchmarks
# ---------------------------------------------------------------------------

def bench_pattern_matching() -> list[BenchmarkResult]:
    """Benchmark the impact of scanning with all categories vs specific
    categories, require_context, and min_confidence filtering.
    """
    text = _build_text(50 * 1024)  # 50 KB
    actual_bytes = len(text.encode("utf-8"))
    iterations = 30

    results: list[BenchmarkResult] = []

    # -- All categories (default) --
    def scan_all(t=text):
        list(enhanced_scan_text(t))
    results.append(_run_bench(
        "All categories", scan_all, iterations, actual_bytes))

    # -- Single category --
    def scan_cc(t=text):
        list(enhanced_scan_text(t, categories={"Credit Card Numbers"}))
    results.append(_run_bench(
        "Single category (Credit Cards)", scan_cc, iterations, actual_bytes))

    # -- Two categories --
    def scan_two(t=text):
        list(enhanced_scan_text(
            t, categories={"Credit Card Numbers", "Contact Information"}))
    results.append(_run_bench(
        "Two categories (CC + Contact)", scan_two, iterations, actual_bytes))

    # -- require_context=True --
    def scan_ctx(t=text):
        list(enhanced_scan_text(t, require_context=True))
    results.append(_run_bench(
        "All + require_context=True", scan_ctx, iterations, actual_bytes))

    # -- require_context on single category --
    def scan_cc_ctx(t=text):
        list(enhanced_scan_text(
            t, categories={"Credit Card Numbers"}, require_context=True))
    results.append(_run_bench(
        "Single category + require_context", scan_cc_ctx, iterations, actual_bytes))

    # -- min_confidence filtering via InputGuard --
    guard_hi = InputGuard(
        presets=[Preset.PCI_DSS, Preset.PII],
        action=Action.FLAG,
        min_confidence=0.8,
    )

    def scan_hi(g=guard_hi, t=text):
        g.scan(t)
    results.append(_run_bench(
        "Guard scan, min_confidence=0.8", scan_hi, iterations, actual_bytes))

    guard_lo = InputGuard(
        presets=[Preset.PCI_DSS, Preset.PII],
        action=Action.FLAG,
        min_confidence=0.0,
    )

    def scan_lo(g=guard_lo, t=text):
        g.scan(t)
    results.append(_run_bench(
        "Guard scan, min_confidence=0.0", scan_lo, iterations, actual_bytes))

    return results


# ---------------------------------------------------------------------------
# Threshold evaluation
# ---------------------------------------------------------------------------

# Baseline thresholds.  These reflect scanning with ALL pattern categories
# enabled (the default).  When scanning all categories the regex workload is
# significant, so the baselines are calibrated accordingly.
#
# Aspirational targets (for reference / future optimisation):
#   Small text:  >1000 ops/sec
#   Medium text: >50 ops/sec
#   Large text:  >5 ops/sec
#
# Current realistic baselines (all-category scan):
_THRESHOLDS: dict[str, float] = {
    "Small (1 KB)":     50.0,   # >50 ops/sec   (all categories, ~6 ms each)
    "Medium (100 KB)":   1.0,   # >1 ops/sec    (all categories, ~600 ms each)
    "Large (1 MB)":      0.1,   # >0.1 ops/sec  (all categories, ~6 s each)
}

# InputGuard check (short text, specific presets) must exceed 500 ops/sec.
_GUARD_CHECK_THRESHOLD = 500.0


def _evaluate_thresholds(
    text_results: list[BenchmarkResult],
    guard_results: list[BenchmarkResult],
) -> list[tuple[str, float, float, bool]]:
    """Return list of (label, measured, threshold, passed) tuples."""
    verdicts: list[tuple[str, float, float, bool]] = []

    for r in text_results:
        if r.name in _THRESHOLDS:
            threshold = _THRESHOLDS[r.name]
            passed = r.ops_per_sec >= threshold
            verdicts.append((r.name, r.ops_per_sec, threshold, passed))

    for r in guard_results:
        if r.name.startswith("guard.check"):
            passed = r.ops_per_sec >= _GUARD_CHECK_THRESHOLD
            verdicts.append((r.name, r.ops_per_sec,
                             _GUARD_CHECK_THRESHOLD, passed))

    return verdicts


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    """Run all benchmarks and print results."""
    print()
    print("=" * 98)
    print("  dlpscan Performance Benchmarks")
    print(f"  Python {sys.version.split()[0]}  |  PID {os.getpid()}")
    print("=" * 98)

    # 1. Text scanning.
    print("\n  Running text scanning benchmarks ...")
    text_results = bench_text_scanning()
    _print_table("Text Scanning", text_results)

    # 2. File scanning.
    print("\n  Running file scanning benchmarks ...")
    file_results = bench_file_scanning()
    _print_table("File Scanning", file_results)

    # 3. Pipeline.
    print("\n  Running pipeline benchmarks ...")
    pipeline_results = bench_pipeline()
    _print_table("Pipeline (concurrent file processing)", pipeline_results)

    # 4. InputGuard.
    print("\n  Running InputGuard benchmarks ...")
    guard_results = bench_input_guard()
    _print_table("InputGuard Latency", guard_results)

    # 5. Pattern matching.
    print("\n  Running pattern matching benchmarks ...")
    pattern_results = bench_pattern_matching()
    _print_table("Pattern Matching Options", pattern_results)

    # --- Threshold summary ---
    verdicts = _evaluate_thresholds(text_results, guard_results)

    print()
    print("  === Threshold Summary ===")
    print(_SECTION_SEP)
    print(f"  {'Benchmark':<44s} {'Measured':>12s} {'Threshold':>12s} {'Result':>8s}")
    print(_SECTION_SEP)

    all_passed = True
    for label, measured, threshold, passed in verdicts:
        status = "PASS" if passed else "FAIL"
        if not passed:
            all_passed = False
        print(f"  {label:<44s} {measured:>12.1f} {threshold:>12.1f} {status:>8s}")

    print(_SECTION_SEP)

    if all_passed:
        print("\n  RESULT: ALL BENCHMARKS PASSED\n")
    else:
        print("\n  RESULT: SOME BENCHMARKS FAILED -- review results above\n")

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
