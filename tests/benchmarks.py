#!/usr/bin/env python3
"""Performance benchmarks for dlpscan.

Measures scanning speed against various input sizes and establishes baseline
performance expectations.  Uses only the standard library ``time`` module --
no third-party benchmark frameworks required.

Run::

    python tests/benchmarks.py
"""

import io
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

from dlpscan import enhanced_scan_text, scan_file, scan_stream
from dlpscan.pipeline import Pipeline
from dlpscan.guard import InputGuard, Preset
from dlpscan.guard.enums import Action

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Sample realistic text used to build payloads.  Sensitive tokens are spliced
# in at random positions to exercise actual pattern matching.
_BASE_TEXT = (
    "Dear customer, thank you for contacting our support team. "
    "Your reference number is REF-20250317-4821. We have reviewed "
    "the details you provided regarding your recent transaction. "
    "Please allow 3-5 business days for the refund to appear on "
    "your statement. If you have any questions, please do not "
    "hesitate to reach out to our team at support@example.com. "
    "Our offices are located at 123 Main Street, Anytown, USA 90210. "
    "For security purposes, never share your password or PIN with anyone. "
    "Thank you for your continued trust in our services. "
    "Best regards, The Customer Service Team.\n"
)

_SENSITIVE_SAMPLES = [
    "My credit card number is 4532015112830366.",
    "SSN: 123-45-6789",
    "My email is john.doe@example.org",
    "AWS secret key: AKIAIOSFODNN7EXAMPLE",
    "ghp_ABCDEfghij1234567890abcdefgh1234",
    "Phone: +1 (555) 867-5309",
    "Driver license: D12345678",
    "IBAN: GB29 NWBK 6016 1331 9268 19",
    "Bitcoin address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    "Password: S3cur3P@ssw0rd!",
]


def _build_text(target_bytes: int) -> str:
    """Generate a text payload of approximately *target_bytes* bytes.

    Realistic filler text is repeated and sensitive tokens are inserted at
    random positions roughly every 2 KB.
    """
    rng = random.Random(42)  # Deterministic for reproducibility.
    chunks: list[str] = []
    current_size = 0
    insert_interval = 2048  # Insert sensitive data roughly every 2 KB.
    next_insert = insert_interval

    while current_size < target_bytes:
        chunks.append(_BASE_TEXT)
        current_size += len(_BASE_TEXT.encode("utf-8"))
        if current_size >= next_insert:
            token = rng.choice(_SENSITIVE_SAMPLES)
            chunks.append(token + " ")
            current_size += len(token.encode("utf-8")) + 1
            next_insert += insert_interval

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


def _fmt_float(value: float, width: int = 10, precision: int = 2) -> str:
    return f"{value:{width}.{precision}f}"


def _fmt_int(value: int, width: int = 10) -> str:
    return f"{value:{width},}"


# ---------------------------------------------------------------------------
# Benchmark runner
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


def _run_bench(name: str, func, iterations: int, data_bytes: int = 0) -> BenchmarkResult:
    """Run *func* for *iterations* and return a BenchmarkResult."""
    # Warm-up pass.
    func()

    start = time.perf_counter()
    for _ in range(iterations):
        func()
    elapsed = time.perf_counter() - start

    return BenchmarkResult(name, iterations, elapsed, data_bytes)


# ---------------------------------------------------------------------------
# 1. Text scanning benchmarks
# ---------------------------------------------------------------------------

def bench_text_scanning() -> list[BenchmarkResult]:
    """Benchmark enhanced_scan_text at different input sizes."""
    configs = [
        ("Small (1 KB)",       1 * 1024,       1000),
        ("Medium (100 KB)",    100 * 1024,      100),
        ("Large (1 MB)",       1 * 1024 * 1024, 10),
        ("Very large (10 MB)", 10 * 1024 * 1024, 3),
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
    """Benchmark scan_file at different sizes."""
    sizes = [
        ("File 1 KB",    1 * 1024,       200),
        ("File 100 KB",  100 * 1024,     50),
        ("File 1 MB",    1 * 1024 * 1024, 10),
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
    """Benchmark Pipeline.process_files with varying file counts and workers."""
    file_text = _build_text(10 * 1024)  # 10 KB per file
    file_counts = [10, 50, 100]
    worker_configs = [1, 4, 8]

    temp_paths: list[str] = []
    results: list[BenchmarkResult] = []

    try:
        # Create the maximum number of temp files needed.
        max_files = max(file_counts)
        for _ in range(max_files):
            path = _write_temp_file(file_text)
            temp_paths.append(path)

        for n_files in file_counts:
            paths = temp_paths[:n_files]
            for workers in worker_configs:
                label = f"Pipeline {n_files} files / {workers} workers"

                def run(p=paths, w=workers):
                    with Pipeline(max_workers=w) as pipe:
                        pipe.process_files(p)

                start = time.perf_counter()
                run()
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
    """Benchmark InputGuard check / scan / sanitize at various preset combos."""
    text_clean = _build_text(1 * 1024)
    text_dirty = (
        "Please process payment for card 4532015112830366 "
        "and SSN 123-45-6789. Contact me at user@example.com."
    )

    iterations = 500

    preset_combos = [
        ("PCI_DSS only",      [Preset.PCI_DSS]),
        ("PII",               [Preset.PII]),
        ("CREDENTIALS",       [Preset.CREDENTIALS]),
        ("PCI + SSN + PII",   [Preset.PCI_DSS, Preset.SSN_SIN, Preset.PII]),
    ]

    results: list[BenchmarkResult] = []

    for combo_label, presets in preset_combos:
        guard = InputGuard(presets=presets, action=Action.FLAG)

        # check()
        def do_check(g=guard, t=text_dirty):
            g.check(t)
        res = _run_bench(f"guard.check  [{combo_label}]", do_check, iterations)
        results.append(res)

        # scan()
        def do_scan(g=guard, t=text_dirty):
            g.scan(t)
        res = _run_bench(f"guard.scan   [{combo_label}]", do_scan, iterations)
        results.append(res)

        # sanitize()
        guard_redact = InputGuard(presets=presets, action=Action.REDACT)

        def do_sanitize(g=guard_redact, t=text_dirty):
            g.sanitize(t)
        res = _run_bench(f"guard.sanitize [{combo_label}]", do_sanitize, iterations)
        results.append(res)

    # Clean text baseline with broad presets.
    guard_all = InputGuard(
        presets=[Preset.PCI_DSS, Preset.PII, Preset.CREDENTIALS],
        action=Action.FLAG,
    )

    def do_check_clean(g=guard_all, t=text_clean):
        g.check(t)
    res = _run_bench("guard.check  [clean input]", do_check_clean, iterations)
    results.append(res)

    return results


# ---------------------------------------------------------------------------
# 5. Pattern matching benchmarks
# ---------------------------------------------------------------------------

def bench_pattern_matching() -> list[BenchmarkResult]:
    """Benchmark impact of categories, require_context, and min_confidence."""
    text = _build_text(50 * 1024)  # 50 KB
    actual_bytes = len(text.encode("utf-8"))
    iterations = 30

    results: list[BenchmarkResult] = []

    # All categories (default).
    def scan_all(t=text):
        list(enhanced_scan_text(t))
    results.append(_run_bench("All categories", scan_all, iterations, actual_bytes))

    # Single category.
    def scan_single(t=text):
        list(enhanced_scan_text(t, categories={"Credit Card Numbers"}))
    results.append(_run_bench("Single category (CC)", scan_single, iterations, actual_bytes))

    # Two categories.
    def scan_two(t=text):
        list(enhanced_scan_text(t, categories={"Credit Card Numbers", "Contact Information"}))
    results.append(_run_bench("Two categories", scan_two, iterations, actual_bytes))

    # require_context=True.
    def scan_ctx(t=text):
        list(enhanced_scan_text(t, require_context=True))
    results.append(_run_bench("All + require_context", scan_ctx, iterations, actual_bytes))

    # min_confidence filtering via InputGuard.
    guard_hi = InputGuard(
        presets=[Preset.PCI_DSS, Preset.PII],
        action=Action.FLAG,
        min_confidence=0.8,
    )

    def scan_hi_conf(g=guard_hi, t=text):
        g.scan(t)
    results.append(_run_bench("All + min_confidence=0.8", scan_hi_conf, iterations, actual_bytes))

    guard_lo = InputGuard(
        presets=[Preset.PCI_DSS, Preset.PII],
        action=Action.FLAG,
        min_confidence=0.0,
    )

    def scan_lo_conf(g=guard_lo, t=text):
        g.scan(t)
    results.append(_run_bench("All + min_confidence=0.0", scan_lo_conf, iterations, actual_bytes))

    return results


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

_HEADER_FMT = "  {:<42s} {:>8s} {:>12s} {:>12s} {:>12s}"
_ROW_FMT    = "  {:<42s} {:>8d} {:>12s} {:>12s} {:>12s}"

_SECTION_SEP = "  " + "-" * 92


def _print_table(title: str, results: list[BenchmarkResult]) -> None:
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
# Threshold checks
# ---------------------------------------------------------------------------

_THRESHOLDS: dict[str, float] = {
    "Small (1 KB)":       1000.0,
    "Medium (100 KB)":    50.0,
    "Large (1 MB)":       5.0,
}

# InputGuard check threshold -- any guard.check row must exceed this.
_GUARD_CHECK_THRESHOLD = 500.0


def _evaluate_thresholds(
    text_results: list[BenchmarkResult],
    guard_results: list[BenchmarkResult],
) -> list[tuple[str, float, float, bool]]:
    """Return list of (label, measured, threshold, passed)."""
    verdicts: list[tuple[str, float, float, bool]] = []

    for r in text_results:
        if r.name in _THRESHOLDS:
            threshold = _THRESHOLDS[r.name]
            passed = r.ops_per_sec >= threshold
            verdicts.append((r.name, r.ops_per_sec, threshold, passed))

    for r in guard_results:
        if r.name.startswith("guard.check"):
            passed = r.ops_per_sec >= _GUARD_CHECK_THRESHOLD
            verdicts.append((r.name, r.ops_per_sec, _GUARD_CHECK_THRESHOLD, passed))

    return verdicts


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    print()
    print("=" * 96)
    print("  dlpscan Performance Benchmarks")
    print("=" * 96)

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
    _print_table("Pipeline (concurrent)", pipeline_results)

    # 4. InputGuard.
    print("\n  Running InputGuard benchmarks ...")
    guard_results = bench_input_guard()
    _print_table("InputGuard", guard_results)

    # 5. Pattern matching.
    print("\n  Running pattern matching benchmarks ...")
    pattern_results = bench_pattern_matching()
    _print_table("Pattern Matching Options", pattern_results)

    # Summary.
    verdicts = _evaluate_thresholds(text_results, guard_results)

    print()
    print("  === Threshold Summary ===")
    print(_SECTION_SEP)
    print(f"  {'Benchmark':<42s} {'Measured':>12s} {'Threshold':>12s} {'Result':>8s}")
    print(_SECTION_SEP)

    all_passed = True
    for label, measured, threshold, passed in verdicts:
        status = "PASS" if passed else "FAIL"
        if not passed:
            all_passed = False
        print(f"  {label:<42s} {measured:>12.1f} {threshold:>12.1f} {status:>8s}")

    print(_SECTION_SEP)

    if all_passed:
        print("\n  All benchmarks PASSED.\n")
    else:
        print("\n  Some benchmarks FAILED. Review results above.\n")

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
