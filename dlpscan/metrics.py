"""Observability hooks for enterprise monitoring.

Provides a callback-based metrics system that enterprises can wire into
Prometheus, StatsD, Datadog, or any other monitoring backend.

Usage::

    from dlpscan.metrics import set_metrics_callback, ScanMetrics

    def my_callback(metrics: ScanMetrics) -> None:
        statsd.timing('dlpscan.scan_duration_ms', metrics.duration_ms)
        statsd.incr('dlpscan.matches', metrics.match_count)
        statsd.incr('dlpscan.files_scanned', metrics.files_scanned)

    set_metrics_callback(my_callback)

    # All subsequent scans will invoke the callback automatically.
"""

import time
import threading
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class ScanMetrics:
    """Metrics collected from a single scan operation.

    Attributes:
        duration_ms: Wall-clock scan time in milliseconds.
        match_count: Number of matches found.
        files_scanned: Number of files scanned (0 for text-only scans).
        files_skipped: Number of files skipped (binary, errors, allowlist).
        bytes_scanned: Approximate bytes of text processed.
        patterns_timed_out: Number of patterns that hit the regex timeout.
        scan_truncated: Whether the scan was cut short by max_matches or timeout.
        categories_scanned: Number of pattern categories checked.
        error: Exception if the scan failed, None otherwise.
    """
    duration_ms: float = 0.0
    match_count: int = 0
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    patterns_timed_out: int = 0
    scan_truncated: bool = False
    categories_scanned: int = 0
    error: Optional[Exception] = None


# Global callback — set by the enterprise consumer.
_metrics_callback: Optional[Callable[[ScanMetrics], None]] = None
_metrics_lock = threading.Lock()


def set_metrics_callback(callback: Optional[Callable[[ScanMetrics], None]]) -> None:
    """Register a callback that receives ScanMetrics after each scan.

    Pass None to disable metrics collection.

    Args:
        callback: A callable that accepts a ScanMetrics instance.
    """
    global _metrics_callback
    with _metrics_lock:
        _metrics_callback = callback


def get_metrics_callback() -> Optional[Callable[[ScanMetrics], None]]:
    """Return the currently registered metrics callback, or None."""
    with _metrics_lock:
        return _metrics_callback


class MetricsCollector:
    """Context manager for collecting scan metrics.

    Usage::

        with MetricsCollector() as mc:
            mc.bytes_scanned = len(text)
            mc.match_count = len(results)
        # Callback is invoked automatically on exit.
    """

    def __init__(self):
        self.metrics = ScanMetrics()
        self._start_time: float = 0.0

    def __enter__(self) -> 'ScanMetrics':
        self._start_time = time.monotonic()
        return self.metrics

    def __exit__(self, exc_type, exc_val, exc_tb):
        elapsed = time.monotonic() - self._start_time
        self.metrics.duration_ms = round(elapsed * 1000, 2)

        if exc_val is not None:
            self.metrics.error = exc_val

        cb = get_metrics_callback()
        if cb is not None:
            try:
                cb(self.metrics)
            except Exception:
                pass  # Never let metrics callback crash the scan.

        return False  # Don't suppress exceptions.
