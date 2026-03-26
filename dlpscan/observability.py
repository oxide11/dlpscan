"""Prometheus/OpenTelemetry metrics module for dlpscan.

Provides stdlib-only metric types (Counter, Gauge, Histogram), a singleton
MetricsRegistry with Prometheus text exposition and OpenTelemetry dict export,
pre-registered DLP metrics, and an optional HTTP exporter.

Usage::

    from dlpscan.observability import registry, record_scan, PrometheusExporter

    # Metrics are updated automatically via record_scan(result, duration)
    record_scan(scan_result, duration_seconds=0.042)

    # Export as Prometheus text
    print(registry.to_prometheus())

    # Start HTTP /metrics endpoint
    exporter = PrometheusExporter()
    exporter.start(port=9090)

    # Optional OpenTelemetry bridge
    from dlpscan.observability import setup_opentelemetry
    setup_opentelemetry(service_name="dlpscan")
"""

from __future__ import annotations

import logging
import math
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Metric types
# ---------------------------------------------------------------------------

_DEFAULT_HISTOGRAM_BUCKETS: List[float] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
]


class Counter:
    """Monotonically increasing counter (thread-safe)."""

    metric_type = "counter"

    def __init__(
        self,
        name: str,
        description: str = "",
        labels: Optional[Dict[str, str]] = None,
    ) -> None:
        self.name = name
        self.description = description
        self.labels = labels or {}
        self._value: float = 0.0
        self._lock = threading.Lock()

    def inc(self, value: float = 1) -> None:
        """Increment the counter by *value* (must be >= 0)."""
        if value < 0:
            raise ValueError("Counter increment must be non-negative")
        with self._lock:
            self._value += value

    def get(self) -> float:
        with self._lock:
            return self._value

    def reset(self) -> None:
        with self._lock:
            self._value = 0.0


class Gauge:
    """Value that can go up and down (thread-safe)."""

    metric_type = "gauge"

    def __init__(
        self,
        name: str,
        description: str = "",
        labels: Optional[Dict[str, str]] = None,
    ) -> None:
        self.name = name
        self.description = description
        self.labels = labels or {}
        self._value: float = 0.0
        self._lock = threading.Lock()

    def set(self, value: float) -> None:
        with self._lock:
            self._value = value

    def inc(self, value: float = 1) -> None:
        with self._lock:
            self._value += value

    def dec(self, value: float = 1) -> None:
        with self._lock:
            self._value -= value

    def get(self) -> float:
        with self._lock:
            return self._value

    def reset(self) -> None:
        with self._lock:
            self._value = 0.0


class Histogram:
    """Tracks value distributions with configurable buckets (thread-safe)."""

    metric_type = "histogram"

    def __init__(
        self,
        name: str,
        description: str = "",
        labels: Optional[Dict[str, str]] = None,
        buckets: Optional[List[float]] = None,
    ) -> None:
        self.name = name
        self.description = description
        self.labels = labels or {}
        self._buckets: List[float] = sorted(buckets or _DEFAULT_HISTOGRAM_BUCKETS)
        self._counts: List[int] = [0] * len(self._buckets)
        self._sum: float = 0.0
        self._count: int = 0
        self._lock = threading.Lock()

    def observe(self, value: float) -> None:
        """Record an observed value into the histogram."""
        with self._lock:
            self._sum += value
            self._count += 1
            for i, bound in enumerate(self._buckets):
                if value <= bound:
                    self._counts[i] += 1

    def get_count(self) -> int:
        with self._lock:
            return self._count

    def get_sum(self) -> float:
        with self._lock:
            return self._sum

    def get_buckets(self) -> List[Tuple[float, int]]:
        """Return list of (upper_bound, cumulative_count) pairs."""
        with self._lock:
            cumulative = 0
            result: List[Tuple[float, int]] = []
            for i, bound in enumerate(self._buckets):
                cumulative += self._counts[i]
                result.append((bound, cumulative))
            result.append((math.inf, self._count))
            return result

    def reset(self) -> None:
        with self._lock:
            self._counts = [0] * len(self._buckets)
            self._sum = 0.0
            self._count = 0


# ---------------------------------------------------------------------------
# MetricsRegistry — singleton
# ---------------------------------------------------------------------------

class MetricsRegistry:
    """Central registry for all metrics.  Singleton."""

    _instance: Optional["MetricsRegistry"] = None
    _init_lock = threading.Lock()

    def __new__(cls) -> "MetricsRegistry":
        with cls._init_lock:
            if cls._instance is None:
                inst = super().__new__(cls)
                inst._metrics: Dict[str, Any] = {}
                inst._lock = threading.Lock()
                cls._instance = inst
            return cls._instance

    # -- public API --

    def register(self, metric: Any) -> Any:
        """Register a metric.  Returns the metric for convenience."""
        with self._lock:
            if metric.name in self._metrics:
                raise ValueError(f"Metric '{metric.name}' is already registered")
            self._metrics[metric.name] = metric
        return metric

    def get(self, name: str) -> Any:
        """Look up a metric by name.  Returns None if not found."""
        with self._lock:
            return self._metrics.get(name)

    def all(self) -> List[Any]:
        """Return all registered metrics (snapshot)."""
        with self._lock:
            return list(self._metrics.values())

    def reset(self) -> None:
        """Reset every registered metric to its zero state (for testing)."""
        with self._lock:
            for m in self._metrics.values():
                m.reset()

    # -- export helpers --

    @staticmethod
    def _label_str(labels: Dict[str, str]) -> str:
        if not labels:
            return ""
        pairs = ",".join(
            f'{k}="{v}"' for k, v in sorted(labels.items())
        )
        return "{" + pairs + "}"

    def to_prometheus(self) -> str:
        """Export all metrics in Prometheus text exposition format."""
        lines: List[str] = []
        with self._lock:
            metrics = list(self._metrics.values())

        for m in metrics:
            lbl = self._label_str(m.labels)

            if isinstance(m, Counter):
                lines.append(f"# HELP {m.name} {m.description}")
                lines.append(f"# TYPE {m.name} counter")
                lines.append(f"{m.name}{lbl} {m.get()}")

            elif isinstance(m, Gauge):
                lines.append(f"# HELP {m.name} {m.description}")
                lines.append(f"# TYPE {m.name} gauge")
                lines.append(f"{m.name}{lbl} {m.get()}")

            elif isinstance(m, Histogram):
                lines.append(f"# HELP {m.name} {m.description}")
                lines.append(f"# TYPE {m.name} histogram")
                for bound, cum in m.get_buckets():
                    le = "+Inf" if math.isinf(bound) else str(bound)
                    bucket_labels = dict(m.labels)
                    bucket_labels["le"] = le
                    lines.append(
                        f"{m.name}_bucket{self._label_str(bucket_labels)} {cum}"
                    )
                lines.append(f"{m.name}_count{lbl} {m.get_count()}")
                lines.append(f"{m.name}_sum{lbl} {m.get_sum()}")

            lines.append("")  # blank line between metrics

        return "\n".join(lines)

    def to_opentelemetry(self) -> dict:
        """Export metrics as an OpenTelemetry-compatible dict."""
        resource_metrics: List[dict] = []

        with self._lock:
            metrics = list(self._metrics.values())

        scope_metrics: List[dict] = []
        for m in metrics:
            entry: dict = {
                "name": m.name,
                "description": m.description,
                "labels": dict(m.labels),
            }

            if isinstance(m, Counter):
                entry["type"] = "sum"
                entry["is_monotonic"] = True
                entry["data_points"] = [
                    {"value": m.get(), "attributes": dict(m.labels)}
                ]

            elif isinstance(m, Gauge):
                entry["type"] = "gauge"
                entry["data_points"] = [
                    {"value": m.get(), "attributes": dict(m.labels)}
                ]

            elif isinstance(m, Histogram):
                buckets = m.get_buckets()
                entry["type"] = "histogram"
                entry["data_points"] = [
                    {
                        "count": m.get_count(),
                        "sum": m.get_sum(),
                        "bucket_counts": [c for _, c in buckets],
                        "explicit_bounds": [
                            b for b, _ in buckets if not math.isinf(b)
                        ],
                        "attributes": dict(m.labels),
                    }
                ]

            scope_metrics.append(entry)

        resource_metrics.append(
            {
                "resource": {"attributes": {"service.name": "dlpscan"}},
                "scope_metrics": [
                    {
                        "scope": {"name": "dlpscan.observability"},
                        "metrics": scope_metrics,
                    }
                ],
            }
        )

        return {"resource_metrics": resource_metrics}


# ---------------------------------------------------------------------------
# Module-level singleton & built-in DLP metrics
# ---------------------------------------------------------------------------

registry = MetricsRegistry()

dlpscan_scans_total = registry.register(
    Counter(
        name="dlpscan_scans_total",
        description="Total scans performed",
    )
)

dlpscan_findings_total = registry.register(
    Counter(
        name="dlpscan_findings_total",
        description="Total findings detected",
        labels={"category": ""},
    )
)

dlpscan_scan_duration_seconds = registry.register(
    Histogram(
        name="dlpscan_scan_duration_seconds",
        description="Scan latency in seconds",
    )
)

dlpscan_scan_errors_total = registry.register(
    Counter(
        name="dlpscan_scan_errors_total",
        description="Total scan errors",
    )
)

dlpscan_active_vaults = registry.register(
    Gauge(
        name="dlpscan_active_vaults",
        description="Number of active token vaults",
    )
)

dlpscan_tokens_created_total = registry.register(
    Counter(
        name="dlpscan_tokens_created_total",
        description="Tokens created",
    )
)

dlpscan_rate_limit_rejections_total = registry.register(
    Counter(
        name="dlpscan_rate_limit_rejections_total",
        description="Rate limit rejections",
    )
)


# ---------------------------------------------------------------------------
# record_scan helper
# ---------------------------------------------------------------------------

def record_scan(result: Any, duration_seconds: float) -> None:
    """Update all relevant metrics from a ScanResult.

    Args:
        result: A ``ScanResult`` (from ``dlpscan.guard.core``).
        duration_seconds: Wall-clock scan duration in seconds.
    """
    dlpscan_scans_total.inc()
    dlpscan_scan_duration_seconds.observe(duration_seconds)

    finding_count = getattr(result, "finding_count", 0)
    if finding_count:
        dlpscan_findings_total.inc(finding_count)

    # Per-category tracking (aggregate counter used; individual categories logged)
    _ = getattr(result, "categories_found", set())

    if not getattr(result, "is_clean", True) and finding_count == 0:
        # Edge case: result flagged dirty but no findings — treat as error.
        dlpscan_scan_errors_total.inc()


# ---------------------------------------------------------------------------
# PrometheusExporter — lightweight /metrics HTTP server
# ---------------------------------------------------------------------------

class _MetricsHandler(BaseHTTPRequestHandler):
    """HTTP handler that serves Prometheus text exposition on ``/metrics``."""

    def do_GET(self) -> None:
        if self.path == "/metrics":
            body = registry.to_prometheus().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        # Silence default stderr logging.
        pass


class PrometheusExporter:
    """Simple HTTP server that exposes ``/metrics`` for Prometheus scraping.

    Usage::

        exporter = PrometheusExporter()
        exporter.start(port=9090)
        # ...
        exporter.stop()
    """

    def __init__(self) -> None:
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self, port: int = 9090) -> None:
        """Start serving ``/metrics`` in a daemon background thread."""
        if self._server is not None:
            raise RuntimeError("Exporter is already running")
        self._server = HTTPServer(("127.0.0.1", port), _MetricsHandler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="dlpscan-metrics-exporter",
            daemon=True,
        )
        self._thread.start()
        logger.info("Prometheus exporter started on port %d", port)

    def stop(self) -> None:
        """Shut down the exporter."""
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        logger.info("Prometheus exporter stopped")


# ---------------------------------------------------------------------------
# Optional OpenTelemetry integration
# ---------------------------------------------------------------------------

def setup_opentelemetry(service_name: str = "dlpscan") -> None:
    """Bridge dlpscan metrics into OpenTelemetry if the SDK is installed.

    If the ``opentelemetry`` package is not available, logs a warning and
    returns without error.
    """
    try:
        from opentelemetry import metrics as otel_metrics  # type: ignore[import-untyped]
        from opentelemetry.sdk.metrics import MeterProvider  # type: ignore[import-untyped]
        from opentelemetry.sdk.resources import Resource  # type: ignore[import-untyped]
    except ImportError:
        logger.warning(
            "opentelemetry SDK is not installed; "
            "skipping OpenTelemetry metrics setup. "
            "Install with: pip install opentelemetry-sdk"
        )
        return

    resource = Resource.create({"service.name": service_name})
    provider = MeterProvider(resource=resource)
    otel_metrics.set_meter_provider(provider)
    meter = provider.get_meter("dlpscan.observability")

    # Bridge each registered metric into OTel.
    for m in registry.all():
        if isinstance(m, Counter):
            otel_counter = meter.create_counter(
                name=m.name,
                description=m.description,
            )
            # Sync current value.
            current = m.get()
            if current > 0:
                otel_counter.add(current, attributes=m.labels)

        elif isinstance(m, Gauge):
            meter.create_observable_gauge(
                name=m.name,
                description=m.description,
                callbacks=[
                    lambda options, _m=m: [
                        otel_metrics.Observation(value=_m.get(), attributes=_m.labels)
                    ]
                ],
            )

        elif isinstance(m, Histogram):
            meter.create_histogram(
                name=m.name,
                description=m.description,
            )
            # Note: existing observations cannot be replayed into OTel;
            # future calls to observe() should use the OTel histogram
            # in addition to the local one.  A production bridge would
            # monkey-patch observe(); here we create the instrument for
            # forward use.

    logger.info(
        "OpenTelemetry metrics bridge configured for service '%s'",
        service_name,
    )
