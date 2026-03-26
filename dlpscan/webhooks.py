"""Webhook/callback notifications for DLP findings."""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.request
from datetime import datetime, timezone
from typing import Any, List, Optional, Sequence

logger = logging.getLogger(__name__)

_notifiers: List[WebhookNotifier] = []


def _build_payload(
    result: Any,
    source: Optional[str] = None,
) -> dict:
    """Build the JSON payload from a scan result."""
    details = []
    for m in getattr(result, "findings", []):
        details.append({
            "category": m.category,
            "redacted_match": m.redacted_text,
        })
    return {
        "event_type": "dlp_finding",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "finding_count": len(details),
        "categories": sorted(getattr(result, "categories_found", set())),
        "source": source,
        "details": details,
    }


class WebhookNotifier:
    """Sends HTTP POST notifications to one or more webhook URLs.

    Delivery is fire-and-forget in a background daemon thread with
    configurable retry and exponential backoff.
    """

    def __init__(
        self,
        urls: Sequence[str],
        *,
        retries: int = 2,
        timeout: float = 10,
        backoff_base: float = 1.0,
    ) -> None:
        self.urls = list(urls)
        self.retries = retries
        self.timeout = timeout
        self.backoff_base = backoff_base
        self._lock = threading.Lock()

    # -- public API ----------------------------------------------------------

    def add_url(self, url: str) -> None:
        """Register an additional webhook URL (thread-safe)."""
        with self._lock:
            if url not in self.urls:
                self.urls.append(url)

    def remove_url(self, url: str) -> None:
        """Remove a webhook URL (thread-safe)."""
        with self._lock:
            try:
                self.urls.remove(url)
            except ValueError:
                pass

    def notify(self, result: Any, *, source: Optional[str] = None) -> None:
        """Send finding notifications to all URLs in a background thread."""
        payload = _build_payload(result, source=source)
        if payload["finding_count"] == 0:
            return
        data = json.dumps(payload).encode()
        with self._lock:
            urls = list(self.urls)
        for url in urls:
            t = threading.Thread(
                target=self._deliver,
                args=(url, data),
                daemon=True,
            )
            t.start()

    # -- internal ------------------------------------------------------------

    def _deliver(self, url: str, data: bytes) -> None:
        """POST *data* to *url* with retry + exponential backoff."""
        for attempt in range(1 + self.retries):
            try:
                req = urllib.request.Request(
                    url,
                    data=data,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=self.timeout):
                    return
            except Exception:
                if attempt < self.retries:
                    delay = self.backoff_base * (2 ** attempt)
                    logger.debug(
                        "Webhook %s attempt %d failed, retrying in %.1fs",
                        url, attempt + 1, delay,
                    )
                    time.sleep(delay)
                else:
                    logger.warning("Webhook delivery to %s failed after %d attempts", url, 1 + self.retries)


def register_notifier(notifier: WebhookNotifier) -> None:
    """Add a notifier to the global registry."""
    _notifiers.append(notifier)


def unregister_notifier(notifier: WebhookNotifier) -> None:
    """Remove a notifier from the global registry."""
    try:
        _notifiers.remove(notifier)
    except ValueError:
        pass


def notify_findings(result: Any, source: Optional[str] = None) -> None:
    """Convenience: send *result* to every registered :class:`WebhookNotifier`."""
    for n in list(_notifiers):
        n.notify(result, source=source)
