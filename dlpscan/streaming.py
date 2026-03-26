"""Real-time streaming scanner for chat, logs, and webhook payloads.

Provides ``StreamScanner`` for scanning text as it arrives in chunks
(e.g., from a chat stream, log tail, or webhook endpoint) and an
async-compatible ``WebhookScanner`` for HTTP request body scanning.

Usage::

    from dlpscan.streaming import StreamScanner

    scanner = StreamScanner(categories={'Credit Card Numbers', 'Contact Information'})

    # Feed chunks as they arrive
    for chunk in incoming_stream():
        results = scanner.feed(chunk)
        for match in results:
            print(f"ALERT: {match.category} — {match.sub_category}")

    # Flush remaining buffer
    results = scanner.flush()

Webhook usage::

    from dlpscan.streaming import WebhookScanner

    webhook = WebhookScanner(presets=[Preset.PCI_DSS], action=Action.REJECT)

    # Scan a webhook payload
    result = webhook.scan_payload(request_body, content_type='application/json')
"""

import json
import logging
import threading
from typing import Callable, Dict, List, Optional, Set

from .exceptions import EmptyInputError
from .guard import Action, InputGuard, Mode, Preset, ScanResult
from .models import Match
from .scanner import enhanced_scan_text

logger = logging.getLogger(__name__)


class StreamScanner:
    """Stateful scanner for real-time text streams.

    Buffers incoming text and scans at configurable intervals or buffer
    sizes. Thread-safe — can be shared across producer/consumer threads.

    Args:
        categories: Pattern categories to scan (None = all).
        require_context: Only report matches with context keywords.
        min_confidence: Minimum confidence threshold.
        buffer_size: Characters to accumulate before scanning (default 4096).
        overlap: Characters to carry over between scans to catch boundary matches.
        on_match: Optional callback invoked for each match found.
    """

    def __init__(
        self,
        categories: Optional[Set[str]] = None,
        require_context: bool = False,
        min_confidence: float = 0.0,
        buffer_size: int = 4096,
        overlap: int = 256,
        on_match: Optional[Callable[[Match], None]] = None,
    ):
        self._categories = categories
        self._require_context = require_context
        self._min_confidence = min_confidence
        self._buffer_size = buffer_size
        self._overlap = overlap
        self._on_match = on_match
        self._buffer = ''
        self._lock = threading.Lock()
        self._total_offset = 0
        self._seen_spans: set = set()

    def feed(self, text: str) -> List[Match]:
        """Feed a chunk of text. Returns matches found if buffer is ready.

        Accumulates text until buffer_size is reached, then scans and
        returns any matches found. Returns empty list if buffer isn't
        full yet.
        """
        with self._lock:
            self._buffer += text

            if len(self._buffer) < self._buffer_size:
                return []

            return self._scan_buffer()

    def flush(self) -> List[Match]:
        """Flush remaining buffer and return any matches found."""
        with self._lock:
            if not self._buffer.strip():
                return []
            return self._scan_buffer(final=True)

    def reset(self) -> None:
        """Clear the buffer and offset tracking."""
        with self._lock:
            self._buffer = ''
            self._total_offset = 0
            self._seen_spans.clear()

    def _scan_buffer(self, final: bool = False) -> List[Match]:
        """Scan the current buffer and return matches."""
        matches = []
        text = self._buffer

        try:
            for m in enhanced_scan_text(
                text,
                categories=self._categories,
                require_context=self._require_context,
            ):
                if m.confidence < self._min_confidence:
                    continue

                # Calculate absolute span offset.
                abs_span = (
                    m.span[0] + self._total_offset,
                    m.span[1] + self._total_offset,
                )

                if abs_span in self._seen_spans:
                    continue
                self._seen_spans.add(abs_span)

                adjusted = Match(
                    text=m.text,
                    category=m.category,
                    sub_category=m.sub_category,
                    has_context=m.has_context,
                    confidence=m.confidence,
                    span=abs_span,
                    context_required=m.context_required,
                )
                matches.append(adjusted)

                if self._on_match is not None:
                    try:
                        self._on_match(adjusted)
                    except Exception:
                        pass

        except EmptyInputError:
            pass

        # Keep overlap for next scan, advance offset.
        if final:
            self._total_offset += len(text)
            self._buffer = ''
        else:
            keep = min(self._overlap, len(text))
            consumed = len(text) - keep
            self._total_offset += consumed
            self._buffer = text[-keep:] if keep > 0 else ''

        # Prune old spans.
        cutoff = self._total_offset - self._overlap
        self._seen_spans = {s for s in self._seen_spans if s[1] > cutoff}

        return matches


class WebhookScanner:
    """Scanner for HTTP webhook payloads.

    Wraps InputGuard for scanning structured payloads (JSON, form data,
    plain text) from webhook endpoints.

    Args:
        presets: Compliance presets (passed to InputGuard).
        categories: Explicit categories (passed to InputGuard).
        action: What to do on detection (default REJECT).
        mode: DENYLIST or ALLOWLIST (default DENYLIST).
        min_confidence: Minimum confidence threshold.
        on_detect: Optional callback on detection.

    Example::

        scanner = WebhookScanner(presets=[Preset.PCI_DSS])
        try:
            result = scanner.scan_payload(body, content_type='application/json')
        except InputGuardError as e:
            return {"error": "Sensitive data detected"}, 400
    """

    def __init__(
        self,
        presets: Optional[List[Preset]] = None,
        categories: Optional[Set[str]] = None,
        action: Action = Action.REJECT,
        mode: Mode = Mode.DENYLIST,
        min_confidence: float = 0.0,
        on_detect: Optional[Callable[[ScanResult], None]] = None,
    ):
        self._guard = InputGuard(
            presets=presets,
            categories=categories,
            action=action,
            mode=mode,
            min_confidence=min_confidence,
            on_detect=on_detect,
        )

    def scan_payload(
        self,
        body: str,
        content_type: str = 'text/plain',
    ) -> ScanResult:
        """Scan a webhook payload body.

        For JSON payloads, extracts all string values and scans them.
        For other content types, scans the raw body.

        Args:
            body: The raw request body as a string.
            content_type: Content-Type header value.

        Returns:
            ScanResult with findings.

        Raises:
            InputGuardError: If action=REJECT and sensitive data is found.
        """
        if 'json' in content_type.lower():
            text = self._extract_json_strings(body)
        else:
            text = body

        if not text or not text.strip():
            return ScanResult(text=body, is_clean=True)

        return self._guard.scan(text)

    def scan_headers(self, headers: Dict[str, str]) -> ScanResult:
        """Scan HTTP headers for sensitive data (e.g., leaked tokens in custom headers).

        Skips standard auth headers (Authorization, Cookie) and only
        scans custom header values.

        Args:
            headers: Dict of header name -> value.

        Returns:
            ScanResult with findings.
        """
        skip = {'authorization', 'cookie', 'set-cookie'}
        values = [
            v for k, v in headers.items()
            if k.lower() not in skip and isinstance(v, str)
        ]
        if not values:
            return ScanResult(text='', is_clean=True)

        combined = '\n'.join(values)
        return self._guard.scan(combined)

    @staticmethod
    def _extract_json_strings(body: str) -> str:
        """Recursively extract all string values from a JSON payload."""
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            return body

        strings: List[str] = []
        _MAX_DEPTH = 64

        def _walk(obj, depth=0):
            if depth > _MAX_DEPTH:
                return
            if isinstance(obj, str):
                strings.append(obj)
            elif isinstance(obj, dict):
                for v in obj.values():
                    _walk(v, depth + 1)
            elif isinstance(obj, (list, tuple)):
                for item in obj:
                    _walk(item, depth + 1)

        _walk(data)
        return '\n'.join(strings)
