"""Rate limiter for protecting DLP scanning in API contexts.

Provides a thread-safe token bucket rate limiter that can be used
to throttle scanning requests by count and payload size.

Usage::

    from dlpscan.rate_limit import RateLimiter, rate_limited

    # Standalone usage
    limiter = RateLimiter(max_requests=100, window_seconds=60)
    if limiter.check(payload_size=len(data)):
        scan(data)

    # As a decorator
    limiter = RateLimiter(max_requests=50)

    @rate_limited(limiter)
    def my_scan(text):
        return guard.scan(text)

    # Global default
    set_default_limiter(RateLimiter(max_requests=200))
    limiter = get_default_limiter()
"""

import functools
import threading
import time
from typing import Optional


class RateLimitExceeded(Exception):
    """Raised when the rate limit has been exceeded.

    Attributes:
        retry_after: Seconds until the next request will be allowed.
    """

    def __init__(self, retry_after: float, message: Optional[str] = None):
        self.retry_after = retry_after
        super().__init__(
            message or f"Rate limit exceeded. Retry after {retry_after:.2f}s."
        )


class RateLimiter:
    """Thread-safe token bucket rate limiter.

    Args:
        max_requests: Maximum requests per window.
        window_seconds: Time window in seconds (default 60).
        max_payload_bytes: Maximum payload size per request (default 10 MB).
    """

    def __init__(
        self,
        max_requests: int = 100,
        window_seconds: float = 60,
        max_payload_bytes: int = 10 * 1024 * 1024,
    ) -> None:
        if max_requests < 1:
            raise ValueError("max_requests must be >= 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        if max_payload_bytes < 0:
            raise ValueError("max_payload_bytes must be >= 0")

        self._max_requests = max_requests
        self._window_seconds = float(window_seconds)
        self._max_payload_bytes = max_payload_bytes

        self._lock = threading.Lock()
        self._request_times: list = []  # timestamps of accepted requests

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _purge_expired(self, now: float) -> None:
        """Remove request timestamps older than the current window."""
        cutoff = now - self._window_seconds
        # _request_times is kept sorted; trim from the front.
        while self._request_times and self._request_times[0] <= cutoff:
            self._request_times.pop(0)

    def _seconds_until_slot(self, now: float) -> float:
        """Return how many seconds until a slot opens, or 0.0 if available."""
        if len(self._request_times) < self._max_requests:
            return 0.0
        # Oldest request in the window determines when a slot frees up.
        oldest = self._request_times[0]
        wait = (oldest + self._window_seconds) - now
        return max(wait, 0.0)

    def _validate_payload(self, payload_size: int) -> None:
        """Raise if payload exceeds the configured maximum."""
        if self._max_payload_bytes and payload_size > self._max_payload_bytes:
            raise RateLimitExceeded(
                retry_after=0.0,
                message=(
                    f"Payload size {payload_size} bytes exceeds maximum "
                    f"of {self._max_payload_bytes} bytes."
                ),
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(self, payload_size: int = 0) -> bool:
        """Check whether a request is allowed and, if so, record it.

        Args:
            payload_size: Size of the request payload in bytes.

        Returns:
            True if the request is allowed, False otherwise.

        Raises:
            RateLimitExceeded: If *payload_size* exceeds *max_payload_bytes*.
        """
        self._validate_payload(payload_size)

        now = time.monotonic()
        with self._lock:
            self._purge_expired(now)
            if len(self._request_times) < self._max_requests:
                self._request_times.append(now)
                return True
            return False

    def wait(self, payload_size: int = 0) -> float:
        """Block until a request is allowed, then record it.

        Args:
            payload_size: Size of the request payload in bytes.

        Returns:
            The total time spent waiting (in seconds). Returns 0.0 if the
            request was immediately allowed.

        Raises:
            RateLimitExceeded: If *payload_size* exceeds *max_payload_bytes*.
        """
        self._validate_payload(payload_size)

        total_waited = 0.0
        while True:
            now = time.monotonic()
            with self._lock:
                self._purge_expired(now)
                delay = self._seconds_until_slot(now)
                if delay <= 0.0:
                    self._request_times.append(now)
                    return total_waited

            # Sleep outside the lock.
            time.sleep(delay)
            total_waited += delay

    def reset(self) -> None:
        """Clear all recorded request timestamps."""
        with self._lock:
            self._request_times.clear()

    @property
    def remaining(self) -> int:
        """Number of remaining requests allowed in the current window."""
        now = time.monotonic()
        with self._lock:
            self._purge_expired(now)
            return max(0, self._max_requests - len(self._request_times))

    # Convenience -------------------------------------------------------

    @property
    def max_requests(self) -> int:
        return self._max_requests

    @property
    def window_seconds(self) -> float:
        return self._window_seconds

    @property
    def max_payload_bytes(self) -> int:
        return self._max_payload_bytes

    def __repr__(self) -> str:
        return (
            f"RateLimiter(max_requests={self._max_requests}, "
            f"window_seconds={self._window_seconds}, "
            f"max_payload_bytes={self._max_payload_bytes})"
        )


# ----------------------------------------------------------------------
# Decorator
# ----------------------------------------------------------------------

def rate_limited(limiter: RateLimiter):
    """Decorator that rate-limits calls to the wrapped function.

    If the rate limit is exceeded the decorator blocks (via
    ``limiter.wait()``) until a slot is available.

    Args:
        limiter: A :class:`RateLimiter` instance to enforce.

    Example::

        limiter = RateLimiter(max_requests=10, window_seconds=1)

        @rate_limited(limiter)
        def process(data):
            ...
    """

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            limiter.wait()
            return func(*args, **kwargs)
        return wrapper

    return decorator


# ----------------------------------------------------------------------
# Global default limiter
# ----------------------------------------------------------------------

_default_limiter: Optional[RateLimiter] = None
_default_lock = threading.Lock()


def set_default_limiter(limiter: Optional[RateLimiter] = None) -> None:
    """Set the global default rate limiter.

    Args:
        limiter: A :class:`RateLimiter` instance, or ``None`` to clear.
    """
    global _default_limiter
    with _default_lock:
        _default_limiter = limiter


def get_default_limiter() -> Optional[RateLimiter]:
    """Return the global default rate limiter, or ``None`` if not set."""
    with _default_lock:
        return _default_limiter
