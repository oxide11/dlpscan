"""Timeout mechanisms for regex and scan operations."""

import signal
import threading
from typing import Optional


class _RegexTimeout(Exception):
    """Raised when a regex operation exceeds the time limit."""


def _timeout_handler(signum, frame):
    raise _RegexTimeout("Regex operation timed out")


def _can_use_sigalrm() -> bool:
    """Check if SIGALRM is available and we are in the main thread."""
    return (
        hasattr(signal, 'SIGALRM')
        and threading.current_thread() is threading.main_thread()
    )


class _ThreadTimeout:
    """Cross-platform timeout using threading.Timer for non-Unix/non-main-thread.

    Sets a flag that the scan loop checks periodically. Unlike SIGALRM this
    cannot interrupt a blocking regex mid-execution, but it prevents runaway
    scans from consuming unbounded time across pattern iterations.
    """

    def __init__(self, seconds: int):
        self._seconds = seconds
        self._expired = False
        self._timer: Optional[threading.Timer] = None

    def start(self) -> None:
        if self._seconds <= 0:
            return
        self._expired = False
        self._timer = threading.Timer(self._seconds, self._expire)
        self._timer.daemon = True
        self._timer.start()

    def _expire(self) -> None:
        self._expired = True

    @property
    def expired(self) -> bool:
        return self._expired

    def cancel(self) -> None:
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
