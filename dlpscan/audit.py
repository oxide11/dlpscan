"""Comprehensive audit logging for enterprise DLP compliance.

Provides a structured audit trail for every scan, tokenize, detokenize,
obfuscate, redact, reject, and flag operation.  All timestamps use ISO 8601
format and all public operations are thread-safe.

Usage::

    from dlpscan.audit import (
        AuditEvent, AuditLogger, StderrAuditHandler, FileAuditHandler,
        set_audit_logger, get_audit_logger, audit_event, event_from_scan,
    )

    # Quick start — stderr JSON logging (default)
    logger = AuditLogger()
    set_audit_logger(logger)

    # After a scan
    event = event_from_scan(result, action="redact", source="api")
    audit_event(event)

    # File-based audit log
    logger = AuditLogger(handlers=[FileAuditHandler("/var/log/dlp-audit.jsonl")])
    set_audit_logger(logger)
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Protocol, runtime_checkable

# ---------------------------------------------------------------------------
# AuditEvent
# ---------------------------------------------------------------------------

_VALID_EVENT_TYPES = frozenset({
    "SCAN",
    "TOKENIZE",
    "DETOKENIZE",
    "OBFUSCATE",
    "REDACT",
    "REJECT",
    "FLAG",
})


def _iso_now() -> str:
    """Return the current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


@dataclass
class AuditEvent:
    """A single auditable DLP operation.

    Attributes:
        event_type: One of SCAN, TOKENIZE, DETOKENIZE, OBFUSCATE, REDACT,
                    REJECT, FLAG.
        timestamp: ISO 8601 UTC timestamp.
        user: The user who triggered the operation (env ``USER`` or explicit).
        action: The :class:`Action` enum *value* (e.g. ``"redact"``).
        categories_scanned: Categories that were included in the scan.
        categories_found: Categories for which findings were reported.
        finding_count: Total number of individual findings.
        is_clean: ``True`` when no sensitive data was detected.
        source: Origin of the data — file path, ``"stdin"``, ``"api"``, etc.
        duration_ms: Wall-clock time of the operation in milliseconds.
        metadata: Arbitrary extra key/value pairs for extensibility.
    """

    event_type: str
    timestamp: str = field(default_factory=_iso_now)
    user: Optional[str] = field(
        default_factory=lambda: os.environ.get("USER") or os.environ.get("USERNAME"),
    )
    action: str = ""
    categories_scanned: List[str] = field(default_factory=list)
    categories_found: List[str] = field(default_factory=list)
    finding_count: int = 0
    is_clean: bool = True
    source: Optional[str] = None
    duration_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.event_type not in _VALID_EVENT_TYPES:
            raise ValueError(
                f"Invalid event_type {self.event_type!r}; "
                f"must be one of {sorted(_VALID_EVENT_TYPES)}"
            )

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain dictionary suitable for ``json.dumps``."""
        d = asdict(self)
        # asdict already handles nested structures; keep it JSON-clean.
        return d


# ---------------------------------------------------------------------------
# Audit handler protocol & built-in handlers
# ---------------------------------------------------------------------------

@runtime_checkable
class AuditHandler(Protocol):
    """Protocol that all audit handlers must satisfy."""

    def handle(self, event: AuditEvent) -> None:  # pragma: no cover
        ...


class StderrAuditHandler:
    """Emit each audit event as a single JSON line to stderr via
    :mod:`logging`."""

    def __init__(self) -> None:
        self._logger = logging.getLogger("dlpscan.audit")
        # Ensure at least one handler on the logger so events are not silently
        # dropped when the root logger has no configuration.
        if not self._logger.handlers:
            handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(handler)
            self._logger.setLevel(logging.INFO)

    def handle(self, event: AuditEvent) -> None:
        self._logger.info(json.dumps(event.to_dict(), default=str))


class FileAuditHandler:
    """Append each audit event as a JSON-lines entry to a file.

    The file is opened in append mode and flushed after every write so that
    events survive unexpected process termination.  A per-handler lock
    serialises writes from concurrent threads.
    """

    def __init__(self, path: str) -> None:
        self._path = os.path.realpath(path)
        # Reject symlinks to prevent symlink attacks
        if os.path.islink(path):
            raise ValueError(f"Refusing to use symlink path: {path}")
        self._lock = threading.Lock()

    def handle(self, event: AuditEvent) -> None:
        line = json.dumps(event.to_dict(), default=str) + "\n"
        with self._lock:
            fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()


class CallbackAuditHandler:
    """Invoke a user-supplied callable for every audit event.

    The callback receives a single :class:`AuditEvent` argument.
    """

    def __init__(self, callback: Callable[[AuditEvent], None]) -> None:
        if not callable(callback):
            raise TypeError("callback must be callable")
        self._callback = callback

    def handle(self, event: AuditEvent) -> None:
        self._callback(event)


class NullAuditHandler:
    """Silently discard all events.  Useful for testing."""

    def handle(self, event: AuditEvent) -> None:
        pass


# ---------------------------------------------------------------------------
# AuditLogger
# ---------------------------------------------------------------------------

class AuditLogger:
    """Central dispatcher that fans out :class:`AuditEvent` instances to one
    or more :class:`AuditHandler` implementations.

    Thread-safe: a :class:`threading.Lock` serialises calls to :meth:`log`.

    Parameters:
        handlers: Iterable of handler instances.  When *None* (the default),
                  a single :class:`StderrAuditHandler` is installed.
        user: Optional override for the ``user`` field on every event.  When
              set, events that have ``user=None`` will be stamped with this
              value before dispatch.
        include_findings: Reserved for future use — when *True*, raw finding
                          text may be included in the audit payload.
    """

    def __init__(
        self,
        handlers: Optional[List[AuditHandler]] = None,
        user: Optional[str] = None,
        include_findings: bool = False,
    ) -> None:
        self._handlers: List[AuditHandler] = (
            list(handlers) if handlers is not None else [StderrAuditHandler()]
        )
        self._user = user
        self._include_findings = include_findings
        self._lock = threading.Lock()

    # -- public API ---------------------------------------------------------

    def log(self, event: AuditEvent) -> None:
        """Dispatch *event* to every registered handler.

        If this logger has a default ``user`` and the event's ``user`` is
        *None*, the default is applied before dispatch.
        """
        if event.user is None and self._user is not None:
            # Dataclass is mutable — stamp in place.
            event.user = self._user

        with self._lock:
            for handler in self._handlers:
                handler.handle(event)

    @property
    def handlers(self) -> List[AuditHandler]:
        """Return a snapshot of the current handler list."""
        with self._lock:
            return list(self._handlers)

    def add_handler(self, handler: AuditHandler) -> None:
        """Add a handler at runtime."""
        with self._lock:
            self._handlers.append(handler)

    def remove_handler(self, handler: AuditHandler) -> None:
        """Remove a handler at runtime (no-op if not present)."""
        with self._lock:
            try:
                self._handlers.remove(handler)
            except ValueError:
                pass


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------

_global_logger: Optional[AuditLogger] = None
_global_lock = threading.Lock()


def set_audit_logger(logger: AuditLogger) -> None:
    """Install *logger* as the process-wide audit logger."""
    global _global_logger
    with _global_lock:
        _global_logger = logger


def get_audit_logger() -> Optional[AuditLogger]:
    """Return the process-wide audit logger, or *None* if not set."""
    with _global_lock:
        return _global_logger


def audit_event(event: AuditEvent) -> None:
    """Log *event* via the global audit logger.

    If no global logger has been configured the call is silently ignored,
    following the same convention as :func:`logging.warning` before
    ``basicConfig`` is called.
    """
    logger = get_audit_logger()
    if logger is not None:
        logger.log(event)


# ---------------------------------------------------------------------------
# Helper: create AuditEvent from a ScanResult
# ---------------------------------------------------------------------------

def event_from_scan(
    result: Any,
    action: str,
    source: Optional[str] = None,
    duration_ms: float = 0.0,
    user: Optional[str] = None,
) -> AuditEvent:
    """Build an :class:`AuditEvent` from a :class:`~dlpscan.guard.core.ScanResult`.

    The ``event_type`` is inferred from *action*:

    * ``"tokenize"`` → ``TOKENIZE``
    * ``"detokenize"`` → ``DETOKENIZE``
    * ``"obfuscate"`` → ``OBFUSCATE``
    * ``"redact"`` → ``REDACT``
    * ``"reject"`` → ``REJECT``
    * ``"flag"`` → ``FLAG``
    * anything else → ``SCAN``

    Parameters:
        result: A :class:`ScanResult` (or any object with ``is_clean``,
                ``findings``, and ``categories_found`` attributes).
        action: The action string (typically an :class:`Action` enum value).
        source: Human-readable origin of the scanned data.
        duration_ms: Elapsed wall-clock time in milliseconds.
        user: Explicit user override (falls back to env ``USER``).
    """
    _ACTION_TO_EVENT: Dict[str, str] = {
        "tokenize": "TOKENIZE",
        "detokenize": "DETOKENIZE",
        "obfuscate": "OBFUSCATE",
        "redact": "REDACT",
        "reject": "REJECT",
        "flag": "FLAG",
    }

    action_lower = action.lower() if action else ""
    event_type = _ACTION_TO_EVENT.get(action_lower, "SCAN")

    # categories_found may be a set on ScanResult — normalise to sorted list.
    categories_found: List[str] = sorted(
        getattr(result, "categories_found", set())
    )

    # Gather the distinct categories that individual findings belong to.
    categories_scanned: List[str] = sorted(
        {m.category for m in getattr(result, "findings", [])}
    )

    finding_count: int = getattr(result, "finding_count", len(getattr(result, "findings", [])))

    return AuditEvent(
        event_type=event_type,
        user=user,
        action=action,
        categories_scanned=categories_scanned,
        categories_found=categories_found,
        finding_count=finding_count,
        is_clean=getattr(result, "is_clean", True),
        source=source,
        duration_ms=duration_ms,
    )
