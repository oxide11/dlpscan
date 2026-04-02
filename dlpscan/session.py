"""Stateful session correlation for drip exfiltration detection.

Tracks cumulative data exposure across scans, users, and time windows
using Count-Min Sketch (frequency) and HyperLogLog (cardinality).
Catches insiders who leak small amounts of data over long periods.

Usage::

    from dlpscan.session import SessionCorrelator

    correlator = SessionCorrelator(window_seconds=3600)  # 1-hour window
    correlator.set_policy("Credit Card Numbers", max_total=50, max_unique=20)

    # After each scan:
    alerts = correlator.record_scan(scan_result, user_id="user@company.com")
    for alert in alerts:
        print(f"ALERT: {alert.alert_type} — {alert.user_id} "
              f"({alert.count}/{alert.limit} {alert.category})")

DLP Use Case:

    "An employee can email up to 5 customer IDs per day, but flag
    anyone sending more than 50 in aggregate." Pattern matching catches
    each individual ID; session correlation catches the pattern of abuse.
"""

import fnmatch
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .countmin import CountMinSketch
from .hyperloglog import HyperLogLog

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class CorrelationAlert:
    """Alert generated when a threshold is exceeded."""
    alert_type: str  # "total_threshold" or "unique_threshold"
    user_id: str
    category: str
    count: int
    limit: int
    window_seconds: int = 0
    timestamp: float = 0.0

    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = time.time()

    def to_dict(self) -> dict:
        return {
            'alert_type': self.alert_type,
            'user_id': self.user_id,
            'category': self.category,
            'count': self.count,
            'limit': self.limit,
            'window_seconds': self.window_seconds,
            'timestamp': self.timestamp,
        }


@dataclass
class Policy:
    """Threshold policy for a category."""
    category: str
    max_total: int = 0       # Max total occurrences (0 = no limit)
    max_unique: int = 0      # Max unique values (0 = no limit)
    user_pattern: str = "*"  # fnmatch pattern for user_id filtering
    action: str = "alert"    # alert, block, escalate


@dataclass
class SessionStats:
    """Statistics for a user session."""
    user_id: str
    total_matches: int = 0
    categories: Dict[str, int] = field(default_factory=dict)
    first_seen: float = 0.0
    last_seen: float = 0.0


# ---------------------------------------------------------------------------
# Session Correlator
# ---------------------------------------------------------------------------

class SessionCorrelator:
    """Stateful correlation across scans for behavioral DLP.

    Combines Count-Min Sketch (frequency estimation) and HyperLogLog
    (cardinality estimation) to track per-user, per-category exposure
    over sliding time windows.

    Args:
        window_seconds: Duration of the monitoring window in seconds.
                        Counters reset when the window expires.
        cms_width: Width of the Count-Min Sketch (default 50,000).
        cms_depth: Depth of the Count-Min Sketch (default 7).
        hll_precision: HyperLogLog precision (default 12, ~1.63% error).

    Thread Safety:
        All methods are thread-safe via internal locking.

    Memory:
        CMS: ~1.4 MB (50,000 × 7 × 4 bytes)
        HLL: ~4 KB per active user (precision=12)
        Total for 100 users: ~1.8 MB
    """

    def __init__(
        self,
        window_seconds: int = 3600,
        cms_width: int = 50000,
        cms_depth: int = 7,
        hll_precision: int = 12,
    ):
        self._window = window_seconds
        self._cms_width = cms_width
        self._cms_depth = cms_depth
        self._hll_precision = hll_precision

        self._cms = CountMinSketch(width=cms_width, depth=cms_depth)
        self._hll_per_user: Dict[str, HyperLogLog] = {}
        self._policies: List[Policy] = []
        self._window_start = time.time()
        self._lock = threading.Lock()

        # Stats tracking
        self._user_stats: Dict[str, SessionStats] = {}
        self._total_alerts = 0

    def set_policy(self, category: str, max_total: int = 0,
                   max_unique: int = 0, user_pattern: str = "*",
                   action: str = "alert") -> None:
        """Set a threshold policy for a category.

        Args:
            category: Pattern category name (e.g., "Credit Card Numbers").
            max_total: Maximum total matches before alerting (0 = no limit).
            max_unique: Maximum unique values before alerting (0 = no limit).
            user_pattern: fnmatch glob pattern for user_id filtering.
            action: Action to take on threshold breach.
        """
        policy = Policy(
            category=category,
            max_total=max_total,
            max_unique=max_unique,
            user_pattern=user_pattern,
            action=action,
        )
        with self._lock:
            # Replace existing policy for same category+pattern
            self._policies = [
                p for p in self._policies
                if not (p.category == category and p.user_pattern == user_pattern)
            ]
            self._policies.append(policy)

    def record_scan(self, scan_result, user_id: str,
                    source: Optional[str] = None) -> List[CorrelationAlert]:
        """Record findings from a scan and check threshold policies.

        Args:
            scan_result: A ScanResult or any object with a .findings attribute
                        containing Match objects.
            user_id: Identifier for the user/source of the scan.
            source: Optional source identifier (e.g., email address, endpoint).

        Returns:
            List of CorrelationAlert objects for any threshold breaches.
        """
        with self._lock:
            self._maybe_rotate_window()
            now = time.time()
            alerts: List[CorrelationAlert] = []

            findings = getattr(scan_result, 'findings', [])
            if not findings:
                return alerts

            # Initialize user stats
            if user_id not in self._user_stats:
                self._user_stats[user_id] = SessionStats(
                    user_id=user_id, first_seen=now
                )
            stats = self._user_stats[user_id]
            stats.last_seen = now

            # Initialize user HLL
            if user_id not in self._hll_per_user:
                self._hll_per_user[user_id] = HyperLogLog(
                    precision=self._hll_precision
                )
            user_hll = self._hll_per_user[user_id]

            for match in findings:
                category = match.category

                # Update CMS (total count)
                cms_key = f"{user_id}:{category}"
                self._cms.increment(cms_key)
                total = self._cms.estimate(cms_key)

                # Update HLL (unique count)
                value_key = f"{category}:{match.text}"
                user_hll.add(value_key)
                unique = user_hll.count()

                # Update stats
                stats.total_matches += 1
                stats.categories[category] = stats.categories.get(category, 0) + 1

                # Check policies
                for policy in self._policies:
                    if policy.category != category:
                        continue
                    if not fnmatch.fnmatch(user_id, policy.user_pattern):
                        continue

                    if policy.max_total > 0 and total > policy.max_total:
                        alert = CorrelationAlert(
                            alert_type="total_threshold",
                            user_id=user_id,
                            category=category,
                            count=total,
                            limit=policy.max_total,
                            window_seconds=self._window,
                        )
                        alerts.append(alert)
                        self._total_alerts += 1
                        logger.warning(
                            "Threshold breach: %s — %s total %d/%d for %s",
                            user_id, category, total, policy.max_total, category,
                        )

                    if policy.max_unique > 0 and unique > policy.max_unique:
                        alert = CorrelationAlert(
                            alert_type="unique_threshold",
                            user_id=user_id,
                            category=category,
                            count=unique,
                            limit=policy.max_unique,
                            window_seconds=self._window,
                        )
                        alerts.append(alert)
                        self._total_alerts += 1
                        logger.warning(
                            "Threshold breach: %s — %s unique %d/%d for %s",
                            user_id, category, unique, policy.max_unique, category,
                        )

            return alerts

    def record_matches(self, matches, user_id: str) -> List[CorrelationAlert]:
        """Record a list of Match objects directly (without ScanResult wrapper)."""

        class _FakeResult:
            def __init__(self, findings):
                self.findings = findings

        return self.record_scan(_FakeResult(matches), user_id)

    def get_user_stats(self, user_id: str) -> Optional[SessionStats]:
        """Get accumulated stats for a user in the current window."""
        with self._lock:
            return self._user_stats.get(user_id)

    def estimate_total(self, user_id: str, category: str) -> int:
        """Estimate total match count for a user+category in current window."""
        with self._lock:
            return self._cms.estimate(f"{user_id}:{category}")

    def estimate_unique(self, user_id: str) -> int:
        """Estimate unique value count for a user in current window."""
        with self._lock:
            hll = self._hll_per_user.get(user_id)
            return hll.count() if hll else 0

    @property
    def window_seconds(self) -> int:
        return self._window

    @property
    def window_remaining(self) -> float:
        """Seconds remaining in the current window."""
        elapsed = time.time() - self._window_start
        return max(0.0, self._window - elapsed)

    @property
    def total_alerts(self) -> int:
        return self._total_alerts

    @property
    def active_users(self) -> int:
        return len(self._user_stats)

    @property
    def policies(self) -> List[Policy]:
        return list(self._policies)

    def _maybe_rotate_window(self) -> None:
        """Rotate the window if expired — clear all counters."""
        if time.time() - self._window_start >= self._window:
            self._cms.clear()
            self._hll_per_user.clear()
            self._user_stats.clear()
            self._window_start = time.time()
            logger.debug("Session window rotated (every %ds)", self._window)

    def reset(self) -> None:
        """Force-reset all counters and stats."""
        with self._lock:
            self._cms.clear()
            self._hll_per_user.clear()
            self._user_stats.clear()
            self._window_start = time.time()
            self._total_alerts = 0
