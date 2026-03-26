"""Allowlist and ignore rules for suppressing known false positives.

Supports three ignore mechanisms:
    1. allowlist — exact matched text values to skip
    2. ignore_patterns — sub_category names to skip entirely
    3. ignore_paths — file path globs to skip in directory scanning

Usage::

    from dlpscan.allowlist import Allowlist

    al = Allowlist(
        texts=['test@example.com', 'AKIAIOSFODNN7EXAMPLE'],
        patterns=['Gender Marker', 'Hashtag'],
        paths=['*.md', 'tests/**'],
    )

    # Filter scan results
    filtered = al.filter_matches(matches)

    # Check if a file path should be skipped
    al.should_skip_path('tests/unit.py')  # True

Inline suppression:
    Lines containing ``# dlpscan:ignore`` are skipped during scanning.
"""

import fnmatch
from typing import Iterable, List, Optional, Set

from .models import Match


class Allowlist:
    """Filter for suppressing known matches and paths."""

    def __init__(
        self,
        texts: Optional[List[str]] = None,
        patterns: Optional[List[str]] = None,
        paths: Optional[List[str]] = None,
    ):
        """Initialize the allowlist.

        Args:
            texts: Exact matched text values to ignore.
            patterns: Sub-category names to skip entirely.
            paths: File path glob patterns to skip in directory scanning.
        """
        self.texts: Set[str] = set(texts) if texts else set()
        self.patterns: Set[str] = set(patterns) if patterns else set()
        self.paths: List[str] = list(paths) if paths else []

    @classmethod
    def from_config(cls, config: dict) -> 'Allowlist':
        """Create an Allowlist from a config dictionary."""
        return cls(
            texts=config.get('allowlist', []),
            patterns=config.get('ignore_patterns', []),
            paths=config.get('ignore_paths', []),
        )

    def is_allowed(self, match: Match) -> bool:
        """Check if a match should be suppressed.

        Returns True if the match should be KEPT (not suppressed).
        """
        if match.text in self.texts:
            return False
        if match.sub_category in self.patterns:
            return False
        return True

    def filter_matches(self, matches: Iterable[Match]) -> List[Match]:
        """Filter a list of matches, removing suppressed ones."""
        return [m for m in matches if self.is_allowed(m)]

    def should_skip_path(self, path: str) -> bool:
        """Check if a file path should be skipped.

        Args:
            path: Relative or absolute file path to check.

        Returns:
            True if the path matches any ignore_paths glob.
        """
        for pattern in self.paths:
            if fnmatch.fnmatch(path, pattern):
                return True
        return False

    def __bool__(self) -> bool:
        """True if any rules are configured."""
        return bool(self.texts or self.patterns or self.paths)


def has_inline_ignore(line: str) -> bool:
    """Check if a line contains an inline dlpscan:ignore directive.

    Supports:
        some_text  # dlpscan:ignore
        some_text  // dlpscan:ignore
        some_text  -- dlpscan:ignore
    """
    return 'dlpscan:ignore' in line
