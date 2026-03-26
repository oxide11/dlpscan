#!/usr/bin/env python3
"""Pre-commit hook for scanning staged git diffs for sensitive data.

Install:
    # Option 1: Copy to .git/hooks/
    cp dlpscan/hooks.py .git/hooks/pre-commit
    chmod +x .git/hooks/pre-commit

    # Option 2: Use as a pre-commit framework hook (.pre-commit-config.yaml):
    repos:
      - repo: local
        hooks:
          - id: dlpscan
            name: dlpscan
            entry: python -m dlpscan.hooks
            language: python
            stages: [commit]

Usage:
    python -m dlpscan.hooks [--min-confidence 0.5] [--require-context]
"""

import argparse
import logging
import subprocess
import sys

from .scanner import enhanced_scan_text
from .exceptions import RedactionError

logger = logging.getLogger(__name__)


def get_staged_diff() -> str:
    """Get the staged diff from git."""
    try:
        result = subprocess.run(
            ['git', 'diff', '--cached', '--diff-filter=ACMR', '-U0'],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            logger.debug("git diff exited with code %d: %s",
                         result.returncode, result.stderr.strip())
            return ''
        return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        logger.debug("Could not run git diff: %s", exc)
        return ''


def extract_added_lines(diff: str) -> list:
    """Extract added lines from a unified diff, with file context.

    Returns list of (filename, line_number, line_text) tuples.
    """
    import re

    _HUNK_RE = re.compile(r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@')

    added = []
    current_file = None
    current_line = 0

    for line in diff.splitlines():
        if line.startswith('+++ b/'):
            current_file = line[6:]
        elif line.startswith('@@'):
            m = _HUNK_RE.match(line)
            if m:
                current_line = int(m.group(1))
            else:
                current_line = 0
        elif line.startswith('+') and not line.startswith('+++'):
            added.append((current_file, current_line, line[1:]))
            current_line += 1
        elif not line.startswith('-'):
            current_line += 1

    return added


def main():
    parser = argparse.ArgumentParser(
        description='Scan staged git changes for sensitive data.',
    )
    parser.add_argument(
        '--min-confidence', type=float, default=0.5,
        help='Minimum confidence to report (default: 0.5).',
    )
    parser.add_argument(
        '--require-context', action='store_true',
        help='Only report matches with context keywords nearby.',
    )
    args = parser.parse_args()

    diff = get_staged_diff()
    if not diff:
        sys.exit(0)

    added_lines = extract_added_lines(diff)
    if not added_lines:
        sys.exit(0)

    findings = []

    for filename, line_no, line_text in added_lines:
        if not line_text.strip():
            continue

        try:
            matches = list(enhanced_scan_text(
                line_text,
                require_context=args.require_context,
                deduplicate=True,
            ))
        except (RedactionError, TypeError, ValueError):
            continue

        for m in matches:
            if m.confidence >= args.min_confidence:
                findings.append((filename, line_no, m))

    if not findings:
        sys.exit(0)

    print(f"\n{'='*60}")
    print(f"dlpscan: {len(findings)} potential sensitive data match(es) found")
    print(f"{'='*60}\n")

    for filename, line_no, m in findings:
        print(f"  {filename}:{line_no}")
        print(f"    [{m.category} > {m.sub_category}] "
              f"confidence: {m.confidence:.0%}")
        # Show redacted match text for safety.
        redacted = m.text[:3] + '...' + m.text[-3:] if len(m.text) > 8 else '***'
        print(f"    matched: {redacted}")
        print()

    print("To commit anyway, use: git commit --no-verify")
    print()
    sys.exit(1)


if __name__ == '__main__':
    main()
