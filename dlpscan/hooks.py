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
        [--categories CAT ...] [--allowlist PATH] [--format text|json]
        [--baseline PATH]
"""

import argparse
import fnmatch
import json
import logging
import os
import subprocess
import sys

from .scanner import enhanced_scan_text
from .exceptions import RedactionError
from .allowlist import Allowlist

logger = logging.getLogger(__name__)

# Exit codes
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def get_repo_root() -> str:
    """Get the root directory of the current git repository."""
    try:
        result = subprocess.run(
            ['git', 'rev-parse', '--show-toplevel'],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return ''


def load_dlpscanignore(repo_root: str) -> list:
    """Load ignore patterns from a .dlpscanignore file in the repo root.

    The file contains glob patterns, one per line.  Lines starting with
    ``#`` and blank lines are skipped.

    Returns:
        A list of glob pattern strings.
    """
    ignore_path = os.path.join(repo_root, '.dlpscanignore')
    patterns = []
    try:
        with open(ignore_path, 'r') as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith('#'):
                    patterns.append(line)
    except FileNotFoundError:
        pass
    return patterns


def should_ignore_file(filepath: str, ignore_patterns: list) -> bool:
    """Check whether *filepath* matches any of the ignore patterns."""
    for pattern in ignore_patterns:
        if fnmatch.fnmatch(filepath, pattern):
            return True
    return False


def load_baseline(baseline_path: str) -> set:
    """Load a baseline JSON file and return a set of (filename, category, sub_category) tuples.

    The baseline file is expected to be a JSON array of objects, each with
    at least ``filename``, ``category``, and ``sub_category`` keys.
    """
    try:
        with open(baseline_path, 'r') as fh:
            data = json.load(fh)
        return {
            (entry['filename'], entry['category'], entry['sub_category'])
            for entry in data
        }
    except (FileNotFoundError, json.JSONDecodeError, KeyError, TypeError) as exc:
        logger.error("Failed to load baseline file %s: %s", baseline_path, exc)
        return set()


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


def format_findings_text(findings: list) -> str:
    """Format findings as human-readable text."""
    lines = []
    lines.append(f"\n{'='*60}")
    lines.append(f"dlpscan: {len(findings)} potential sensitive data match(es) found")
    lines.append(f"{'='*60}\n")

    for filename, line_no, m in findings:
        lines.append(f"  {filename}:{line_no}")
        lines.append(f"    [{m.category} > {m.sub_category}] "
                      f"confidence: {m.confidence:.0%}")
        redacted = m.text[:3] + '...' + m.text[-3:] if len(m.text) > 8 else '***'
        lines.append(f"    matched: {redacted}")
        lines.append('')

    lines.append("To commit anyway, use: git commit --no-verify")
    lines.append('')
    return '\n'.join(lines)


def format_findings_json(findings: list) -> str:
    """Format findings as JSON for CI integration."""
    records = []
    for filename, line_no, m in findings:
        records.append({
            'filename': filename,
            'line': line_no,
            'category': m.category,
            'sub_category': m.sub_category,
            'confidence': m.confidence,
            'matched': m.text[:3] + '...' + m.text[-3:] if len(m.text) > 8 else '***',
        })
    return json.dumps(records, indent=2)


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
    parser.add_argument(
        '--categories', nargs='+', default=None,
        help='Space-separated category names to restrict scanning to.',
    )
    parser.add_argument(
        '--allowlist', default=None, dest='allowlist_path',
        help='Path to a JSON allowlist file for filtering matches.',
    )
    parser.add_argument(
        '--format', choices=['text', 'json'], default='text',
        dest='output_format',
        help='Output format: text (default) or json for CI integration.',
    )
    parser.add_argument(
        '--baseline', default=None,
        help='Path to a JSON baseline file of known findings to ignore.',
    )
    args = parser.parse_args()

    try:
        # Load allowlist if provided.
        allowlist = None
        if args.allowlist_path:
            try:
                with open(args.allowlist_path, 'r') as fh:
                    allowlist_config = json.load(fh)
                allowlist = Allowlist.from_config(allowlist_config)
            except (FileNotFoundError, json.JSONDecodeError, TypeError) as exc:
                print(f"dlpscan: error loading allowlist: {exc}", file=sys.stderr)
                sys.exit(EXIT_ERROR)

        # Load baseline if provided.
        baseline = set()
        if args.baseline:
            baseline = load_baseline(args.baseline)
            if args.baseline and not baseline:
                # File was specified but could not be loaded — warn but continue.
                logger.warning("Baseline file specified but no entries loaded.")

        # Load .dlpscanignore patterns.
        repo_root = get_repo_root()
        ignore_patterns = load_dlpscanignore(repo_root) if repo_root else []

        # Determine categories filter (as a set for fast lookup).
        categories_filter = set(args.categories) if args.categories else None

        diff = get_staged_diff()
        if not diff:
            sys.exit(EXIT_CLEAN)

        added_lines = extract_added_lines(diff)
        if not added_lines:
            sys.exit(EXIT_CLEAN)

        findings = []

        for filename, line_no, line_text in added_lines:
            if not line_text.strip():
                continue

            # Skip files matching .dlpscanignore patterns.
            if filename and should_ignore_file(filename, ignore_patterns):
                continue

            try:
                matches = list(enhanced_scan_text(
                    line_text,
                    require_context=args.require_context,
                    deduplicate=True,
                ))
            except (RedactionError, TypeError, ValueError):
                continue

            # Apply category filter.
            if categories_filter:
                matches = [m for m in matches if m.category in categories_filter]

            # Apply allowlist filtering.
            if allowlist:
                matches = allowlist.filter_matches(matches)

            for m in matches:
                if m.confidence >= args.min_confidence:
                    # Skip findings present in the baseline.
                    if baseline and (filename, m.category, m.sub_category) in baseline:
                        continue
                    findings.append((filename, line_no, m))

        if not findings:
            sys.exit(EXIT_CLEAN)

        if args.output_format == 'json':
            print(format_findings_json(findings))
        else:
            print(format_findings_text(findings))

        sys.exit(EXIT_FINDINGS)

    except Exception as exc:
        print(f"dlpscan: unexpected error: {exc}", file=sys.stderr)
        sys.exit(EXIT_ERROR)


if __name__ == '__main__':
    main()
