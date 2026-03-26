import argparse
import csv
import io
import json
import sys

from .scanner import enhanced_scan_text, scan_file
from .exceptions import RedactionError


def _format_text(findings):
    """Format findings as human-readable text."""
    if not findings:
        return "No sensitive data detected.\n"
    lines = [f"\nFound {len(findings)} potential match(es):\n"]
    for m in findings:
        ctx = "WITH context" if m.has_context else "no context"
        lines.append(
            f"  [{m.category} > {m.sub_category}] "
            f"'{m.text}' (confidence: {m.confidence:.0%}, {ctx})"
        )
    return '\n'.join(lines) + '\n'


def _format_json(findings):
    """Format findings as JSON."""
    return json.dumps([m.to_dict() for m in findings], indent=2)


def _format_csv(findings, stream):
    """Write findings as CSV to a stream."""
    writer = csv.writer(stream)
    writer.writerow(['text', 'category', 'sub_category', 'has_context',
                      'confidence', 'span_start', 'span_end'])
    for m in findings:
        writer.writerow([m.text, m.category, m.sub_category, m.has_context,
                          m.confidence, m.span[0], m.span[1]])


def main():
    parser = argparse.ArgumentParser(
        prog='dlpscan',
        description='Scan text or files for sensitive data.',
    )
    parser.add_argument(
        'file', nargs='?', default=None,
        help='File to scan. If omitted, reads from stdin or prompts for input.',
    )
    parser.add_argument(
        '-f', '--format', choices=['text', 'json', 'csv'], default='text',
        help='Output format (default: text).',
    )
    parser.add_argument(
        '-c', '--categories', nargs='+', default=None,
        help='Category names to scan (default: all).',
    )
    parser.add_argument(
        '--require-context', action='store_true',
        help='Only report matches with nearby context keywords.',
    )
    parser.add_argument(
        '--no-dedup', action='store_true',
        help='Disable overlap deduplication.',
    )
    parser.add_argument(
        '--min-confidence', type=float, default=0.0,
        help='Minimum confidence threshold (0.0-1.0). Only report matches above this.',
    )
    parser.add_argument(
        '--max-matches', type=int, default=50000,
        help='Maximum number of matches to return.',
    )

    args = parser.parse_args()

    cats = set(args.categories) if args.categories else None
    deduplicate = not args.no_dedup

    try:
        if args.file:
            findings = list(scan_file(
                args.file,
                categories=cats,
                require_context=args.require_context,
                max_matches=args.max_matches,
                deduplicate=deduplicate,
            ))
        elif not sys.stdin.isatty():
            # Piped input
            text = sys.stdin.read()
            if not text.strip():
                print("No input provided.")
                return
            findings = list(enhanced_scan_text(
                text,
                categories=cats,
                require_context=args.require_context,
                max_matches=args.max_matches,
                deduplicate=deduplicate,
            ))
        else:
            # Interactive mode
            try:
                user_input = input("Enter something: ")
            except (EOFError, KeyboardInterrupt):
                print()
                sys.exit(0)
            if not user_input.strip():
                print("No input provided.")
                return
            findings = list(enhanced_scan_text(
                user_input,
                categories=cats,
                require_context=args.require_context,
                max_matches=args.max_matches,
                deduplicate=deduplicate,
            ))
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except (RedactionError, TypeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    # Apply confidence threshold.
    if args.min_confidence > 0:
        findings = [m for m in findings if m.confidence >= args.min_confidence]

    # Output.
    if args.format == 'json':
        print(_format_json(findings))
    elif args.format == 'csv':
        _format_csv(findings, sys.stdout)
    else:
        print(_format_text(findings), end='')


if __name__ == '__main__':
    main()
