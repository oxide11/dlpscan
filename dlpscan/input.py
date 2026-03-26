import argparse
import csv
import json
import os
import sys

from .scanner import enhanced_scan_text, scan_file, scan_directory
from .config import load_config, apply_config_to_args
from .allowlist import Allowlist
from .exceptions import RedactionError, ExtractionError
from .extractors import get_extractor, extract_text
from .pipeline import Pipeline


def _display_text(m, redact=False):
    """Return the matched text or its redacted form."""
    return m.redacted_text if redact else m.text


def _format_text(findings, file_context=False, redact=False):
    """Format findings as human-readable text."""
    if not findings:
        return "No sensitive data detected.\n"
    lines = [f"\nFound {len(findings)} potential match(es):\n"]
    for item in findings:
        if file_context:
            path, m = item
            ctx = "WITH context" if m.has_context else "no context"
            lines.append(
                f"  {path}:{m.span[0]} [{m.category} > {m.sub_category}] "
                f"'{_display_text(m, redact)}' (confidence: {m.confidence:.0%}, {ctx})"
            )
        else:
            m = item
            ctx = "WITH context" if m.has_context else "no context"
            lines.append(
                f"  [{m.category} > {m.sub_category}] "
                f"'{_display_text(m, redact)}' (confidence: {m.confidence:.0%}, {ctx})"
            )
    return '\n'.join(lines) + '\n'


def _format_json(findings, file_context=False, redact=False):
    """Format findings as JSON."""
    if file_context:
        return json.dumps(
            [{'file': path, **m.to_dict(redact=redact)} for path, m in findings],
            indent=2,
        )
    return json.dumps([m.to_dict(redact=redact) for m in findings], indent=2)


def _format_csv(findings, stream, file_context=False, redact=False):
    """Write findings as CSV to a stream."""
    writer = csv.writer(stream)
    if file_context:
        writer.writerow(['file', 'text', 'category', 'sub_category', 'has_context',
                          'confidence', 'span_start', 'span_end'])
        for path, m in findings:
            writer.writerow([path, _display_text(m, redact), m.category, m.sub_category,
                              m.has_context, m.confidence, m.span[0], m.span[1]])
    else:
        writer.writerow(['text', 'category', 'sub_category', 'has_context',
                          'confidence', 'span_start', 'span_end'])
        for m in findings:
            writer.writerow([_display_text(m, redact), m.category, m.sub_category,
                              m.has_context, m.confidence, m.span[0], m.span[1]])


def _format_sarif(findings, file_context=False):
    """Format findings as SARIF 2.1.0 JSON.

    SARIF (Static Analysis Results Interchange Format) is the industry
    standard for security tool output.  Supported by GitHub Code Scanning,
    Azure DevOps, and many other platforms.

    Note: SARIF output never includes matched text (safe by design).
    """
    # Build unique rule set from findings.
    rules_map = {}
    results = []

    items = findings
    for item in items:
        if file_context:
            path, m = item
        else:
            m = item
            path = None

        rule_id = f"dlpscan/{m.category}/{m.sub_category}".replace(' ', '-')

        if rule_id not in rules_map:
            rules_map[rule_id] = {
                'id': rule_id,
                'name': m.sub_category,
                'shortDescription': {
                    'text': f"Detects {m.sub_category} patterns",
                },
                'properties': {
                    'category': m.category,
                },
            }

        # Build result entry.
        result_entry = {
            'ruleId': rule_id,
            'level': 'warning' if m.confidence >= 0.5 else 'note',
            'message': {
                'text': f"Potential {m.sub_category} detected "
                        f"(confidence: {m.confidence:.0%})",
            },
            'properties': {
                'confidence': m.confidence,
                'has_context': m.has_context,
            },
        }

        if path:
            result_entry['locations'] = [{
                'physicalLocation': {
                    'artifactLocation': {'uri': path},
                    'region': {
                        'charOffset': m.span[0],
                        'charLength': m.span[1] - m.span[0],
                    },
                },
            }]

        results.append(result_entry)

    sarif = {
        '$schema': 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json',
        'version': '2.1.0',
        'runs': [{
            'tool': {
                'driver': {
                    'name': 'dlpscan',
                    'informationUri': 'https://github.com/oxide11/dlpscan',
                    'rules': list(rules_map.values()),
                },
            },
            'results': results,
        }],
    }

    return json.dumps(sarif, indent=2)


def main():
    parser = argparse.ArgumentParser(
        prog='dlpscan',
        description='Scan text or files for sensitive data.',
    )
    parser.add_argument(
        'file', nargs='?', default=None,
        help='File or directory to scan. If omitted, reads from stdin or prompts for input.',
    )
    parser.add_argument(
        '-f', '--format', choices=['text', 'json', 'csv', 'sarif'], default='text',
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
    parser.add_argument(
        '--config', default=None,
        help='Path to config file (pyproject.toml or .dlpscanrc).',
    )
    parser.add_argument(
        '--redact', action='store_true', default=False,
        help='Redact matched text in output (shows first/last 3 chars only). '
             'Recommended for production use.',
    )

    args = parser.parse_args()

    # Load config and apply as defaults.
    config = load_config(path=args.config)
    apply_config_to_args(config, args)

    # Build allowlist from config.
    allowlist = Allowlist.from_config(config)

    cats = set(args.categories) if args.categories else None
    deduplicate = not args.no_dedup
    redact = args.redact
    file_context = False

    try:
        if args.file and os.path.isdir(args.file):
            # Directory scanning via pipeline (handles all formats).
            file_context = True
            with Pipeline(
                categories=cats,
                require_context=args.require_context,
                min_confidence=args.min_confidence,
                deduplicate=deduplicate,
                allowlist=allowlist or None,
            ) as pipe:
                results = pipe.process_directory(args.file)
            findings = []
            for r in results:
                if r.success:
                    rel = os.path.relpath(r.file_path, args.file)
                    for m in r.matches:
                        findings.append((rel, m))
                elif r.error:
                    print(f"Warning: {r.file_path}: {r.error}", file=sys.stderr)

        elif args.file and get_extractor(args.file) is not None:
            # Binary format file — route through pipeline extractor.
            with Pipeline(
                categories=cats,
                require_context=args.require_context,
                min_confidence=args.min_confidence,
                deduplicate=deduplicate,
                allowlist=allowlist or None,
            ) as pipe:
                result = pipe.process_file(args.file)
            if not result.success:
                print(f"Error: {result.error}", file=sys.stderr)
                sys.exit(1)
            findings = result.matches

        elif args.file:
            # Plain text file scanning (legacy path).
            raw = list(scan_file(
                args.file,
                categories=cats,
                require_context=args.require_context,
                max_matches=args.max_matches,
                deduplicate=deduplicate,
            ))
            findings = allowlist.filter_matches(raw) if allowlist else raw

        elif not sys.stdin.isatty():
            # Piped input.
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
            findings = allowlist.filter_matches(findings) if allowlist else findings

        else:
            # Interactive mode.
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
            findings = allowlist.filter_matches(findings) if allowlist else findings

    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except (RedactionError, ExtractionError, TypeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    # Apply confidence threshold.
    if args.min_confidence > 0:
        if file_context:
            findings = [(p, m) for p, m in findings if m.confidence >= args.min_confidence]
        else:
            findings = [m for m in findings if m.confidence >= args.min_confidence]

    # Output.
    if args.format == 'json':
        print(_format_json(findings, file_context=file_context, redact=redact))
    elif args.format == 'csv':
        _format_csv(findings, sys.stdout, file_context=file_context, redact=redact)
    elif args.format == 'sarif':
        print(_format_sarif(findings, file_context=file_context))
    else:
        print(_format_text(findings, file_context=file_context, redact=redact), end='')


if __name__ == '__main__':
    main()
