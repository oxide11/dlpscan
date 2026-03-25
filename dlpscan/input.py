import sys

from .scanner import enhanced_scan_text
from .exceptions import RedactionError


def main():
    try:
        user_input = input("Enter something: ")
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)

    if not user_input.strip():
        print("No input provided.")
        return

    try:
        findings = list(enhanced_scan_text(user_input))
    except (RedactionError, TypeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    if not findings:
        print("No sensitive data detected.")
        return

    print(f"\nFound {len(findings)} potential match(es):\n")
    for match_text, sub_category, has_context, category, _ in findings:
        context_label = "WITH context" if has_context else "no context"
        print(f"  [{category} > {sub_category}] '{match_text}' ({context_label})")


if __name__ == '__main__':
    main()
