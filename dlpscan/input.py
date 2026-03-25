from .scanner import enhanced_scan_text, redact_sensitive_info


def main():
    user_input = input("Enter something: ")
    print("You entered:", user_input)

    findings = list(enhanced_scan_text(user_input))

    if not findings:
        print("No sensitive data detected.")
        return

    print(f"\nFound {len(findings)} potential match(es):\n")
    for match_text, sub_category, has_context, category, _ in findings:
        context_label = "WITH context" if has_context else "no context"
        print(f"  [{category} > {sub_category}] '{match_text}' ({context_label})")


if __name__ == '__main__':
    main()
