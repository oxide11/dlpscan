from dlpscan.scanner import enhanced_scan_text, redact_sensitive_info

# Define the test cases
test_cases = [
    # Include your updated test cases here with the correct format
    # (Text, Description, Expects Pattern Match, Expects Context Match)
    ("My SIN is 123-456-789.", "Canada SIN", True, False),
    ("Found SSN: 987-65-4321 in the text.", "USA SSN", True, False),
    ("Credit card number 4111 1111 1111 1111 is a Visa.", "Visa Credit Card", True, False),
    ("SIN 123 456 789 valid format", "Canada SIN with spaces", True, False),
    ("SSN format 987-65-4321 found", "USA SSN with dashes", True, False),
    ("Invalid SSN 1234-567-89 in text", "Invalid USA SSN format", False, False),
    ("Visa starts with 4: 4111-1111-1111-1111", "Visa with dashes", True, False),
    ("MasterCard format: 5500 0000 0000 0004", "MasterCard with spaces", True, False),
    ("Amex card 340000000000009 in email", "Amex without delimiters", True, False),
    ("Discover: 6011.0000.0000.0004", "Discover with dots", True, False),
    ("Random number: 1234.5678.9101.1121", "Random with dots", False, False),
    ("Ontario Driver's License: A1234-12345-12345", "Ontario DL with dashes", True, False),
    ("BCDL1234567 without spaces", "British Columbia DL without spaces", True, False),
    ("ON Health 1234 567 890 potential match", "Ontario Health Card with spaces", True, False),
    ("Canadian Passport No: AB123456 in form", "Canadian Passport", True, False),
    ("981-FC-234 by non-standard SSN format", "Non-standard SSN", False, False),
    ("Temp SIN used: 919 123 456 in system", "Temporary Canada SIN with spaces", True, False),
    ("Alberta HC 1234567890 found in database", "Alberta Health Card without delimiters", True, False),
    ("PEI DL 1234 5678 during check", "PEI Driver License with spaces", True, False),
    ("Nunavut DL#1234567 expired", "Nunavut Driver License with hash", True, False),
    ("4111111111111111 Visa mentioned", "Visa without delimiter", True, True),
    ("MC Number: 2221-0000-0000-0000", "MasterCard with dashes new series", True, False),
    ("Email contained Amex: 3700 000000 00002", "Amex in email", True, True),
    ("John Doe SSN: 123.45.6789 in record", "USA SSN with dots", True, True),
    ("Random text should not match 9988-7766-5544", "Random text with hyphens", False, False),
    ("Query returned SIN: 123456789", "Canada SIN without delimiters", True, True),
    ("Found Visa 41111111 1111 1111 in log", "Visa with mixed delimiters", True, False),
    ("Invalid MC: 5400222233334444 in file", "Invalid MasterCard", True, False),
    ("Detected Discover card: 6011 1111 1111 1111", "Discover with spaces", True, True),
    ("SSN not found: 999-99-9999 in system", "Invalid SSN format", True, False),
    ("Input: Amex 3777-777777-77777", "Amex with dashes", True, False),
    ("User's MC: 5555555555554444", "MasterCard without delimiters", True, True),
    ("Potential Visa: 4222 2222 2222 2", "Incomplete Visa", False, False),
    ("DL from Manitoba: A123456789012", "Manitoba DL without delimiters", True, False),
    ("SIN match: 130-692-004", "Canada SIN with specific format", True, True),
    ("SSN input: 987.65.4321", "USA SSN with dots format", True, True),
    ("Random ID: 0000-0000-0000-0000", "Random ID with dashes", False, False),
    ("Credit card found: 6011601160116011", "Discover without spaces", True, False),
    ("DL format error: ABCD1234EFGH", "Invalid DL format", False, False),
    ("Health Card: 1234-567-890 Ontario", "Ontario Health Card with dashes", True, True),
    ("Email Amex: 378282246310005", "Amex in email without delimiters", True, True),
    ("Invalid Passport: A12B345C", "Invalid Canadian Passport", False, False),
    ("Found MasterCard: 2223000048400011 in transaction", "MasterCard with spaces new series", True, True),
    ("I'm looking for help with my phone, it's not working!", "Message Statement", False, False),
]


def run_tests():
    for text, description, expects_pattern, expects_context in test_cases:
        print(f"Test: {description}")
        findings = enhanced_scan_text(text)
        
        # Check if any patterns were detected
        pattern_detected = any(findings)
        # Check if any context was detected
        context_detected = any(finding[2] for finding in findings)
        
        # Print matched patterns and redacted text
        if pattern_detected:
            print(" Matched Patterns and Redacted Output:")
            for finding in findings:
                matched_pattern, label, has_context = finding
                print(f"  - Matched: {matched_pattern} | Label: {label} | Context Detected: {has_context}")
                redacted_text = text.replace(matched_pattern, redact_sensitive_info(matched_pattern))
                print(f"  - Redacted Output: {redacted_text}")
        else:
            print(" No patterns detected.")
        
        # Display test status
        pattern_status = "passed" if pattern_detected == expects_pattern else "failed"
        context_status = "passed" if context_detected == expects_context else "failed"
        print(f" Pattern Detection: {pattern_status}")
        print(f" Context Detection: {context_status}\n")

if __name__ == "__main__":
    run_tests()
