from scanner import enhanced_scan_text, redact_sensitive_info

user_input = input("Enter something: ")
print("You entered : ", user_input)

findings = enhanced_scan_text(user_input)
# Check if any patterns were detected
pattern_detected = any(findings)
# Check if any context was detected
context_detected = any(finding[2] for finding in findings)

print("Pattern Detected : ", pattern_detected)
print("Context Detected : ", context_detected)