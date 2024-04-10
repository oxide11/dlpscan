# dlpscan

`dlpscan` is a Python package designed to scan texts for sensitive information like Social Insurance Numbers (SIN), Social Security Numbers (SSN), credit card numbers, and more, providing tools for redacting or highlighting this information for privacy and data protection.

## Installation

To install `dlpscan`, simply use pip:

```bash
pip install dlpscan

from dlpscan.scanner import enhanced_scan_text

text_to_scan = "My SIN is 123-456-789 and my credit card number is 4111 1111 1111 1111."
redacted_text = enhanced_scan_text(text_to_scan)
print(redacted_text)
