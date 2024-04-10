import unittest

# Place the revised redact_sensitive_info function here
def redact_sensitive_info(match, redaction_char='X'):
    # Make sure the match string is not None or Empty
    if not match:
        raise ValueError("Input string cannot be None or Empty.")

    # Check for non-printable characters in the input
    if any(not c.isprintable() for c in match):
        raise ValueError("Input contains non-printable characters.")
    
    cleaned_match = ''.join(c for c in match if c.isprintable())
    
    if len(cleaned_match) < 4:
        raise ValueError("Input string must have at least 4 printable characters.")
    
    return redaction_char * (len(cleaned_match) - 4) + cleaned_match[-4:]


# Place the revised is_luhn_valid function here
def is_luhn_valid(card_number: str) -> bool:
    # Check for non-digit characters
    if not all(char.isdigit() or char in " -" for char in card_number):
        raise ValueError("Card number must contain only digits, spaces, or hyphens.")

    # Remove any non-digit characters like spaces or hyphens
    sanitized_card_number = ''.join(filter(str.isdigit, card_number))
    
    # Check that the sanitized card number is not just an empty string.
    if not sanitized_card_number:
        raise ValueError("Card number must not be empty after removing spaces and hyphens.")
    
    num_sum = sum(int(digit) if (idx + 1) % 2 else (int(digit) * 2 - 9) if (int(digit) * 2 > 9)
                  else int(digit) * 2 for idx, digit in enumerate(reversed(sanitized_card_number)))

    return num_sum % 10 == 0


    
class TestRedactionAndValidation(unittest.TestCase):
    def test_redact_basic(self):
        self.assertEqual(redact_sensitive_info('12345678'), 'XXXX5678')

    def test_redact_short_input(self):
        with self.assertRaises(ValueError):
            redact_sensitive_info('123')

    def test_redact_empty_input(self):
        with self.assertRaises(ValueError):
            redact_sensitive_info('')

    def test_redact_control_characters(self):
        with self.assertRaises(ValueError):
            redact_sensitive_info('\x00\x02\x03\x04test')  # Input with non-printable chars
    
    def test_luhn_valid_card(self):
        self.assertTrue(is_luhn_valid('4532015112830366'))

    def test_luhn_invalid_card(self):
        self.assertFalse(is_luhn_valid('4532015112830365'))

    def test_luhn_non_digit_characters(self):
        with self.assertRaises(ValueError):
            is_luhn_valid('4532-0151x1283-0366')

    def test_luhn_empty_string(self):
        with self.assertRaises(ValueError):
            is_luhn_valid('')
            
    def test_luhn_spaces_and_hyphens(self):
        self.assertTrue(is_luhn_valid('4532 0151 1283 0366'))  # Spaces are allowed but sanitized

if __name__ == '__main__':
    unittest.main()
