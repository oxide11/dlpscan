import unittest

from dlpscan.scanner import redact_sensitive_info, is_luhn_valid, enhanced_scan_text
from dlpscan.exceptions import EmptyInputError, ShortInputError, InvalidCardNumberError


class TestRedactSensitiveInfo(unittest.TestCase):
    def test_redact_basic(self):
        result = redact_sensitive_info('12345678')
        self.assertEqual(result, 'XXXXXXXX')

    def test_redact_preserves_separators(self):
        result = redact_sensitive_info('123-456-789')
        self.assertEqual(result, 'XXX-XXX-XXX')

    def test_redact_preserves_spaces(self):
        result = redact_sensitive_info('1234 5678')
        self.assertEqual(result, 'XXXX XXXX')

    def test_redact_short_input(self):
        with self.assertRaises(ShortInputError):
            redact_sensitive_info('123')

    def test_redact_empty_input(self):
        with self.assertRaises(EmptyInputError):
            redact_sensitive_info('')

    def test_redact_none_input(self):
        with self.assertRaises(EmptyInputError):
            redact_sensitive_info(None)

    def test_redact_custom_char(self):
        result = redact_sensitive_info('12345678', redaction_char='*')
        self.assertEqual(result, '********')


class TestLuhnValidation(unittest.TestCase):
    def test_valid_card(self):
        self.assertTrue(is_luhn_valid('4532015112830366'))

    def test_invalid_card(self):
        self.assertFalse(is_luhn_valid('4532015112830365'))

    def test_valid_card_with_spaces(self):
        self.assertTrue(is_luhn_valid('4532 0151 1283 0366'))

    def test_valid_card_with_hyphens(self):
        self.assertTrue(is_luhn_valid('4532-0151-1283-0366'))

    def test_empty_string(self):
        with self.assertRaises(InvalidCardNumberError):
            is_luhn_valid('')

    def test_only_spaces(self):
        with self.assertRaises(InvalidCardNumberError):
            is_luhn_valid('   ')


class TestEnhancedScanText(unittest.TestCase):
    def test_finds_credit_card_with_context(self):
        text = "My credit card number is 4532015112830366"
        results = list(enhanced_scan_text(text))
        # Should find the Visa number
        visa_results = [r for r in results if r[3] == 'Credit Card Numbers' and r[1] == 'Visa']
        self.assertTrue(len(visa_results) > 0)

    def test_finds_ssn_with_context(self):
        text = "My SSN is 123-45-6789"
        results = list(enhanced_scan_text(text))
        ssn_results = [r for r in results if r[1] == 'USA SSN']
        self.assertTrue(len(ssn_results) > 0)
        # Should have context match
        self.assertTrue(any(r[2] for r in ssn_results))

    def test_finds_email(self):
        text = "Contact email: test@example.com"
        results = list(enhanced_scan_text(text))
        email_results = [r for r in results if r[1] == 'Email Address']
        self.assertTrue(len(email_results) > 0)

    def test_finds_aws_key(self):
        text = "AWS access key: AKIAIOSFODNN7EXAMPLE"
        results = list(enhanced_scan_text(text))
        aws_results = [r for r in results if r[1] == 'AWS Access Key']
        self.assertTrue(len(aws_results) > 0)

    def test_rejects_invalid_credit_card(self):
        text = "credit card 4532015112830365"
        results = list(enhanced_scan_text(text))
        # Invalid Luhn should be filtered out
        visa_results = [r for r in results if r[3] == 'Credit Card Numbers' and r[1] == 'Visa']
        self.assertEqual(len(visa_results), 0)

    def test_no_matches_returns_empty(self):
        text = "This is a normal sentence with no sensitive data."
        results = list(enhanced_scan_text(text))
        self.assertEqual(len(results), 0)


if __name__ == '__main__':
    unittest.main()
