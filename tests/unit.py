import unittest

from dlpscan.scanner import (
    redact_sensitive_info,
    redact_sensitive_info_with_patterns,
    is_luhn_valid,
    enhanced_scan_text,
    scan_for_context,
    MAX_INPUT_SIZE,
)
from dlpscan.exceptions import (
    EmptyInputError,
    ShortInputError,
    InvalidCardNumberError,
    SubCategoryNotFoundError,
)


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

    def test_redact_invalid_char_length(self):
        with self.assertRaises(ValueError):
            redact_sensitive_info('12345678', redaction_char='XX')


class TestRedactWithPatterns(unittest.TestCase):
    def test_redacts_email_in_text(self):
        text = "Contact us at test@example.com for help."
        result = redact_sensitive_info_with_patterns(text, 'Contact Information', 'Email Address')
        self.assertNotIn('test@example.com', result)
        self.assertIn('for help.', result)

    def test_regex_sub_not_string_replace(self):
        # Ensure we use regex sub, not str.replace — "1234" as non-match should survive
        text = "Call 1234 or email test@example.com"
        result = redact_sensitive_info_with_patterns(text, 'Contact Information', 'Email Address')
        self.assertIn('1234', result)
        self.assertNotIn('test@example.com', result)

    def test_invalid_category_raises(self):
        with self.assertRaises(SubCategoryNotFoundError):
            redact_sensitive_info_with_patterns("text", 'Nonexistent', 'Nothing')

    def test_none_input_raises(self):
        with self.assertRaises(EmptyInputError):
            redact_sensitive_info_with_patterns(None, 'Contact Information', 'Email Address')

    def test_non_string_raises(self):
        with self.assertRaises(TypeError):
            redact_sensitive_info_with_patterns(12345, 'Contact Information', 'Email Address')


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

    def test_non_string_raises(self):
        with self.assertRaises(InvalidCardNumberError):
            is_luhn_valid(4532015112830366)


class TestEnhancedScanText(unittest.TestCase):
    def test_finds_credit_card_with_context(self):
        text = "My credit card number is 4532015112830366"
        results = list(enhanced_scan_text(text))
        visa_results = [r for r in results if r[3] == 'Credit Card Numbers' and r[1] == 'Visa']
        self.assertTrue(len(visa_results) > 0)

    def test_finds_ssn_with_context(self):
        text = "My SSN is 123-45-6789"
        results = list(enhanced_scan_text(text))
        ssn_results = [r for r in results if r[1] == 'USA SSN']
        self.assertTrue(len(ssn_results) > 0)
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
        visa_results = [r for r in results if r[3] == 'Credit Card Numbers' and r[1] == 'Visa']
        self.assertEqual(len(visa_results), 0)

    def test_no_matches_returns_empty(self):
        text = "This is a normal sentence with no sensitive data."
        results = list(enhanced_scan_text(text))
        self.assertEqual(len(results), 0)

    def test_none_input_raises(self):
        with self.assertRaises(EmptyInputError):
            list(enhanced_scan_text(None))

    def test_non_string_raises(self):
        with self.assertRaises(TypeError):
            list(enhanced_scan_text(12345))

    def test_empty_string_raises(self):
        with self.assertRaises(EmptyInputError):
            list(enhanced_scan_text(''))

    def test_oversized_input_raises(self):
        with self.assertRaises(ValueError):
            list(enhanced_scan_text('x' * (MAX_INPUT_SIZE + 1)))

    def test_category_filter(self):
        text = "My credit card is 4532015112830366 and email is test@example.com"
        results = list(enhanced_scan_text(text, categories={'Credit Card Numbers'}))
        # Should find credit card but not email
        categories_found = {r[3] for r in results}
        self.assertNotIn('Contact Information', categories_found)

    def test_require_context_filters(self):
        text = "The number is 4532015112830366"
        # Without context keyword "credit card", require_context should filter
        results_all = list(enhanced_scan_text(text))
        results_ctx = list(enhanced_scan_text(text, require_context=True))
        self.assertTrue(len(results_ctx) <= len(results_all))

    def test_classification_label_detection(self):
        text = "This document contains Confidential Supervisory Information"
        results = list(enhanced_scan_text(text))
        csi = [r for r in results if r[1] == 'CSI']
        self.assertTrue(len(csi) > 0)

    def test_privileged_info_detection(self):
        text = "This memo is Attorney-Client Privileged and Confidential"
        results = list(enhanced_scan_text(text))
        priv = [r for r in results if r[3] == 'Privileged Information']
        self.assertTrue(len(priv) > 0)


class TestScanForContext(unittest.TestCase):
    def test_context_found_before_match(self):
        text = "My credit card number is 4532015112830366"
        result = scan_for_context(text, 25, 41, 'Credit Card Numbers', 'Visa')
        self.assertTrue(result)

    def test_no_context_returns_false(self):
        text = "Random text 4532015112830366 more text"
        result = scan_for_context(text, 12, 28, 'Credit Card Numbers', 'Visa')
        self.assertFalse(result)

    def test_missing_category_returns_false(self):
        result = scan_for_context("text", 0, 4, 'Nonexistent', 'Nothing')
        self.assertFalse(result)


if __name__ == '__main__':
    unittest.main()
