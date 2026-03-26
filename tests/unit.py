import unittest
import threading

from dlpscan.scanner import (
    redact_sensitive_info,
    redact_sensitive_info_with_patterns,
    is_luhn_valid,
    enhanced_scan_text,
    scan_for_context,
    MAX_INPUT_SIZE,
    MAX_MATCHES,
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

    def test_redact_preserves_slashes(self):
        result = redact_sensitive_info('123/45/6789')
        self.assertEqual(result, 'XXX/XX/XXXX')

    def test_redact_preserves_en_dash(self):
        result = redact_sensitive_info('123\u201345\u20136789')
        self.assertEqual(result, 'XXX\u2013XX\u2013XXXX')

    def test_redact_preserves_underscore(self):
        result = redact_sensitive_info('123_45_6789')
        self.assertEqual(result, 'XXX_XX_XXXX')

    def test_redact_short_input(self):
        with self.assertRaises(ShortInputError):
            redact_sensitive_info('123')

    def test_redact_empty_input(self):
        with self.assertRaises(EmptyInputError):
            redact_sensitive_info('')

    def test_redact_none_input(self):
        with self.assertRaises(EmptyInputError):
            redact_sensitive_info(None)

    def test_redact_non_string_raises(self):
        with self.assertRaises(TypeError):
            redact_sensitive_info(12345678)

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
        categories_found = {r[3] for r in results}
        self.assertNotIn('Contact Information', categories_found)

    def test_require_context_filters(self):
        text = "The number is 4532015112830366"
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

    def test_tuple_has_four_elements(self):
        """Verify the yield tuple is (text, sub_category, has_context, category)."""
        text = "My credit card number is 4532015112830366"
        results = list(enhanced_scan_text(text))
        for r in results:
            self.assertEqual(len(r), 4, f"Expected 4-element tuple, got {len(r)}: {r}")

    def test_max_matches_limit(self):
        """Verify that max_matches caps the number of results."""
        text = "email: a@b.com, b@c.com, c@d.com, d@e.com, e@f.com"
        results = list(enhanced_scan_text(text, categories={'Contact Information'}, max_matches=2))
        self.assertLessEqual(len(results), 2)

    def test_empty_categories_scans_nothing(self):
        """Passing an empty set should scan nothing and return no results."""
        text = "My credit card is 4532015112830366"
        results = list(enhanced_scan_text(text, categories=set()))
        self.assertEqual(len(results), 0)

    def test_nonexistent_category_returns_empty(self):
        """An unknown category silently returns no results."""
        text = "My credit card is 4532015112830366"
        results = list(enhanced_scan_text(text, categories={'DoesNotExist'}))
        self.assertEqual(len(results), 0)


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

    def test_non_string_text_raises(self):
        with self.assertRaises(TypeError):
            scan_for_context(12345, 0, 4, 'Credit Card Numbers', 'Visa')

    def test_negative_index_raises(self):
        with self.assertRaises(ValueError):
            scan_for_context("some text", -1, 4, 'Credit Card Numbers', 'Visa')

    def test_end_exceeds_length_raises(self):
        with self.assertRaises(ValueError):
            scan_for_context("short", 0, 100, 'Credit Card Numbers', 'Visa')

    def test_start_exceeds_end_raises(self):
        with self.assertRaises(ValueError):
            scan_for_context("some text", 5, 3, 'Credit Card Numbers', 'Visa')

    def test_context_found_after_match(self):
        text = "4532015112830366 is my credit card"
        result = scan_for_context(text, 0, 16, 'Credit Card Numbers', 'Visa')
        self.assertTrue(result)

    def test_match_at_start_of_text(self):
        text = "credit card 4532015112830366"
        result = scan_for_context(text, 12, 28, 'Credit Card Numbers', 'Visa')
        self.assertTrue(result)


class TestRegionalPatterns(unittest.TestCase):
    """Test that regional patterns detect known-format IDs."""

    def test_detects_uk_nhs(self):
        text = "NHS number is 943 476 5919"
        results = list(enhanced_scan_text(text, categories={'Europe - United Kingdom'}))
        nhs = [r for r in results if r[1] == 'British NHS']
        self.assertTrue(len(nhs) > 0)

    def test_detects_canada_sin(self):
        text = "My SIN is 046-454-286"
        results = list(enhanced_scan_text(text, categories={'North America - Canada'}))
        sin = [r for r in results if r[1] == 'Canada SIN']
        self.assertTrue(len(sin) > 0)

    def test_detects_india_aadhaar(self):
        text = "Aadhaar number: 2345 6789 0123"
        results = list(enhanced_scan_text(text, categories={'Asia-Pacific - India'}))
        aadhaar = [r for r in results if r[1] == 'India Aadhaar']
        self.assertTrue(len(aadhaar) > 0)

    def test_detects_brazil_cpf(self):
        text = "CPF: 123.456.789-09"
        results = list(enhanced_scan_text(text, categories={'Latin America - Brazil'}))
        cpf = [r for r in results if r[1] == 'Brazil CPF']
        self.assertTrue(len(cpf) > 0)

    def test_detects_iban(self):
        text = "IBAN: DE89370400440532013000"
        results = list(enhanced_scan_text(text, categories={'Banking and Financial'}))
        iban = [r for r in results if r[1] == 'IBAN Generic']
        self.assertTrue(len(iban) > 0)

    def test_detects_swift(self):
        text = "SWIFT code: DEUTDEFF500"
        results = list(enhanced_scan_text(text, categories={'Banking and Financial'}))
        swift = [r for r in results if r[1] == 'SWIFT/BIC']
        self.assertTrue(len(swift) > 0)


class TestSecrets(unittest.TestCase):
    """Test detection of API keys and tokens."""

    def test_detects_github_token(self):
        text = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        results = list(enhanced_scan_text(text))
        gh = [r for r in results if 'GitHub' in r[1]]
        self.assertTrue(len(gh) > 0)

    def test_detects_jwt(self):
        text = "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        results = list(enhanced_scan_text(text))
        jwt = [r for r in results if r[1] == 'JWT Token']
        self.assertTrue(len(jwt) > 0)

    def test_detects_stripe_key(self):
        # Build the test key dynamically to avoid GitHub push protection
        prefix = 'sk' + '_' + 'live' + '_'
        key = prefix + 'A' * 24
        text = f"stripe key: {key}"
        results = list(enhanced_scan_text(text))
        stripe = [r for r in results if r[1] == 'Stripe Secret Key']
        self.assertTrue(len(stripe) > 0)


class TestFalsePositiveReduction(unittest.TestCase):
    """Verify that tightened patterns don't match normal text."""

    def test_plain_sentence_no_matches(self):
        text = "The quick brown fox jumps over the lazy dog."
        results = list(enhanced_scan_text(text))
        self.assertEqual(len(results), 0)

    def test_ticker_requires_dollar_sign(self):
        """Ticker should require $ prefix to avoid matching random uppercase words."""
        text = "The AAPL stock rose today"
        results = list(enhanced_scan_text(text, categories={'Securities Identifiers'}))
        ticker = [r for r in results if r[1] == 'Ticker Symbol']
        self.assertEqual(len(ticker), 0)

    def test_ticker_with_dollar_sign(self):
        text = "Buy $AAPL at current price"
        results = list(enhanced_scan_text(text, categories={'Securities Identifiers'}))
        ticker = [r for r in results if r[1] == 'Ticker Symbol']
        self.assertTrue(len(ticker) > 0)

    def test_short_number_not_matched_as_sensitive(self):
        """Simple numbers like '42' or '100' should not trigger matches in tightened patterns."""
        text = "There are 42 items and 100 people."
        results = list(enhanced_scan_text(text, categories={'Customer Financial Data'}))
        # Credit Score was removed (too broad), so this should be empty
        self.assertEqual(len(results), 0)


class TestDelimiterHandling(unittest.TestCase):
    """Verify that multi-group patterns handle various delimiters."""

    def test_ssn_with_slash(self):
        text = "SSN: 123/45/6789"
        results = list(enhanced_scan_text(text, categories={'North America - United States'}))
        ssn = [r for r in results if r[1] == 'USA SSN']
        self.assertTrue(len(ssn) > 0)

    def test_ssn_with_underscore(self):
        text = "SSN: 123_45_6789"
        results = list(enhanced_scan_text(text, categories={'North America - United States'}))
        ssn = [r for r in results if r[1] == 'USA SSN']
        self.assertTrue(len(ssn) > 0)

    def test_credit_card_with_spaces(self):
        text = "credit card 4532 0151 1283 0366"
        results = list(enhanced_scan_text(text, categories={'Credit Card Numbers'}))
        visa = [r for r in results if r[1] == 'Visa']
        self.assertTrue(len(visa) > 0)

    def test_redact_preserves_original_delimiter(self):
        self.assertEqual(redact_sensitive_info('123/45/6789'), 'XXX/XX/XXXX')
        self.assertEqual(redact_sensitive_info('123_45_6789'), 'XXX_XX_XXXX')
        self.assertEqual(redact_sensitive_info('123-45-6789'), 'XXX-XX-XXXX')


if __name__ == '__main__':
    unittest.main()
