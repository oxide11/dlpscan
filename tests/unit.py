import io
import os
import re
import tempfile
import unittest

from dlpscan.scanner import (
    redact_sensitive_info,
    redact_sensitive_info_with_patterns,
    is_luhn_valid,
    enhanced_scan_text,
    scan_for_context,
    scan_file,
    scan_stream,
    register_patterns,
    unregister_patterns,
    MAX_INPUT_SIZE,
    MAX_MATCHES,
)
from dlpscan.models import Match, CONTEXT_REQUIRED_PATTERNS
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
        """Match objects support 4-element tuple unpacking for backward compat."""
        text = "My credit card number is 4532015112830366"
        results = list(enhanced_scan_text(text))
        for r in results:
            self.assertEqual(len(r), 4, f"Expected 4-element tuple, got {len(r)}: {r}")

    def test_max_matches_limit(self):
        text = "email: a@b.com, b@c.com, c@d.com, d@e.com, e@f.com"
        results = list(enhanced_scan_text(text, categories={'Contact Information'}, max_matches=2))
        self.assertLessEqual(len(results), 2)

    def test_empty_categories_scans_nothing(self):
        text = "My credit card is 4532015112830366"
        results = list(enhanced_scan_text(text, categories=set()))
        self.assertEqual(len(results), 0)

    def test_nonexistent_category_returns_empty(self):
        text = "My credit card is 4532015112830366"
        results = list(enhanced_scan_text(text, categories={'DoesNotExist'}))
        self.assertEqual(len(results), 0)


class TestMatchDataclass(unittest.TestCase):
    """Test the Match structured output."""

    def test_match_has_confidence(self):
        text = "My credit card number is 4532015112830366"
        results = list(enhanced_scan_text(text))
        for m in results:
            self.assertIsInstance(m, Match)
            self.assertGreater(m.confidence, 0.0)
            self.assertLessEqual(m.confidence, 1.0)

    def test_match_has_span(self):
        text = "My credit card number is 4532015112830366"
        results = list(enhanced_scan_text(text))
        visa = [m for m in results if m.sub_category == 'Visa']
        self.assertTrue(len(visa) > 0)
        m = visa[0]
        self.assertEqual(text[m.span[0]:m.span[1]], m.text)

    def test_match_to_dict(self):
        text = "email: test@example.com"
        results = list(enhanced_scan_text(text, categories={'Contact Information'}))
        self.assertTrue(len(results) > 0)
        d = results[0].to_dict()
        self.assertIn('text', d)
        self.assertIn('category', d)
        self.assertIn('confidence', d)
        self.assertIn('span', d)

    def test_match_tuple_unpacking(self):
        """Verify backward-compatible tuple unpacking."""
        text = "email: test@example.com"
        results = list(enhanced_scan_text(text, categories={'Contact Information'}))
        for m in results:
            matched_text, sub_cat, has_ctx, cat = m
            self.assertEqual(matched_text, m.text)
            self.assertEqual(sub_cat, m.sub_category)
            self.assertEqual(has_ctx, m.has_context)
            self.assertEqual(cat, m.category)

    def test_match_index_access(self):
        text = "email: test@example.com"
        results = list(enhanced_scan_text(text, categories={'Contact Information'}))
        m = results[0]
        self.assertEqual(m[0], m.text)
        self.assertEqual(m[1], m.sub_category)
        self.assertEqual(m[2], m.has_context)
        self.assertEqual(m[3], m.category)


class TestConfidenceScoring(unittest.TestCase):
    """Test confidence scoring logic."""

    def test_context_boosts_confidence(self):
        """With context, confidence should be higher than without."""
        with_ctx = "My credit card number is 4532015112830366"
        without_ctx = "number 4532015112830366 appears"
        r_ctx = [m for m in enhanced_scan_text(with_ctx) if m.sub_category == 'Visa']
        r_no = [m for m in enhanced_scan_text(without_ctx) if m.sub_category == 'Visa']
        if r_ctx and r_no:
            self.assertGreater(r_ctx[0].confidence, r_no[0].confidence)

    def test_specific_patterns_high_confidence(self):
        """Highly specific patterns like JWT should have high confidence."""
        text = "token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        results = [m for m in enhanced_scan_text(text) if m.sub_category == 'JWT Token']
        self.assertTrue(len(results) > 0)
        self.assertGreaterEqual(results[0].confidence, 0.90)

    def test_email_has_high_base_specificity(self):
        text = "test@example.com"
        results = [m for m in enhanced_scan_text(text) if m.sub_category == 'Email Address']
        self.assertTrue(len(results) > 0)
        self.assertGreaterEqual(results[0].confidence, 0.85)


class TestContextRequired(unittest.TestCase):
    """Test per-pattern context requirements."""

    def test_broad_pattern_without_context_filtered(self):
        """Gender marker without context keyword should be filtered."""
        text = "The male connector fits into the female port."
        results = list(enhanced_scan_text(text))
        gender = [m for m in results if m.sub_category == 'Gender Marker']
        self.assertEqual(len(gender), 0)

    def test_broad_pattern_with_context_included(self):
        """Gender marker with context should be included."""
        text = "Patient gender: male, Date of Birth: 01/15/1990"
        results = list(enhanced_scan_text(text))
        gender = [m for m in results if m.sub_category == 'Gender Marker']
        self.assertTrue(len(gender) > 0)

    def test_cardholder_name_filtered_without_context(self):
        """Cardholder Name Pattern should not match random 'John Smith'."""
        text = "John Smith went to the store."
        results = list(enhanced_scan_text(text))
        name = [m for m in results if m.sub_category == 'Cardholder Name Pattern']
        self.assertEqual(len(name), 0)


class TestOverlapDeduplication(unittest.TestCase):
    """Test overlap deduplication."""

    def test_dedup_reduces_overlaps(self):
        text = "My SSN is 123-45-6789"
        raw = list(enhanced_scan_text(text, deduplicate=False))
        dedup = list(enhanced_scan_text(text, deduplicate=True))
        self.assertLessEqual(len(dedup), len(raw))

    def test_dedup_keeps_highest_confidence(self):
        text = "My credit card number is 4532015112830366"
        results = list(enhanced_scan_text(text, deduplicate=True))
        # Should keep Visa (high confidence) over PAN (lower confidence)
        # if they overlap on the same span
        for m in results:
            if m.span == results[0].span and m != results[0]:
                self.fail("Duplicate span found after dedup")


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
        prefix = 'sk' + '_' + 'live' + '_'
        key = prefix + 'A' * 24
        text = f"stripe key: {key}"
        results = list(enhanced_scan_text(text))
        stripe = [r for r in results if r[1] == 'Stripe Secret Key']
        self.assertTrue(len(stripe) > 0)


class TestFalsePositiveReduction(unittest.TestCase):
    def test_plain_sentence_no_matches(self):
        text = "The quick brown fox jumps over the lazy dog."
        results = list(enhanced_scan_text(text))
        self.assertEqual(len(results), 0)

    def test_ticker_requires_dollar_sign(self):
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
        text = "There are 42 items and 100 people."
        results = list(enhanced_scan_text(text, categories={'Customer Financial Data'}))
        self.assertEqual(len(results), 0)


class TestDelimiterHandling(unittest.TestCase):
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


class TestFileScanming(unittest.TestCase):
    """Test file and stream scanning."""

    def test_scan_file_detects_email(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Contact email: test@example.com\n")
            f.write("More normal text here.\n")
            path = f.name
        try:
            results = list(scan_file(path, categories={'Contact Information'}))
            emails = [m for m in results if m.sub_category == 'Email Address']
            self.assertTrue(len(emails) > 0)
        finally:
            os.unlink(path)

    def test_scan_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            list(scan_file('/nonexistent/file.txt'))

    def test_scan_stream(self):
        text = "Contact email: test@example.com\nNormal text.\n"
        stream = io.StringIO(text)
        results = list(scan_stream(stream, categories={'Contact Information'}))
        emails = [m for m in results if m.sub_category == 'Email Address']
        self.assertTrue(len(emails) > 0)

    def test_scan_stream_empty(self):
        stream = io.StringIO("")
        results = list(scan_stream(stream))
        self.assertEqual(len(results), 0)

    def test_scan_file_span_offset(self):
        """Verify that span offsets are relative to file start."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("test@example.com\n")
            path = f.name
        try:
            results = list(scan_file(path, categories={'Contact Information'}))
            emails = [m for m in results if m.sub_category == 'Email Address']
            if emails:
                m = emails[0]
                self.assertEqual(m.span[0], 0)
        finally:
            os.unlink(path)


class TestCustomPatterns(unittest.TestCase):
    """Test custom pattern registration."""

    def setUp(self):
        register_patterns(
            category='Test Custom',
            patterns={
                'Test ID': re.compile(r'\bTST-\d{6}\b'),
            },
            context={
                'Identifiers': {
                    'Test ID': ['test id', 'tst'],
                },
                'distance': 50,
            },
            specificity={'Test ID': 0.85},
        )

    def tearDown(self):
        unregister_patterns('Test Custom')

    def test_custom_pattern_detected(self):
        text = "The test id is TST-123456"
        results = list(enhanced_scan_text(text, categories={'Test Custom'}))
        self.assertTrue(len(results) > 0)
        self.assertEqual(results[0].sub_category, 'Test ID')

    def test_custom_pattern_with_context(self):
        text = "test id: TST-123456"
        results = list(enhanced_scan_text(text, categories={'Test Custom'}))
        self.assertTrue(len(results) > 0)
        self.assertTrue(results[0].has_context)

    def test_custom_pattern_confidence(self):
        text = "test id: TST-123456"
        results = list(enhanced_scan_text(text, categories={'Test Custom'}))
        self.assertTrue(len(results) > 0)
        # Specificity 0.85 + context boost = 1.0 (capped)
        self.assertGreaterEqual(results[0].confidence, 0.85)

    def test_unregister_removes_pattern(self):
        unregister_patterns('Test Custom')
        text = "test id is TST-123456"
        results = list(enhanced_scan_text(text, categories={'Test Custom'}))
        self.assertEqual(len(results), 0)
        # Re-register for tearDown
        register_patterns(
            category='Test Custom',
            patterns={'Test ID': re.compile(r'\bTST-\d{6}\b')},
        )

    def test_register_invalid_category_raises(self):
        with self.assertRaises(ValueError):
            register_patterns('', {'X': re.compile(r'x')})

    def test_register_empty_patterns_raises(self):
        with self.assertRaises(ValueError):
            register_patterns('Valid', {})


if __name__ == '__main__':
    unittest.main()
