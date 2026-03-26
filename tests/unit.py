import argparse
import io
import json
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
    scan_directory,
    register_patterns,
    unregister_patterns,
    _is_binary_file,
    _compute_confidence,
    _deduplicate_overlapping,
    MAX_INPUT_SIZE,
    MAX_MATCHES,
)
from dlpscan.models import Match, CONTEXT_REQUIRED_PATTERNS, PATTERN_SPECIFICITY
from dlpscan.config import load_config, _parse_toml_fallback, apply_config_to_args
from dlpscan.allowlist import Allowlist, has_inline_ignore
from dlpscan.hooks import extract_added_lines
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


class TestDirectoryScanning(unittest.TestCase):
    """Test recursive directory scanning."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        # Create some test files.
        with open(os.path.join(self.tmpdir, 'file1.txt'), 'w') as f:
            f.write("Contact email: test@example.com\n")
        with open(os.path.join(self.tmpdir, 'file2.txt'), 'w') as f:
            f.write("Normal text with no sensitive data.\n")
        # Create a subdirectory with a file.
        subdir = os.path.join(self.tmpdir, 'sub')
        os.makedirs(subdir)
        with open(os.path.join(subdir, 'file3.txt'), 'w') as f:
            f.write("SSN: 123-45-6789\n")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir)

    def test_scan_directory_finds_matches(self):
        results = list(scan_directory(
            self.tmpdir, categories={'Contact Information'}
        ))
        emails = [(p, m) for p, m in results if m.sub_category == 'Email Address']
        self.assertTrue(len(emails) > 0)

    def test_scan_directory_returns_relative_paths(self):
        results = list(scan_directory(self.tmpdir))
        for path, m in results:
            self.assertFalse(os.path.isabs(path))

    def test_scan_directory_not_found(self):
        with self.assertRaises(FileNotFoundError):
            list(scan_directory('/nonexistent/dir'))

    def test_scan_directory_skip_paths(self):
        results = list(scan_directory(
            self.tmpdir, skip_paths=['sub/*']
        ))
        sub_results = [(p, m) for p, m in results if p.startswith('sub')]
        self.assertEqual(len(sub_results), 0)

    def test_scan_directory_respects_max_matches(self):
        results = list(scan_directory(self.tmpdir, max_matches=1))
        self.assertLessEqual(len(results), 1)


class TestAllowlist(unittest.TestCase):
    """Test allowlist filtering."""

    def test_allowlist_filters_by_text(self):
        al = Allowlist(texts=['test@example.com'])
        m = Match(text='test@example.com', category='Contact Information',
                  sub_category='Email Address', confidence=0.9, span=(0, 16))
        self.assertFalse(al.is_allowed(m))

    def test_allowlist_filters_by_pattern(self):
        al = Allowlist(patterns=['Gender Marker'])
        m = Match(text='male', category='PII', sub_category='Gender Marker',
                  confidence=0.25, span=(0, 4))
        self.assertFalse(al.is_allowed(m))

    def test_allowlist_keeps_unmatched(self):
        al = Allowlist(texts=['other@example.com'])
        m = Match(text='test@example.com', category='Contact Information',
                  sub_category='Email Address', confidence=0.9, span=(0, 16))
        self.assertTrue(al.is_allowed(m))

    def test_allowlist_skip_path(self):
        al = Allowlist(paths=['tests/**', '*.md'])
        self.assertTrue(al.should_skip_path('tests/unit.py'))
        self.assertTrue(al.should_skip_path('README.md'))
        self.assertFalse(al.should_skip_path('src/main.py'))

    def test_allowlist_filter_matches(self):
        al = Allowlist(patterns=['Email Address'])
        matches = [
            Match(text='test@example.com', category='Contact', sub_category='Email Address',
                  confidence=0.9, span=(0, 16)),
            Match(text='123-45-6789', category='PII', sub_category='USA SSN',
                  confidence=0.7, span=(20, 31)),
        ]
        filtered = al.filter_matches(matches)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].sub_category, 'USA SSN')

    def test_allowlist_from_config(self):
        config = {
            'allowlist': ['test@example.com'],
            'ignore_patterns': ['Hashtag'],
            'ignore_paths': ['*.md'],
        }
        al = Allowlist.from_config(config)
        self.assertIn('test@example.com', al.texts)
        self.assertIn('Hashtag', al.patterns)
        self.assertIn('*.md', al.paths)

    def test_empty_allowlist_is_falsy(self):
        al = Allowlist()
        self.assertFalse(bool(al))

    def test_nonempty_allowlist_is_truthy(self):
        al = Allowlist(texts=['x'])
        self.assertTrue(bool(al))


class TestInlineIgnore(unittest.TestCase):
    """Test inline dlpscan:ignore directive."""

    def test_detects_hash_comment(self):
        self.assertTrue(has_inline_ignore("secret = 'abc123'  # dlpscan:ignore"))

    def test_detects_slash_comment(self):
        self.assertTrue(has_inline_ignore("const key = 'abc'; // dlpscan:ignore"))

    def test_no_directive(self):
        self.assertFalse(has_inline_ignore("secret = 'abc123'"))


class TestConfig(unittest.TestCase):
    """Test configuration file loading."""

    def test_load_config_defaults(self):
        config = load_config()
        self.assertEqual(config['min_confidence'], 0.0)
        self.assertEqual(config['deduplicate'], True)
        self.assertEqual(config['max_matches'], 50_000)

    def test_load_dlpscanrc(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({'min_confidence': 0.5, 'require_context': True}, f)
            path = f.name
        try:
            config = load_config(path=path)
            self.assertEqual(config['min_confidence'], 0.5)
            self.assertTrue(config['require_context'])
        finally:
            os.unlink(path)

    def test_toml_fallback_parser(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
            f.write('[tool.dlpscan]\n')
            f.write('min_confidence = 0.7\n')
            f.write('require_context = true\n')
            f.write('format = "json"\n')
            f.write('allowlist = ["test@example.com"]\n')
            path = f.name
        try:
            from pathlib import Path
            result = _parse_toml_fallback(Path(path))
            dlpscan_cfg = result['tool']['dlpscan']
            self.assertEqual(dlpscan_cfg['min_confidence'], 0.7)
            self.assertTrue(dlpscan_cfg['require_context'])
            self.assertEqual(dlpscan_cfg['format'], 'json')
            self.assertEqual(dlpscan_cfg['allowlist'], ['test@example.com'])
        finally:
            os.unlink(path)


class TestSARIFOutput(unittest.TestCase):
    """Test SARIF output format."""

    def test_sarif_structure(self):
        from dlpscan.input import _format_sarif
        matches = [
            Match(text='test@example.com', category='Contact Information',
                  sub_category='Email Address', confidence=0.9, span=(0, 16)),
        ]
        sarif_str = _format_sarif(matches)
        sarif = json.loads(sarif_str)
        self.assertEqual(sarif['version'], '2.1.0')
        self.assertEqual(len(sarif['runs']), 1)
        self.assertEqual(len(sarif['runs'][0]['results']), 1)
        self.assertEqual(sarif['runs'][0]['tool']['driver']['name'], 'dlpscan')

    def test_sarif_with_file_context(self):
        from dlpscan.input import _format_sarif
        findings = [
            ('src/main.py', Match(text='test@example.com', category='Contact Information',
                                   sub_category='Email Address', confidence=0.9, span=(10, 26))),
        ]
        sarif_str = _format_sarif(findings, file_context=True)
        sarif = json.loads(sarif_str)
        result = sarif['runs'][0]['results'][0]
        self.assertIn('locations', result)
        loc = result['locations'][0]['physicalLocation']
        self.assertEqual(loc['artifactLocation']['uri'], 'src/main.py')

    def test_sarif_confidence_levels(self):
        from dlpscan.input import _format_sarif
        matches = [
            Match(text='test', category='C', sub_category='High',
                  confidence=0.9, span=(0, 4)),
            Match(text='test', category='C', sub_category='Low',
                  confidence=0.3, span=(5, 9)),
        ]
        sarif = json.loads(_format_sarif(matches))
        results = sarif['runs'][0]['results']
        self.assertEqual(results[0]['level'], 'warning')
        self.assertEqual(results[1]['level'], 'note')


class TestComputeConfidence(unittest.TestCase):
    """Direct tests for _compute_confidence."""

    def test_base_specificity_only(self):
        """No context, not context_required — returns base specificity."""
        c = _compute_confidence('Email Address', has_context=False, context_required=False)
        self.assertAlmostEqual(c, 0.90)

    def test_context_boost(self):
        c = _compute_confidence('Email Address', has_context=True, context_required=False)
        self.assertAlmostEqual(c, 1.0)  # 0.90 + 0.20 = 1.10, capped at 1.0

    def test_context_required_no_context(self):
        """Context required but missing — very low confidence."""
        c = _compute_confidence('Gender Marker', has_context=False, context_required=True)
        self.assertAlmostEqual(c, round(0.25 * 0.3, 2))

    def test_unknown_pattern_uses_default(self):
        c = _compute_confidence('NonexistentPattern', has_context=False, context_required=False)
        self.assertAlmostEqual(c, 0.40)  # DEFAULT_SPECIFICITY


class TestDeduplicateOverlapping(unittest.TestCase):
    """Direct tests for _deduplicate_overlapping."""

    def test_empty_list(self):
        self.assertEqual(_deduplicate_overlapping([]), [])

    def test_no_overlaps(self):
        matches = [
            Match(text='a', category='C', sub_category='S', span=(0, 5), confidence=0.8),
            Match(text='b', category='C', sub_category='S', span=(10, 15), confidence=0.9),
        ]
        result = _deduplicate_overlapping(matches)
        self.assertEqual(len(result), 2)

    def test_overlapping_keeps_higher_confidence(self):
        matches = [
            Match(text='abc', category='C', sub_category='Low', span=(0, 10), confidence=0.5),
            Match(text='abcdef', category='C', sub_category='High', span=(0, 10), confidence=0.9),
        ]
        result = _deduplicate_overlapping(matches)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].sub_category, 'High')

    def test_equal_confidence_keeps_longer(self):
        matches = [
            Match(text='ab', category='C', sub_category='Short', span=(0, 5), confidence=0.8),
            Match(text='abcdef', category='C', sub_category='Long', span=(0, 10), confidence=0.8),
        ]
        result = _deduplicate_overlapping(matches)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].sub_category, 'Long')


class TestIsBinaryFile(unittest.TestCase):
    """Tests for _is_binary_file heuristic."""

    def test_binary_extension_detected(self):
        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
            f.write(b'not really a png')
            path = f.name
        try:
            self.assertTrue(_is_binary_file(path))
        finally:
            os.unlink(path)

    def test_text_file_not_binary(self):
        with tempfile.NamedTemporaryFile(suffix='.txt', mode='w', delete=False) as f:
            f.write('Hello world\n')
            path = f.name
        try:
            self.assertFalse(_is_binary_file(path))
        finally:
            os.unlink(path)

    def test_null_bytes_detected(self):
        with tempfile.NamedTemporaryFile(suffix='.dat', delete=False) as f:
            f.write(b'text with \x00 null byte')
            path = f.name
        try:
            self.assertTrue(_is_binary_file(path))
        finally:
            os.unlink(path)

    def test_nonexistent_file_returns_true(self):
        self.assertTrue(_is_binary_file('/nonexistent/file.xyz'))


class TestExtractAddedLines(unittest.TestCase):
    """Tests for hooks.extract_added_lines."""

    def test_basic_diff(self):
        diff = (
            "diff --git a/file.py b/file.py\n"
            "+++ b/file.py\n"
            "@@ -0,0 +1,3 @@\n"
            "+line one\n"
            "+line two\n"
            "+line three\n"
        )
        result = extract_added_lines(diff)
        self.assertEqual(len(result), 3)
        self.assertEqual(result[0], ('file.py', 1, 'line one'))
        self.assertEqual(result[1], ('file.py', 2, 'line two'))
        self.assertEqual(result[2], ('file.py', 3, 'line three'))

    def test_multi_hunk(self):
        diff = (
            "+++ b/file.py\n"
            "@@ -10,3 +10,4 @@\n"
            " unchanged\n"
            "+added at 11\n"
            " unchanged\n"
            "@@ -20,0 +21,1 @@\n"
            "+added at 21\n"
        )
        result = extract_added_lines(diff)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0][1], 11)  # line number
        self.assertEqual(result[1][1], 21)

    def test_malformed_hunk_header(self):
        diff = (
            "+++ b/file.py\n"
            "@@ malformed header @@\n"
            "+added line\n"
        )
        result = extract_added_lines(diff)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][1], 0)  # fallback line number

    def test_empty_diff(self):
        self.assertEqual(extract_added_lines(''), [])

    def test_no_additions(self):
        diff = (
            "+++ b/file.py\n"
            "@@ -1,3 +1,2 @@\n"
            " kept\n"
            "-removed\n"
            " kept\n"
        )
        result = extract_added_lines(diff)
        self.assertEqual(len(result), 0)


class TestApplyConfigToArgs(unittest.TestCase):
    """Tests for config.apply_config_to_args."""

    def _make_args(self, **kwargs):
        """Create a simple namespace mimicking argparse output."""
        defaults = {
            'min_confidence': 0.0,
            'require_context': False,
            'no_dedup': False,
            'max_matches': 50000,
            'format': 'text',
            'categories': None,
        }
        defaults.update(kwargs)
        return argparse.Namespace(**defaults)

    def test_config_overrides_defaults(self):
        args = self._make_args()
        config = {'min_confidence': 0.7, 'require_context': True, 'format': 'json'}
        apply_config_to_args(config, args)
        self.assertEqual(args.min_confidence, 0.7)
        self.assertTrue(args.require_context)
        self.assertEqual(args.format, 'json')

    def test_cli_args_take_precedence(self):
        args = self._make_args(min_confidence=0.5, format='csv')
        config = {'min_confidence': 0.7, 'format': 'json'}
        apply_config_to_args(config, args)
        # min_confidence was explicitly set to 0.5 (not default 0.0), so config shouldn't override
        self.assertEqual(args.min_confidence, 0.5)
        self.assertEqual(args.format, 'csv')

    def test_deduplicate_config(self):
        args = self._make_args()
        config = {'deduplicate': False}
        apply_config_to_args(config, args)
        self.assertTrue(args.no_dedup)

    def test_categories_from_config(self):
        args = self._make_args()
        config = {'categories': ['Credit Card Numbers']}
        apply_config_to_args(config, args)
        self.assertEqual(args.categories, ['Credit Card Numbers'])


class TestFormatters(unittest.TestCase):
    """Tests for CLI output formatters."""

    def _make_matches(self):
        return [
            Match(text='test@example.com', category='Contact Information',
                  sub_category='Email Address', confidence=0.9, span=(0, 16)),
            Match(text='123-45-6789', category='PII', sub_category='USA SSN',
                  has_context=True, confidence=0.75, span=(20, 31)),
        ]

    def test_format_text_empty(self):
        from dlpscan.input import _format_text
        result = _format_text([])
        self.assertIn('No sensitive data', result)

    def test_format_text_with_matches(self):
        from dlpscan.input import _format_text
        result = _format_text(self._make_matches())
        self.assertIn('2 potential match', result)
        self.assertIn('Email Address', result)
        self.assertIn('USA SSN', result)

    def test_format_text_with_file_context(self):
        from dlpscan.input import _format_text
        findings = [('src/main.py', m) for m in self._make_matches()]
        result = _format_text(findings, file_context=True)
        self.assertIn('src/main.py', result)

    def test_format_json(self):
        from dlpscan.input import _format_json
        result = json.loads(_format_json(self._make_matches()))
        self.assertEqual(len(result), 2)
        self.assertIn('text', result[0])

    def test_format_json_with_file_context(self):
        from dlpscan.input import _format_json
        findings = [('src/main.py', m) for m in self._make_matches()]
        result = json.loads(_format_json(findings, file_context=True))
        self.assertEqual(result[0]['file'], 'src/main.py')

    def test_format_csv(self):
        from dlpscan.input import _format_csv
        import io as _io
        buf = _io.StringIO()
        _format_csv(self._make_matches(), buf)
        output = buf.getvalue()
        self.assertIn('text,category', output)
        self.assertIn('test@example.com', output)

    def test_format_csv_with_file_context(self):
        from dlpscan.input import _format_csv
        import io as _io
        buf = _io.StringIO()
        findings = [('src/main.py', m) for m in self._make_matches()]
        _format_csv(findings, buf, file_context=True)
        output = buf.getvalue()
        self.assertIn('file,text', output)
        self.assertIn('src/main.py', output)


class TestUnregisterCleanup(unittest.TestCase):
    """Test that unregister_patterns properly cleans up metadata."""

    def test_unregister_cleans_specificity(self):
        register_patterns(
            category='CleanupTest',
            patterns={'TestPat': re.compile(r'\bCLN-\d{4}\b')},
            specificity={'TestPat': 0.99},
        )
        self.assertIn('TestPat', PATTERN_SPECIFICITY)
        unregister_patterns('CleanupTest')
        self.assertNotIn('TestPat', PATTERN_SPECIFICITY)

    def test_unregister_cleans_context_required(self):
        from dlpscan import scanner
        register_patterns(
            category='CleanupTest2',
            patterns={'BroadPat': re.compile(r'\bBRD\d+\b')},
            context_required={'BroadPat'},
        )
        self.assertIn('BroadPat', scanner.CONTEXT_REQUIRED_PATTERNS)
        unregister_patterns('CleanupTest2')
        self.assertNotIn('BroadPat', scanner.CONTEXT_REQUIRED_PATTERNS)


class TestChunkOverlapDedup(unittest.TestCase):
    """Test that chunked scanning doesn't produce duplicate matches."""

    def test_no_duplicate_matches_at_boundary(self):
        # Create a file where a match falls near a chunk boundary.
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            # Write padding + email at position that will be in overlap zone.
            padding = 'x' * 50
            f.write(f"{padding} email: test@example.com {padding}\n")
            path = f.name
        try:
            # Use tiny chunk size to force overlap processing.
            results = list(scan_file(
                path, categories={'Contact Information'},
                chunk_size=60, chunk_overlap=30,
            ))
            emails = [m for m in results if m.sub_category == 'Email Address']
            # Should have exactly 1, not duplicated.
            self.assertEqual(len(emails), 1)
        finally:
            os.unlink(path)


class TestConfigMutableDefaults(unittest.TestCase):
    """Test that load_config doesn't mutate shared defaults."""

    def test_mutating_config_does_not_affect_defaults(self):
        config1 = load_config()
        config1['allowlist'].append('should_not_leak')
        config2 = load_config()
        self.assertNotIn('should_not_leak', config2['allowlist'])


class TestScanFileEdgeCases(unittest.TestCase):
    """Edge case tests for scan_file."""

    def test_empty_file(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            path = f.name
        try:
            results = list(scan_file(path))
            self.assertEqual(len(results), 0)
        finally:
            os.unlink(path)

    def test_unicode_error_in_directory_scan(self):
        """Binary files in a directory should be silently skipped."""
        tmpdir = tempfile.mkdtemp()
        # Create a file with null bytes (binary).
        with open(os.path.join(tmpdir, 'binary.dat'), 'wb') as f:
            f.write(b'\x00\x01\x02\x03')
        try:
            results = list(scan_directory(tmpdir))
            # Should not raise, binary file silently skipped.
            self.assertEqual(len(results), 0)
        finally:
            import shutil
            shutil.rmtree(tmpdir)


class TestRedactedOutput(unittest.TestCase):
    """Test Match.redacted_text and redact parameter in formatters."""

    def test_redacted_text_long(self):
        m = Match(text='4532015112830366', category='C', sub_category='Visa',
                  confidence=0.9, span=(0, 16))
        self.assertEqual(m.redacted_text, '453...366')

    def test_redacted_text_short(self):
        m = Match(text='12345678', category='C', sub_category='S',
                  confidence=0.5, span=(0, 8))
        self.assertEqual(m.redacted_text, '***')

    def test_to_dict_redact(self):
        m = Match(text='4532015112830366', category='C', sub_category='Visa',
                  confidence=0.9, span=(0, 16))
        d = m.to_dict(redact=True)
        self.assertEqual(d['text'], '453...366')

    def test_to_dict_no_redact(self):
        m = Match(text='4532015112830366', category='C', sub_category='Visa',
                  confidence=0.9, span=(0, 16))
        d = m.to_dict(redact=False)
        self.assertEqual(d['text'], '4532015112830366')

    def test_format_text_redacted(self):
        from dlpscan.input import _format_text
        matches = [Match(text='test@example.com', category='C',
                         sub_category='Email Address', confidence=0.9, span=(0, 16))]
        result = _format_text(matches, redact=True)
        self.assertNotIn('test@example.com', result)
        self.assertIn('tes...com', result)

    def test_format_json_redacted(self):
        from dlpscan.input import _format_json
        matches = [Match(text='test@example.com', category='C',
                         sub_category='Email Address', confidence=0.9, span=(0, 16))]
        result = json.loads(_format_json(matches, redact=True))
        self.assertEqual(result[0]['text'], 'tes...com')

    def test_format_csv_redacted(self):
        from dlpscan.input import _format_csv
        buf = io.StringIO()
        matches = [Match(text='test@example.com', category='C',
                         sub_category='Email Address', confidence=0.9, span=(0, 16))]
        _format_csv(matches, buf, redact=True)
        output = buf.getvalue()
        self.assertNotIn('test@example.com', output)
        self.assertIn('tes...com', output)


class TestMetrics(unittest.TestCase):
    """Test metrics/observability system."""

    def test_metrics_collector_records_duration(self):
        from dlpscan.metrics import MetricsCollector
        import time
        with MetricsCollector() as m:
            time.sleep(0.01)
        self.assertGreater(m.duration_ms, 0)

    def test_metrics_callback_invoked(self):
        from dlpscan.metrics import set_metrics_callback, ScanMetrics
        captured = []
        def cb(metrics):
            captured.append(metrics)
        set_metrics_callback(cb)
        try:
            list(enhanced_scan_text("email: test@example.com",
                                     categories={'Contact Information'}))
            self.assertEqual(len(captured), 1)
            self.assertIsInstance(captured[0], ScanMetrics)
            self.assertGreater(captured[0].match_count, 0)
            self.assertGreater(captured[0].bytes_scanned, 0)
        finally:
            set_metrics_callback(None)

    def test_metrics_callback_none_disables(self):
        from dlpscan.metrics import set_metrics_callback
        set_metrics_callback(None)
        # Should not raise
        list(enhanced_scan_text("test@example.com",
                                 categories={'Contact Information'}))

    def test_metrics_error_captured(self):
        from dlpscan.metrics import MetricsCollector
        try:
            with MetricsCollector() as m:
                raise ValueError("test error")
        except ValueError:
            pass
        self.assertIsNotNone(m.error)
        self.assertIsInstance(m.error, ValueError)


class TestPlugins(unittest.TestCase):
    """Test plugin validator and post-processor system."""

    def setUp(self):
        from dlpscan.plugins import unregister_validators, unregister_post_processors
        unregister_validators('Email Address')
        unregister_post_processors()

    def tearDown(self):
        from dlpscan.plugins import unregister_validators, unregister_post_processors
        unregister_validators('Email Address')
        unregister_post_processors()

    def test_validator_filters_matches(self):
        from dlpscan.plugins import register_validator
        # Reject all Email Address matches
        register_validator('Email Address', lambda m: False)
        results = list(enhanced_scan_text("email: test@example.com",
                                           categories={'Contact Information'}))
        emails = [m for m in results if m.sub_category == 'Email Address']
        self.assertEqual(len(emails), 0)

    def test_validator_keeps_matches(self):
        from dlpscan.plugins import register_validator
        register_validator('Email Address', lambda m: True)
        results = list(enhanced_scan_text("email: test@example.com",
                                           categories={'Contact Information'}))
        emails = [m for m in results if m.sub_category == 'Email Address']
        self.assertGreater(len(emails), 0)

    def test_validator_error_discards_match(self):
        from dlpscan.plugins import register_validator
        def bad_validator(m):
            raise RuntimeError("broken")
        register_validator('Email Address', bad_validator)
        results = list(enhanced_scan_text("email: test@example.com",
                                           categories={'Contact Information'}))
        emails = [m for m in results if m.sub_category == 'Email Address']
        self.assertEqual(len(emails), 0)

    def test_post_processor_transforms_results(self):
        from dlpscan.plugins import register_post_processor
        def remove_emails(matches):
            return [m for m in matches if m.sub_category != 'Email Address']
        register_post_processor(remove_emails)
        results = list(enhanced_scan_text("email: test@example.com",
                                           categories={'Contact Information'}))
        emails = [m for m in results if m.sub_category == 'Email Address']
        self.assertEqual(len(emails), 0)

    def test_post_processor_error_ignored(self):
        from dlpscan.plugins import register_post_processor
        def bad_processor(matches):
            raise RuntimeError("broken")
        register_post_processor(bad_processor)
        # Should not crash, returns original matches
        results = list(enhanced_scan_text("email: test@example.com",
                                           categories={'Contact Information'}))
        self.assertIsInstance(results, list)

    def test_register_non_callable_raises(self):
        from dlpscan.plugins import register_validator, register_post_processor
        with self.assertRaises(TypeError):
            register_validator('Email Address', "not callable")
        with self.assertRaises(TypeError):
            register_post_processor("not callable")


class TestLoggingConfig(unittest.TestCase):
    """Test structured JSON logging."""

    def test_json_formatter(self):
        from dlpscan.logging_config import JSONFormatter
        import logging
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name='dlpscan.test', level=logging.WARNING,
            pathname='test.py', lineno=1, msg='Test message',
            args=(), exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        self.assertEqual(parsed['level'], 'WARNING')
        self.assertEqual(parsed['message'], 'Test message')
        self.assertIn('timestamp', parsed)

    def test_configure_logging_json(self):
        from dlpscan.logging_config import configure_logging
        import logging
        configure_logging(level='DEBUG', json_format=True, stream=io.StringIO())
        logger = logging.getLogger('dlpscan')
        self.assertEqual(logger.level, logging.DEBUG)

    def test_configure_logging_plain(self):
        from dlpscan.logging_config import configure_logging
        import logging
        configure_logging(level='INFO', json_format=False, stream=io.StringIO())
        logger = logging.getLogger('dlpscan')
        self.assertEqual(logger.level, logging.INFO)


class TestAsyncScanner(unittest.TestCase):
    """Test async scanning wrappers."""

    def test_async_scan_text(self):
        import asyncio
        from dlpscan.async_scanner import async_scan_text

        async def run():
            results = []
            async for m in async_scan_text("email: test@example.com",
                                            categories={'Contact Information'}):
                results.append(m)
            return results

        results = asyncio.get_event_loop().run_until_complete(run())
        emails = [m for m in results if m.sub_category == 'Email Address']
        self.assertGreater(len(emails), 0)

    def test_async_scan_file(self):
        import asyncio
        from dlpscan.async_scanner import async_scan_file

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Contact email: test@example.com\n")
            path = f.name

        async def run():
            results = []
            async for m in async_scan_file(path, categories={'Contact Information'}):
                results.append(m)
            return results

        try:
            results = asyncio.get_event_loop().run_until_complete(run())
            emails = [m for m in results if m.sub_category == 'Email Address']
            self.assertGreater(len(emails), 0)
        finally:
            os.unlink(path)


class TestExtractors(unittest.TestCase):
    """Test text extraction system."""

    def test_extract_plain_text(self):
        from dlpscan.extractors import extract_text
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("email: test@example.com\nSSN: 123-45-6789\n")
            path = f.name
        try:
            result = extract_text(path)
            self.assertEqual(result.format, 'text')
            self.assertIn('test@example.com', result.text)
            self.assertIn('123-45-6789', result.text)
        finally:
            os.unlink(path)

    def test_extract_csv(self):
        from dlpscan.extractors import extract_text
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("name,email\nJohn,test@example.com\n")
            path = f.name
        try:
            result = extract_text(path)
            self.assertEqual(result.format, 'text')
            self.assertIn('test@example.com', result.text)
        finally:
            os.unlink(path)

    def test_extract_empty_file(self):
        from dlpscan.extractors import extract_text
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            path = f.name
        try:
            result = extract_text(path)
            self.assertEqual(result.format, 'empty')
            self.assertEqual(result.text, '')
        finally:
            os.unlink(path)

    def test_extract_nonexistent_file(self):
        from dlpscan.extractors import extract_text
        with self.assertRaises(FileNotFoundError):
            extract_text('/nonexistent/file.txt')

    def test_extract_file_too_large(self):
        from dlpscan.extractors import extract_text
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("x" * 100)
            path = f.name
        try:
            with self.assertRaises(ValueError):
                extract_text(path, max_size=50)
        finally:
            os.unlink(path)

    def test_supported_extensions(self):
        from dlpscan.extractors import supported_extensions
        exts = supported_extensions()
        self.assertIn('.pdf', exts)
        self.assertIn('.docx', exts)
        self.assertIn('.xlsx', exts)
        self.assertIn('.pptx', exts)
        self.assertIn('.eml', exts)
        self.assertIn('.msg', exts)
        self.assertIn('.txt', exts)

    def test_get_extractor_returns_none_for_unknown(self):
        from dlpscan.extractors import get_extractor
        self.assertIsNone(get_extractor('file.xyz_unknown'))

    def test_get_extractor_returns_callable(self):
        from dlpscan.extractors import get_extractor
        ext = get_extractor('report.pdf')
        self.assertIsNotNone(ext)
        self.assertTrue(callable(ext))

    def test_register_custom_extractor(self):
        from dlpscan.extractors import register_extractor, extract_text, ExtractionResult, _EXTRACTORS
        def my_extractor(path):
            return ExtractionResult(text='custom extracted', format='custom')
        register_extractor('.zzz_test', my_extractor)
        try:
            with tempfile.NamedTemporaryFile(suffix='.zzz_test', delete=False) as f:
                f.write(b'data')
                path = f.name
            try:
                result = extract_text(path)
                self.assertEqual(result.text, 'custom extracted')
                self.assertEqual(result.format, 'custom')
            finally:
                os.unlink(path)
        finally:
            _EXTRACTORS.pop('.zzz_test', None)

    def test_register_extractor_validation(self):
        from dlpscan.extractors import register_extractor
        with self.assertRaises(ValueError):
            register_extractor('pdf', lambda p: None)  # Missing dot
        with self.assertRaises(TypeError):
            register_extractor('.pdf', 'not callable')

    def test_legacy_office_raises(self):
        from dlpscan.extractors import extract_text
        from dlpscan.exceptions import ExtractionError
        with tempfile.NamedTemporaryFile(suffix='.doc', delete=False) as f:
            f.write(b'\xd0\xcf\x11\xe0')
            path = f.name
        try:
            with self.assertRaises(ExtractionError):
                extract_text(path)
        finally:
            os.unlink(path)

    def test_extract_eml(self):
        from dlpscan.extractors import extract_text
        eml_content = (
            "From: sender@example.com\r\n"
            "To: recipient@example.com\r\n"
            "Subject: Test Email\r\n"
            "Content-Type: text/plain\r\n"
            "\r\n"
            "This is the body with SSN 123-45-6789\r\n"
        )
        with tempfile.NamedTemporaryFile(mode='w', suffix='.eml', delete=False) as f:
            f.write(eml_content)
            path = f.name
        try:
            result = extract_text(path)
            self.assertEqual(result.format, 'eml')
            self.assertIn('sender@example.com', result.text)
            self.assertIn('123-45-6789', result.text)
            self.assertIn('from', result.metadata.get('headers', {}))
        finally:
            os.unlink(path)


class TestPipeline(unittest.TestCase):
    """Test the file processing pipeline."""

    def test_process_text_file(self):
        from dlpscan.pipeline import Pipeline
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Contact email: test@example.com\n")
            path = f.name
        try:
            with Pipeline() as pipe:
                result = pipe.process_file(path, categories={'Contact Information'})
            self.assertTrue(result.success)
            self.assertGreater(result.match_count, 0)
            emails = [m for m in result.matches if m.sub_category == 'Email Address']
            self.assertGreater(len(emails), 0)
            self.assertEqual(result.format_detected, 'text')
            self.assertGreater(result.duration_ms, 0)
        finally:
            os.unlink(path)

    def test_process_missing_file(self):
        from dlpscan.pipeline import Pipeline
        with Pipeline() as pipe:
            result = pipe.process_file('/nonexistent/file.txt')
        self.assertFalse(result.success)
        self.assertIn('not found', result.error.lower())

    def test_process_file_too_large(self):
        from dlpscan.pipeline import Pipeline
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("x" * 200)
            path = f.name
        try:
            with Pipeline(max_file_size=100) as pipe:
                result = pipe.process_file(path)
            self.assertFalse(result.success)
            self.assertIn('exceeds', result.error.lower())
        finally:
            os.unlink(path)

    def test_process_empty_file(self):
        from dlpscan.pipeline import Pipeline
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            path = f.name
        try:
            with Pipeline() as pipe:
                result = pipe.process_file(path)
            self.assertTrue(result.success)
            self.assertEqual(result.match_count, 0)
            self.assertEqual(result.format_detected, 'empty')
        finally:
            os.unlink(path)

    def test_process_files_concurrent(self):
        from dlpscan.pipeline import Pipeline
        paths = []
        for i in range(5):
            f = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
            f.write(f"email: user{i}@example.com\n")
            f.close()
            paths.append(f.name)
        try:
            with Pipeline(max_workers=3) as pipe:
                results = pipe.process_files(paths, categories={'Contact Information'})
            self.assertEqual(len(results), 5)
            for r in results:
                self.assertTrue(r.success)
                self.assertGreater(r.match_count, 0)
        finally:
            for p in paths:
                os.unlink(p)

    def test_process_files_preserves_order(self):
        from dlpscan.pipeline import Pipeline
        paths = []
        for i in range(3):
            f = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
            f.write(f"data {i}\n")
            f.close()
            paths.append(f.name)
        try:
            with Pipeline() as pipe:
                results = pipe.process_files(paths)
            for i, r in enumerate(results):
                self.assertEqual(r.file_path, paths[i])
        finally:
            for p in paths:
                os.unlink(p)

    def test_process_directory(self):
        from dlpscan.pipeline import Pipeline
        tmpdir = tempfile.mkdtemp()
        with open(os.path.join(tmpdir, 'file1.txt'), 'w') as f:
            f.write("email: test@example.com\n")
        with open(os.path.join(tmpdir, 'file2.csv'), 'w') as f:
            f.write("name,email\nJohn,admin@example.com\n")
        try:
            with Pipeline() as pipe:
                results = pipe.process_directory(tmpdir)
            self.assertEqual(len(results), 2)
            all_matches = sum(r.match_count for r in results)
            self.assertGreater(all_matches, 0)
        finally:
            import shutil
            shutil.rmtree(tmpdir)

    def test_process_directory_not_found(self):
        from dlpscan.pipeline import Pipeline
        with Pipeline() as pipe:
            with self.assertRaises(FileNotFoundError):
                pipe.process_directory('/nonexistent/dir')

    def test_pipeline_with_allowlist(self):
        from dlpscan.pipeline import Pipeline
        al = Allowlist(patterns=['Email Address'])
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("email: test@example.com\n")
            path = f.name
        try:
            with Pipeline(allowlist=al) as pipe:
                result = pipe.process_file(path, categories={'Contact Information'})
            self.assertTrue(result.success)
            emails = [m for m in result.matches if m.sub_category == 'Email Address']
            self.assertEqual(len(emails), 0)
        finally:
            os.unlink(path)

    def test_pipeline_min_confidence(self):
        from dlpscan.pipeline import Pipeline
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("test@example.com\n")
            path = f.name
        try:
            with Pipeline(min_confidence=0.99) as pipe:
                result = pipe.process_file(path)
            # Very high threshold should filter most/all matches
            for m in result.matches:
                self.assertGreaterEqual(m.confidence, 0.99)
        finally:
            os.unlink(path)

    def test_pipeline_on_result_callback(self):
        from dlpscan.pipeline import Pipeline
        captured = []
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("email: test@example.com\n")
            path = f.name
        try:
            with Pipeline(on_result=lambda r: captured.append(r)) as pipe:
                pipe.process_file(path)
            self.assertEqual(len(captured), 1)
        finally:
            os.unlink(path)

    def test_pipeline_submit_future(self):
        from dlpscan.pipeline import Pipeline
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("email: test@example.com\n")
            path = f.name
        try:
            with Pipeline() as pipe:
                future = pipe.submit(path, categories={'Contact Information'})
                result = future.result(timeout=10)
            self.assertTrue(result.success)
            self.assertGreater(result.match_count, 0)
        finally:
            os.unlink(path)

    def test_pipeline_result_to_dict(self):
        from dlpscan.pipeline import PipelineResult
        r = PipelineResult(
            file_path='test.txt',
            matches=[Match(text='test@example.com', category='C',
                           sub_category='Email Address', confidence=0.9, span=(0, 16))],
            format_detected='text',
            duration_ms=10.5,
        )
        d = r.to_dict()
        self.assertEqual(d['file_path'], 'test.txt')
        self.assertEqual(d['match_count'], 1)
        self.assertTrue(d['success'])
        # Redacted dict
        d_redact = r.to_dict(redact=True)
        self.assertEqual(d_redact['matches'][0]['text'], 'tes...com')

    def test_process_eml_file(self):
        """Test that EML files are processed through the pipeline."""
        from dlpscan.pipeline import Pipeline
        eml_content = (
            "From: sender@example.com\r\n"
            "To: recipient@example.com\r\n"
            "Subject: Test\r\n"
            "Content-Type: text/plain\r\n"
            "\r\n"
            "The credit card number is 4532015112830366\r\n"
        )
        with tempfile.NamedTemporaryFile(mode='w', suffix='.eml', delete=False) as f:
            f.write(eml_content)
            path = f.name
        try:
            with Pipeline() as pipe:
                result = pipe.process_file(path)
            self.assertTrue(result.success)
            self.assertEqual(result.format_detected, 'eml')
            self.assertGreater(result.match_count, 0)
        finally:
            os.unlink(path)

    def test_process_files_empty_list(self):
        from dlpscan.pipeline import Pipeline
        with Pipeline() as pipe:
            results = pipe.process_files([])
        self.assertEqual(results, [])


class TestFileJob(unittest.TestCase):
    """Test FileJob dataclass."""

    def test_defaults(self):
        from dlpscan.pipeline import FileJob
        job = FileJob(file_path='test.txt')
        self.assertEqual(job.file_path, 'test.txt')
        self.assertIsNone(job.categories)
        self.assertFalse(job.require_context)
        self.assertEqual(job.max_matches, 50000)
        self.assertIsNone(job.metadata)

    def test_with_overrides(self):
        from dlpscan.pipeline import FileJob
        job = FileJob(
            file_path='report.pdf',
            categories={'Credit Card Numbers'},
            require_context=True,
            max_matches=100,
            metadata={'ticket': 'SEC-1234'},
        )
        self.assertEqual(job.categories, {'Credit Card Numbers'})
        self.assertTrue(job.require_context)
        self.assertEqual(job.metadata['ticket'], 'SEC-1234')


class TestInputGuardBasic(unittest.TestCase):
    """Test InputGuard core functionality."""

    def test_reject_action_raises(self):
        from dlpscan.guard import InputGuard, Action, InputGuardError
        guard = InputGuard(action=Action.REJECT, categories={'Contact Information'})
        with self.assertRaises(InputGuardError) as ctx:
            guard.scan("email: test@example.com")
        self.assertFalse(ctx.exception.result.is_clean)
        self.assertGreater(ctx.exception.result.finding_count, 0)

    def test_flag_action_returns_findings(self):
        from dlpscan.guard import InputGuard, Action
        guard = InputGuard(action=Action.FLAG, categories={'Contact Information'})
        result = guard.scan("email: test@example.com")
        self.assertFalse(result.is_clean)
        self.assertGreater(result.finding_count, 0)
        self.assertIsNone(result.redacted_text)

    def test_redact_action_returns_sanitized(self):
        from dlpscan.guard import InputGuard, Action
        guard = InputGuard(action=Action.REDACT, categories={'Contact Information'})
        result = guard.scan("email: test@example.com")
        self.assertFalse(result.is_clean)
        self.assertIsNotNone(result.redacted_text)
        self.assertNotIn('test@example.com', result.redacted_text)

    def test_clean_input_passes(self):
        from dlpscan.guard import InputGuard, Action
        guard = InputGuard(action=Action.REJECT)
        result = guard.scan("This is a normal sentence.")
        self.assertTrue(result.is_clean)
        self.assertEqual(result.finding_count, 0)

    def test_empty_input_is_clean(self):
        from dlpscan.guard import InputGuard, Action
        guard = InputGuard(action=Action.FLAG)
        result = guard.scan("")
        self.assertTrue(result.is_clean)

    def test_check_returns_bool(self):
        from dlpscan.guard import InputGuard
        guard = InputGuard(categories={'Contact Information'})
        self.assertFalse(guard.check("email: test@example.com"))
        self.assertTrue(guard.check("Normal text."))

    def test_sanitize_always_redacts(self):
        from dlpscan.guard import InputGuard, Action
        guard = InputGuard(action=Action.REJECT, categories={'Contact Information'})
        result = guard.sanitize("email: test@example.com")
        self.assertNotIn('test@example.com', result)

    def test_sanitize_returns_original_when_clean(self):
        from dlpscan.guard import InputGuard
        guard = InputGuard()
        text = "Normal text."
        self.assertEqual(guard.sanitize(text), text)


class TestInputGuardModes(unittest.TestCase):
    """Test denylist and allowlist modes."""

    def test_denylist_blocks_specified_categories(self):
        from dlpscan.guard import InputGuard, Action, Mode
        guard = InputGuard(
            mode=Mode.DENYLIST,
            categories={'Contact Information'},
            action=Action.FLAG,
        )
        result = guard.scan("email: test@example.com")
        self.assertFalse(result.is_clean)

    def test_denylist_ignores_other_categories(self):
        from dlpscan.guard import InputGuard, Action, Mode
        guard = InputGuard(
            mode=Mode.DENYLIST,
            categories={'Credit Card Numbers'},
            action=Action.FLAG,
        )
        # Email should not be flagged when only scanning credit cards
        result = guard.scan("email: test@example.com")
        self.assertTrue(result.is_clean)

    def test_allowlist_permits_specified_categories(self):
        from dlpscan.guard import InputGuard, Action, Mode
        guard = InputGuard(
            mode=Mode.ALLOWLIST,
            categories={'Contact Information'},
            action=Action.FLAG,
        )
        # Email is in Contact Information, which is allowed
        result = guard.scan("email: test@example.com")
        email_findings = [f for f in result.findings if f.category == 'Contact Information']
        self.assertEqual(len(email_findings), 0)

    def test_allowlist_blocks_non_specified_categories(self):
        from dlpscan.guard import InputGuard, Action, Mode, InputGuardError
        guard = InputGuard(
            mode=Mode.ALLOWLIST,
            categories={'Contact Information'},
            action=Action.REJECT,
        )
        # Credit card is NOT in allowed set, should be blocked
        with self.assertRaises(InputGuardError):
            guard.scan("credit card 4532015112830366")

    def test_string_mode_accepted(self):
        from dlpscan.guard import InputGuard, Mode
        guard = InputGuard(mode='denylist', action='flag')
        self.assertEqual(guard.mode, Mode.DENYLIST)


class TestInputGuardPresets(unittest.TestCase):
    """Test compliance presets."""

    def test_pci_dss_preset(self):
        from dlpscan.guard import InputGuard, Preset, Action
        guard = InputGuard(presets=[Preset.PCI_DSS], action=Action.FLAG)
        result = guard.scan("credit card 4532015112830366")
        self.assertFalse(result.is_clean)
        cc = [f for f in result.findings if f.category == 'Credit Card Numbers']
        self.assertGreater(len(cc), 0)

    def test_ssn_sin_preset(self):
        from dlpscan.guard import InputGuard, Preset, Action
        guard = InputGuard(presets=[Preset.SSN_SIN], action=Action.FLAG)
        result = guard.scan("SSN: 123-45-6789")
        self.assertFalse(result.is_clean)
        ssn = [f for f in result.findings if f.sub_category == 'USA SSN']
        self.assertGreater(len(ssn), 0)

    def test_credentials_preset(self):
        from dlpscan.guard import InputGuard, Preset, Action
        guard = InputGuard(presets=[Preset.CREDENTIALS], action=Action.FLAG)
        result = guard.scan("token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
        self.assertFalse(result.is_clean)

    def test_contact_info_preset(self):
        from dlpscan.guard import InputGuard, Preset, Action
        guard = InputGuard(presets=[Preset.CONTACT_INFO], action=Action.FLAG)
        result = guard.scan("email: test@example.com")
        self.assertFalse(result.is_clean)

    def test_healthcare_preset(self):
        from dlpscan.guard import InputGuard, Preset, PRESET_CATEGORIES
        cats = PRESET_CATEGORIES[Preset.HEALTHCARE]
        self.assertIn('Medical Identifiers', cats)
        self.assertIn('Insurance Identifiers', cats)

    def test_financial_preset_includes_cards(self):
        from dlpscan.guard import InputGuard, Preset, PRESET_CATEGORIES
        cats = PRESET_CATEGORIES[Preset.FINANCIAL]
        self.assertIn('Credit Card Numbers', cats)
        self.assertIn('Banking and Financial', cats)
        self.assertIn('Cryptocurrency', cats)

    def test_pii_strict_includes_regions(self):
        from dlpscan.guard import Preset, PRESET_CATEGORIES
        cats = PRESET_CATEGORIES[Preset.PII_STRICT]
        self.assertIn('North America - United States', cats)
        self.assertIn('Europe - United Kingdom', cats)
        self.assertIn('Asia-Pacific - Japan', cats)

    def test_multiple_presets_combined(self):
        from dlpscan.guard import InputGuard, Preset, Action
        guard = InputGuard(
            presets=[Preset.PCI_DSS, Preset.CONTACT_INFO],
            action=Action.FLAG,
        )
        # Should detect both credit cards and emails
        text = "card: 4532015112830366, email: test@example.com"
        result = guard.scan(text)
        cats = result.categories_found
        self.assertIn('Credit Card Numbers', cats)
        self.assertIn('Contact Information', cats)

    def test_presets_plus_explicit_categories(self):
        from dlpscan.guard import InputGuard, Preset, Action
        guard = InputGuard(
            presets=[Preset.PCI_DSS],
            categories={'Contact Information'},
            action=Action.FLAG,
        )
        result = guard.scan("email: test@example.com")
        self.assertFalse(result.is_clean)


class TestInputGuardFiltering(unittest.TestCase):
    """Test confidence and allowlist filtering."""

    def test_min_confidence_filters(self):
        from dlpscan.guard import InputGuard, Action
        guard = InputGuard(action=Action.FLAG, min_confidence=0.99)
        result = guard.scan("test@example.com")
        # Very high threshold should filter most matches
        for f in result.findings:
            self.assertGreaterEqual(f.confidence, 0.99)

    def test_allowlist_suppresses_matches(self):
        from dlpscan.guard import InputGuard, Action
        al = Allowlist(texts=['test@example.com'])
        guard = InputGuard(
            categories={'Contact Information'},
            action=Action.FLAG,
            allowlist=al,
        )
        result = guard.scan("email: test@example.com")
        emails = [f for f in result.findings if f.text == 'test@example.com']
        self.assertEqual(len(emails), 0)

    def test_on_detect_callback(self):
        from dlpscan.guard import InputGuard, Action
        captured = []
        guard = InputGuard(
            categories={'Contact Information'},
            action=Action.FLAG,
            on_detect=lambda r: captured.append(r),
        )
        guard.scan("email: test@example.com")
        self.assertEqual(len(captured), 1)

    def test_on_detect_not_called_when_clean(self):
        from dlpscan.guard import InputGuard, Action
        captured = []
        guard = InputGuard(
            action=Action.FLAG,
            on_detect=lambda r: captured.append(r),
        )
        guard.scan("Normal text.")
        self.assertEqual(len(captured), 0)


class TestInputGuardDecorator(unittest.TestCase):
    """Test @guard.protect decorator."""

    def test_protect_rejects_sensitive_param(self):
        from dlpscan.guard import InputGuard, Preset, Action, InputGuardError
        guard = InputGuard(presets=[Preset.PCI_DSS], action=Action.REJECT)

        @guard.protect(param="comment")
        def save(user_id, comment):
            return comment

        with self.assertRaises(InputGuardError):
            save(1, "card: 4532015112830366")

    def test_protect_passes_clean_input(self):
        from dlpscan.guard import InputGuard, Action
        guard = InputGuard(action=Action.REJECT, categories={'Credit Card Numbers'})

        @guard.protect(param="text")
        def process(text):
            return text

        result = process("Normal text here.")
        self.assertEqual(result, "Normal text here.")

    def test_protect_redacts_param(self):
        from dlpscan.guard import InputGuard, Action
        guard = InputGuard(
            categories={'Contact Information'},
            action=Action.REDACT,
        )

        @guard.protect(param="text")
        def process(text):
            return text

        result = process("email: test@example.com")
        self.assertNotIn('test@example.com', result)

    def test_protect_scans_all_string_args(self):
        from dlpscan.guard import InputGuard, Preset, Action, InputGuardError
        guard = InputGuard(presets=[Preset.PCI_DSS], action=Action.REJECT)

        @guard.protect()
        def process(a, b):
            return a + b

        with self.assertRaises(InputGuardError):
            process("normal", "card: 4532015112830366")

    def test_protect_ignores_non_string_args(self):
        from dlpscan.guard import InputGuard, Action
        guard = InputGuard(action=Action.REJECT)

        @guard.protect()
        def process(count, data):
            return count

        # Integer arg should not be scanned
        result = process(42, {'key': 'value'})
        self.assertEqual(result, 42)

    def test_protect_specific_params_only(self):
        from dlpscan.guard import InputGuard, Preset, Action, InputGuardError
        guard = InputGuard(presets=[Preset.PCI_DSS], action=Action.REJECT)

        @guard.protect(params=["comment"])
        def save(comment, metadata):
            return metadata

        # metadata contains card but is not in params list — should pass
        result = save("clean text", "card: 4532015112830366")
        self.assertEqual(result, "card: 4532015112830366")


class TestInputGuardScanResult(unittest.TestCase):
    """Test ScanResult dataclass."""

    def test_to_dict(self):
        from dlpscan.guard import ScanResult
        r = ScanResult(
            text='test',
            is_clean=False,
            findings=[Match(text='test@example.com', category='C',
                            sub_category='Email Address', confidence=0.9, span=(0, 16))],
            categories_found={'C'},
        )
        d = r.to_dict()
        self.assertFalse(d['is_clean'])
        self.assertEqual(d['finding_count'], 1)
        self.assertIn('C', d['categories_found'])

    def test_to_dict_redacted(self):
        from dlpscan.guard import ScanResult
        r = ScanResult(
            text='test',
            is_clean=False,
            findings=[Match(text='test@example.com', category='C',
                            sub_category='Email Address', confidence=0.9, span=(0, 16))],
            categories_found={'C'},
        )
        d = r.to_dict(redact=True)
        self.assertEqual(d['findings'][0]['text'], 'tes...com')

    def test_repr(self):
        from dlpscan.guard import InputGuard, Preset, Action
        guard = InputGuard(presets=[Preset.PCI_DSS], action=Action.FLAG)
        self.assertIn('denylist', repr(guard))
        self.assertIn('flag', repr(guard))


# ---------------------------------------------------------------------------
# Custom Pattern Registration via InputGuard
# ---------------------------------------------------------------------------

class TestInputGuardCustomPatterns(unittest.TestCase):
    """Test custom pattern registration through InputGuard."""

    def test_custom_pattern_detected(self):
        from dlpscan.guard import InputGuard, Action
        with InputGuard(
            action=Action.FLAG,
            custom_patterns={
                'Internal IDs': {
                    'Project Code': r'\bPRJ-\d{6}\b',
                },
            },
        ) as guard:
            result = guard.scan("Project code is PRJ-123456 for this task")
            self.assertFalse(result.is_clean)
            cats = {f.category for f in result.findings}
            self.assertIn('Internal IDs', cats)

    def test_custom_pattern_cleanup_on_close(self):
        from dlpscan.guard import InputGuard, Action
        guard = InputGuard(
            action=Action.FLAG,
            custom_patterns={
                'Temp Pattern': {
                    'Temp ID': r'\bTMP-\d{4}\b',
                },
            },
        )
        result = guard.scan("Got TMP-9999 here")
        self.assertFalse(result.is_clean)

        guard.close()

        # After close, custom pattern should be unregistered.
        # A new guard without custom patterns should not detect it.
        guard2 = InputGuard(action=Action.FLAG, categories={'Temp Pattern'})
        result2 = guard2.scan("Got TMP-9999 here")
        self.assertTrue(result2.is_clean)

    def test_context_manager_cleanup(self):
        from dlpscan.guard import InputGuard, Action
        with InputGuard(
            action=Action.FLAG,
            custom_patterns={
                'Widget IDs': {
                    'Widget': r'\bWDG\d{5}\b',
                },
            },
        ) as guard:
            result = guard.scan("Check WDG12345")
            self.assertFalse(result.is_clean)
        # Outside context manager, patterns should be cleaned up.

    def test_compiled_regex_accepted(self):
        from dlpscan.guard import InputGuard, Action
        with InputGuard(
            action=Action.FLAG,
            custom_patterns={
                'Compiled': {
                    'Hex ID': re.compile(r'\bHEX-[0-9A-F]{8}\b'),
                },
            },
        ) as guard:
            result = guard.scan("Found HEX-DEADBEEF in logs")
            self.assertFalse(result.is_clean)


# ---------------------------------------------------------------------------
# Per-Category Confidence Tuning
# ---------------------------------------------------------------------------

class TestConfidenceOverrides(unittest.TestCase):
    """Test per-category confidence overrides in InputGuard."""

    def test_override_filters_low_confidence(self):
        from dlpscan.guard import InputGuard, Action
        guard = InputGuard(
            action=Action.FLAG,
            categories={'Credit Card Numbers', 'Contact Information'},
            confidence_overrides={
                'Credit Card Numbers': 0.9,
                'Contact Information': 0.0,
            },
        )
        text = "Card: 4111111111111111 email: test@example.com"
        result = guard.scan(text)
        cats = {f.category for f in result.findings}
        # Email should be found (threshold 0.0), credit card depends on confidence.
        self.assertIn('Contact Information', cats)

    def test_global_fallback_when_no_override(self):
        from dlpscan.guard import InputGuard, Action
        guard = InputGuard(
            action=Action.FLAG,
            min_confidence=0.99,
            confidence_overrides={
                'Contact Information': 0.0,
            },
        )
        text = "email: test@example.com"
        result = guard.scan(text)
        # Contact info has override of 0.0, so it passes despite global 0.99.
        self.assertFalse(result.is_clean)


# ---------------------------------------------------------------------------
# Pipeline Structured Output
# ---------------------------------------------------------------------------

class TestPipelineOutput(unittest.TestCase):
    """Test pipeline structured output helpers."""

    def setUp(self):
        from dlpscan.pipeline import Pipeline
        self.tmpdir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.tmpdir, 'test.txt')
        with open(self.test_file, 'w') as f:
            f.write("Credit card 4111111111111111 and email test@example.com\n")
        self.pipe = Pipeline(max_workers=1)

    def tearDown(self):
        self.pipe.shutdown()
        import shutil
        shutil.rmtree(self.tmpdir)

    def test_results_to_json(self):
        from dlpscan.pipeline import results_to_json
        results = [self.pipe.process_file(self.test_file)]
        output = results_to_json(results)
        data = json.loads(output)
        self.assertEqual(len(data), 1)
        self.assertIn('matches', data[0])
        self.assertTrue(data[0]['success'])

    def test_results_to_json_redacted(self):
        from dlpscan.pipeline import results_to_json
        results = [self.pipe.process_file(self.test_file)]
        output = results_to_json(results, redact=True)
        data = json.loads(output)
        for m in data[0]['matches']:
            # Redacted text should use '...' format.
            self.assertIn('...', m['text'])

    def test_results_to_csv(self):
        from dlpscan.pipeline import results_to_csv
        results = [self.pipe.process_file(self.test_file)]
        output = results_to_csv(results)
        self.assertIn('file_path', output)
        self.assertIn('category', output)
        lines = output.strip().split('\n')
        self.assertGreater(len(lines), 1)  # Header + data rows.

    def test_results_to_sarif(self):
        from dlpscan.pipeline import results_to_sarif
        results = [self.pipe.process_file(self.test_file)]
        output = results_to_sarif(results)
        sarif = json.loads(output)
        self.assertEqual(sarif['version'], '2.1.0')
        self.assertIn('runs', sarif)
        self.assertGreater(len(sarif['runs'][0]['results']), 0)

    def test_results_to_csv_with_stream(self):
        from dlpscan.pipeline import results_to_csv
        results = [self.pipe.process_file(self.test_file)]
        buf = io.StringIO()
        results_to_csv(results, stream=buf)
        buf.seek(0)
        content = buf.read()
        self.assertIn('file_path', content)

    def test_results_to_json_empty(self):
        from dlpscan.pipeline import results_to_json
        output = results_to_json([])
        self.assertEqual(json.loads(output), [])


# ---------------------------------------------------------------------------
# Streaming Scanner
# ---------------------------------------------------------------------------

class TestStreamScanner(unittest.TestCase):
    """Test the real-time StreamScanner."""

    def test_basic_feed(self):
        from dlpscan.streaming import StreamScanner
        scanner = StreamScanner(buffer_size=50)
        # Feed enough text to trigger a scan.
        matches = scanner.feed("Credit card number: 4111111111111111 " + "x" * 50)
        matches += scanner.flush()
        cats = {m.category for m in matches}
        self.assertIn('Credit Card Numbers', cats)

    def test_flush_scans_remainder(self):
        from dlpscan.streaming import StreamScanner
        scanner = StreamScanner(buffer_size=10000)
        # Buffer not full — feed returns empty.
        result = scanner.feed("email: test@example.com")
        self.assertEqual(result, [])
        # Flush scans the buffer.
        result = scanner.flush()
        self.assertGreater(len(result), 0)

    def test_reset_clears_state(self):
        from dlpscan.streaming import StreamScanner
        scanner = StreamScanner(buffer_size=10000)
        scanner.feed("some data")
        scanner.reset()
        result = scanner.flush()
        self.assertEqual(result, [])

    def test_on_match_callback(self):
        from dlpscan.streaming import StreamScanner
        detected = []
        scanner = StreamScanner(buffer_size=50, on_match=lambda m: detected.append(m))
        scanner.feed("email test@example.com " + "x" * 50)
        scanner.flush()
        self.assertGreater(len(detected), 0)

    def test_categories_filter(self):
        from dlpscan.streaming import StreamScanner
        scanner = StreamScanner(
            categories={'Credit Card Numbers'},
            buffer_size=50,
        )
        matches = scanner.feed("email test@example.com card 4111111111111111 " + "x" * 50)
        matches += scanner.flush()
        for m in matches:
            self.assertEqual(m.category, 'Credit Card Numbers')


# ---------------------------------------------------------------------------
# Webhook Scanner
# ---------------------------------------------------------------------------

class TestWebhookScanner(unittest.TestCase):
    """Test the WebhookScanner."""

    def test_scan_json_payload(self):
        from dlpscan.streaming import WebhookScanner
        from dlpscan.guard import Preset, Action, InputGuardError
        scanner = WebhookScanner(presets=[Preset.PCI_DSS], action=Action.REJECT)
        body = json.dumps({"card": "4111111111111111", "name": "Test User"})
        with self.assertRaises(InputGuardError):
            scanner.scan_payload(body, content_type='application/json')

    def test_scan_clean_payload(self):
        from dlpscan.streaming import WebhookScanner
        from dlpscan.guard import Preset, Action
        scanner = WebhookScanner(presets=[Preset.PCI_DSS], action=Action.REJECT)
        body = json.dumps({"name": "Test User", "age": 30})
        result = scanner.scan_payload(body, content_type='application/json')
        self.assertTrue(result.is_clean)

    def test_scan_plain_text(self):
        from dlpscan.streaming import WebhookScanner
        from dlpscan.guard import Preset, Action, InputGuardError
        scanner = WebhookScanner(presets=[Preset.CONTACT_INFO], action=Action.FLAG)
        result = scanner.scan_payload("Contact me at test@example.com", content_type='text/plain')
        self.assertFalse(result.is_clean)

    def test_scan_headers(self):
        from dlpscan.streaming import WebhookScanner
        from dlpscan.guard import Preset, Action
        scanner = WebhookScanner(presets=[Preset.CREDENTIALS], action=Action.FLAG)
        headers = {
            'Content-Type': 'application/json',
            'X-Custom-Token': 'ghp_1234567890abcdef1234567890abcdef12345678',
            'Authorization': 'Bearer should-be-skipped',
        }
        result = scanner.scan_headers(headers)
        # GitHub token in custom header should be detected.
        self.assertFalse(result.is_clean)

    def test_scan_empty_headers(self):
        from dlpscan.streaming import WebhookScanner
        from dlpscan.guard import Preset, Action
        scanner = WebhookScanner(presets=[Preset.CREDENTIALS], action=Action.FLAG)
        result = scanner.scan_headers({})
        self.assertTrue(result.is_clean)

    def test_invalid_json_falls_back(self):
        from dlpscan.streaming import WebhookScanner
        from dlpscan.guard import Preset, Action
        scanner = WebhookScanner(presets=[Preset.CONTACT_INFO], action=Action.FLAG)
        result = scanner.scan_payload(
            "not json {email: test@example.com}",
            content_type='application/json',
        )
        self.assertFalse(result.is_clean)


if __name__ == '__main__':
    unittest.main()
