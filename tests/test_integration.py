"""Integration tests for dlpscan — end-to-end flows with real files."""

import io
import json
import os
import re
import shutil
import tempfile
import unittest

from dlpscan import (
    Allowlist,
    enhanced_scan_text,
    register_patterns,
    scan_stream,
    unregister_patterns,
)
from dlpscan.guard import Action, InputGuard, InputGuardError, Mode, Preset
from dlpscan.pipeline import (
    Pipeline,
    results_to_csv,
    results_to_json,
    results_to_sarif,
)
from dlpscan.streaming import StreamScanner, WebhookScanner

# ---------------------------------------------------------------------------
# Test data
# ---------------------------------------------------------------------------

SENSITIVE_TEXT = """\
Customer Report
Name: John Doe
Email: john.doe@example.com
Phone: +1-555-123-4567
SSN: 123-45-6789
Credit Card: 4111111111111111
IBAN: GB29NWBK60161331926819
AWS Key: AKIAIOSFODNN7EXAMPLE
GitHub Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12
"""

CLEAN_TEXT = """\
Meeting Notes - Q4 Planning
Attendees: Team Alpha
Discussed roadmap priorities and timeline.
Action items assigned. Next meeting in two weeks.
"""


class TestEndToEndTextScanning(unittest.TestCase):
    """Full flow: scan text with known sensitive data."""

    def test_detects_credit_card(self):
        matches = list(enhanced_scan_text("Card: 4111111111111111"))
        cats = {m.category for m in matches}
        self.assertIn('Credit Card Numbers', cats)

    def test_detects_email(self):
        matches = list(enhanced_scan_text("Email: john.doe@example.com"))
        cats = {m.category for m in matches}
        self.assertIn('Contact Information', cats)

    def test_detects_multiple_types(self):
        matches = list(enhanced_scan_text(SENSITIVE_TEXT))
        cats = {m.category for m in matches}
        self.assertIn('Contact Information', cats)
        self.assertIn('Credit Card Numbers', cats)
        self.assertTrue(len(matches) >= 3)

    def test_clean_text_no_matches(self):
        matches = list(enhanced_scan_text(CLEAN_TEXT))
        self.assertEqual(len(matches), 0)

    def test_category_filter(self):
        matches = list(enhanced_scan_text(
            SENSITIVE_TEXT,
            categories={'Credit Card Numbers'},
        ))
        for m in matches:
            self.assertEqual(m.category, 'Credit Card Numbers')

    def test_confidence_scores_populated(self):
        matches = list(enhanced_scan_text(SENSITIVE_TEXT))
        for m in matches:
            self.assertGreaterEqual(m.confidence, 0.0)
            self.assertLessEqual(m.confidence, 1.0)

    def test_spans_valid(self):
        text = "Card: 4111111111111111"
        matches = list(enhanced_scan_text(text))
        for m in matches:
            self.assertEqual(text[m.span[0]:m.span[1]], m.text)


class TestEndToEndFilePipeline(unittest.TestCase):
    """Process temp files through the pipeline."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.sensitive_file = os.path.join(self.tmpdir, 'sensitive.txt')
        with open(self.sensitive_file, 'w') as f:
            f.write(SENSITIVE_TEXT)
        self.clean_file = os.path.join(self.tmpdir, 'clean.txt')
        with open(self.clean_file, 'w') as f:
            f.write(CLEAN_TEXT)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_process_sensitive_file(self):
        with Pipeline(max_workers=1) as pipe:
            result = pipe.process_file(self.sensitive_file)
        self.assertTrue(result.success)
        self.assertGreater(result.match_count, 0)
        self.assertGreater(result.duration_ms, 0)

    def test_process_clean_file(self):
        with Pipeline(max_workers=1) as pipe:
            result = pipe.process_file(self.clean_file)
        self.assertTrue(result.success)
        self.assertEqual(result.match_count, 0)

    def test_process_multiple_files(self):
        with Pipeline(max_workers=2) as pipe:
            results = pipe.process_files([self.sensitive_file, self.clean_file])
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r.success for r in results))

    def test_process_nonexistent_file(self):
        with Pipeline(max_workers=1) as pipe:
            result = pipe.process_file('/nonexistent/file.txt')
        self.assertFalse(result.success)
        self.assertIsNotNone(result.error)

    def test_pipeline_result_to_dict(self):
        with Pipeline(max_workers=1) as pipe:
            result = pipe.process_file(self.sensitive_file)
        d = result.to_dict()
        self.assertIn('matches', d)
        self.assertIn('file_path', d)
        self.assertTrue(d['success'])


class TestEndToEndDirectoryScanning(unittest.TestCase):
    """Process a temp directory through the pipeline."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        # Create subdir with files.
        self.subdir = os.path.join(self.tmpdir, 'reports')
        os.makedirs(self.subdir)
        with open(os.path.join(self.subdir, 'report1.txt'), 'w') as f:
            f.write("SSN: 123-45-6789\n")
        with open(os.path.join(self.subdir, 'report2.txt'), 'w') as f:
            f.write("All clear, nothing sensitive here.\n")
        with open(os.path.join(self.tmpdir, 'top.txt'), 'w') as f:
            f.write("Card: 4111111111111111\n")

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_directory_scanning(self):
        with Pipeline(max_workers=2) as pipe:
            results = pipe.process_directory(self.tmpdir)
        self.assertEqual(len(results), 3)
        total_matches = sum(r.match_count for r in results)
        self.assertGreater(total_matches, 0)

    def test_directory_not_found(self):
        with Pipeline(max_workers=1) as pipe:
            with self.assertRaises(FileNotFoundError):
                pipe.process_directory('/nonexistent/dir/')


class TestEndToEndInputGuard(unittest.TestCase):
    """Full flow with InputGuard presets and actions."""

    def test_reject_pci_data(self):
        guard = InputGuard(presets=[Preset.PCI_DSS], action=Action.REJECT)
        with self.assertRaises(InputGuardError) as ctx:
            guard.scan("Payment card: 4111111111111111")
        self.assertFalse(ctx.exception.result.is_clean)

    def test_flag_contact_info(self):
        guard = InputGuard(presets=[Preset.CONTACT_INFO], action=Action.FLAG)
        result = guard.scan("Contact me at user@test.com")
        self.assertFalse(result.is_clean)
        self.assertIsNone(result.redacted_text)

    def test_redact_credentials(self):
        guard = InputGuard(presets=[Preset.CREDENTIALS], action=Action.REDACT)
        result = guard.scan("Key: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12")
        if not result.is_clean:
            self.assertIsNotNone(result.redacted_text)
            self.assertNotIn('ghp_ABCD', result.redacted_text)

    def test_clean_input_passes(self):
        guard = InputGuard(presets=[Preset.PCI_DSS], action=Action.REJECT)
        result = guard.scan("Hello, this is a clean message.")
        self.assertTrue(result.is_clean)

    def test_check_method(self):
        guard = InputGuard(presets=[Preset.PCI_DSS])
        self.assertTrue(guard.check("No cards here"))
        self.assertFalse(guard.check("Card: 4111111111111111"))

    def test_sanitize_method(self):
        guard = InputGuard(presets=[Preset.CONTACT_INFO])
        sanitized = guard.sanitize("Email: user@test.com")
        self.assertNotIn('user@test.com', sanitized)

    def test_allowlist_mode(self):
        guard = InputGuard(
            mode=Mode.ALLOWLIST,
            categories={'Contact Information'},
            action=Action.FLAG,
        )
        # Email is allowed, so should not trigger.
        result = guard.scan("user@test.com")
        self.assertTrue(result.is_clean)


class TestEndToEndRedaction(unittest.TestCase):
    """Verify redacted output masks data while preserving structure."""

    def test_redacted_text_masks_card(self):
        guard = InputGuard(presets=[Preset.PCI_DSS], action=Action.REDACT)
        text = "Card: 4111111111111111"
        result = guard.scan(text)
        if not result.is_clean:
            self.assertNotIn('4111111111111111', result.redacted_text)
            self.assertIn('Card:', result.redacted_text)

    def test_redacted_preserves_structure(self):
        guard = InputGuard(presets=[Preset.CONTACT_INFO], action=Action.REDACT)
        text = "Email: user@test.com then more text"
        result = guard.scan(text)
        if not result.is_clean:
            self.assertIn('then more text', result.redacted_text)


class TestPipelineWithExtractors(unittest.TestCase):
    """Test extraction + scanning through the pipeline with text formats."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_txt_file(self):
        path = os.path.join(self.tmpdir, 'data.txt')
        with open(path, 'w') as f:
            f.write("SSN: 123-45-6789\nCard: 4111111111111111\n")
        with Pipeline(max_workers=1) as pipe:
            result = pipe.process_file(path)
        self.assertTrue(result.success)
        self.assertGreater(result.match_count, 0)

    def test_csv_file(self):
        path = os.path.join(self.tmpdir, 'data.csv')
        with open(path, 'w') as f:
            f.write("name,email,card\n")
            f.write("John,john@example.com,4111111111111111\n")
        with Pipeline(max_workers=1) as pipe:
            result = pipe.process_file(path)
        self.assertTrue(result.success)
        self.assertGreater(result.match_count, 0)

    def test_eml_file(self):
        path = os.path.join(self.tmpdir, 'message.eml')
        with open(path, 'w') as f:
            f.write("From: sender@example.com\n")
            f.write("To: recipient@example.com\n")
            f.write("Subject: Test\n")
            f.write("\n")
            f.write("Credit card: 4111111111111111\n")
        with Pipeline(max_workers=1) as pipe:
            result = pipe.process_file(path)
        self.assertTrue(result.success)
        self.assertGreater(result.match_count, 0)

    def test_empty_file(self):
        path = os.path.join(self.tmpdir, 'empty.txt')
        with open(path, 'w'):
            pass
        with Pipeline(max_workers=1) as pipe:
            result = pipe.process_file(path)
        self.assertTrue(result.success)
        self.assertEqual(result.match_count, 0)


class TestInputGuardDecorator(unittest.TestCase):
    """Test decorator-based function argument scanning."""

    def test_reject_on_sensitive_arg(self):
        guard = InputGuard(presets=[Preset.PCI_DSS], action=Action.REJECT)

        @guard.protect(param='comment')
        def save_comment(user_id, comment):
            return comment

        with self.assertRaises(InputGuardError):
            save_comment(1, "Card 4111111111111111")

    def test_pass_on_clean_arg(self):
        guard = InputGuard(presets=[Preset.PCI_DSS], action=Action.REJECT)

        @guard.protect(param='comment')
        def save_comment(user_id, comment):
            return comment

        result = save_comment(1, "Just a normal comment")
        self.assertEqual(result, "Just a normal comment")

    def test_redact_argument(self):
        guard = InputGuard(presets=[Preset.CONTACT_INFO], action=Action.REDACT)

        @guard.protect(param='message')
        def log_message(message):
            return message

        result = log_message("Contact user@test.com for info")
        self.assertNotIn('user@test.com', result)

    def test_scan_all_string_args(self):
        guard = InputGuard(presets=[Preset.PCI_DSS], action=Action.REJECT)

        @guard.protect()
        def process(a, b):
            return a + b

        with self.assertRaises(InputGuardError):
            process("Card: 4111111111111111", "clean")


class TestCustomPatternRegistration(unittest.TestCase):
    """Register custom patterns, scan, unregister."""

    def test_register_scan_unregister(self):
        register_patterns(
            category='Test IDs',
            patterns={'Test Code': re.compile(r'\bTST-\d{4}\b')},
        )
        try:
            matches = list(enhanced_scan_text(
                "Found TST-1234 in the logs",
                categories={'Test IDs'},
            ))
            self.assertGreater(len(matches), 0)
            self.assertEqual(matches[0].category, 'Test IDs')
        finally:
            unregister_patterns('Test IDs')

        # After unregister, should not detect.
        matches = list(enhanced_scan_text(
            "Found TST-1234 in the logs",
            categories={'Test IDs'},
        ))
        self.assertEqual(len(matches), 0)


class TestAllowlistIntegration(unittest.TestCase):
    """Test allowlist filtering end-to-end."""

    def test_allowlist_suppresses_known_value(self):
        al = Allowlist(texts=['test@example.com'])
        matches = list(enhanced_scan_text("Contact: test@example.com"))
        filtered = al.filter_matches(matches)
        # The exact email should be filtered out.
        texts = [m.text for m in filtered]
        self.assertNotIn('test@example.com', texts)

    def test_allowlist_in_pipeline(self):
        tmpdir = tempfile.mkdtemp()
        try:
            path = os.path.join(tmpdir, 'test.txt')
            with open(path, 'w') as f:
                f.write("Contact: test@example.com\n")
            al = Allowlist(texts=['test@example.com'])
            with Pipeline(max_workers=1, allowlist=al) as pipe:
                result = pipe.process_file(path)
            email_matches = [m for m in result.matches if m.text == 'test@example.com']
            self.assertEqual(len(email_matches), 0)
        finally:
            shutil.rmtree(tmpdir)


class TestStreamScanningIntegration(unittest.TestCase):
    """Test scan_stream with StringIO."""

    def test_stream_scanning(self):
        text = "SSN: 123-45-6789\nCard: 4111111111111111\n"
        stream = io.StringIO(text)
        matches = list(scan_stream(stream))
        self.assertGreater(len(matches), 0)

    def test_large_stream(self):
        # Generate a large stream with sensitive data sprinkled in.
        lines = ["Line {} of the report\n".format(i) for i in range(1000)]
        lines[500] = "Card: 4111111111111111\n"
        lines[800] = "Email: found@example.com\n"
        stream = io.StringIO(''.join(lines))
        matches = list(scan_stream(stream))
        self.assertGreater(len(matches), 0)


class TestPipelineStructuredOutput(unittest.TestCase):
    """Test JSON/CSV/SARIF export from pipeline results."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        path = os.path.join(self.tmpdir, 'test.txt')
        with open(path, 'w') as f:
            f.write("Card: 4111111111111111\n")
        with Pipeline(max_workers=1) as pipe:
            self.results = [pipe.process_file(path)]

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_json_export(self):
        output = results_to_json(self.results)
        data = json.loads(output)
        self.assertIsInstance(data, list)
        self.assertTrue(data[0]['success'])

    def test_csv_export(self):
        output = results_to_csv(self.results)
        self.assertIn('file_path', output)
        self.assertIn('category', output)

    def test_sarif_export(self):
        output = results_to_sarif(self.results)
        sarif = json.loads(output)
        self.assertEqual(sarif['version'], '2.1.0')

    def test_json_redacted(self):
        output = results_to_json(self.results, redact=True)
        data = json.loads(output)
        for m in data[0]['matches']:
            self.assertIn('...', m['text'])


class TestStreamScannerIntegration(unittest.TestCase):
    """Test StreamScanner end-to-end."""

    def test_incremental_feed(self):
        scanner = StreamScanner(buffer_size=100)
        all_matches = []
        # Feed in small chunks.
        text = "Here is a credit card: 4111111111111111 in the middle of text " * 3
        for i in range(0, len(text), 50):
            all_matches.extend(scanner.feed(text[i:i + 50]))
        all_matches.extend(scanner.flush())
        self.assertGreater(len(all_matches), 0)

    def test_thread_safety(self):
        import threading
        scanner = StreamScanner(buffer_size=100)
        results = []

        def feed_data():
            for _ in range(5):
                m = scanner.feed("Card 4111111111111111 " * 5)
                results.extend(m)

        threads = [threading.Thread(target=feed_data) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        results.extend(scanner.flush())
        # Should have found some matches without crashing.
        self.assertGreater(len(results), 0)


class TestWebhookScannerIntegration(unittest.TestCase):
    """Test WebhookScanner end-to-end."""

    def test_json_with_nested_sensitive_data(self):
        webhook = WebhookScanner(presets=[Preset.CONTACT_INFO], action=Action.FLAG)
        body = json.dumps({
            'user': {
                'name': 'John',
                'email': 'john@example.com',
                'address': {
                    'street': '123 Main St',
                },
            },
            'items': ['product1', 'product2'],
        })
        result = webhook.scan_payload(body, content_type='application/json')
        self.assertFalse(result.is_clean)

    def test_form_data_scanning(self):
        webhook = WebhookScanner(presets=[Preset.PCI_DSS], action=Action.FLAG)
        body = "card_number=4111111111111111&name=John+Doe"
        result = webhook.scan_payload(body, content_type='application/x-www-form-urlencoded')
        self.assertFalse(result.is_clean)


if __name__ == '__main__':
    unittest.main()
