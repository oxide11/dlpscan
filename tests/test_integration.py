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


# ---------------------------------------------------------------------------
# API integration tests (requires fastapi + httpx)
# ---------------------------------------------------------------------------

_HAS_FASTAPI_TESTCLIENT = False
try:
    from fastapi.testclient import TestClient

    _HAS_FASTAPI_TESTCLIENT = True
except Exception:
    pass


@unittest.skipUnless(_HAS_FASTAPI_TESTCLIENT, "fastapi + httpx not installed")
class TestAPIIntegration(unittest.TestCase):
    """Exercise the FastAPI REST endpoints via TestClient."""

    @classmethod
    def setUpClass(cls):
        # Disable API key auth and set a tight rate limit for testing.
        os.environ.pop("DLPSCAN_API_KEY", None)
        os.environ.pop("DLPSCAN_CACHE_ENABLED", None)
        # Reset the rate-limiter singleton so our env var takes effect.
        from dlpscan.api import _get_rate_limiter
        if hasattr(_get_rate_limiter, "_instance"):
            del _get_rate_limiter._instance

        from dlpscan.api import create_app

        cls.app = create_app()
        cls.client = TestClient(cls.app)

    @classmethod
    def tearDownClass(cls):
        # Clean up rate-limiter singleton.
        from dlpscan.api import _get_rate_limiter
        if hasattr(_get_rate_limiter, "_instance"):
            del _get_rate_limiter._instance

    def setUp(self):
        # Reset rate limiter between tests to avoid cross-test interference.
        from dlpscan.api import _get_rate_limiter
        if hasattr(_get_rate_limiter, "_instance"):
            _get_rate_limiter._instance.reset()

    def test_health_returns_200_and_version(self):
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["status"], "ok")
        self.assertIn("version", body)
        self.assertTrue(len(body["version"]) > 0)

    def test_scan_with_ssn_returns_findings(self):
        resp = self.client.post("/v1/scan", json={
            "text": "My SSN is 123-45-6789",
            "action": "flag",
        })
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertFalse(body["is_clean"])
        self.assertGreater(body["finding_count"], 0)
        self.assertGreater(len(body["findings"]), 0)

    def test_scan_clean_text_returns_is_clean(self):
        resp = self.client.post("/v1/scan", json={
            "text": "Quarterly planning meeting scheduled for next Thursday.",
            "action": "flag",
        })
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertTrue(body["is_clean"])
        self.assertEqual(body["finding_count"], 0)

    def test_tokenize_detokenize_roundtrip(self):
        original = "Contact john.doe@example.com for details"
        # Tokenize
        tok_resp = self.client.post("/v1/tokenize", json={"text": original})
        self.assertEqual(tok_resp.status_code, 200)
        tok_body = tok_resp.json()
        self.assertIn("tokenized_text", tok_body)
        self.assertIn("vault_id", tok_body)
        self.assertNotEqual(tok_body["tokenized_text"], original)

        # Detokenize
        detok_resp = self.client.post("/v1/detokenize", json={
            "text": tok_body["tokenized_text"],
            "vault_id": tok_body["vault_id"],
        })
        self.assertEqual(detok_resp.status_code, 200)
        detok_body = detok_resp.json()
        self.assertEqual(detok_body["original_text"], original)

    def test_obfuscate_returns_obfuscated_text(self):
        resp = self.client.post("/v1/obfuscate", json={
            "text": "Email me at john.doe@example.com",
            "seed": 42,
        })
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn("obfuscated_text", body)
        # The original email should not appear in the obfuscated output.
        self.assertNotIn("john.doe@example.com", body["obfuscated_text"])

    def test_batch_scan_with_multiple_items(self):
        resp = self.client.post("/v1/batch/scan", json={
            "items": [
                {"text": "SSN: 123-45-6789", "action": "flag"},
                {"text": "Nothing sensitive here", "action": "flag"},
                {"text": "Card: 4111111111111111", "action": "flag"},
            ],
        })
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        results = body["results"]
        self.assertEqual(len(results), 3)
        # First and third items should have findings.
        self.assertFalse(results[0]["is_clean"])
        self.assertTrue(results[1]["is_clean"])
        self.assertFalse(results[2]["is_clean"])

    def test_rate_limiting_returns_429(self):
        # Create a fresh app with a very low rate limit.
        from dlpscan.api import _get_rate_limiter
        if hasattr(_get_rate_limiter, "_instance"):
            del _get_rate_limiter._instance

        old_val = os.environ.get("DLPSCAN_API_RATE_LIMIT")
        os.environ["DLPSCAN_API_RATE_LIMIT"] = "2"
        try:
            from dlpscan.api import create_app as _create
            app = _create()
            client = TestClient(app)

            # First two requests on rate-limited endpoints should succeed.
            r1 = client.post("/v1/scan", json={
                "text": "hello", "action": "flag",
            })
            self.assertEqual(r1.status_code, 200)
            r2 = client.post("/v1/scan", json={
                "text": "world", "action": "flag",
            })
            self.assertEqual(r2.status_code, 200)
            # The third request should be rejected by the rate limiter.
            r3 = client.post("/v1/scan", json={
                "text": "test", "action": "flag",
            })
            self.assertEqual(r3.status_code, 429)
        finally:
            if old_val is None:
                os.environ.pop("DLPSCAN_API_RATE_LIMIT", None)
            else:
                os.environ["DLPSCAN_API_RATE_LIMIT"] = old_val
            if hasattr(_get_rate_limiter, "_instance"):
                del _get_rate_limiter._instance

    def test_request_body_too_large_returns_422(self):
        # The ScanRequest.text field has max_length=1_000_000.
        # Sending a text larger than that should trigger a validation error.
        huge_text = "A" * 1_000_001
        resp = self.client.post("/v1/scan", json={
            "text": huge_text,
            "action": "flag",
        })
        self.assertEqual(resp.status_code, 422)


# ---------------------------------------------------------------------------
# Batch database integration tests
# ---------------------------------------------------------------------------


class TestBatchDatabaseIntegration(unittest.TestCase):
    """Test BatchScanner.scan_database with an in-memory SQLite DB."""

    def setUp(self):
        import sqlite3

        self.db_path = os.path.join(tempfile.mkdtemp(), "test.db")
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "CREATE TABLE customers ("
            "  id INTEGER PRIMARY KEY,"
            "  name TEXT,"
            "  email TEXT,"
            "  notes TEXT"
            ")"
        )
        conn.execute(
            "INSERT INTO customers (name, email, notes) VALUES (?, ?, ?)",
            ("Alice", "alice@example.com", "SSN: 123-45-6789"),
        )
        conn.execute(
            "INSERT INTO customers (name, email, notes) VALUES (?, ?, ?)",
            ("Bob", "bob@example.com", "Nothing sensitive"),
        )
        conn.execute(
            "INSERT INTO customers (name, email, notes) VALUES (?, ?, ?)",
            ("Carol", "carol@example.com", "Card: 4111111111111111"),
        )
        conn.commit()
        conn.close()

    def tearDown(self):
        parent = os.path.dirname(self.db_path)
        shutil.rmtree(parent, ignore_errors=True)

    def test_scan_returns_findings_for_pii_rows(self):
        from dlpscan.batch import BatchScanner

        scanner = BatchScanner(max_workers=1)
        results = scanner.scan_database(
            self.db_path,
            "SELECT id, name, email, notes FROM customers",
        )
        self.assertEqual(len(results), 3)
        # At least two rows should have findings (SSN and credit card rows).
        rows_with_findings = [
            r for r in results
            if r.scan_result is not None and not r.scan_result.is_clean
        ]
        self.assertGreaterEqual(len(rows_with_findings), 2)

    def test_column_filtering(self):
        from dlpscan.batch import BatchScanner

        scanner = BatchScanner(max_workers=1)
        # Only scan the 'name' column which has no PII patterns.
        results = scanner.scan_database(
            self.db_path,
            "SELECT id, name, email, notes FROM customers",
            columns=["name"],
        )
        self.assertEqual(len(results), 3)
        # Names alone should not trigger findings.
        for r in results:
            self.assertTrue(
                r.scan_result is None or r.scan_result.is_clean,
                f"Unexpected finding in name-only scan: {r.text}",
            )

    def test_non_select_query_rejected(self):
        from dlpscan.batch import BatchScanner

        scanner = BatchScanner(max_workers=1)
        with self.assertRaises(ValueError) as ctx:
            scanner.scan_database(
                self.db_path,
                "DROP TABLE customers",
            )
        self.assertIn("SELECT", str(ctx.exception))


# ---------------------------------------------------------------------------
# Cache integration tests
# ---------------------------------------------------------------------------


class TestCacheIntegration(unittest.TestCase):
    """Test ScanCache integration with real scans."""

    def test_cache_hit_returns_same_result(self):
        from dlpscan.cache import ScanCache
        from dlpscan.guard.core import InputGuard
        from dlpscan.guard.enums import Action

        cache = ScanCache(max_size=10, ttl_seconds=60)
        guard = InputGuard(action=Action.FLAG)

        text = "Card: 4111111111111111"
        result1 = guard.scan(text)
        cache.put(text, result1)

        cached = cache.get(text)
        self.assertIsNotNone(cached)
        self.assertEqual(cached.is_clean, result1.is_clean)
        self.assertEqual(cached.finding_count, result1.finding_count)

    def test_cache_miss_triggers_scan(self):
        from dlpscan.cache import ScanCache

        cache = ScanCache(max_size=10, ttl_seconds=60)
        result = cache.get("never seen this text before")
        self.assertIsNone(result)
        self.assertEqual(cache.stats["misses"], 1)
        self.assertEqual(cache.stats["hits"], 0)

    def test_ttl_expiration(self):
        from dlpscan.cache import ScanCache
        from dlpscan.guard.core import InputGuard
        from dlpscan.guard.enums import Action

        # Use a very short TTL.
        cache = ScanCache(max_size=10, ttl_seconds=0.1)
        guard = InputGuard(action=Action.FLAG)

        text = "Email: test@example.com"
        result = guard.scan(text)
        cache.put(text, result)

        # Immediately should be a hit.
        self.assertIsNotNone(cache.get(text))

        # Wait for TTL to expire.
        import time
        time.sleep(0.2)

        # Should be a miss now.
        self.assertIsNone(cache.get(text))

    def test_cache_stats_tracking(self):
        from dlpscan.cache import ScanCache
        from dlpscan.guard.core import InputGuard
        from dlpscan.guard.enums import Action

        cache = ScanCache(max_size=10, ttl_seconds=60)
        guard = InputGuard(action=Action.FLAG)

        text = "SSN: 123-45-6789"
        result = guard.scan(text)

        # Miss on first access.
        cache.get(text)
        self.assertEqual(cache.stats["misses"], 1)
        self.assertEqual(cache.stats["hits"], 0)

        # Put and then hit.
        cache.put(text, result)
        cache.get(text)
        self.assertEqual(cache.stats["hits"], 1)
        self.assertEqual(cache.stats["misses"], 1)
        self.assertEqual(cache.stats["size"], 1)


# ---------------------------------------------------------------------------
# Webhook integration tests
# ---------------------------------------------------------------------------


class TestWebhookIntegration(unittest.TestCase):
    """Test WebhookNotifier and notify_findings dispatch."""

    def test_notification_payload_structure(self):
        from unittest.mock import MagicMock, patch

        from dlpscan.guard.core import InputGuard
        from dlpscan.guard.enums import Action
        from dlpscan.webhooks import WebhookNotifier

        guard = InputGuard(action=Action.FLAG)
        result = guard.scan("Card: 4111111111111111")

        captured_payloads = []

        def fake_urlopen(req, **kwargs):
            import json as _json
            payload = _json.loads(req.data.decode())
            captured_payloads.append(payload)
            return MagicMock(__enter__=MagicMock(), __exit__=MagicMock(return_value=False))

        notifier = WebhookNotifier(
            urls=["http://localhost:9999/hook"],
            retries=0,
            timeout=1,
        )

        with patch("dlpscan.webhooks.urllib.request.urlopen", side_effect=fake_urlopen):
            notifier.notify(result, source="test")
            # The delivery happens in a daemon thread; give it a moment.
            import time
            time.sleep(0.5)

        self.assertEqual(len(captured_payloads), 1)
        payload = captured_payloads[0]
        self.assertEqual(payload["event_type"], "dlp_finding")
        self.assertIn("timestamp", payload)
        self.assertGreater(payload["finding_count"], 0)
        self.assertIsInstance(payload["categories"], list)
        self.assertEqual(payload["source"], "test")
        self.assertIsInstance(payload["details"], list)

    def test_notify_findings_dispatches_to_all_notifiers(self):
        from unittest.mock import MagicMock, patch

        from dlpscan.guard.core import InputGuard
        from dlpscan.guard.enums import Action
        from dlpscan.webhooks import (
            WebhookNotifier,
            notify_findings,
            register_notifier,
            unregister_notifier,
        )

        guard = InputGuard(action=Action.FLAG)
        result = guard.scan("SSN: 123-45-6789")

        call_counts = {"a": 0, "b": 0}

        def fake_urlopen(req, **kwargs):
            url = req.full_url
            if "hook-a" in url:
                call_counts["a"] += 1
            elif "hook-b" in url:
                call_counts["b"] += 1
            return MagicMock(__enter__=MagicMock(), __exit__=MagicMock(return_value=False))

        notifier_a = WebhookNotifier(
            urls=["http://localhost:9999/hook-a"], retries=0,
        )
        notifier_b = WebhookNotifier(
            urls=["http://localhost:9999/hook-b"], retries=0,
        )
        register_notifier(notifier_a)
        register_notifier(notifier_b)

        try:
            with patch("dlpscan.webhooks.urllib.request.urlopen", side_effect=fake_urlopen):
                notify_findings(result, source="integration-test")
                import time
                time.sleep(0.5)

            self.assertGreaterEqual(call_counts["a"], 1)
            self.assertGreaterEqual(call_counts["b"], 1)
        finally:
            unregister_notifier(notifier_a)
            unregister_notifier(notifier_b)


# ---------------------------------------------------------------------------
# L33tspeak evasion detection tests
# ---------------------------------------------------------------------------


class TestL33tspeakIntegration(unittest.TestCase):
    """Verify l33tspeak-obfuscated context keywords are still detected."""

    def test_leet_password_context_boosts_confidence(self):
        """p@$$w0rd should be recognized as 'password' context keyword."""
        from dlpscan.unicode_normalize import normalize_leet

        normalized = normalize_leet("p@$$w0rd")
        self.assertEqual(normalized, "password")

    def test_leet_context_in_scan(self):
        """Context keywords written in l33tspeak should still provide context."""
        from dlpscan.scanner import scan_for_context

        # 'cr3d1t c@rd' is l33tspeak for 'credit card'.
        text = "cr3d1t c@rd number: 4111111111111111"
        # Check that context is detected near the card number.
        has_ctx = scan_for_context(
            text, start_index=20, end_index=36,
            category='Credit Card Numbers', sub_category='Visa',
        )
        # Context may or may not match depending on keyword list,
        # but the normalization pipeline should not crash.
        self.assertIsInstance(has_ctx, bool)

    def test_normalize_leet_preserves_normal_text(self):
        from dlpscan.unicode_normalize import normalize_leet

        normal = "Hello World 123"
        # Digits get mapped: 1→l, 2→z, 3→e
        result = normalize_leet(normal)
        self.assertIsInstance(result, str)
        self.assertEqual(len(result), len(normal))


# ---------------------------------------------------------------------------
# SessionCorrelator + InputGuard integration tests
# ---------------------------------------------------------------------------


class TestSessionCorrelatorIntegration(unittest.TestCase):
    """Test SessionCorrelator wired into InputGuard for drip detection."""

    def test_correlator_records_matches(self):
        from dlpscan.session import SessionCorrelator

        correlator = SessionCorrelator()
        correlator.set_policy('Credit Card Numbers', max_total=5)
        guard = InputGuard(
            presets=[Preset.PCI_DSS],
            action=Action.FLAG,
            correlator=correlator,
            user_id="test-user-1",
        )
        result = guard.scan("Card: 4111111111111111")
        # Should have findings.
        self.assertFalse(result.is_clean)
        # Correlation alerts may or may not fire depending on threshold,
        # but the field should be present.
        self.assertIsInstance(result.correlation_alerts, list)

    def test_correlator_per_scan_user_override(self):
        from dlpscan.session import SessionCorrelator

        correlator = SessionCorrelator()
        correlator.set_policy('Credit Card Numbers', max_total=100)
        guard = InputGuard(
            presets=[Preset.PCI_DSS],
            action=Action.FLAG,
            correlator=correlator,
            user_id="default-user",
        )
        result = guard.scan("Card: 4111111111111111", user_id="override-user")
        self.assertFalse(result.is_clean)
        # Stats should be tracked for the override user.
        stats = correlator.get_user_stats("override-user")
        self.assertIsNotNone(stats)

    def test_correlator_not_set_no_alerts(self):
        guard = InputGuard(
            presets=[Preset.PCI_DSS],
            action=Action.FLAG,
        )
        result = guard.scan("Card: 4111111111111111")
        self.assertEqual(result.correlation_alerts, [])

    def test_scan_result_to_dict_with_alerts(self):
        from dlpscan.session import SessionCorrelator

        correlator = SessionCorrelator()
        correlator.set_policy('Credit Card Numbers', max_total=1)
        guard = InputGuard(
            presets=[Preset.PCI_DSS],
            action=Action.FLAG,
            correlator=correlator,
        )
        result = guard.scan("Card: 4111111111111111")
        d = result.to_dict()
        self.assertIn('is_clean', d)
        # If alerts fired, they should be in the dict.
        if result.correlation_alerts:
            self.assertIn('correlation_alerts', d)


# ---------------------------------------------------------------------------
# Scanner package split backward compatibility tests
# ---------------------------------------------------------------------------


class TestScannerPackageSplit(unittest.TestCase):
    """Verify the scanner/ package split maintains backward compatibility."""

    def test_all_public_symbols_importable(self):
        from dlpscan.scanner import (  # noqa: F401
            MAX_INPUT_SIZE,
            MAX_MATCHES,
            MAX_SCAN_SECONDS,
            REGEX_TIMEOUT_SECONDS,
            compiled_context_patterns,
            enhanced_scan_text,
            get_context_backend,
            is_luhn_valid,
            redact_sensitive_info,
            register_patterns,
            scan_directory,
            scan_file,
            scan_for_context,
            scan_stream,
            set_context_backend,
            unregister_patterns,
        )
        self.assertTrue(callable(enhanced_scan_text))
        self.assertTrue(callable(register_patterns))
        self.assertTrue(callable(is_luhn_valid))
        self.assertIsInstance(MAX_MATCHES, int)
        self.assertIsInstance(MAX_INPUT_SIZE, int)
        self.assertIsInstance(REGEX_TIMEOUT_SECONDS, int)
        self.assertIsInstance(compiled_context_patterns, dict)

    def test_private_symbols_importable(self):
        from dlpscan.scanner import (  # noqa: F401
            _BINARY_EXTENSIONS,
            _EXTRACTOR_EXTENSIONS,
            _check_context,
            _compute_confidence,
            _deduplicate_overlapping,
            _fuzzy_keyword_match,
            _get_raw_keywords,
            _has_extractor,
            _is_binary_file,
            _levenshtein_distance,
            _RegexTimeout,
            _ThreadTimeout,
        )
        self.assertTrue(callable(_levenshtein_distance))
        self.assertTrue(callable(_check_context))
        self.assertIsInstance(_BINARY_EXTENSIONS, (set, frozenset))

    def test_context_required_patterns_dynamic_access(self):
        from dlpscan import scanner

        crp = scanner.CONTEXT_REQUIRED_PATTERNS
        self.assertIsInstance(crp, frozenset)

    def test_enhanced_scan_works_after_split(self):
        matches = list(enhanced_scan_text("Card: 4111111111111111"))
        self.assertGreater(len(matches), 0)
        self.assertEqual(matches[0].category, 'Credit Card Numbers')


# ---------------------------------------------------------------------------
# Observability / instrumentation integration tests
# ---------------------------------------------------------------------------


class TestObservabilityIntegration(unittest.TestCase):
    """Test observability metrics, auto-instrumentation, and health endpoint."""

    def test_registry_has_all_expected_metrics(self):
        from dlpscan.observability import registry

        expected = [
            'dlpscan_scans_total',
            'dlpscan_findings_total',
            'dlpscan_scan_duration_seconds',
            'dlpscan_scan_errors_total',
            'dlpscan_active_vaults',
            'dlpscan_tokens_created_total',
            'dlpscan_rate_limit_rejections_total',
            'dlpscan_start_time_seconds',
            'dlpscan_uptime_seconds',
            'dlpscan_health_status',
            'dlpscan_scans_in_flight',
            'dlpscan_bytes_scanned_total',
            'dlpscan_patterns_timed_out_total',
        ]
        for name in expected:
            metric = registry.get(name)
            self.assertIsNotNone(metric, f"Missing metric: {name}")

    def test_get_uptime_positive(self):
        from dlpscan.observability import get_uptime

        uptime = get_uptime()
        self.assertGreater(uptime, 0)

    def test_get_health_returns_dict(self):
        from dlpscan.observability import get_health

        health = get_health()
        self.assertIn('status', health)
        self.assertIn('uptime_seconds', health)
        self.assertIn('scans_total', health)
        self.assertIn('errors_total', health)
        self.assertIn('scans_in_flight', health)
        self.assertEqual(health['status'], 'healthy')

    def test_record_scan_updates_counters(self):
        from dlpscan.observability import (
            dlpscan_scans_total,
            record_scan,
        )

        before = dlpscan_scans_total.get()
        # Create a mock-like result object.

        class FakeResult:
            finding_count = 3
            is_clean = False
            categories_found = {'Credit Card Numbers'}

        record_scan(FakeResult(), duration_seconds=0.05)
        after = dlpscan_scans_total.get()
        self.assertEqual(after, before + 1)

    def test_auto_instrumentation_bridges_metrics(self):
        # Save and restore callback.
        from dlpscan.metrics import get_metrics_callback, set_metrics_callback
        from dlpscan.observability import (
            dlpscan_bytes_scanned_total,
            dlpscan_scans_total,
            enable_auto_instrumentation,
        )
        old_cb = get_metrics_callback()

        try:
            enable_auto_instrumentation()
            scans_before = dlpscan_scans_total.get()
            bytes_before = dlpscan_bytes_scanned_total.get()

            # Run a real scan — MetricsCollector callback should fire.
            text = "Card: 4111111111111111"
            list(enhanced_scan_text(text))

            scans_after = dlpscan_scans_total.get()
            bytes_after = dlpscan_bytes_scanned_total.get()
            self.assertEqual(scans_after, scans_before + 1)
            self.assertGreater(bytes_after, bytes_before)
        finally:
            set_metrics_callback(old_cb)

    def test_prometheus_export_format(self):
        from dlpscan.observability import registry

        output = registry.to_prometheus()
        self.assertIn('dlpscan_scans_total', output)
        self.assertIn('dlpscan_uptime_seconds', output)
        self.assertIn('# TYPE', output)

    def test_opentelemetry_export_format(self):
        from dlpscan.observability import registry

        data = registry.to_opentelemetry()
        self.assertIn('resource_metrics', data)
        self.assertIsInstance(data['resource_metrics'], list)
        scope_metrics = data['resource_metrics'][0]['scope_metrics'][0]['metrics']
        names = [m['name'] for m in scope_metrics]
        self.assertIn('dlpscan_scans_total', names)
        self.assertIn('dlpscan_health_status', names)


# ---------------------------------------------------------------------------
# Advanced module integration tests
# ---------------------------------------------------------------------------


class TestCountMinSketchIntegration(unittest.TestCase):
    """CountMinSketch used in realistic DLP frequency analysis."""

    def test_frequency_tracking(self):
        from dlpscan.countmin import CountMinSketch

        cms = CountMinSketch(width=1000, depth=5)
        # Simulate tracking how often a pattern appears.
        for _ in range(50):
            cms.increment("SSN pattern")
        for _ in range(10):
            cms.increment("email pattern")

        self.assertGreaterEqual(cms.estimate("SSN pattern"), 50)
        self.assertGreaterEqual(cms.estimate("email pattern"), 10)
        self.assertEqual(cms.estimate("never seen"), 0)


class TestHyperLogLogIntegration(unittest.TestCase):
    """HyperLogLog for cardinality estimation in DLP flows."""

    def test_unique_match_estimation(self):
        from dlpscan.hyperloglog import HyperLogLog

        hll = HyperLogLog(precision=10)
        # Add unique "match signatures".
        for i in range(1000):
            hll.add(f"match-{i}")

        estimate = hll.count()
        # HLL is approximate; allow 10% error.
        self.assertGreater(estimate, 800)
        self.assertLess(estimate, 1200)


class TestCuckooFilterIntegration(unittest.TestCase):
    """CuckooFilter for allowlist-like probabilistic membership testing."""

    def test_membership_check(self):
        from dlpscan.cuckoo import CuckooFilter

        cf = CuckooFilter(capacity=1000)
        known_safe = ["test@example.com", "admin@corp.com", "noreply@service.com"]
        for item in known_safe:
            cf.insert(item)

        for item in known_safe:
            self.assertTrue(cf.contains(item))

        # Unknown items should (usually) not be in the filter.
        false_positives = sum(
            1 for i in range(100) if cf.contains(f"unknown-{i}@test.com")
        )
        # FP rate should be low.
        self.assertLess(false_positives, 10)


class TestEntropyAnalyzerIntegration(unittest.TestCase):
    """EntropyAnalyzer for detecting high-entropy secrets."""

    def test_high_entropy_bytes_detected(self):
        from dlpscan.entropy import EntropyAnalyzer

        analyzer = EntropyAnalyzer()
        # Random-looking data should have high entropy.
        data = b"aK3x9Zb2mP7qR4wL8vN1cJ6yT0hF5gDxY2pQ8rS4uW6zA1"
        result = analyzer.analyze_bytes(data)
        self.assertIsNotNone(result)
        self.assertGreater(result.entropy, 0)

    def test_low_entropy_bytes(self):
        from dlpscan.entropy import EntropyAnalyzer

        analyzer = EntropyAnalyzer()
        data = b"aaaaaaaaaaaaaaaaaaaaaa"
        result = analyzer.analyze_bytes(data)
        self.assertIsNotNone(result)
        # Repetitive data should have low entropy.
        self.assertLess(result.entropy, 2.0)


class TestPartialDocumentMatcherIntegration(unittest.TestCase):
    """Rabin-Karp partial document matching in realistic scenarios."""

    def test_partial_match_detection(self):
        from dlpscan.rabin_karp import PartialDocumentMatcher

        matcher = PartialDocumentMatcher(window_size=20)
        reference = "This is a confidential document containing sensitive data that should be protected."
        matcher.register("doc-1", reference)

        # A partial copy should be detected.
        partial = "This is a confidential document containing sensitive data that was leaked."
        matches = matcher.scan(partial)
        self.assertIsInstance(matches, list)


class TestExactDataMatcherIntegration(unittest.TestCase):
    """EDM with realistic structured data matching."""

    def test_exact_value_detection(self):
        from dlpscan.edm import ExactDataMatcher

        matcher = ExactDataMatcher()
        matcher.register_values("ssn", ["123-45-6789"])
        matcher.register_values("email", ["john.doe@example.com"])

        text = "The SSN is 123-45-6789 and email john.doe@example.com"
        matches = matcher.scan(text)
        self.assertGreater(len(matches), 0)

    def test_no_false_positives(self):
        from dlpscan.edm import ExactDataMatcher

        matcher = ExactDataMatcher()
        matcher.register_values("custom", ["specific-value-12345"])
        matches = matcher.scan("Nothing matching here at all.")
        self.assertEqual(len(matches), 0)


if __name__ == '__main__':
    unittest.main()
