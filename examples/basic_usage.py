"""Basic usage examples for dlpscan's InputGuard.

Demonstrates standalone scanning, preset selection, allowlist/denylist modes,
custom categories, decorator-based protection, sanitization, and callbacks.

Run:
    python -m examples.basic_usage
"""

from dlpscan.guard import InputGuard, Preset, Action, Mode, InputGuardError, ScanResult


# ---------------------------------------------------------------------------
# 1. Simple scanning — reject mode (default)
# ---------------------------------------------------------------------------

def simple_scan_example():
    """Scan text and reject if sensitive data is found."""
    guard = InputGuard(presets=[Preset.PCI_DSS])

    # Clean text passes without issue.
    result = guard.scan("Hello, this is a normal message.")
    print(f"Clean text  -> is_clean={result.is_clean}, findings={result.finding_count}")

    # Text with a credit card number triggers InputGuardError.
    try:
        guard.scan("Please charge card 4532015112830366 for the order.")
    except InputGuardError as exc:
        print(f"Rejected    -> {exc}")
        print(f"  categories: {sorted(exc.result.categories_found)}")
        print(f"  findings:   {exc.result.finding_count}")


# ---------------------------------------------------------------------------
# 2. Preset combinations
# ---------------------------------------------------------------------------

def preset_example():
    """Combine multiple presets to widen detection coverage."""
    guard = InputGuard(
        presets=[Preset.PCI_DSS, Preset.SSN_SIN, Preset.CREDENTIALS],
        action=Action.FLAG,  # Do not reject; just flag findings.
    )

    text = "SSN 078-05-1120, card 4532015112830366, token ghp_abc123def456ghi789"
    result = guard.scan(text)
    print(f"Flagged {result.finding_count} finding(s) across: {sorted(result.categories_found)}")
    for finding in result.findings:
        print(f"  - [{finding.category}] confidence={finding.confidence:.2f}")


# ---------------------------------------------------------------------------
# 3. Denylist vs. Allowlist modes
# ---------------------------------------------------------------------------

def denylist_example():
    """Denylist mode blocks the specified categories and allows everything else."""
    guard = InputGuard(
        presets=[Preset.PCI_DSS],
        mode=Mode.DENYLIST,
        action=Action.FLAG,
    )
    result = guard.scan("Card 4532015112830366, SSN 078-05-1120")
    # Only credit card findings are flagged; SSN is ignored because PCI_DSS
    # does not include SSN categories.
    print(f"Denylist -> flagged categories: {sorted(result.categories_found)}")


def allowlist_example():
    """Allowlist mode allows only the specified categories; everything else is blocked."""
    # Only allow contact info — block all other sensitive data types.
    guard = InputGuard(
        presets=[Preset.CONTACT_INFO],
        mode=Mode.ALLOWLIST,
        action=Action.FLAG,
    )
    result = guard.scan("Card 4532015112830366, email user@example.com")
    # Contact info is allowed (not flagged), but credit card data IS flagged
    # because it is not in the allowlist.
    print(f"Allowlist -> flagged categories: {sorted(result.categories_found)}")


# ---------------------------------------------------------------------------
# 4. Custom categories (without presets)
# ---------------------------------------------------------------------------

def custom_categories_example():
    """Specify exact category names instead of using presets."""
    guard = InputGuard(
        categories={"Credit Card Numbers", "Banking and Financial"},
        action=Action.FLAG,
    )
    result = guard.scan("Card 4532015112830366, IBAN GB29NWBK60161331926819")
    print(f"Custom categories -> {sorted(result.categories_found)}, "
          f"findings={result.finding_count}")


# ---------------------------------------------------------------------------
# 5. Decorator-based protection
# ---------------------------------------------------------------------------

def decorator_example():
    """Protect individual functions using the @guard.protect decorator."""
    # REJECT mode: InputGuardError is raised before the function body runs.
    guard = InputGuard(
        presets=[Preset.PCI_DSS, Preset.SSN_SIN],
        action=Action.REJECT,
    )

    @guard.protect(param="user_input")
    def process_form(user_id: int, user_input: str):
        """Only reached when user_input is clean."""
        return f"Saved input from user {user_id}: {user_input}"

    # Clean input goes through.
    print(process_form(42, "Just a regular comment"))

    # Sensitive input is rejected before process_form executes.
    try:
        process_form(42, "My SSN is 078-05-1120")
    except InputGuardError as exc:
        print(f"Decorator blocked call: {exc}")

    # REDACT mode: sensitive data is replaced before the function runs.
    redact_guard = InputGuard(
        presets=[Preset.PCI_DSS],
        action=Action.REDACT,
        redaction_char="*",
    )

    @redact_guard.protect(param="comment")
    def save_comment(comment: str):
        return f"Stored: {comment}"

    print(save_comment("Pay with 4532015112830366 please"))


# ---------------------------------------------------------------------------
# 6. Sanitization (always redact, never raise)
# ---------------------------------------------------------------------------

def sanitize_example():
    """Use sanitize() to always get clean text back, regardless of action setting."""
    guard = InputGuard(
        presets=[Preset.PCI_DSS, Preset.CREDENTIALS],
        redaction_char="X",
    )

    dirty = "Card 4532015112830366, key ghp_abc123def456ghi789jkl012mno345pqr678"
    clean = guard.sanitize(dirty)
    print(f"Original:  {dirty}")
    print(f"Sanitized: {clean}")

    # sanitize() never raises, even when action=REJECT.
    clean_safe = guard.sanitize("Nothing sensitive here.")
    print(f"Clean input returned as-is: {clean_safe}")


# ---------------------------------------------------------------------------
# 7. Quick boolean check
# ---------------------------------------------------------------------------

def check_example():
    """Use check() for a fast pass/fail decision without exception handling."""
    guard = InputGuard(presets=[Preset.PCI_DSS])

    texts = [
        "Normal message",
        "Card 4532015112830366",
    ]
    for text in texts:
        ok = guard.check(text)
        print(f"check({text!r:.40}) -> {ok}")


# ---------------------------------------------------------------------------
# 8. Callback on detection
# ---------------------------------------------------------------------------

def callback_example():
    """Register a callback that fires whenever sensitive data is detected."""
    alerts = []

    def on_detect(result: ScanResult):
        """Called each time guard.scan() finds sensitive data."""
        alerts.append({
            "categories": sorted(result.categories_found),
            "count": result.finding_count,
        })

    guard = InputGuard(
        presets=[Preset.PCI_DSS],
        action=Action.FLAG,  # FLAG so scan() does not raise.
        on_detect=on_detect,
    )

    guard.scan("Nothing here.")
    guard.scan("Card 4532015112830366")
    guard.scan("Another card: 5425233430109903")

    print(f"Callback fired {len(alerts)} time(s):")
    for alert in alerts:
        print(f"  {alert}")


# ---------------------------------------------------------------------------
# 9. Confidence threshold filtering
# ---------------------------------------------------------------------------

def confidence_example():
    """Filter out low-confidence matches with min_confidence."""
    # Low threshold — more findings, potentially more false positives.
    guard_low = InputGuard(
        presets=[Preset.PII],
        action=Action.FLAG,
        min_confidence=0.3,
    )
    # High threshold — only high-confidence matches.
    guard_high = InputGuard(
        presets=[Preset.PII],
        action=Action.FLAG,
        min_confidence=0.9,
    )

    text = "John Doe, SSN 078-05-1120, DOB 1990-01-15"
    low_result = guard_low.scan(text)
    high_result = guard_high.scan(text)
    print(f"min_confidence=0.3 -> {low_result.finding_count} finding(s)")
    print(f"min_confidence=0.9 -> {high_result.finding_count} finding(s)")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    sections = [
        ("1. Simple scanning", simple_scan_example),
        ("2. Preset combinations", preset_example),
        ("3a. Denylist mode", denylist_example),
        ("3b. Allowlist mode", allowlist_example),
        ("4. Custom categories", custom_categories_example),
        ("5. Decorator protection", decorator_example),
        ("6. Sanitization", sanitize_example),
        ("7. Quick boolean check", check_example),
        ("8. Detection callbacks", callback_example),
        ("9. Confidence threshold", confidence_example),
    ]

    for title, fn in sections:
        print(f"\n{'='*60}")
        print(f"  {title}")
        print(f"{'='*60}")
        fn()
