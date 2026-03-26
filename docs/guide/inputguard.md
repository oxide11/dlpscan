# InputGuard

The `InputGuard` is the primary API for protecting application inputs against data leakage.

## Basic Usage

```python
from dlpscan import InputGuard, Preset, Action, Mode

guard = InputGuard(
    presets=[Preset.PCI_DSS, Preset.SSN_SIN],
    action=Action.REJECT,
    min_confidence=0.5,
)

result = guard.scan("My card is 4532015112830366")
# Raises InputGuardError with details
```

## Constructor Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `presets` | `List[Preset]` | `None` | Compliance presets to activate |
| `categories` | `Set[str]` | `None` | Explicit category names to scan |
| `mode` | `Mode` | `DENYLIST` | DENYLIST (block listed) or ALLOWLIST (allow only listed) |
| `action` | `Action` | `REJECT` | What to do on detection |
| `min_confidence` | `float` | `0.0` | Ignore findings below this threshold |
| `require_context` | `bool` | `False` | Only flag matches with context keywords nearby |
| `redaction_char` | `str` | `"X"` | Character used for redaction |
| `allowlist` | `Allowlist` | `None` | Known false positives to suppress |
| `on_detect` | `Callable` | `None` | Callback when sensitive data is found |
| `custom_patterns` | `Dict` | `None` | Custom regex patterns to register |
| `confidence_overrides` | `Dict` | `None` | Per-category confidence thresholds |
| `token_vault` | `TokenVault` | `None` | Custom vault for tokenization |

## Actions

| Action | Behavior |
|--------|----------|
| `REJECT` | Raises `InputGuardError` |
| `REDACT` | Replaces with redaction characters |
| `FLAG` | Returns findings but passes text through |
| `TOKENIZE` | Replaces with reversible tokens |
| `OBFUSCATE` | Replaces with realistic fake data |

## Presets

| Preset | Categories |
|--------|------------|
| `PCI_DSS` | Credit cards, PANs, track data, expiration dates |
| `SSN_SIN` | US SSN, US ITIN, Canada SIN |
| `CREDENTIALS` | API keys, tokens, secrets, cloud credentials |
| `PII` | Email, phone, SSN, geolocation, device IDs |
| `HIPAA` | Medical identifiers, insurance IDs |
| `FINANCIAL` | Banking, wire transfer, IBAN, securities |

## Methods

### `scan(text) -> ScanResult`

Scan text and apply the configured action.

### `check(text) -> bool`

Quick boolean check. Returns `True` if text is clean.

### `sanitize(text) -> str`

Always returns redacted text regardless of configured action.

### `tokenize(text) -> Tuple[str, TokenVault]`

Scan and replace with reversible tokens.

### `obfuscate(text) -> str`

Scan and replace with realistic fake data.

### `detokenize(text) -> str`

Reverse tokenization using the guard's vault.

### `protect(param=None, params=None)`

Decorator that scans function arguments before execution.

## Custom Patterns

```python
with InputGuard(
    custom_patterns={
        "Internal IDs": {
            "Employee ID": r"EMP-\d{6}",
            "Project Code": r"PRJ-[A-Z]{3}-\d{4}",
        }
    },
    action=Action.REDACT,
) as guard:
    result = guard.scan("Employee EMP-123456 on PRJ-ABC-1234")
```

## Per-Category Confidence

```python
guard = InputGuard(
    presets=[Preset.PCI_DSS, Preset.PII],
    confidence_overrides={
        "Credit Card Numbers": 0.8,
        "Contact Information": 0.3,
    },
)
```
