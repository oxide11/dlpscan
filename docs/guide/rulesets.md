# YAML Scan Rulesets

Rulesets are YAML configuration files that define **what** dlpscan should scan
for by selecting patterns from the catalog, setting actions and thresholds,
and optionally adding custom patterns and allowlists.

## Quick Start

```python
from dlpscan.rulesets import load_ruleset

ruleset = load_ruleset("rulesets/pci-production.yaml")
result = ruleset.scan("Card: 4111-1111-1111-1111")

if not result.is_clean:
    print(f"Found {len(result.findings)} issues")
```

## Ruleset Structure

```yaml
name: PCI Production                    # Required
description: PCI-DSS compliance scan    # Optional
version: "1"                            # Optional

# --- Pattern Selection ---
baselines:                              # Select by control baseline
  - pci
  - source_code_secrets

presets:                                # Select by preset
  - pci_dss

categories:                             # Select individual categories
  - Credit Card Numbers
  - Banking Authentication

exclude_categories:                     # Remove specific categories
  - Check and MICR Data

# --- Global Settings ---
action: reject        # reject | redact | flag | tokenize | obfuscate
mode: denylist         # denylist | allowlist
min_confidence: 0.6    # Minimum confidence threshold (0.0 - 1.0)
require_context: false # Require keyword context for matches
redaction_char: "X"    # Character used for redaction

# --- Per-Category Overrides ---
overrides:
  - category: Card Expiration Dates
    min_confidence: 0.8
    require_context: true
  - category: Dates
    enabled: false           # Disable this category entirely

# --- Custom Patterns ---
custom_patterns:
  - name: Internal Project Code
    regex: 'PROJ-[A-Z]{2,4}-\d{4,8}'
    category: Custom Identifiers
    confidence: 0.9
    keywords:
      - project
      - code
    keyword_proximity: 50

# --- Allowlist ---
allowlist:
  - "4111-1111-1111-1111"    # Test card
  - "000-00-0000"            # Placeholder SSN
```

## Pattern Selection

Patterns are selected through three mechanisms, which are combined (union):

### Baselines

Baselines are predefined groups aligned to compliance control objectives:

| Baseline | Description |
|----------|-------------|
| `pii` | Personal identifiers, contact info, biometrics, employment data |
| `pii_regional` | Region-specific IDs (SSN, NHS, Aadhaar, etc.) |
| `pci` | Credit cards, PANs, track data, payment secrets |
| `phi` | Medical IDs, health plan data, HIPAA identifiers |
| `internal_financial` | Banking, wire transfers, securities, crypto, regulatory |
| `source_code_secrets` | API keys, tokens, credentials, connection strings |
| `confidential_documents` | Classification labels, privilege markings, regulatory designations |

```python
from dlpscan.rulesets import available_baselines
print(available_baselines())
```

### Presets

Presets from the existing InputGuard preset system:

| Preset | Description |
|--------|-------------|
| `pci_dss` | PCI-DSS focused patterns |
| `ssn_sin` | SSN and SIN detection |
| `pii` | General PII |
| `pii_strict` | Strict PII with context |
| `credentials` | Credentials and secrets |
| `financial` | Financial data |
| `healthcare` | Healthcare data |
| `contact_info` | Contact information |

### Categories

Individual categories from the pattern catalog:

```python
from dlpscan.rulesets import available_categories
print(available_categories())  # Lists all ~60+ categories
```

## Actions

| Action | Behavior |
|--------|----------|
| `reject` | Block the input entirely |
| `redact` | Replace sensitive data with redaction characters |
| `flag` | Allow through but report findings |
| `tokenize` | Replace with reversible tokens |
| `obfuscate` | Replace with realistic fake data |

## Per-Category Overrides

Override settings for specific categories:

```yaml
overrides:
  - category: Credit Card Numbers
    action: reject              # Override global action
    min_confidence: 0.9         # Higher confidence threshold
    require_context: false      # Don't require keywords
  - category: Postal Codes
    enabled: false              # Disable entirely
```

## Custom Patterns

Add inline regex patterns:

```yaml
custom_patterns:
  - name: Employee Badge ID
    regex: 'EMP-\d{6}'
    category: Employee Identifiers
    confidence: 0.95
    keywords:
      - employee
      - badge
      - id
    keyword_proximity: 40
```

## Loading Rulesets

### From a File

```python
from dlpscan.rulesets import load_ruleset

ruleset = load_ruleset("rulesets/pci-production.yaml")
guard = ruleset.to_guard()
result = guard.scan(text)
```

### From a String

```python
from dlpscan.rulesets import load_ruleset_from_string

yaml_config = """
name: Quick PCI Check
baselines:
  - pci
action: flag
"""

ruleset = load_ruleset_from_string(yaml_config)
result = ruleset.scan(text)
```

### Inspecting a Ruleset

```python
import json
print(json.dumps(ruleset.summary(), indent=2))
```

Output:
```json
{
  "name": "PCI Production",
  "action": "reject",
  "total_categories": 8,
  "categories": ["Card Expiration Dates", "Credit Card Numbers", ...],
  "custom_patterns": 0,
  "allowlist_entries": 3
}
```

## Built-in Rulesets

dlpscan ships with ready-to-use rulesets in the `rulesets/` directory:

| File | Baseline | Action |
|------|----------|--------|
| `pci-production.yaml` | PCI | reject |
| `pii-standard.yaml` | PII | flag |
| `phi-hipaa.yaml` | PHI | redact |
| `financial-internal.yaml` | Internal Financial | flag |
| `secrets-cicd.yaml` | Source Code Secrets | reject |
| `confidential-docs.yaml` | Confidential Documents | flag |
| `comprehensive.yaml` | All baselines | flag |

## Advanced: Converting to InputGuard

The `to_guard()` method creates a fully configured `InputGuard`:

```python
ruleset = load_ruleset("rulesets/pci-production.yaml")
guard = ruleset.to_guard()

# Use all InputGuard features
result = guard.scan(text)
guard.protect(my_function)(text)
```

## JSON Support

Rulesets can also be written in JSON format:

```json
{
  "name": "PCI Check",
  "baselines": ["pci"],
  "action": "reject",
  "min_confidence": 0.7
}
```

Load the same way:
```python
ruleset = load_ruleset("rulesets/my-ruleset.json")
```
