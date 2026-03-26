# Policy Engine

Define scanning policies in YAML for version-controlled, auditable security configuration.

## Policy File Format

```yaml
version: "1"
name: "pci-production"
description: "PCI-DSS production scanning policy"

scan:
  presets:
    - pci_dss
    - ssn_sin
  action: reject
  mode: denylist
  min_confidence: 0.5
  require_context: true
  redaction_char: "X"

rules:
  - name: block-credit-cards
    match:
      categories:
        - "Credit Card Numbers"
        - "Primary Account Numbers"
    action: reject
    min_confidence: 0.8

  - name: redact-emails
    match:
      categories:
        - "Contact Information"
    action: redact
    min_confidence: 0.3

audit:
  enabled: true
  file: /var/log/dlp-audit.jsonl

rate_limit:
  max_requests: 100
  window_seconds: 60
```

## Usage

```python
from dlpscan.policy import load_policy, PolicyEngine

policy = load_policy("policies/pci-production.yml")
engine = PolicyEngine(policy)

# Scan with policy
result = engine.scan("Card: 4111111111111111")

# Or get a configured guard
guard = engine.create_guard()
```

## Policy Directory

Load all policies from a directory:

```python
from dlpscan.policy import load_policies_from_dir

policies = load_policies_from_dir("policies/")
engine = PolicyEngine(policies["pci-production"])
```

## Validation

```python
from dlpscan.policy import validate_policy

warnings = validate_policy(policy)
for w in warnings:
    print(f"Warning: {w}")
```

## Rules

Rules override the default scan action for specific categories:

```yaml
rules:
  - name: strict-credit-cards
    match:
      categories: ["Credit Card Numbers"]
    action: reject
    min_confidence: 0.9

  - name: lenient-emails
    match:
      categories: ["Contact Information"]
      sub_categories: ["Email Address"]
    action: flag
    min_confidence: 0.2
```
