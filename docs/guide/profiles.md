# Masking Profiles

Masking profiles are named, reusable configurations that bundle presets, actions, and confidence settings.

## Built-in Profiles

| Profile | Action | Presets | Confidence | Context |
|---------|--------|---------|------------|---------|
| `pci-production` | reject | PCI-DSS | 0.7 | Required |
| `pci-development` | obfuscate | PCI-DSS | 0.3 | No |
| `hipaa-strict` | reject | HIPAA | 0.5 | No |
| `hipaa-redact` | redact | HIPAA | 0.3 | No |
| `gdpr-compliance` | tokenize | PII | 0.3 | No |
| `soc2-secrets` | reject | Credentials | 0.5 | No |
| `full-scan` | flag | All | 0.0 | No |
| `development` | obfuscate | All | 0.3 | No |
| `ci-pipeline` | reject | All | 0.5 | Required |

## Usage

```python
from dlpscan.profiles import get_profile, list_profiles

# List available profiles
print(list_profiles())

# Use a profile
profile = get_profile("pci-production")
guard = profile.to_guard()
result = guard.scan("Card: 4111111111111111")
```

## Custom Profiles

```python
from dlpscan.profiles import MaskingProfile, register_profile

profile = MaskingProfile(
    name="my-custom",
    description="Custom scan for internal use",
    presets=["pci_dss", "credentials"],
    action="redact",
    min_confidence=0.6,
    confidence_overrides={"Credit Card Numbers": 0.9},
)
register_profile(profile)
```

## Saving & Loading

```python
from dlpscan.profiles import ProfileRegistry

registry = ProfileRegistry()
registry.save_to_file("profiles.json")
registry.load_from_file("profiles.json")
```
