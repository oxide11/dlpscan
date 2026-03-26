# dlpscan

**Enterprise data security scanning and protection SDK for Python.**

dlpscan detects, redacts, tokenizes, and obfuscates sensitive data in text, files, and streams. Built for developers and security teams who need production-grade data loss prevention.

## Key Features

- **800+ detection patterns** — Credit cards, SSNs, IBANs, API keys, PII, and more across 80+ countries
- **Multiple actions** — Reject, redact, tokenize (reversible), or obfuscate (irreversible)
- **InputGuard API** — Drop-in protection for application inputs with compliance presets
- **REST API** — FastAPI server for language-agnostic integration
- **Policy-as-code** — YAML policy definitions for version-controlled security rules
- **Enterprise ready** — Audit logging, RBAC, SIEM integration, compliance reporting
- **Observable** — Prometheus metrics, OpenTelemetry support
- **Batch processing** — Scan CSV, JSON, databases, and DataFrames at scale

## Quick Example

```python
from dlpscan import InputGuard, Preset, Action

guard = InputGuard(presets=[Preset.PCI_DSS], action=Action.REDACT)
result = guard.scan("My card is 4111-1111-1111-1111")
print(result.redacted_text)  # "My card is XXXX-XXXX-XXXX-XXXX"
```

## Installation

```bash
pip install dlpscan
```

See [Installation](getting-started/installation.md) for extras and optional dependencies.

## License

MIT License. See [LICENSE](https://github.com/oxide11/dlpscan/blob/main/LICENSE) for details.
