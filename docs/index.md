# dlpscan

**High-performance enterprise DLP scanner written in Rust.**

dlpscan detects, redacts, tokenizes, and obfuscates sensitive data in text, files,
and streams. Built for developers and security teams who need production-grade data
loss prevention with exceptional throughput (30-64x faster than the Python version).

## Key Features

- **560 detection patterns** across **126 categories** — Credit cards, SSNs, IBANs, API keys, PII, and more across 80+ countries
- **2,718 context keywords** — Proximity-based detection boosting with Aho-Corasick prefilter
- **5-stage Unicode normalization** — Defeats evasion via zero-width chars, combining marks, homoglyphs, and 1,650+ confusable mappings
- **Multiple actions** — Reject, redact, tokenize (reversible), or obfuscate (irreversible with realistic fake data)
- **InputGuard API** — Drop-in protection for application inputs with compliance presets (PCI-DSS, HIPAA, PII, etc.)
- **REST API** — Async HTTP server with per-IP rate limiting, TLS, and API key auth
- **Enterprise ready** — Audit logging, RBAC, SIEM integration (Splunk, Elasticsearch, Syslog, Datadog), compliance reporting
- **Observable** — Prometheus metrics with `/metrics` endpoint
- **Security hardened** — SSRF protection, input validation, header injection prevention, constant-time auth
- **Batch processing** — CSV, JSON/JSONL parallel batch scanning with Rayon
- **20+ file formats** — DOCX, XLSX, PDF, EML, MBOX, ICS, WARC, ZIP, RAR, 7z, Parquet, SQLite, and more

## Quick Example

```rust
use dlpscan::{InputGuard, Preset, Action};

let guard = InputGuard::new()
    .with_presets(vec![Preset::PciDss])
    .with_action(Action::Redact);

let result = guard.scan("My card is 4111-1111-1111-1111")?;
println!("{}", result.redacted_text.unwrap()); // "My card is XXXXXXXXXXXXXXXX"
```

## Installation

```bash
cargo build --release
```

See [Installation](getting-started/installation.md) for feature flags and optional dependencies.

## Reference

- [Pattern Reference](../PATTERNS.md) — Complete inventory of all 560 detection patterns
- [Keywords Reference](../KEYWORDS.md) — Complete inventory of all 2,718 context keywords

## License

MIT License. See [LICENSE](https://github.com/oxide11/dlpscan/blob/main/LICENSE) for details.
