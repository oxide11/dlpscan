# Security Hardening

dlpscan includes comprehensive security controls to protect against common
attack vectors. This page documents the measures in place and how to
configure them.

## API Security

### Authentication

The REST API supports API key authentication via the `X-API-Key` header.
Set the `DLPSCAN_API_KEY` environment variable to enable it:

```bash
export DLPSCAN_API_KEY="your-secret-key-here"
```

Key validation uses constant-time comparison via SHA-256 hash comparison
to prevent timing side-channel attacks.

!!! warning
    When `DLPSCAN_API_KEY` is not set, authentication is **disabled**.
    Always set this variable in production.

### Per-IP Rate Limiting

The API server enforces per-IP sliding-window rate limiting. Each client
IP address is tracked independently with configurable request limits:

```bash
export DLPSCAN_API_RATE_LIMIT=100  # requests per 60-second window
```

The rate limiter automatically evicts stale IP entries (max 10,000 tracked
IPs) to prevent memory exhaustion from distributed clients.

### Request Size Limits

| Limit | Value |
|---|---|
| Single scan text | 10 MB |
| Batch scan items | 1,000 items |
| Batch item text | 10 MB each |
| HTTP request body | 10 MB |
| Custom patterns | 100 max |
| Pattern regex length | 4,096 chars |
| Pattern name/category | 256 chars |
| Confidence range | 0.0–1.0 |

### Connection Limits

The server enforces a maximum of **256 concurrent connections**. Excess
connections receive `503 Service Unavailable` immediately.

### Error Sanitization

API error responses never expose internal exception details. All
unhandled errors return structured JSON error messages while full details
are logged server-side with request correlation IDs.

### Data Leak Prevention

`ScanResult.text` is annotated with `#[serde(skip_serializing)]` to
prevent the original sensitive input text from appearing in JSON API
responses, logs, or serialized output.

### Metrics Endpoint

The Prometheus metrics exporter is available at `GET /metrics` (requires
the `metrics` feature). It does not require authentication, so it should
not be exposed to untrusted networks.

## SSRF Protection

All outbound URL destinations are validated against private/internal
ranges before any HTTP request is made:

- **RFC 1918** private ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- **Loopback**: `127.0.0.0/8`, `::1`
- **Link-local**: `169.254.0.0/16`, `fe80::/10`
- **Zero address**: `0.0.0.0/8`
- **IPv4-mapped IPv6**: `::ffff:0:0/96` (with private IPv4)
- **Localhost hostnames**: `localhost`, `localhost.localdomain`

This protection applies to:

- Webhook notification URLs (`WebhookNotifier`)
- SIEM adapter URLs (Splunk HEC, Elasticsearch, webhook, Datadog)
- URLs added at construction time and via `add_url()`

### HTTP Header Injection

Raw HTTP request construction in SIEM adapters validates all header
key/value pairs for CR (`\r`), LF (`\n`), and NUL (`\0`) characters.
Headers containing these characters are silently skipped with a warning log.

## Unicode Evasion Defense

dlpscan implements a 5-stage normalization pipeline to defeat Unicode-based
evasion attempts:

| Stage | Operation | Details |
|---|---|---|
| 1 | Invisible character strip | Removes Unicode Format (Cf) characters and combining diacritical marks (6 Unicode ranges) |
| 2 | Whitespace normalization | Converts Unicode Space Separator (Zs) characters to ASCII space |
| 3 | NFKC decomposition | Standard Unicode compatibility decomposition |
| 4 | Confusable/homoglyph mapping | 1,650+ character mappings (auto-generated from NFKC/NFKD decompositions + manual overrides for Cyrillic, Greek, IPA, small caps, letterlike symbols) |
| 5 | Offset tracking | Byte-level offset map for original↔normalized position mapping |

Character classification uses the `unicode-general-category` crate for
standards-compliant detection of invisible characters (`GeneralCategory::Format`)
and Unicode spaces (`GeneralCategory::SpaceSeparator`).

## Cryptography

### Token Generation

`TokenVault` uses HMAC-SHA256 with a cryptographically random secret to
generate deterministic tokens. This prevents token precomputation.

### Constant-Time Comparison

API key verification hashes both the expected and provided keys with
SHA-256, then performs byte-by-byte XOR comparison to prevent timing
side-channel attacks.

## File System Security

### Archive Bomb Protection

ZIP, RAR, and 7z extraction enforces:
- Maximum extracted file size limits
- Maximum file count per archive
- Path traversal prevention via entry name validation and canonicalization

### Path Traversal Prevention

All file extraction paths are validated and canonicalized. Entries with
`..` components, absolute paths, or symlink targets are rejected.

## Input Validation

### Regex Safety

Custom patterns submitted via `POST /v1/patterns` are compiled with
`regex::Regex::new()` which enforces safe regex compilation (no
catastrophic backtracking by design — Rust's regex crate guarantees
linear-time matching).

### Scan Timeouts

- Per-pattern regex timeout: **5 seconds**
- Total scan timeout: **120 seconds**
- Maximum matches per scan: **50,000**
- Maximum input size: **10 MB**

## Deployment Recommendations

1. **Always set `DLPSCAN_API_KEY`** in production API deployments.
2. **Enable TLS** via `DLPSCAN_TLS_CERT` and `DLPSCAN_TLS_KEY`, or run
   behind a reverse proxy (nginx, Caddy) with TLS termination.
3. **Restrict metrics access** — if exposing Prometheus metrics, use
   network policies or a sidecar proxy with authentication.
4. **Configure rate limits** — set `DLPSCAN_API_RATE_LIMIT` appropriate
   to your traffic patterns. The default is 100 requests per 60 seconds
   per IP.
5. **Monitor audit logs** — use SIEM integration (Splunk, Elasticsearch,
   Syslog, or Datadog) for compliance-grade audit trails.
6. **Use connection limits** — the server caps at 256 concurrent
   connections. Scale horizontally for higher throughput.
