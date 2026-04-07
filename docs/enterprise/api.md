# REST API

dlpscan includes an async HTTP API server for language-agnostic integration.
Requires the `async-support` feature flag.

## Quick Start

```bash
# Build with API support
cargo build --release --features async-support

# Run the server
./target/release/dlpscan serve
# Server starts at http://127.0.0.1:8000
```

## Configuration

| Environment Variable | Default | Description |
|---|---|---|
| `DLPSCAN_API_HOST` | `127.0.0.1` | Server bind address |
| `DLPSCAN_API_PORT` | `8000` | Server port |
| `DLPSCAN_API_KEY` | (none) | API key for authentication |
| `DLPSCAN_API_RATE_LIMIT` | `100` | Requests per 60s per IP |
| `DLPSCAN_TLS_CERT` | (none) | TLS certificate PEM path |
| `DLPSCAN_TLS_KEY` | (none) | TLS private key PEM path |

## Authentication

Set the `DLPSCAN_API_KEY` environment variable to enable API key authentication:

```bash
export DLPSCAN_API_KEY=your-secret-key
```

All requests (except `GET /health`) must include the `X-API-Key` header:

```bash
curl -X POST http://localhost:8000/v1/scan \
  -H "X-API-Key: your-secret-key" \
  -H "Content-Type: application/json" \
  -d '{"text": "Card: 4111111111111111", "action": "redact"}'
```

Authentication uses constant-time SHA-256 hash comparison to prevent timing
side-channel attacks.

## Endpoints

### `GET /health`

Health check endpoint (no authentication required).

```json
{"status": "ok", "version": "0.1.0"}
```

### `GET /metrics`

Prometheus metrics endpoint (requires `metrics` feature). Returns text/plain
Prometheus exposition format.

### `POST /v1/scan`

Scan text for sensitive data.

**Request:**
```json
{
  "text": "My card is 4111-1111-1111-1111",
  "presets": ["pci_dss"],
  "action": "redact",
  "min_confidence": 0.5,
  "require_context": false
}
```

**Response:**
```json
{
  "is_clean": false,
  "finding_count": 1,
  "categories_found": ["Credit Card Numbers"],
  "redacted_text": "My card is XXXXXXXXXXXXXXXX",
  "findings": [
    {
      "text": "4111111111111111",
      "category": "Credit Card Numbers",
      "sub_category": "Visa",
      "confidence": 0.95,
      "has_context": true,
      "span": [14, 33]
    }
  ]
}
```

**Limits:** Maximum text size is 10 MB.

### `POST /v1/batch/scan`

Scan multiple texts in a single request (parallelized with Rayon).

**Request:**
```json
{
  "items": [
    {"text": "Card: 4111111111111111", "action": "flag"},
    {"text": "SSN: 123-45-6789", "action": "flag"}
  ]
}
```

**Limits:** Maximum 1,000 items, 10 MB per item.

### `POST /v1/patterns`

Add a custom detection pattern.

**Request:**
```json
{
  "name": "Internal Employee ID",
  "pattern": "EMP-\\d{6}",
  "category": "Internal IDs",
  "confidence": 0.8
}
```

**Limits:**
- Maximum 100 custom patterns
- Pattern regex: max 4,096 characters
- Name/category: max 256 characters
- Confidence: must be between 0.0 and 1.0

### `GET /v1/patterns`

List all custom patterns.

## Rate Limiting

Per-IP sliding-window rate limiting. Default: 100 requests per 60 seconds per IP.
Configure via `DLPSCAN_API_RATE_LIMIT`.

Returns `429 Too Many Requests` when exceeded:
```json
{"detail": "Rate limit exceeded"}
```

## Connection Limits

- Maximum concurrent connections: 256
- Maximum request body size: 10 MB
- Graceful shutdown on SIGTERM/SIGINT with 30-second connection drain

## TLS

Enable HTTPS by setting both TLS environment variables:

```bash
export DLPSCAN_TLS_CERT=/path/to/cert.pem
export DLPSCAN_TLS_KEY=/path/to/key.pem
```

Uses `rustls` for TLS — no OpenSSL dependency.

## Docker Deployment

```dockerfile
FROM rust:1.82-slim AS builder
WORKDIR /build
COPY . .
RUN cargo build --release --features async-support

FROM debian:bookworm-slim
COPY --from=builder /build/target/release/dlpscan /usr/local/bin/
EXPOSE 8000
USER 1000
CMD ["dlpscan", "serve"]
```
