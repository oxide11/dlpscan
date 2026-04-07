# Rate Limiting

Per-IP sliding-window rate limiter for API and service protection.

## Configuration

Set via environment variable:

```bash
export DLPSCAN_API_RATE_LIMIT=100  # Max requests per 60-second window per IP
```

Default: **100 requests per 60 seconds per IP address**.

## How It Works

The API server tracks request timestamps per client IP address using a
sliding window algorithm:

1. Each incoming request records the client's IP address
2. Timestamps older than the window (60 seconds) are evicted
3. If the IP has fewer than `max_requests` in the window, the request proceeds
4. Otherwise, a `429 Too Many Requests` response is returned

### Memory Management

The rate limiter caps tracked IPs at **10,000**. When this limit is reached,
stale entries (IPs with no recent requests) are automatically evicted.

## API Response

When rate limited:

```
HTTP/1.1 429 Too Many Requests
Content-Type: application/json

{"detail":"Rate limit exceeded"}
```

## Rust API

```rust
use dlpscan::api::RateLimiter;

let mut limiter = RateLimiter::new(100, 60);  // 100 req/60s

// Check per-IP
if limiter.check_ip("192.168.1.1") {
    // Request allowed
}

// Legacy global check
if limiter.check() {
    // Request allowed
}
```

## Additional Limits

The API server enforces several complementary limits:

| Limit | Value |
|---|---|
| Concurrent connections | 256 |
| Request body size | 10 MB |
| Single scan text | 10 MB |
| Batch items | 1,000 |
| Custom patterns | 100 |
