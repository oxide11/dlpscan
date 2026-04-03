# Streaming & Webhooks

## StreamScanner

Scan real-time text streams with a stateful buffer:

```python
from dlpscan import StreamScanner

scanner = StreamScanner(
    min_confidence=0.5,
    buffer_size=4096,
    overlap=256,
    on_match=lambda m: print(f"Found: {m.sub_category}"),
)

# Feed chunks as they arrive
for chunk in stream:
    matches = scanner.feed(chunk)

# Flush remaining buffer
final_matches = scanner.flush()
```

## WebhookScanner

Scan HTTP webhook payloads:

```python
from dlpscan import WebhookScanner

scanner = WebhookScanner(min_confidence=0.5)

# Scan JSON body
findings = scanner.scan_payload(request.body, content_type="application/json")

# Scan headers (skips Authorization/Cookie)
header_findings = scanner.scan_headers(request.headers)
```
