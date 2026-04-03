# Scanning

## Text Scanning

```python
from dlpscan import enhanced_scan_text

matches = list(enhanced_scan_text("My SSN is 123-45-6789"))
for m in matches:
    print(f"{m.category} > {m.sub_category}")
    print(f"  Text: {m.text}")
    print(f"  Confidence: {m.confidence:.0%}")
    print(f"  Span: {m.span}")
    print(f"  Context: {m.has_context}")
```

## File Scanning

```python
from dlpscan import scan_file

for match in scan_file("data.csv"):
    print(match.sub_category, match.text)
```

## Directory Scanning

```python
from dlpscan import scan_directory

for match in scan_directory("./data/", skip_paths=["node_modules"]):
    print(match.text)
```

## Pipeline (Multi-Format)

The `Pipeline` supports PDF, DOCX, XLSX, PPTX, MSG, and plain text:

```python
from dlpscan import Pipeline

with Pipeline(min_confidence=0.5) as pipe:
    results = pipe.process_directory("./uploads/")
    for r in results:
        if r.matches:
            print(f"{r.file_path}: {len(r.matches)} findings")
```

## Category Filtering

```python
matches = enhanced_scan_text(
    text,
    categories={"Credit Card Numbers", "Contact Information"},
)
```

## Context Keywords

Enable context-aware scanning to reduce false positives:

```python
matches = enhanced_scan_text(text, require_context=True)
```

A match like `123-45-6789` only reports if keywords like "SSN", "social security" appear nearby.

## Confidence Scoring

Each match has a confidence score (0.0 to 1.0) based on:

- Pattern specificity (unique patterns score higher)
- Context keyword proximity
- Validation checks (e.g., Luhn for credit cards)

```python
matches = enhanced_scan_text(text)
high_confidence = [m for m in matches if m.confidence >= 0.7]
```

## Async Scanning

```python
import asyncio
from dlpscan import async_scan_text

async def scan():
    async for match in async_scan_text("Card: 4111111111111111"):
        print(match.sub_category)

asyncio.run(scan())
```
