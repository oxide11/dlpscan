# OCR Scanning

DLPScan can extract and scan text from images and scanned PDFs using Optical Character Recognition (OCR).

## Installation

OCR requires [Tesseract](https://github.com/tesseract-ocr/tesseract) and optionally [Poppler](https://poppler.freedesktop.org/) for PDF support.

### System Dependencies

```bash
# Ubuntu/Debian
sudo apt install tesseract-ocr poppler-utils

# macOS
brew install tesseract poppler

# Windows (via Chocolatey)
choco install tesseract poppler
```

### Python Dependencies

```bash
# Image OCR only
pip install dlpscan[ocr]

# Image + scanned PDF OCR
pip install dlpscan[pdf-ocr]

# Everything (all formats + OCR)
pip install dlpscan[all-formats]
```

## Quick Start

### Scan an Image

```python
from dlpscan.ocr import ocr_image

result = ocr_image('screenshot.png')
print(result.text)
print(f"Confidence: {result.confidence:.1f}%")
```

### Scan via Extractor Pipeline

```python
from dlpscan.extractors import extract_text

# Automatically uses OCR for image files
result = extract_text('document_scan.jpg')
print(result.text)
```

### Scan with InputGuard

```python
from dlpscan import InputGuard, Action
from dlpscan.extractors import extract_text

guard = InputGuard(action=Action.REDACT)

# Extract text from image, then scan
extraction = extract_text('id_card.png')
scan_result = guard.scan(extraction.text)

if not scan_result.is_clean:
    print(f"Found {len(scan_result.findings)} sensitive items")
    print(scan_result.redacted_text)
```

### Pipeline Integration

```python
from dlpscan.pipeline import Pipeline

with Pipeline(max_workers=4) as pipe:
    # Process images alongside documents
    results = pipe.process_files([
        'screenshot.png',
        'scanned_invoice.pdf',
        'report.docx',
    ])
    for r in results:
        print(f"{r.file_path}: {len(r.matches)} findings")
```

### Directory Scanning

```python
from dlpscan.scanner import scan_directory

# Images in the directory are automatically OCR-processed
for file_path, match in scan_directory('./documents/'):
    print(f"{file_path}: {match.category} - {match.sub_category}")
```

## Supported Formats

| Format | Extensions | Notes |
|--------|-----------|-------|
| PNG | `.png` | Screenshots, screen captures |
| JPEG | `.jpg`, `.jpeg` | Photos of documents |
| TIFF | `.tiff`, `.tif` | Enterprise document scans |
| BMP | `.bmp` | Legacy bitmap images |
| WebP | `.webp` | Modern web format |
| PDF | `.pdf` | Automatic OCR fallback for scanned pages |

## Scanned PDF Handling

DLPScan uses a hybrid approach for PDFs:

1. **Text-layer extraction** via pdfplumber (fast, accurate)
2. **OCR fallback** for pages with no extractable text (scanned pages)

This means mixed PDFs (some pages typed, some scanned) are handled efficiently.

```python
from dlpscan.ocr import ocr_pdf

result = ocr_pdf('mixed_document.pdf', dpi=300)
print(f"Total pages: {result.page_count}")
print(f"OCR pages: {result.metadata['ocr_pages']}")
print(f"Text pages: {result.metadata['text_pages']}")
```

## Configuration

### OCR Options

```python
from dlpscan.ocr import ocr_image

result = ocr_image(
    'document.png',
    lang='eng+fra',         # Multiple languages
    config='--oem 3 --psm 6',  # Tesseract config
    preprocess=True,        # Enable preprocessing
    grayscale=True,         # Convert to grayscale
    threshold=False,        # Binary thresholding
    dpi=300,                # Target DPI
    compute_confidence=True,  # Calculate confidence scores
)
```

### PDF OCR Options

```python
from dlpscan.ocr import ocr_pdf

result = ocr_pdf(
    'scanned.pdf',
    lang='eng',
    dpi=300,              # Higher = better accuracy, slower
    max_pages=50,         # Limit pages for large documents
    text_threshold=50,    # Min chars before OCR fallback
)
```

### Image Preprocessing

DLPScan automatically preprocesses images to improve OCR accuracy:

- **Grayscale conversion** reduces noise from color channels
- **Downscaling** prevents memory issues with very large images (>10000px)
- **DPI normalization** rescales images to a consistent resolution
- **Binary thresholding** (optional) improves contrast for noisy scans

## Checking Availability

```python
from dlpscan.ocr import ocr_available, pdf_ocr_available

# Check if basic OCR is available
if ocr_available():
    print("Image OCR ready")

# Check if PDF OCR is available
if pdf_ocr_available():
    print("PDF OCR ready")
```

## Language Support

Tesseract supports 100+ languages. Install language packs:

```bash
# Ubuntu/Debian
sudo apt install tesseract-ocr-fra  # French
sudo apt install tesseract-ocr-deu  # German
sudo apt install tesseract-ocr-chi-sim  # Simplified Chinese

# List installed languages
tesseract --list-langs
```

Use multiple languages:

```python
result = ocr_image('multilingual.png', lang='eng+fra+deu')
```

## Performance Tips

1. **Use appropriate DPI**: 300 DPI is a good balance. Higher is slower but more accurate.
2. **Limit pages**: Use `max_pages` for large PDFs to avoid long processing times.
3. **Preprocess images**: Enable grayscale and threshold for noisy scans.
4. **Use the pipeline**: `Pipeline` processes files concurrently for batch OCR.
5. **Check confidence**: Low confidence (<30%) indicates poor image quality.
