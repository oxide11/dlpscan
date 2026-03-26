"""OCR text extraction from images and scanned documents.

Extracts text from image files (PNG, JPEG, TIFF, BMP, WebP) and scanned
PDF pages using Tesseract OCR via pytesseract. All OCR dependencies are
optional — a clear error message is raised if they are not installed.

Usage::

    from dlpscan.ocr import ocr_image, ocr_available

    if ocr_available():
        text = ocr_image('screenshot.png')
        print(text)

Install OCR dependencies::

    pip install dlpscan[ocr]          # Image OCR (pytesseract + Pillow)
    pip install dlpscan[pdf-ocr]      # PDF OCR (adds pdf2image + pdfplumber)

System requirements::

    # Ubuntu/Debian
    apt install tesseract-ocr

    # macOS
    brew install tesseract

    # For PDF OCR, also install poppler:
    apt install poppler-utils          # Ubuntu/Debian
    brew install poppler               # macOS
"""

import logging
import os
import shutil
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)

# Supported image extensions for OCR.
IMAGE_EXTENSIONS = frozenset({
    '.png', '.jpg', '.jpeg', '.tiff', '.tif', '.bmp', '.webp',
})

# Default Tesseract configuration.
DEFAULT_LANG = 'eng'
DEFAULT_CONFIG = '--oem 3 --psm 3'

# Minimum average OCR confidence to consider text reliable (0-100 scale).
MIN_OCR_CONFIDENCE = 30

# Maximum image dimension (pixels) before downscaling to avoid memory issues.
MAX_IMAGE_DIMENSION = 10000


@dataclass
class OCRResult:
    """Result of OCR text extraction.

    Attributes:
        text: Extracted text content.
        confidence: Average OCR confidence score (0-100).
        language: Language used for OCR.
        page_count: Number of pages processed (1 for images).
        metadata: Additional OCR metadata.
        warnings: Non-fatal issues encountered during OCR.
    """
    text: str
    confidence: float = 0.0
    language: str = DEFAULT_LANG
    page_count: int = 1
    metadata: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)


def ocr_available() -> bool:
    """Check if OCR dependencies (pytesseract + Tesseract binary) are installed."""
    try:
        import pytesseract  # noqa: F401
    except ImportError:
        return False

    return shutil.which('tesseract') is not None


def pdf_ocr_available() -> bool:
    """Check if PDF OCR dependencies (pdf2image + poppler) are installed."""
    if not ocr_available():
        return False
    try:
        import pdf2image  # noqa: F401
    except ImportError:
        return False
    # pdf2image requires poppler (pdftoppm).
    return shutil.which('pdftoppm') is not None


def _ensure_pytesseract():
    """Import and return pytesseract, raising a clear error if unavailable."""
    try:
        import pytesseract
    except ImportError:
        raise ImportError(
            "OCR requires 'pytesseract'. "
            "Install with: pip install dlpscan[ocr]"
        )

    if shutil.which('tesseract') is None:
        raise RuntimeError(
            "Tesseract binary not found. "
            "Install with: apt install tesseract-ocr (Linux) "
            "or brew install tesseract (macOS)"
        )
    return pytesseract


def _ensure_pillow():
    """Import and return PIL.Image, raising a clear error if unavailable."""
    try:
        from PIL import Image
    except ImportError:
        raise ImportError(
            "OCR requires 'Pillow'. "
            "Install with: pip install dlpscan[ocr]"
        )
    return Image


def _preprocess_image(image, *, grayscale: bool = True, threshold: bool = False,
                       dpi: Optional[int] = None):
    """Apply preprocessing to improve OCR accuracy.

    Args:
        image: PIL Image object.
        grayscale: Convert to grayscale (default True).
        threshold: Apply binary thresholding for noisy images.
        dpi: Target DPI for rescaling (None to skip).

    Returns:
        Preprocessed PIL Image.
    """
    # Downscale oversized images to avoid memory issues.
    w, h = image.size
    if max(w, h) > MAX_IMAGE_DIMENSION:
        scale = MAX_IMAGE_DIMENSION / max(w, h)
        new_w = int(w * scale)
        new_h = int(h * scale)
        image = image.resize((new_w, new_h))
        logger.debug("Downscaled image from %dx%d to %dx%d", w, h, new_w, new_h)

    if grayscale and image.mode != 'L':
        image = image.convert('L')

    if dpi is not None:
        # Rescale based on current DPI info if available.
        current_dpi = image.info.get('dpi', (72, 72))
        if isinstance(current_dpi, tuple) and current_dpi[0] > 0:
            scale = dpi / current_dpi[0]
            if abs(scale - 1.0) > 0.1:
                new_w = int(image.width * scale)
                new_h = int(image.height * scale)
                image = image.resize((new_w, new_h))

    if threshold:
        # Simple binary threshold at 128.
        image = image.point(lambda x: 255 if x > 128 else 0, '1')

    return image


def _compute_confidence(pytesseract, image, lang: str, config: str) -> float:
    """Compute average OCR confidence using pytesseract.image_to_data."""
    try:
        data = pytesseract.image_to_data(image, lang=lang, config=config,
                                          output_type=pytesseract.Output.DICT)
        confidences = [
            int(c) for c in data.get('conf', [])
            if str(c).lstrip('-').isdigit() and int(c) >= 0
        ]
        if confidences:
            return sum(confidences) / len(confidences)
    except Exception as exc:
        logger.debug("Could not compute OCR confidence: %s", exc)
    return 0.0


def ocr_image(
    source: Union[str, Any],
    *,
    lang: str = DEFAULT_LANG,
    config: str = DEFAULT_CONFIG,
    preprocess: bool = True,
    grayscale: bool = True,
    threshold: bool = False,
    dpi: Optional[int] = None,
    compute_confidence: bool = True,
) -> OCRResult:
    """Extract text from an image using Tesseract OCR.

    Args:
        source: File path (str) or PIL Image object.
        lang: Tesseract language code (default 'eng').
        config: Tesseract config string.
        preprocess: Apply image preprocessing (default True).
        grayscale: Convert to grayscale during preprocessing.
        threshold: Apply binary thresholding during preprocessing.
        dpi: Target DPI for rescaling (None to skip).
        compute_confidence: Calculate per-word confidence scores.

    Returns:
        OCRResult with extracted text and metadata.

    Raises:
        ImportError: If pytesseract or Pillow is not installed.
        RuntimeError: If Tesseract binary is not found.
        FileNotFoundError: If source file does not exist.
    """
    pytesseract = _ensure_pytesseract()
    Image = _ensure_pillow()

    warnings = []
    metadata: Dict[str, Any] = {}

    # Load image.
    if isinstance(source, str):
        if not os.path.isfile(source):
            raise FileNotFoundError(f"Image file not found: {source}")
        metadata['file_path'] = source
        metadata['file_size'] = os.path.getsize(source)
        image = Image.open(source)
    else:
        image = source

    metadata['original_size'] = image.size
    metadata['mode'] = image.mode

    # Preprocess.
    if preprocess:
        image = _preprocess_image(image, grayscale=grayscale,
                                   threshold=threshold, dpi=dpi)
        metadata['preprocessed'] = True

    # Run OCR.
    try:
        text = pytesseract.image_to_string(image, lang=lang, config=config)
    except Exception as exc:
        raise RuntimeError(f"OCR failed: {exc}")

    text = text.strip()

    # Compute confidence.
    confidence = 0.0
    if compute_confidence and text:
        confidence = _compute_confidence(pytesseract, image, lang, config)
        if confidence < MIN_OCR_CONFIDENCE:
            warnings.append(
                f"Low OCR confidence ({confidence:.1f}%). "
                "Text may contain errors. Consider preprocessing the image."
            )

    metadata['language'] = lang
    metadata['config'] = config

    return OCRResult(
        text=text,
        confidence=confidence,
        language=lang,
        page_count=1,
        metadata=metadata,
        warnings=warnings,
    )


def ocr_pdf(
    file_path: str,
    *,
    lang: str = DEFAULT_LANG,
    config: str = DEFAULT_CONFIG,
    max_pages: Optional[int] = None,
    dpi: int = 300,
    text_threshold: int = 50,
) -> OCRResult:
    """Extract text from a scanned PDF using OCR.

    For each page, first attempts pdfplumber text extraction. Falls back
    to OCR (via pdf2image + pytesseract) for pages that yield little or
    no text.

    Args:
        file_path: Path to the PDF file.
        lang: Tesseract language code.
        config: Tesseract config string.
        max_pages: Maximum pages to process (None for all).
        dpi: Resolution for PDF-to-image conversion (default 300).
        text_threshold: Minimum characters per page before OCR fallback.

    Returns:
        OCRResult with combined text from all pages.
    """
    pytesseract = _ensure_pytesseract()
    _ensure_pillow()

    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"PDF file not found: {file_path}")

    # Try pdfplumber first for text-layer extraction.
    try:
        import pdfplumber
    except ImportError:
        pdfplumber = None

    try:
        from pdf2image import convert_from_path
    except ImportError:
        raise ImportError(
            "PDF OCR requires 'pdf2image'. "
            "Install with: pip install dlpscan[pdf-ocr]"
        )

    warnings = []
    pages_text = []
    total_confidence = 0.0
    ocr_page_count = 0
    text_page_count = 0

    # Get page count and text-layer text via pdfplumber.
    pdfplumber_texts = {}
    page_count = 0
    if pdfplumber is not None:
        try:
            with pdfplumber.open(file_path) as pdf:
                page_count = len(pdf.pages)
                limit = min(page_count, max_pages) if max_pages else page_count
                for i in range(limit):
                    try:
                        page_text = pdf.pages[i].extract_text() or ''
                        if len(page_text.strip()) >= text_threshold:
                            pdfplumber_texts[i] = page_text
                    except Exception as exc:
                        warnings.append(f"Page {i + 1}: pdfplumber error ({exc})")
        except Exception as exc:
            warnings.append(f"pdfplumber failed, using full OCR: {exc}")

    # Convert pages to images for OCR (only pages without sufficient text).
    limit = min(page_count, max_pages) if (max_pages and page_count) else None
    try:
        # Convert one page at a time to manage memory.
        first_page = 1
        last_page = limit if limit else None
        images = convert_from_path(
            file_path, dpi=dpi,
            first_page=first_page,
            last_page=last_page,
            thread_count=1,
        )
    except Exception as exc:
        raise RuntimeError(
            f"PDF to image conversion failed: {exc}. "
            "Ensure poppler is installed: apt install poppler-utils"
        )

    if not page_count:
        page_count = len(images)

    for i, img in enumerate(images):
        # Use pdfplumber text if available and sufficient.
        if i in pdfplumber_texts:
            pages_text.append(pdfplumber_texts[i])
            text_page_count += 1
            continue

        # OCR fallback for this page.
        try:
            page_text = pytesseract.image_to_string(img, lang=lang, config=config)
            page_text = page_text.strip()
            if page_text:
                pages_text.append(page_text)
                conf = _compute_confidence(pytesseract, img, lang, config)
                total_confidence += conf
                ocr_page_count += 1
            else:
                warnings.append(f"Page {i + 1}: OCR returned no text")
        except Exception as exc:
            warnings.append(f"Page {i + 1}: OCR failed ({exc})")

    avg_confidence = (total_confidence / ocr_page_count) if ocr_page_count else 0.0
    combined_text = '\n\n'.join(pages_text)

    return OCRResult(
        text=combined_text,
        confidence=avg_confidence,
        language=lang,
        page_count=page_count,
        metadata={
            'file_path': file_path,
            'total_pages': page_count,
            'text_pages': text_page_count,
            'ocr_pages': ocr_page_count,
            'dpi': dpi,
        },
        warnings=warnings,
    )
