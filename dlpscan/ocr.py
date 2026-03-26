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
import re
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

# Maximum total pixel area to prevent memory exhaustion.
MAX_PIXEL_AREA = 50_000_000  # 50 megapixels

# Allowed tesseract config flags (whitelist for security).
_ALLOWED_CONFIG_PATTERN = re.compile(
    r'^(--(?:oem|psm|dpi|tessdata-dir|user-words|user-patterns)\s+\S+\s*)*$'
)


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


def _validate_config(config: str) -> str:
    """Validate tesseract config string against an allowlist of safe flags.

    Raises ValueError if the config contains disallowed options.
    """
    config = config.strip()
    if not config:
        return config
    if not _ALLOWED_CONFIG_PATTERN.match(config):
        raise ValueError(
            f"Invalid Tesseract config: {config!r}. "
            "Only --oem, --psm, --dpi, --tessdata-dir, "
            "--user-words, and --user-patterns are allowed."
        )
    return config


def _validate_lang(lang: str) -> str:
    """Validate tesseract language string (alphanumeric + plus signs only)."""
    if not re.match(r'^[a-zA-Z0-9_+]+$', lang):
        raise ValueError(
            f"Invalid Tesseract language code: {lang!r}. "
            "Use alphanumeric codes separated by '+' (e.g., 'eng+fra')."
        )
    return lang


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
    w, h = image.size
    if w == 0 or h == 0:
        return image

    # Check total pixel area to prevent memory exhaustion.
    if w * h > MAX_PIXEL_AREA:
        scale = (MAX_PIXEL_AREA / (w * h)) ** 0.5
        new_w = max(1, int(w * scale))
        new_h = max(1, int(h * scale))
        image = image.resize((new_w, new_h))
        logger.debug("Downscaled image from %dx%d to %dx%d (pixel area limit)", w, h, new_w, new_h)
    elif max(w, h) > MAX_IMAGE_DIMENSION:
        scale = MAX_IMAGE_DIMENSION / max(w, h)
        new_w = max(1, int(w * scale))
        new_h = max(1, int(h * scale))
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
                new_w = max(1, int(image.width * scale))
                new_h = max(1, int(image.height * scale))
                image = image.resize((new_w, new_h))

    if threshold:
        # Simple binary threshold at 128.
        image = image.point(lambda x: 255 if x > 128 else 0, '1')

    return image


def _ocr_with_confidence(pytesseract, image, lang: str, config: str):
    """Run OCR once using image_to_data and extract both text and confidence.

    Returns (text, confidence) tuple. This avoids running the OCR engine
    twice (once for text, once for confidence).
    """
    try:
        data = pytesseract.image_to_data(image, lang=lang, config=config,
                                          output_type=pytesseract.Output.DICT)
        # Build text from word-level tokens.
        words = []
        confidences = []
        prev_block = None
        prev_line = None
        for i, word in enumerate(data.get('text', [])):
            conf = data['conf'][i]
            block = data.get('block_num', [0])[i]
            line = data.get('line_num', [0])[i]

            if word.strip():
                # Add newlines between blocks/lines.
                if prev_block is not None and block != prev_block:
                    words.append('\n\n')
                elif prev_line is not None and line != prev_line:
                    words.append('\n')

                words.append(word)
                prev_block = block
                prev_line = line

                conf_val = int(conf) if str(conf).lstrip('-').isdigit() else -1
                if conf_val >= 0:
                    confidences.append(conf_val)

        text = ' '.join(w for w in words if w not in ('\n', '\n\n'))
        # Restore line structure.
        result_parts = []
        current_line = []
        for w in words:
            if w == '\n\n':
                if current_line:
                    result_parts.append(' '.join(current_line))
                    current_line = []
                result_parts.append('')
            elif w == '\n':
                if current_line:
                    result_parts.append(' '.join(current_line))
                    current_line = []
            else:
                current_line.append(w)
        if current_line:
            result_parts.append(' '.join(current_line))

        text = '\n'.join(result_parts).strip()
        avg_conf = sum(confidences) / len(confidences) if confidences else 0.0
        return text, avg_conf
    except Exception:
        # Fall back to simple image_to_string if image_to_data fails.
        text = pytesseract.image_to_string(image, lang=lang, config=config)
        return text.strip(), 0.0


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
        RuntimeError: If Tesseract binary is not found or OCR fails.
        FileNotFoundError: If source file does not exist.
        ValueError: If config or lang contain invalid values.
    """
    pytesseract = _ensure_pytesseract()
    Image = _ensure_pillow()

    config = _validate_config(config)
    lang = _validate_lang(lang)

    warnings = []
    metadata: Dict[str, Any] = {}
    opened_here = False

    # Load image.
    if isinstance(source, str):
        if not os.path.isfile(source):
            raise FileNotFoundError(f"Image file not found: {source}")
        metadata['file_path'] = source
        metadata['file_size'] = os.path.getsize(source)
        image = Image.open(source)
        opened_here = True
    else:
        image = source

    try:
        metadata['original_size'] = image.size
        metadata['mode'] = image.mode

        # Preprocess.
        if preprocess:
            image = _preprocess_image(image, grayscale=grayscale,
                                       threshold=threshold, dpi=dpi)
            metadata['preprocessed'] = True

        # Run OCR — single pass for both text and confidence.
        if compute_confidence:
            text, confidence = _ocr_with_confidence(pytesseract, image, lang, config)
        else:
            try:
                text = pytesseract.image_to_string(image, lang=lang, config=config).strip()
            except (OSError, RuntimeError) as exc:
                raise RuntimeError(f"OCR failed: {exc}") from exc
            confidence = 0.0

        if compute_confidence and confidence < MIN_OCR_CONFIDENCE and text:
            warnings.append(
                f"Low OCR confidence ({confidence:.1f}%). "
                "Text may contain errors. Consider preprocessing the image."
            )

        metadata['language'] = lang

        return OCRResult(
            text=text,
            confidence=confidence,
            language=lang,
            page_count=1,
            metadata=metadata,
            warnings=warnings,
        )
    finally:
        if opened_here:
            image.close()


def ocr_page_image(pytesseract, image, *, lang: str = DEFAULT_LANG,
                    config: str = DEFAULT_CONFIG):
    """OCR a single page image. Public API for use by extractors.

    Args:
        pytesseract: The pytesseract module.
        image: PIL Image of a single page.
        lang: Tesseract language code.
        config: Tesseract config string.

    Returns:
        Extracted text string (stripped), or empty string on failure.
    """
    try:
        text = pytesseract.image_to_string(image, lang=lang, config=config)
        return text.strip()
    except (OSError, RuntimeError) as exc:
        logger.warning("OCR failed for page image: %s", exc)
        return ''
    finally:
        image.close()


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
    no text. Processes one page at a time to limit memory usage.

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

    config = _validate_config(config)
    lang = _validate_lang(lang)

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

    # Determine how many pages to process.
    effective_limit = min(page_count, max_pages) if (max_pages and page_count) else (page_count or None)

    # Process one page at a time to limit memory usage.
    page_idx = 0
    while True:
        page_num = page_idx + 1  # 1-based for pdf2image
        if effective_limit is not None and page_idx >= effective_limit:
            break

        # Use pdfplumber text if available and sufficient.
        if page_idx in pdfplumber_texts:
            pages_text.append(pdfplumber_texts[page_idx])
            text_page_count += 1
            page_idx += 1
            continue

        # Convert single page to image for OCR.
        try:
            images = convert_from_path(
                file_path, dpi=dpi,
                first_page=page_num,
                last_page=page_num,
                thread_count=1,
            )
        except Exception as exc:
            if page_idx == 0 and not page_count:
                # First page failed and we don't know page count — can't continue.
                raise RuntimeError(
                    f"PDF to image conversion failed: {exc}. "
                    "Ensure poppler is installed: apt install poppler-utils"
                ) from exc
            warnings.append(f"Page {page_num}: image conversion failed ({exc})")
            page_idx += 1
            continue

        if not images:
            # No more pages — we've reached the end.
            if not page_count:
                break
            page_idx += 1
            continue

        # OCR the page image and close it immediately.
        img = images[0]
        try:
            page_text = pytesseract.image_to_string(img, lang=lang, config=config).strip()
            if page_text:
                pages_text.append(page_text)
                ocr_page_count += 1
            else:
                warnings.append(f"Page {page_num}: OCR returned no text")
        except (OSError, RuntimeError) as exc:
            warnings.append(f"Page {page_num}: OCR failed ({exc})")
        finally:
            img.close()

        page_idx += 1

        # If we don't know page_count (no pdfplumber), stop after conversion returns empty.
        if not page_count and not images:
            break

    if not page_count:
        page_count = page_idx

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
