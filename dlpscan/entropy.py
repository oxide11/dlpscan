"""Entropy analysis and recursive unpacking for DLP evasion detection.

Detects encrypted, compressed, or obfuscated payloads by computing Shannon
entropy. Supports recursive extraction of nested archives (ZIP, tar, gzip)
before scanning.

Usage::

    from dlpscan.entropy import EntropyAnalyzer, RecursiveExtractor

    # Analyze a file's entropy
    analyzer = EntropyAnalyzer()
    result = analyzer.analyze_file("suspicious.docx")
    if result.is_suspicious:
        print(f"High entropy ({result.entropy:.2f}): {result.classification}")

    # Recursively extract and scan nested archives
    extractor = RecursiveExtractor()
    for extracted in extractor.extract("nested_archive.zip"):
        print(f"Extracted: {extracted.path} (entropy: {extracted.entropy:.2f})")

DLP Use Case:

    An attacker compresses sensitive data into a nested ZIP, renames it
    .docx, and emails it. Entropy analysis detects that the file has
    suspiciously high randomness for a document file. Recursive unpacking
    cracks open the archive layers and scans the contents.
"""

import gzip
import logging
import math
import os
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from typing import List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Entropy analysis
# ---------------------------------------------------------------------------

@dataclass
class EntropyResult:
    """Result of entropy analysis on a file or data block."""
    entropy: float             # Shannon entropy (0.0 to 8.0 bits/byte)
    is_suspicious: bool        # True if entropy exceeds threshold for the format
    classification: str        # "normal", "compressed", "encrypted", "suspicious_for_format"
    file_path: Optional[str] = None
    file_size: int = 0
    format_hint: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            'entropy': round(self.entropy, 4),
            'is_suspicious': self.is_suspicious,
            'classification': self.classification,
            'file_path': self.file_path,
            'file_size': self.file_size,
            'format_hint': self.format_hint,
        }


# Expected entropy ranges by format
_FORMAT_ENTROPY = {
    '.txt': (3.0, 5.5),
    '.csv': (3.0, 5.5),
    '.json': (3.5, 5.5),
    '.xml': (3.5, 5.5),
    '.html': (3.5, 5.5),
    '.py': (3.5, 5.5),
    '.js': (3.5, 5.5),
    '.log': (3.0, 5.5),
    '.md': (3.0, 5.5),
    # Binary formats have naturally higher entropy
    '.pdf': (5.0, 7.8),
    '.docx': (7.0, 8.0),   # ZIP-compressed, naturally high
    '.xlsx': (7.0, 8.0),
    '.pptx': (7.0, 8.0),
    '.zip': (7.0, 8.0),
    '.gz': (7.5, 8.0),
    '.png': (6.0, 8.0),
    '.jpg': (7.0, 8.0),
}


class EntropyAnalyzer:
    """Shannon entropy analyzer for detecting encrypted/compressed content.

    Args:
        threshold: Global entropy threshold for suspicion (default 7.5).
                   Files above this are flagged regardless of format.
        sample_size: Bytes to read for analysis (default 8192).
                     Larger = more accurate but slower.
    """

    def __init__(self, threshold: float = 7.5, sample_size: int = 8192):
        self._threshold = threshold
        self._sample_size = sample_size

    @staticmethod
    def shannon_entropy(data: bytes) -> float:
        """Compute Shannon entropy of a byte sequence.

        Returns entropy in bits per byte (0.0 to 8.0).
        - 0.0: completely uniform (e.g., all zeros)
        - ~4.5: typical English text
        - ~7.5+: compressed or encrypted data
        - 8.0: perfectly random
        """
        if not data:
            return 0.0
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        length = len(data)
        return -sum(
            (f / length) * math.log2(f / length)
            for f in freq if f > 0
        )

    def analyze_bytes(self, data: bytes, format_hint: Optional[str] = None) -> EntropyResult:
        """Analyze entropy of a byte sequence.

        Args:
            data: Raw bytes to analyze.
            format_hint: File extension hint (e.g., ".txt", ".docx").
        """
        entropy = self.shannon_entropy(data)
        classification = self._classify(entropy, format_hint)
        is_suspicious = self._is_suspicious(entropy, format_hint)

        return EntropyResult(
            entropy=entropy,
            is_suspicious=is_suspicious,
            classification=classification,
            file_size=len(data),
            format_hint=format_hint,
        )

    def analyze_file(self, path: str) -> EntropyResult:
        """Analyze entropy of a file.

        Reads up to sample_size bytes from the start of the file.
        """
        ext = os.path.splitext(path)[1].lower()
        file_size = os.path.getsize(path)

        with open(path, 'rb') as f:
            data = f.read(self._sample_size)

        result = self.analyze_bytes(data, format_hint=ext)
        result.file_path = path
        result.file_size = file_size
        return result

    def _classify(self, entropy: float, format_hint: Optional[str]) -> str:
        """Classify entropy level."""
        if entropy >= 7.9:
            return "likely_encrypted"
        if entropy >= 7.5:
            return "compressed_or_encrypted"
        if format_hint and format_hint in _FORMAT_ENTROPY:
            low, high = _FORMAT_ENTROPY[format_hint]
            if entropy > high:
                return "suspicious_for_format"
        if entropy >= 6.0:
            return "moderately_random"
        return "normal"

    def _is_suspicious(self, entropy: float, format_hint: Optional[str]) -> bool:
        """Determine if entropy is suspicious for the given format."""
        # Global threshold
        if entropy >= self._threshold:
            return True
        # Format-specific threshold
        if format_hint and format_hint in _FORMAT_ENTROPY:
            _, high = _FORMAT_ENTROPY[format_hint]
            if entropy > high + 0.5:
                return True
        return False


# ---------------------------------------------------------------------------
# Recursive extractor
# ---------------------------------------------------------------------------

@dataclass
class ExtractedItem:
    """An item extracted from a nested archive."""
    path: str              # Temp file path (or original for non-archives)
    original_name: str     # Name within the archive
    depth: int             # Nesting depth (0 = top-level)
    entropy: float         # Entropy of the extracted content
    classification: str    # Entropy classification
    is_suspicious: bool
    size: int = 0
    parent_archive: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            'original_name': self.original_name,
            'depth': self.depth,
            'entropy': round(self.entropy, 4),
            'classification': self.classification,
            'is_suspicious': self.is_suspicious,
            'size': self.size,
        }


class RecursiveExtractor:
    """Recursively unpack nested archives before scanning.

    Handles ZIP, tar, and gzip formats. Checks entropy at each level
    to detect encrypted payloads that can't be further extracted.

    Args:
        max_depth: Maximum nesting depth (default 5). Prevents zip bombs.
        max_total_size: Maximum total extracted size in bytes (default 500 MB).
        entropy_threshold: Flag files above this entropy (default 7.5).
    """

    def __init__(self, max_depth: int = 5,
                 max_total_size: int = 500 * 1024 * 1024,
                 entropy_threshold: float = 7.5):
        self._max_depth = max_depth
        self._max_total = max_total_size
        self._analyzer = EntropyAnalyzer(threshold=entropy_threshold)
        self._temp_dirs: List[str] = []

    def extract(self, path: str) -> List[ExtractedItem]:
        """Recursively extract a file and return all extracted items.

        Args:
            path: Path to the file to extract.

        Returns:
            List of ExtractedItem objects for each file found.
            Non-archive files are returned as-is with entropy info.
        """
        self._total_extracted = 0
        results = self._extract_recursive(path, depth=0, parent=None)
        return results

    def _extract_recursive(self, path: str, depth: int,
                           parent: Optional[str]) -> List[ExtractedItem]:
        """Internal recursive extraction."""
        results: List[ExtractedItem] = []

        if depth > self._max_depth:
            logger.warning("Max extraction depth (%d) reached at %s",
                           self._max_depth, path)
            return results

        if self._total_extracted > self._max_total:
            logger.warning("Max total extraction size reached (%d bytes)",
                           self._max_total)
            return results

        # Analyze entropy
        entropy_result = self._analyzer.analyze_file(path)
        basename = os.path.basename(path)

        item = ExtractedItem(
            path=path,
            original_name=basename,
            depth=depth,
            entropy=entropy_result.entropy,
            classification=entropy_result.classification,
            is_suspicious=entropy_result.is_suspicious,
            size=entropy_result.file_size,
            parent_archive=parent,
        )
        results.append(item)
        self._total_extracted += entropy_result.file_size

        # Try to extract if it's an archive
        if zipfile.is_zipfile(path):
            results.extend(self._extract_zip(path, depth, basename))
        elif tarfile.is_tarfile(path):
            results.extend(self._extract_tar(path, depth, basename))
        elif path.endswith('.gz') and not path.endswith('.tar.gz'):
            results.extend(self._extract_gzip(path, depth, basename))

        return results

    def _extract_zip(self, path: str, depth: int,
                     parent: str) -> List[ExtractedItem]:
        """Extract a ZIP archive."""
        results = []
        tmpdir = tempfile.mkdtemp(prefix='dlpscan_zip_')
        self._temp_dirs.append(tmpdir)

        try:
            with zipfile.ZipFile(path, 'r') as zf:
                # Check for zip bomb (ratio attack)
                total_size = sum(info.file_size for info in zf.infolist())
                if total_size > self._max_total:
                    logger.warning("ZIP bomb detected: %s claims %d bytes",
                                   path, total_size)
                    return [ExtractedItem(
                        path=path, original_name=parent, depth=depth,
                        entropy=8.0, classification="potential_zip_bomb",
                        is_suspicious=True, size=total_size,
                        parent_archive=parent,
                    )]

                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    # Sanitize filename
                    safe_name = os.path.basename(info.filename)
                    if not safe_name:
                        continue
                    extracted_path = os.path.join(tmpdir, safe_name)
                    with zf.open(info) as src, open(extracted_path, 'wb') as dst:
                        dst.write(src.read(self._max_total))

                    results.extend(
                        self._extract_recursive(extracted_path, depth + 1, parent)
                    )
        except (zipfile.BadZipFile, OSError) as e:
            logger.debug("ZIP extraction failed for %s: %s", path, e)

        return results

    def _extract_tar(self, path: str, depth: int,
                     parent: str) -> List[ExtractedItem]:
        """Extract a tar archive."""
        results = []
        tmpdir = tempfile.mkdtemp(prefix='dlpscan_tar_')
        self._temp_dirs.append(tmpdir)

        try:
            with tarfile.open(path, 'r:*') as tf:
                for member in tf.getmembers():
                    if not member.isfile():
                        continue
                    # Sanitize: prevent path traversal
                    safe_name = os.path.basename(member.name)
                    if not safe_name or safe_name.startswith('.'):
                        continue
                    extracted_path = os.path.join(tmpdir, safe_name)
                    with tf.extractfile(member) as src:
                        if src is None:
                            continue
                        with open(extracted_path, 'wb') as dst:
                            dst.write(src.read(self._max_total))

                    results.extend(
                        self._extract_recursive(extracted_path, depth + 1, parent)
                    )
        except (tarfile.TarError, OSError) as e:
            logger.debug("TAR extraction failed for %s: %s", path, e)

        return results

    def _extract_gzip(self, path: str, depth: int,
                      parent: str) -> List[ExtractedItem]:
        """Extract a gzip file."""
        results = []
        tmpdir = tempfile.mkdtemp(prefix='dlpscan_gz_')
        self._temp_dirs.append(tmpdir)

        try:
            out_name = os.path.basename(path)
            if out_name.endswith('.gz'):
                out_name = out_name[:-3]
            if not out_name:
                out_name = 'extracted'
            extracted_path = os.path.join(tmpdir, out_name)

            with gzip.open(path, 'rb') as src, open(extracted_path, 'wb') as dst:
                dst.write(src.read(self._max_total))

            results.extend(
                self._extract_recursive(extracted_path, depth + 1, parent)
            )
        except (gzip.BadGzipFile, OSError) as e:
            logger.debug("GZIP extraction failed for %s: %s", path, e)

        return results

    def cleanup(self) -> None:
        """Remove all temporary extraction directories."""
        import shutil
        for d in self._temp_dirs:
            try:
                shutil.rmtree(d)
            except OSError:
                pass
        self._temp_dirs.clear()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.cleanup()
        return False
