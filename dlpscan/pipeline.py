"""Queue-based file processing pipeline for DLP scanning.

Ingests files of any supported format, extracts text, runs DLP scanning,
and returns structured results. Handles Office documents, PDFs, emails,
and plain text files concurrently via a thread pool.

Usage::

    from dlpscan.pipeline import Pipeline

    with Pipeline(max_workers=4) as pipe:
        # Process a batch of files
        results = pipe.process_files(['report.pdf', 'data.xlsx', 'notes.docx'])
        for r in results:
            if r.success:
                print(f"{r.file_path}: {len(r.matches)} matches")
            else:
                print(f"{r.file_path}: ERROR — {r.error}")

        # Process a single file
        result = pipe.process_file('email.eml')

        # Process a directory
        results = pipe.process_directory('./documents/')

        # Submit for async processing
        future = pipe.submit('large_report.pdf')
        result = future.result()  # blocks until done
"""

import csv
import io
import json
import logging
import os
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set

from .allowlist import Allowlist
from .exceptions import ExtractionError
from .extractors import (
    MAX_EXTRACT_SIZE,
    extract_text,
)
from .models import Match
from .scanner import MAX_MATCHES, scan_stream

logger = logging.getLogger(__name__)

# Default pipeline constants.
DEFAULT_MAX_WORKERS = 4
DEFAULT_MAX_FILE_SIZE = MAX_EXTRACT_SIZE  # 100 MB


@dataclass
class FileJob:
    """A file submitted to the pipeline for processing.

    Attributes:
        file_path: Path to the file to process.
        categories: Optional set of pattern categories to scan.
        require_context: If True, only report matches with context keywords.
        max_matches: Maximum matches for this file.
        metadata: User-attached metadata (e.g., ticket ID, source system).
    """
    file_path: str
    categories: Optional[Set[str]] = None
    require_context: bool = False
    max_matches: int = MAX_MATCHES
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class PipelineResult:
    """Result of processing a single file through the pipeline.

    Attributes:
        file_path: Path to the processed file.
        matches: List of DLP matches found.
        extraction_metadata: Metadata from text extraction (author, pages, etc.).
        format_detected: Detected file format (e.g., 'pdf', 'docx', 'text').
        duration_ms: Total processing time in milliseconds.
        error: Error message if processing failed, None on success.
        warnings: Non-fatal warnings from extraction.
        file_size_bytes: Size of the input file.
        extracted_text_length: Length of extracted text in characters.
    """
    file_path: str
    matches: List[Match] = field(default_factory=list)
    extraction_metadata: Dict[str, Any] = field(default_factory=dict)
    format_detected: str = 'unknown'
    duration_ms: float = 0.0
    error: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    file_size_bytes: int = 0
    extracted_text_length: int = 0

    @property
    def success(self) -> bool:
        """True if processing completed without error."""
        return self.error is None

    @property
    def match_count(self) -> int:
        """Number of matches found."""
        return len(self.matches)

    def to_dict(self, redact: bool = False) -> dict:
        """Convert to a plain dictionary for JSON serialization.

        Args:
            redact: If True, redact matched text in match dicts.
        """
        return {
            'file_path': self.file_path,
            'matches': [m.to_dict(redact=redact) for m in self.matches],
            'extraction_metadata': self.extraction_metadata,
            'format_detected': self.format_detected,
            'duration_ms': self.duration_ms,
            'error': self.error,
            'warnings': self.warnings,
            'file_size_bytes': self.file_size_bytes,
            'extracted_text_length': self.extracted_text_length,
            'match_count': self.match_count,
            'success': self.success,
        }


class Pipeline:
    """Queue-based concurrent file processing pipeline.

    Extracts text from documents and runs DLP scanning with configurable
    concurrency, filtering, and error isolation.

    Args:
        max_workers: Thread pool size for concurrent processing.
        max_file_size: Maximum file size in bytes (default 100 MB).
        categories: Default pattern categories to scan (None = all).
        require_context: Default context requirement for matches.
        min_confidence: Minimum confidence threshold (0.0-1.0).
        deduplicate: Whether to deduplicate overlapping matches.
        allowlist: Optional Allowlist for filtering false positives.
        on_result: Optional callback invoked for each completed result.

    Example::

        with Pipeline(max_workers=8, min_confidence=0.5) as pipe:
            results = pipe.process_files(glob.glob('*.pdf'))
    """

    def __init__(
        self,
        max_workers: int = DEFAULT_MAX_WORKERS,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        categories: Optional[Set[str]] = None,
        require_context: bool = False,
        min_confidence: float = 0.0,
        deduplicate: bool = True,
        allowlist: Optional[Allowlist] = None,
        on_result: Optional[Callable[['PipelineResult'], None]] = None,
    ):
        self._max_workers = max_workers
        self._max_file_size = max_file_size
        self._categories = categories
        self._require_context = require_context
        self._min_confidence = min_confidence
        self._deduplicate = deduplicate
        self._allowlist = allowlist
        self._on_result = on_result
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix='dlpscan-pipeline',
        )

    def __enter__(self) -> 'Pipeline':
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()
        return False

    def shutdown(self, wait: bool = True) -> None:
        """Shut down the thread pool."""
        self._executor.shutdown(wait=wait)

    def _process_file(self, job: FileJob) -> PipelineResult:
        """Process a single file. Never raises — errors are captured in PipelineResult."""
        start = time.monotonic()
        file_path = job.file_path

        try:
            # 1. Validate file exists and check size.
            try:
                file_size = os.path.getsize(file_path)
            except OSError:
                return PipelineResult(
                    file_path=file_path,
                    error=f"File not found: {file_path}",
                    duration_ms=_elapsed_ms(start),
                )

            if file_size > self._max_file_size:
                return PipelineResult(
                    file_path=file_path,
                    file_size_bytes=file_size,
                    error=(
                        f"File exceeds maximum size "
                        f"({file_size:,} > {self._max_file_size:,} bytes)"
                    ),
                    duration_ms=_elapsed_ms(start),
                )

            if file_size == 0:
                return PipelineResult(
                    file_path=file_path,
                    file_size_bytes=0,
                    format_detected='empty',
                    duration_ms=_elapsed_ms(start),
                )

            # 2. Extract text.
            extraction = extract_text(file_path, max_size=self._max_file_size)

            if not extraction.text.strip():
                return PipelineResult(
                    file_path=file_path,
                    file_size_bytes=file_size,
                    format_detected=extraction.format,
                    extraction_metadata=extraction.metadata,
                    warnings=extraction.warnings,
                    extracted_text_length=0,
                    duration_ms=_elapsed_ms(start),
                )

            # 3. Scan extracted text via scan_stream (handles chunking for large texts).
            categories = job.categories or self._categories
            require_context = job.require_context or self._require_context
            max_matches = job.max_matches

            text_stream = io.StringIO(extraction.text)
            matches = list(scan_stream(
                text_stream,
                categories=categories,
                require_context=require_context,
                max_matches=max_matches,
                deduplicate=self._deduplicate,
            ))

            # 4. Apply allowlist filtering.
            if self._allowlist:
                matches = self._allowlist.filter_matches(matches)

            # 5. Apply confidence threshold.
            if self._min_confidence > 0:
                matches = [m for m in matches if m.confidence >= self._min_confidence]

            result = PipelineResult(
                file_path=file_path,
                matches=matches,
                extraction_metadata=extraction.metadata,
                format_detected=extraction.format,
                warnings=extraction.warnings,
                file_size_bytes=file_size,
                extracted_text_length=len(extraction.text),
                duration_ms=_elapsed_ms(start),
            )

        except (ExtractionError, FileNotFoundError) as exc:
            logger.warning("Pipeline extraction error for %s: %s", file_path, exc)
            result = PipelineResult(
                file_path=file_path,
                error=str(exc),
                duration_ms=_elapsed_ms(start),
            )
        except Exception as exc:
            logger.warning("Pipeline unexpected error for %s: %s", file_path, exc)
            result = PipelineResult(
                file_path=file_path,
                error=f"Unexpected error: {exc}",
                duration_ms=_elapsed_ms(start),
            )

        # Invoke result callback if registered.
        if self._on_result is not None:
            try:
                self._on_result(result)
            except Exception:
                pass  # Never let callback crash the pipeline.

        return result

    def process_file(self, file_path: str, **kwargs) -> PipelineResult:
        """Process a single file synchronously.

        Args:
            file_path: Path to the file.
            **kwargs: Override FileJob fields (categories, require_context, etc.).

        Returns:
            PipelineResult with matches or error.
        """
        job = FileJob(file_path=file_path, **kwargs)
        return self._process_file(job)

    def process_files(self, file_paths: List[str], **kwargs) -> List[PipelineResult]:
        """Process multiple files concurrently.

        Returns results in the same order as the input paths.

        Args:
            file_paths: List of file paths to process.
            **kwargs: Override FileJob fields applied to all files.

        Returns:
            List of PipelineResult in input order.
        """
        if not file_paths:
            return []

        jobs = [FileJob(file_path=p, **kwargs) for p in file_paths]
        futures = {}
        for i, job in enumerate(jobs):
            future = self._executor.submit(self._process_file, job)
            futures[future] = i

        results: List[Optional[PipelineResult]] = [None] * len(jobs)
        for future in as_completed(futures):
            idx = futures[future]
            results[idx] = future.result()

        return results  # type: ignore[return-value]

    def process_directory(
        self,
        dir_path: str,
        recursive: bool = True,
        skip_hidden: bool = True,
        **kwargs,
    ) -> List[PipelineResult]:
        """Discover and process all supported files in a directory.

        Args:
            dir_path: Path to the directory.
            recursive: If True, walk subdirectories.
            skip_hidden: If True, skip files and directories starting with '.'.
            **kwargs: Override FileJob fields applied to all files.

        Returns:
            List of PipelineResult for all discovered files.
        """
        if not os.path.isdir(dir_path):
            raise FileNotFoundError(f"Directory not found: {dir_path}")

        file_paths = []
        if recursive:
            for root, dirs, files in os.walk(dir_path):
                if skip_hidden:
                    dirs[:] = [d for d in dirs if not d.startswith('.')]
                for fname in sorted(files):
                    if skip_hidden and fname.startswith('.'):
                        continue
                    file_paths.append(os.path.join(root, fname))
        else:
            for fname in sorted(os.listdir(dir_path)):
                fpath = os.path.join(dir_path, fname)
                if os.path.isfile(fpath):
                    if skip_hidden and fname.startswith('.'):
                        continue
                    file_paths.append(fpath)

        return self.process_files(file_paths, **kwargs)

    def submit(self, file_path: str, **kwargs) -> Future:
        """Submit a file for asynchronous processing.

        Returns a Future that resolves to a PipelineResult.

        Args:
            file_path: Path to the file.
            **kwargs: Override FileJob fields.

        Returns:
            concurrent.futures.Future[PipelineResult]
        """
        job = FileJob(file_path=file_path, **kwargs)
        return self._executor.submit(self._process_file, job)


def _elapsed_ms(start: float) -> float:
    """Calculate elapsed time in milliseconds from a monotonic start time."""
    return round((time.monotonic() - start) * 1000, 2)


# ---------------------------------------------------------------------------
# Structured output helpers
# ---------------------------------------------------------------------------

def results_to_json(results: List[PipelineResult], redact: bool = False, indent: int = 2) -> str:
    """Export pipeline results as a JSON string."""
    return json.dumps([r.to_dict(redact=redact) for r in results], indent=indent)


def results_to_csv(results: List[PipelineResult], stream: io.StringIO = None,
                   redact: bool = False) -> str:
    """Export pipeline results as CSV. Returns CSV string if no stream given."""
    buf = stream or io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        'file_path', 'format', 'text', 'category', 'sub_category',
        'has_context', 'confidence', 'span_start', 'span_end', 'error',
    ])
    for r in results:
        if r.matches:
            for m in r.matches:
                display = m.redacted_text if redact else m.text
                writer.writerow([
                    r.file_path, r.format_detected, display,
                    m.category, m.sub_category, m.has_context,
                    m.confidence, m.span[0], m.span[1], '',
                ])
        else:
            writer.writerow([
                r.file_path, r.format_detected, '', '', '', '', '', '', '',
                r.error or '',
            ])
    if stream is None:
        return buf.getvalue()
    return ''


def results_to_sarif(results: List[PipelineResult]) -> str:
    """Export pipeline results as SARIF 2.1.0 JSON (safe — no matched text)."""
    rules_map: Dict[str, dict] = {}
    sarif_results: List[dict] = []

    for r in results:
        for m in r.matches:
            rule_id = f"dlpscan/{m.category}/{m.sub_category}".replace(' ', '-')
            if rule_id not in rules_map:
                rules_map[rule_id] = {
                    'id': rule_id,
                    'name': m.sub_category,
                    'shortDescription': {'text': f"Detects {m.sub_category} patterns"},
                    'properties': {'category': m.category},
                }
            sarif_results.append({
                'ruleId': rule_id,
                'level': 'warning' if m.confidence >= 0.5 else 'note',
                'message': {
                    'text': f"Potential {m.sub_category} detected "
                            f"(confidence: {m.confidence:.0%})",
                },
                'locations': [{
                    'physicalLocation': {
                        'artifactLocation': {'uri': r.file_path},
                        'region': {
                            'charOffset': m.span[0],
                            'charLength': m.span[1] - m.span[0],
                        },
                    },
                }],
                'properties': {
                    'confidence': m.confidence,
                    'has_context': m.has_context,
                },
            })

    sarif = {
        '$schema': 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json',
        'version': '2.1.0',
        'runs': [{
            'tool': {
                'driver': {
                    'name': 'dlpscan',
                    'informationUri': 'https://github.com/oxide11/dlpscan',
                    'rules': list(rules_map.values()),
                },
            },
            'results': sarif_results,
        }],
    }
    return json.dumps(sarif, indent=2)
