"""File, stream, and directory scanning with chunked processing."""

import fnmatch
import io
import logging
import os
from typing import Generator, List, Optional, Set, Tuple

from ..exceptions import EmptyInputError
from ..models import Match
from ._core import MAX_MATCHES, enhanced_scan_text

logger = logging.getLogger(__name__)

# Default directories and file extensions to skip during directory scanning.
_SKIP_DIRS = frozenset({
    '.git', '.hg', '.svn', '__pycache__', 'node_modules', '.tox',
    '.mypy_cache', '.ruff_cache', '.pytest_cache', 'venv', '.venv',
    'env', '.env', 'dist', 'build', '.eggs', '*.egg-info',
})

_BINARY_EXTENSIONS = frozenset({
    '.pyc', '.pyo', '.so', '.dylib', '.dll', '.exe', '.bin',
    '.gif', '.ico',
    '.mp3', '.mp4', '.avi', '.mov', '.mkv', '.wav', '.flac',
    '.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.sqlite', '.db', '.pickle', '.pkl',
})

# Extensions that require extractors (not raw text reading).
_EXTRACTOR_EXTENSIONS = frozenset({
    '.png', '.jpg', '.jpeg', '.bmp', '.tiff', '.tif', '.webp',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
})


def _has_extractor(path: str) -> bool:
    """Check if a file has a registered extractor (e.g. images, Office docs)."""
    _, ext = os.path.splitext(path)
    return ext.lower() in _EXTRACTOR_EXTENSIONS


def _is_binary_file(path: str) -> bool:
    """Quick heuristic to detect binary files."""
    _, ext = os.path.splitext(path)
    ext_lower = ext.lower()
    if ext_lower in _BINARY_EXTENSIONS:
        return True
    if ext_lower in _EXTRACTOR_EXTENSIONS:
        return False
    try:
        with open(path, 'rb') as f:
            chunk = f.read(8192)
            return b'\x00' in chunk
    except OSError:
        return True


def _scan_chunks(
    read_fn,
    categories: Optional[Set[str]],
    require_context: bool,
    max_matches: int,
    deduplicate: bool,
    chunk_size: int,
    chunk_overlap: int,
) -> Generator[Match, None, None]:
    """Shared chunked scanning logic for files and streams."""
    total_yielded = 0
    offset = 0
    prev_tail = ''
    seen_spans: set = set()

    while True:
        raw = read_fn(chunk_size)
        if not raw:
            break

        chunk = prev_tail + raw
        chunk_offset = offset - len(prev_tail)

        try:
            for m in enhanced_scan_text(
                chunk,
                categories=categories,
                require_context=require_context,
                max_matches=max_matches - total_yielded,
                deduplicate=deduplicate,
            ):
                abs_span = (m.span[0] + chunk_offset, m.span[1] + chunk_offset)

                if abs_span in seen_spans:
                    continue
                seen_spans.add(abs_span)

                adjusted = Match(
                    text=m.text,
                    category=m.category,
                    sub_category=m.sub_category,
                    has_context=m.has_context,
                    confidence=m.confidence,
                    span=abs_span,
                    context_required=m.context_required,
                )
                yield adjusted
                total_yielded += 1

                if total_yielded >= max_matches:
                    return
        except EmptyInputError:
            pass
        except ValueError as exc:
            logger.debug("Chunk skipped (offset %d): %s", chunk_offset, exc)

        prev_tail = raw[-chunk_overlap:] if len(raw) >= chunk_overlap else raw
        offset += len(raw)

        cutoff = offset - chunk_overlap
        seen_spans = {s for s in seen_spans if s[1] > cutoff}


def scan_file(
    file_path: str,
    categories: Optional[Set[str]] = None,
    require_context: bool = False,
    max_matches: int = MAX_MATCHES,
    deduplicate: bool = True,
    encoding: str = 'utf-8',
    chunk_size: int = 1024 * 1024,
    chunk_overlap: int = 1024,
) -> Generator[Match, None, None]:
    """Scan a file for sensitive data, processing in chunks for memory efficiency."""
    try:
        file_size = os.path.getsize(file_path)
    except OSError:
        raise FileNotFoundError(f"File not found: {file_path}")

    if file_size == 0:
        return

    with open(file_path, 'r', encoding=encoding, errors='replace') as f:
        yield from _scan_chunks(
            f.read, categories, require_context, max_matches,
            deduplicate, chunk_size, chunk_overlap,
        )


def scan_stream(
    stream: io.TextIOBase,
    categories: Optional[Set[str]] = None,
    require_context: bool = False,
    max_matches: int = MAX_MATCHES,
    deduplicate: bool = True,
    chunk_size: int = 1024 * 1024,
    chunk_overlap: int = 1024,
) -> Generator[Match, None, None]:
    """Scan a text stream for sensitive data."""
    yield from _scan_chunks(
        stream.read, categories, require_context, max_matches,
        deduplicate, chunk_size, chunk_overlap,
    )


def scan_directory(
    dir_path: str,
    categories: Optional[Set[str]] = None,
    require_context: bool = False,
    max_matches: int = MAX_MATCHES,
    deduplicate: bool = True,
    encoding: str = 'utf-8',
    skip_paths: Optional[List[str]] = None,
) -> Generator[Tuple[str, Match], None, None]:
    """Recursively scan all text files in a directory."""
    if not os.path.isdir(dir_path):
        raise FileNotFoundError(f"Directory not found: {dir_path}")

    total_yielded = 0
    skip_globs = skip_paths or []

    for root, dirs, files in os.walk(dir_path):
        dirs[:] = [
            d for d in dirs
            if d not in _SKIP_DIRS
            and not any(fnmatch.fnmatch(d, p) for p in _SKIP_DIRS if '*' in p)
        ]

        for filename in sorted(files):
            if total_yielded >= max_matches:
                return

            file_path = os.path.join(root, filename)
            rel_path = os.path.relpath(file_path, dir_path)

            if any(fnmatch.fnmatch(rel_path, g) for g in skip_globs):
                continue

            if _is_binary_file(file_path):
                continue

            try:
                if _has_extractor(file_path):
                    try:
                        from ..extractors import extract_text as _extract
                        result = _extract(file_path)
                        if result.text:
                            for m in enhanced_scan_text(
                                result.text,
                                categories=categories,
                                require_context=require_context,
                                max_matches=max_matches - total_yielded,
                                deduplicate=deduplicate,
                            ):
                                yield (rel_path, m)
                                total_yielded += 1
                                if total_yielded >= max_matches:
                                    return
                    except ImportError as exc:
                        logger.debug("Extractor dependency missing for %s: %s", file_path, exc)
                    except (FileNotFoundError, OSError) as exc:
                        logger.warning("Extractor I/O error for %s: %s", file_path, exc)
                    except Exception as exc:
                        logger.warning("Extractor failed for %s: %s", file_path, exc)
                    continue

                for m in scan_file(
                    file_path,
                    categories=categories,
                    require_context=require_context,
                    max_matches=max_matches - total_yielded,
                    deduplicate=deduplicate,
                    encoding=encoding,
                ):
                    yield (rel_path, m)
                    total_yielded += 1

                    if total_yielded >= max_matches:
                        return
            except (FileNotFoundError, UnicodeDecodeError, OSError) as exc:
                logger.debug("Skipping %s: %s", file_path, exc)
                continue
