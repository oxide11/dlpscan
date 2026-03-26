"""Async scanning support for high-throughput pipelines.

Provides async wrappers around the synchronous scanner for use in
asyncio-based applications (FastAPI, aiohttp, etc.).

Usage::

    import asyncio
    from dlpscan.async_scanner import async_scan_text, async_scan_file

    async def main():
        async for match in async_scan_text("My SSN is 123-45-6789"):
            print(match.sub_category, match.confidence)

        async for match in async_scan_file("data.csv"):
            print(match.text)

    asyncio.run(main())
"""

import asyncio
import io
import os
from concurrent.futures import ThreadPoolExecutor
from typing import AsyncGenerator, List, Optional, Set, Tuple

from .models import Match
from .scanner import (
    enhanced_scan_text as _sync_scan_text,
    scan_file as _sync_scan_file,
    scan_stream as _sync_scan_stream,
    scan_directory as _sync_scan_directory,
    MAX_MATCHES,
)

# Shared thread pool for offloading blocking scans.
_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix='dlpscan')


async def async_scan_text(
    text: str,
    categories: Optional[Set[str]] = None,
    require_context: bool = False,
    max_matches: int = MAX_MATCHES,
    deduplicate: bool = True,
) -> AsyncGenerator[Match, None]:
    """Async version of enhanced_scan_text.

    Runs the synchronous scanner in a thread pool to avoid blocking
    the event loop.

    Yields:
        Match objects.
    """
    loop = asyncio.get_running_loop()
    results: List[Match] = await loop.run_in_executor(
        _executor,
        lambda: list(_sync_scan_text(
            text,
            categories=categories,
            require_context=require_context,
            max_matches=max_matches,
            deduplicate=deduplicate,
        )),
    )
    for m in results:
        yield m


async def async_scan_file(
    file_path: str,
    categories: Optional[Set[str]] = None,
    require_context: bool = False,
    max_matches: int = MAX_MATCHES,
    deduplicate: bool = True,
    encoding: str = 'utf-8',
) -> AsyncGenerator[Match, None]:
    """Async version of scan_file.

    Yields:
        Match objects with span offsets relative to the full file.
    """
    loop = asyncio.get_running_loop()
    results: List[Match] = await loop.run_in_executor(
        _executor,
        lambda: list(_sync_scan_file(
            file_path,
            categories=categories,
            require_context=require_context,
            max_matches=max_matches,
            deduplicate=deduplicate,
            encoding=encoding,
        )),
    )
    for m in results:
        yield m


async def async_scan_directory(
    dir_path: str,
    categories: Optional[Set[str]] = None,
    require_context: bool = False,
    max_matches: int = MAX_MATCHES,
    deduplicate: bool = True,
    encoding: str = 'utf-8',
    skip_paths: Optional[List[str]] = None,
) -> AsyncGenerator[Tuple[str, Match], None]:
    """Async version of scan_directory.

    Yields:
        (relative_path, Match) tuples.
    """
    loop = asyncio.get_running_loop()
    results = await loop.run_in_executor(
        _executor,
        lambda: list(_sync_scan_directory(
            dir_path,
            categories=categories,
            require_context=require_context,
            max_matches=max_matches,
            deduplicate=deduplicate,
            encoding=encoding,
            skip_paths=skip_paths,
        )),
    )
    for item in results:
        yield item
