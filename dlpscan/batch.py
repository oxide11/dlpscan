"""Batch and database scanning module for DLP scanning.

Provides ``BatchScanner`` for scanning large collections of text from
multiple sources: in-memory iterables, CSV files, JSON/JSONL files,
pandas DataFrames, and SQL databases.

Usage::

    from dlpscan.batch import BatchScanner

    scanner = BatchScanner(max_workers=4)

    # Scan a list of texts
    results = scanner.scan_texts(["My SSN is 123-45-6789", "Nothing here"])

    # Scan a CSV file
    results = scanner.scan_csv("data.csv", columns=["notes", "comments"])

    # Generate a summary report
    report = BatchScanner.summarize(results)
    print(f"{report.items_with_findings}/{report.total_items} items flagged")
"""

import csv
import json
import logging
import sqlite3
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    Optional,
    Tuple,
)

from .guard.core import InputGuard, ScanResult
from .guard.enums import Action

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

_TEXT_TRUNCATE_LENGTH = 200


@dataclass
class BatchResult:
    """Result of scanning a single item in a batch.

    Attributes:
        source_id: Identifier for the item (file path, row number, or custom ID).
        text: Original text, truncated to 200 characters.
        scan_result: The ``ScanResult`` from InputGuard.
        error: Error message if scanning this item failed, else ``None``.
    """

    source_id: str
    text: str
    scan_result: Optional[ScanResult] = None
    error: Optional[str] = None


@dataclass
class BatchReport:
    """Aggregated summary of a batch scan.

    Attributes:
        total_items: Number of items scanned.
        items_with_findings: Number of items that had at least one finding.
        total_findings: Total number of individual findings across all items.
        categories_summary: Count of findings per category.
        duration_seconds: Wall-clock duration of the batch scan.
        results: Full list of ``BatchResult`` objects.
    """

    total_items: int
    items_with_findings: int
    total_findings: int
    categories_summary: Dict[str, int]
    duration_seconds: float
    results: List[BatchResult]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _truncate(text: str, max_len: int = _TEXT_TRUNCATE_LENGTH) -> str:
    """Truncate *text* to *max_len* characters, appending an ellipsis if cut."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + "..."


def _chunked(iterable: List[Any], size: int) -> Iterator[List[Any]]:
    """Yield successive chunks of *size* from *iterable*."""
    for i in range(0, len(iterable), size):
        yield iterable[i : i + size]


# ---------------------------------------------------------------------------
# BatchScanner
# ---------------------------------------------------------------------------


class BatchScanner:
    """Scan large collections of text for sensitive data.

    Args:
        guard: An ``InputGuard`` instance to use for scanning.  If ``None``,
            a default guard with ``action=FLAG`` is created so that scanning
            never raises on detection.
        max_workers: Number of threads for parallel scanning.
        on_result: Optional callback invoked with each ``BatchResult`` as it
            completes.
        on_progress: Optional callback invoked with ``(completed, total)``
            during batch operations.
        chunk_size: Number of items to process per chunk.  Limits memory
            usage when scanning very large datasets.
    """

    def __init__(
        self,
        guard: Optional[InputGuard] = None,
        max_workers: int = 4,
        on_result: Optional[Callable[[BatchResult], None]] = None,
        on_progress: Optional[Callable[[int, int], None]] = None,
        chunk_size: int = 1000,
    ):
        if guard is not None:
            self._guard = guard
        else:
            self._guard = InputGuard(action=Action.FLAG)
        self._max_workers = max_workers
        self._on_result = on_result
        self._on_progress = on_progress
        self._chunk_size = chunk_size

    # -- internal helpers ---------------------------------------------------

    def _scan_one(self, source_id: str, text: str) -> BatchResult:
        """Scan a single piece of text, capturing errors."""
        truncated = _truncate(text)
        try:
            result = self._guard.scan(text)
            return BatchResult(
                source_id=source_id,
                text=truncated,
                scan_result=result,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            return BatchResult(
                source_id=source_id,
                text=truncated,
                error=str(exc),
            )

    def _process_pairs(
        self,
        pairs: List[Tuple[str, str]],
    ) -> List[BatchResult]:
        """Process a list of ``(source_id, text)`` pairs in parallel chunks.

        Returns results in the same order as *pairs*.
        """
        total = len(pairs)
        all_results: List[Optional[BatchResult]] = [None] * total
        completed = 0

        for chunk_start in range(0, total, self._chunk_size):
            chunk = pairs[chunk_start : chunk_start + self._chunk_size]
            futures: Dict[Any, int] = {}

            with ThreadPoolExecutor(
                max_workers=self._max_workers,
                thread_name_prefix="dlpscan-batch",
            ) as executor:
                for offset, (sid, text) in enumerate(chunk):
                    idx = chunk_start + offset
                    future = executor.submit(self._scan_one, sid, text)
                    futures[future] = idx

                for future in as_completed(futures):
                    idx = futures[future]
                    batch_result = future.result()
                    all_results[idx] = batch_result

                    # Callbacks
                    if self._on_result is not None:
                        try:
                            self._on_result(batch_result)
                        except Exception as exc:
                            logger.warning("on_result callback error: %s", exc)

                    completed += 1
                    if self._on_progress is not None:
                        try:
                            self._on_progress(completed, total)
                        except Exception as exc:
                            logger.warning("on_progress callback error: %s", exc)

        return all_results  # type: ignore[return-value]

    # -- public API ---------------------------------------------------------

    def scan_texts(
        self,
        texts: Iterable[str],
        source_ids: Optional[List[str]] = None,
    ) -> List[BatchResult]:
        """Scan multiple texts in parallel.

        Args:
            texts: Iterable of text strings to scan.
            source_ids: Optional list of identifiers corresponding to each
                text.  If ``None``, sequential indices (``"0"``, ``"1"``, ...)
                are used.

        Returns:
            List of ``BatchResult`` in the same order as *texts*.
        """
        text_list = list(texts)
        if source_ids is not None:
            if len(source_ids) != len(text_list):
                raise ValueError(
                    f"source_ids length ({len(source_ids)}) does not match "
                    f"texts length ({len(text_list)})"
                )
            ids = source_ids
        else:
            ids = [str(i) for i in range(len(text_list))]

        pairs = list(zip(ids, text_list))
        return self._process_pairs(pairs)

    def scan_csv(
        self,
        path: str,
        columns: Optional[List[str]] = None,
        delimiter: str = ",",
    ) -> List[BatchResult]:
        """Scan specific columns of a CSV file.

        Each row produces one ``BatchResult`` whose text is the concatenation
        of the selected columns (space-separated).

        Args:
            path: Path to the CSV file.
            columns: Column names to scan.  If ``None``, all columns are
                scanned.
            delimiter: CSV field delimiter.

        Returns:
            List of ``BatchResult``, one per row.
        """
        pairs: List[Tuple[str, str]] = []

        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh, delimiter=delimiter)
            for row_num, row in enumerate(reader, start=1):
                if columns is not None:
                    values = [row.get(c, "") for c in columns]
                else:
                    values = list(row.values())
                text = " ".join(v for v in values if v)
                source_id = f"{path}:row:{row_num}"
                pairs.append((source_id, text))

        return self._process_pairs(pairs)

    def scan_json(
        self,
        path: str,
        fields: Optional[List[str]] = None,
    ) -> List[BatchResult]:
        """Scan specific fields of a JSON or JSONL file.

        The file may contain either a single JSON array of objects, or one
        JSON object per line (JSONL / newline-delimited JSON).

        Args:
            path: Path to the JSON/JSONL file.
            fields: Top-level field names to scan.  If ``None``, all string
                values are scanned.

        Returns:
            List of ``BatchResult``, one per record.
        """
        records: List[dict] = []

        with open(path, encoding="utf-8") as fh:
            content = fh.read().strip()

        if not content:
            return []

        # Try standard JSON first (array or single object).
        try:
            parsed = json.loads(content)
            if isinstance(parsed, list):
                records = parsed
            elif isinstance(parsed, dict):
                records = [parsed]
            else:
                return []
        except json.JSONDecodeError:
            # Fall back to JSONL.
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        records.append(obj)
                except json.JSONDecodeError:
                    continue

        pairs: List[Tuple[str, str]] = []
        for idx, record in enumerate(records):
            if not isinstance(record, dict):
                continue
            if fields is not None:
                values = [
                    str(record[f]) for f in fields if f in record and record[f] is not None
                ]
            else:
                values = [
                    str(v) for v in record.values() if isinstance(v, str)
                ]
            text = " ".join(values)
            source_id = f"{path}:record:{idx}"
            pairs.append((source_id, text))

        return self._process_pairs(pairs)

    def scan_dataframe(
        self,
        df: Any,
        columns: Optional[List[str]] = None,
    ) -> List[BatchResult]:
        """Scan columns of a pandas DataFrame.

        Args:
            df: A ``pandas.DataFrame``.
            columns: Column names to scan.  If ``None``, all columns with
                ``object`` (string) dtype are scanned.

        Returns:
            List of ``BatchResult``, one per row.

        Raises:
            ImportError: If pandas is not installed.
        """
        try:
            import pandas as pd  # noqa: F401
        except ImportError:
            raise ImportError(
                "pandas is required for scan_dataframe(). "
                "Install it with: pip install pandas"
            )

        if columns is None:
            columns = [c for c in df.columns if df[c].dtype == object]

        pairs: List[Tuple[str, str]] = []
        for row_idx in range(len(df)):
            values = [
                str(df.iloc[row_idx][c])
                for c in columns
                if df.iloc[row_idx][c] is not None
                and str(df.iloc[row_idx][c]) != "nan"
            ]
            text = " ".join(values)
            source_id = f"dataframe:row:{row_idx}"
            pairs.append((source_id, text))

        return self._process_pairs(pairs)

    def scan_database(
        self,
        connection_string: str,
        query: str,
        columns: Optional[List[str]] = None,
    ) -> List[BatchResult]:
        """Scan results of a database query.

        SQLite is supported via the standard library.  For other databases,
        the appropriate driver must be installed (e.g., ``psycopg2`` for
        PostgreSQL, ``mysql-connector-python`` for MySQL).

        Args:
            connection_string: For SQLite, the path to the database file
                (optionally prefixed with ``sqlite:///``).  For other
                databases, a connection string suitable for the driver.
            query: SQL query to execute.
            columns: Column names to scan from the result set.  If ``None``,
                all columns are scanned.

        Returns:
            List of ``BatchResult``, one per row.
        """
        conn = self._connect_db(connection_string)
        try:
            cursor = conn.cursor()
            cursor.execute(query)
            col_names = [desc[0] for desc in cursor.description] if cursor.description else []

            if columns is not None:
                col_indices = []
                for c in columns:
                    try:
                        col_indices.append(col_names.index(c))
                    except ValueError:
                        raise ValueError(
                            f"Column '{c}' not found in query results. "
                            f"Available columns: {col_names}"
                        )
            else:
                col_indices = list(range(len(col_names)))

            pairs: List[Tuple[str, str]] = []
            for row_num, row in enumerate(cursor.fetchall(), start=1):
                values = [
                    str(row[i])
                    for i in col_indices
                    if row[i] is not None
                ]
                text = " ".join(values)
                source_id = f"db:row:{row_num}"
                pairs.append((source_id, text))
        finally:
            conn.close()

        return self._process_pairs(pairs)

    @staticmethod
    def _connect_db(connection_string: str) -> Any:
        """Open a database connection from a connection string.

        Supports:
        - SQLite: a file path or ``sqlite:///path/to/db``
        - PostgreSQL: ``postgresql://...`` (requires ``psycopg2``)
        - MySQL: ``mysql://...`` (requires ``mysql-connector-python``)

        Returns an open connection object.
        """
        cs = connection_string.strip()

        # SQLite
        if cs.startswith("sqlite:///"):
            db_path = cs[len("sqlite:///"):]
            return sqlite3.connect(db_path)
        if cs.endswith(".db") or cs.endswith(".sqlite") or cs.endswith(".sqlite3"):
            return sqlite3.connect(cs)
        if cs == ":memory:" or cs.startswith("file:"):
            return sqlite3.connect(cs)

        # PostgreSQL
        if cs.startswith("postgresql://") or cs.startswith("postgres://"):
            try:
                import psycopg2  # type: ignore
            except ImportError:
                raise ImportError(
                    "psycopg2 is required for PostgreSQL connections. "
                    "Install it with: pip install psycopg2-binary"
                )
            return psycopg2.connect(cs)

        # MySQL
        if cs.startswith("mysql://"):
            try:
                import mysql.connector  # type: ignore
            except ImportError:
                raise ImportError(
                    "mysql-connector-python is required for MySQL connections. "
                    "Install it with: pip install mysql-connector-python"
                )
            # Parse mysql://user:pass@host:port/dbname
            from urllib.parse import urlparse

            parsed = urlparse(cs)
            return mysql.connector.connect(
                host=parsed.hostname or "localhost",
                port=parsed.port or 3306,
                user=parsed.username,
                password=parsed.password,
                database=parsed.path.lstrip("/") if parsed.path else None,
            )

        # Fallback: try as SQLite path
        return sqlite3.connect(cs)

    # -- summarize ----------------------------------------------------------

    @staticmethod
    def summarize(results: List[BatchResult]) -> BatchReport:
        """Aggregate a list of ``BatchResult`` into a ``BatchReport``.

        This is a static method so it can be called without a scanner
        instance, e.g., after deserializing stored results.

        Args:
            results: List of ``BatchResult`` objects.

        Returns:
            A ``BatchReport`` with aggregated statistics.
        """
        total_items = len(results)
        items_with_findings = 0
        total_findings = 0
        categories: Dict[str, int] = {}

        for r in results:
            if r.scan_result is not None and not r.scan_result.is_clean:
                items_with_findings += 1
                finding_count = r.scan_result.finding_count
                total_findings += finding_count
                for cat in r.scan_result.categories_found:
                    categories[cat] = categories.get(cat, 0) + 1

        return BatchReport(
            total_items=total_items,
            items_with_findings=items_with_findings,
            total_findings=total_findings,
            categories_summary=categories,
            duration_seconds=0.0,
            results=results,
        )
