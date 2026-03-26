"""Structured JSON logging for enterprise log aggregation.

Configures dlpscan's loggers to emit JSON-formatted log records
compatible with ELK, Splunk, Datadog, and other log aggregation
platforms.

Usage::

    from dlpscan.logging_config import configure_logging

    # JSON logging to stderr (default)
    configure_logging(level='INFO', json_format=True)

    # Plain text logging
    configure_logging(level='DEBUG', json_format=False)

    # Custom stream
    configure_logging(level='WARNING', json_format=True, stream=my_file)
"""

import json
import logging
import sys
import time
from typing import Optional, TextIO


class JSONFormatter(logging.Formatter):
    """Format log records as single-line JSON objects.

    Output format::

        {"timestamp":"2026-03-26T12:00:00.000Z","level":"WARNING",
         "logger":"dlpscan.scanner","message":"Match limit reached (50000).",
         "module":"scanner","funcName":"enhanced_scan_text"}
    """

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            'timestamp': self.formatTime(record, datefmt='%Y-%m-%dT%H:%M:%S') + '.{:03d}Z'.format(
                int(record.msecs)),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'funcName': record.funcName,
        }

        if record.exc_info and record.exc_info[1]:
            log_entry['exception'] = {
                'type': type(record.exc_info[1]).__name__,
                'message': str(record.exc_info[1]),
            }

        # Include any extra fields set via logger.warning("msg", extra={...}).
        for key in ('scan_duration_ms', 'match_count', 'file_path',
                     'pattern', 'category', 'bytes_scanned'):
            if hasattr(record, key):
                log_entry[key] = getattr(record, key)

        return json.dumps(log_entry, default=str)


def configure_logging(
    level: str = 'WARNING',
    json_format: bool = True,
    stream: Optional[TextIO] = None,
) -> None:
    """Configure dlpscan logging.

    Args:
        level: Log level string ('DEBUG', 'INFO', 'WARNING', 'ERROR').
        json_format: If True, emit JSON log lines. If False, plain text.
        stream: Output stream (default: sys.stderr).
    """
    dlpscan_logger = logging.getLogger('dlpscan')
    dlpscan_logger.setLevel(getattr(logging, level.upper(), logging.WARNING))

    # Remove existing handlers to avoid duplicate output.
    dlpscan_logger.handlers.clear()

    handler = logging.StreamHandler(stream or sys.stderr)

    if json_format:
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
        ))

    dlpscan_logger.addHandler(handler)
