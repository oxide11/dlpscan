"""Scanner package — backward-compatible re-exports.

All public symbols are available via ``from dlpscan.scanner import ...``
exactly as before the package split.
"""

# Config
# Dynamic re-export for mutable model attributes accessed via scanner module.
from .. import models as _models
from ._config import (  # noqa: F401
    compiled_context_patterns,
    get_context_backend,
    register_patterns,
    set_context_backend,
    unregister_patterns,
)

# Context
from ._context import (  # noqa: F401
    _check_context,
    _fuzzy_keyword_match,
    _get_raw_keywords,
    _levenshtein_distance,
    scan_for_context,
)

# Core
from ._core import (  # noqa: F401
    MAX_MATCHES,
    MAX_SCAN_SECONDS,
    REGEX_TIMEOUT_SECONDS,
    enhanced_scan_text,
)

# I/O
from ._io import (  # noqa: F401
    _BINARY_EXTENSIONS,
    _EXTRACTOR_EXTENSIONS,
    _has_extractor,
    _is_binary_file,
    scan_directory,
    scan_file,
    scan_stream,
)

# Redaction
from ._redaction import (  # noqa: F401
    redact_sensitive_info,
    redact_sensitive_info_with_patterns,
)

# Scoring
from ._scoring import (  # noqa: F401
    _compute_confidence,
    _deduplicate_overlapping,
)

# Timeout
from ._timeout import (  # noqa: F401
    _RegexTimeout,
    _ThreadTimeout,
)

# Validation
from ._validation import (  # noqa: F401
    MAX_INPUT_SIZE,
    is_luhn_valid,
)


def __getattr__(name: str):
    if name == 'CONTEXT_REQUIRED_PATTERNS':
        return _models.CONTEXT_REQUIRED_PATTERNS
    raise AttributeError(f"module 'dlpscan.scanner' has no attribute {name!r}")
