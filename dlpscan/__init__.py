from .scanner import (
    enhanced_scan_text,
    redact_sensitive_info,
    redact_sensitive_info_with_patterns,
    is_luhn_valid,
    scan_for_context,
    scan_file,
    scan_stream,
    scan_directory,
    register_patterns,
    unregister_patterns,
    MAX_INPUT_SIZE,
    MAX_MATCHES,
    MAX_SCAN_SECONDS,
    REGEX_TIMEOUT_SECONDS,
)
from .models import Match
from .config import load_config
from .allowlist import Allowlist
from .patterns import PATTERNS
from .context import CONTEXT_KEYWORDS
from .exceptions import (
    RedactionError,
    EmptyInputError,
    ShortInputError,
    InvalidCardNumberError,
    SubCategoryNotFoundError,
    ExtractionError,
)
from .metrics import ScanMetrics, set_metrics_callback, MetricsCollector
from .plugins import (
    register_validator,
    unregister_validators,
    register_post_processor,
    unregister_post_processors,
    run_validators,
    run_post_processors,
)
from .logging_config import configure_logging
from .async_scanner import async_scan_text, async_scan_file, async_scan_directory
from .extractors import (
    ExtractionResult,
    extract_text,
    register_extractor,
    supported_extensions,
)
from .pipeline import Pipeline, FileJob, PipelineResult
from .input_guard import (
    InputGuard,
    ScanResult,
    Preset,
    Action,
    Mode,
    InputGuardError,
    PRESET_CATEGORIES,
)

__version__ = '1.0.0'
