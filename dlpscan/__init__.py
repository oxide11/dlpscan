from .ahocorasick import (
    CONTEXT_BACKEND_AHOCORASICK,
    CONTEXT_BACKEND_REGEX,
    AhoCorasickMatcher,
    ContextHitIndex,
    get_matcher,
    rebuild_matcher,
)
from .allowlist import Allowlist
from .async_scanner import async_scan_directory, async_scan_file, async_scan_text
from .audit import (
    AuditEvent,
    AuditLogger,
    CallbackAuditHandler,
    FileAuditHandler,
    NullAuditHandler,
    StderrAuditHandler,
    audit_event,
    event_from_scan,
    get_audit_logger,
    set_audit_logger,
)
from .cache import ScanCache, get_default_cache, set_default_cache
from .compliance import ComplianceReport, ComplianceReporter
from .config import load_config
from .context import CONTEXT_KEYWORDS
from .countmin import CountMinSketch
from .cuckoo import CuckooFilter
from .edm import EDMMatch, ExactDataMatcher
from .entropy import EntropyAnalyzer, EntropyResult, ExtractedItem, RecursiveExtractor
from .env_config import apply_env_to_guard_kwargs, configure_from_env
from .exceptions import (
    EmptyInputError,
    ExtractionError,
    InvalidCardNumberError,
    RedactionError,
    ShortInputError,
    SubCategoryNotFoundError,
)
from .extractors import (
    ExtractionResult,
    extract_text,
    register_extractor,
    supported_extensions,
)
from .guard import (
    PRESET_CATEGORIES,
    Action,
    InputGuard,
    InputGuardError,
    Mode,
    Permission,
    PermissionDeniedError,
    Preset,
    RBACPolicy,
    Role,
    ScanResult,
    SecureTokenVault,
    TokenVault,
    get_obfuscation_rng,
    obfuscate_match,
    obfuscate_matches,
    set_obfuscation_seed,
    tokenize_matches,
)
from .hyperloglog import HyperLogLog
from .logging_config import configure_logging
from .lsh import DocumentVault, SimilarityMatch
from .metrics import MetricsCollector, ScanMetrics, set_metrics_callback
from .models import Match
from .ocr import (
    IMAGE_EXTENSIONS,
    OCRResult,
    ocr_available,
    ocr_image,
    ocr_page_image,
    ocr_pdf,
    pdf_ocr_available,
)
from .patterns import PATTERNS
from .pipeline import (
    FileJob,
    Pipeline,
    PipelineResult,
    results_to_csv,
    results_to_json,
    results_to_sarif,
)
from .plugins import (
    register_post_processor,
    register_validator,
    run_post_processors,
    run_validators,
    unregister_post_processors,
    unregister_validators,
)
from .rabin_karp import FragmentMatch, PartialDocumentMatcher
from .rate_limit import RateLimiter, RateLimitExceeded, rate_limited
from .rulesets import (
    CategoryOverride,
    CustomPattern,
    Ruleset,
    available_baselines,
    available_categories,
    available_presets,
    load_ruleset,
    load_ruleset_from_string,
)
from .scanner import (
    MAX_INPUT_SIZE,
    MAX_MATCHES,
    MAX_SCAN_SECONDS,
    REGEX_TIMEOUT_SECONDS,
    enhanced_scan_text,
    get_context_backend,
    is_luhn_valid,
    redact_sensitive_info,
    redact_sensitive_info_with_patterns,
    register_patterns,
    scan_directory,
    scan_file,
    scan_for_context,
    scan_stream,
    set_context_backend,
    unregister_patterns,
)
from .session import CorrelationAlert, Policy, SessionCorrelator, SessionStats
from .siem import (
    DatadogAdapter,
    ElasticsearchAdapter,
    SplunkHECAdapter,
    SyslogAdapter,
    WebhookAdapter,
    create_siem_from_env,
)
from .streaming import StreamScanner, WebhookScanner
from .unicode_normalize import (
    UNICODE_SPACES,
    ZERO_WIDTH_CHARS,
    normalize_homoglyphs,
    normalize_text,
    normalize_whitespace,
    strip_zero_width,
)
from .webhooks import WebhookNotifier, notify_findings

__version__ = '1.7.0'
