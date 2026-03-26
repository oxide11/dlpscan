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
from .pipeline import (
    Pipeline, FileJob, PipelineResult,
    results_to_json, results_to_csv, results_to_sarif,
)
from .streaming import StreamScanner, WebhookScanner
from .guard import (
    InputGuard,
    ScanResult,
    Preset,
    Action,
    Mode,
    InputGuardError,
    PRESET_CATEGORIES,
    TokenVault,
    tokenize_matches,
    obfuscate_matches,
    obfuscate_match,
    set_obfuscation_seed,
    get_obfuscation_rng,
    Role,
    Permission,
    PermissionDeniedError,
    RBACPolicy,
    SecureTokenVault,
)
from .audit import (
    AuditEvent,
    AuditLogger,
    StderrAuditHandler,
    FileAuditHandler,
    CallbackAuditHandler,
    NullAuditHandler,
    set_audit_logger,
    get_audit_logger,
    audit_event,
    event_from_scan,
)
from .rate_limit import RateLimiter, RateLimitExceeded, rate_limited
from .env_config import configure_from_env, apply_env_to_guard_kwargs
from .siem import (
    SplunkHECAdapter,
    ElasticsearchAdapter,
    SyslogAdapter,
    WebhookAdapter,
    DatadogAdapter,
    create_siem_from_env,
)
from .compliance import ComplianceReporter, ComplianceReport

__version__ = '1.3.0'
