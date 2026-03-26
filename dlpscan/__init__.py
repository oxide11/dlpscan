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
from .compliance import ComplianceReport, ComplianceReporter
from .config import load_config
from .context import CONTEXT_KEYWORDS
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
from .logging_config import configure_logging
from .metrics import MetricsCollector, ScanMetrics, set_metrics_callback
from .models import Match
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
from .rate_limit import RateLimiter, RateLimitExceeded, rate_limited
from .scanner import (
    MAX_INPUT_SIZE,
    MAX_MATCHES,
    MAX_SCAN_SECONDS,
    REGEX_TIMEOUT_SECONDS,
    enhanced_scan_text,
    is_luhn_valid,
    redact_sensitive_info,
    redact_sensitive_info_with_patterns,
    register_patterns,
    scan_directory,
    scan_file,
    scan_for_context,
    scan_stream,
    unregister_patterns,
)
from .siem import (
    DatadogAdapter,
    ElasticsearchAdapter,
    SplunkHECAdapter,
    SyslogAdapter,
    WebhookAdapter,
    create_siem_from_env,
)
from .streaming import StreamScanner, WebhookScanner

__version__ = '1.3.0'
