"""Environment variable configuration loader for dlpscan.

Loads dlpscan settings from ``DLPSCAN_*`` environment variables so that
the library can be configured without code changes (e.g. in containers,
CI, or serverless environments).

Usage::

    from dlpscan.env_config import configure_from_env

    # One-call setup — configures logging, audit, and rate limiting.
    configure_from_env()

    # Or get a kwargs dict for InputGuard:
    from dlpscan.env_config import apply_env_to_guard_kwargs
    from dlpscan.guard import InputGuard
    guard = InputGuard(**apply_env_to_guard_kwargs())
"""

import logging
import os
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Truthy / falsy string values accepted for boolean env vars.
_TRUTHY = frozenset({"true", "1", "yes", "on"})
_FALSY = frozenset({"false", "0", "no", "off"})


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    """Return the value of an environment variable, or *default*."""
    return os.environ.get(name, default)


def _env_bool(name: str) -> Optional[bool]:
    """Parse a boolean environment variable. Returns None if unset."""
    value = _env(name)
    if value is None:
        return None
    lower = value.strip().lower()
    if lower in _TRUTHY:
        return True
    if lower in _FALSY:
        return False
    logger.warning("Invalid boolean value for %s: %r (expected true/false/1/0)", name, value)
    return None


def _env_float(name: str) -> Optional[float]:
    """Parse a float environment variable. Returns None if unset."""
    value = _env(name)
    if value is None:
        return None
    try:
        return float(value)
    except ValueError:
        logger.warning("Invalid float value for %s: %r", name, value)
        return None


def _env_int(name: str) -> Optional[int]:
    """Parse an integer environment variable. Returns None if unset."""
    value = _env(name)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        logger.warning("Invalid integer value for %s: %r", name, value)
        return None


def _env_list(name: str) -> Optional[List[str]]:
    """Parse a comma-separated list environment variable. Returns None if unset."""
    value = _env(name)
    if value is None:
        return None
    return [item.strip() for item in value.split(",") if item.strip()]


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------

def load_env_config() -> dict:
    """Load dlpscan configuration from environment variables.

    Supported env vars:
        DLPSCAN_PRESETS: comma-separated preset names (e.g., "pci_dss,ssn_sin")
        DLPSCAN_ACTION: action name (reject, redact, flag, tokenize, obfuscate)
        DLPSCAN_MODE: mode name (denylist, allowlist)
        DLPSCAN_MIN_CONFIDENCE: float (0.0-1.0)
        DLPSCAN_REQUIRE_CONTEXT: bool (true/false/1/0)
        DLPSCAN_CATEGORIES: comma-separated category names
        DLPSCAN_REDACTION_CHAR: single character
        DLPSCAN_MAX_MATCHES: integer
        DLPSCAN_CONTEXT_BACKEND: context matching backend (regex/ahocorasick)
        DLPSCAN_LOG_LEVEL: DEBUG/INFO/WARNING/ERROR
        DLPSCAN_LOG_FORMAT: json/text
        DLPSCAN_AUDIT_FILE: path to audit log file
        DLPSCAN_RATE_LIMIT: max requests per minute
        DLPSCAN_MAX_PAYLOAD: max payload bytes
        DLPSCAN_VAULT_BACKEND: memory/file/redis
        DLPSCAN_VAULT_PATH: path for file backend
        DLPSCAN_VAULT_ENCRYPTION_KEY: encryption key for vault
        DLPSCAN_REDIS_URL: Redis connection URL

    Returns:
        Dictionary of all detected configuration values. Keys whose env
        vars are not set are omitted from the result.
    """
    config: Dict[str, Any] = {}

    # -- Scanning presets & categories --
    presets = _env_list("DLPSCAN_PRESETS")
    if presets is not None:
        config["presets"] = presets

    action = _env("DLPSCAN_ACTION")
    if action is not None:
        config["action"] = action.strip().lower()

    mode = _env("DLPSCAN_MODE")
    if mode is not None:
        config["mode"] = mode.strip().lower()

    min_conf = _env_float("DLPSCAN_MIN_CONFIDENCE")
    if min_conf is not None:
        config["min_confidence"] = max(0.0, min(1.0, min_conf))

    req_ctx = _env_bool("DLPSCAN_REQUIRE_CONTEXT")
    if req_ctx is not None:
        config["require_context"] = req_ctx

    categories = _env_list("DLPSCAN_CATEGORIES")
    if categories is not None:
        config["categories"] = categories

    redaction_char = _env("DLPSCAN_REDACTION_CHAR")
    if redaction_char is not None:
        if len(redaction_char) == 1:
            config["redaction_char"] = redaction_char
        else:
            logger.warning(
                "DLPSCAN_REDACTION_CHAR must be a single character, got %r",
                redaction_char,
            )

    max_matches = _env_int("DLPSCAN_MAX_MATCHES")
    if max_matches is not None:
        config["max_matches"] = max_matches

    context_backend = _env("DLPSCAN_CONTEXT_BACKEND")
    if context_backend is not None:
        config["context_backend"] = context_backend.strip().lower()

    # -- Logging --
    log_level = _env("DLPSCAN_LOG_LEVEL")
    if log_level is not None:
        config["log_level"] = log_level.strip().upper()

    log_format = _env("DLPSCAN_LOG_FORMAT")
    if log_format is not None:
        config["log_format"] = log_format.strip().lower()

    audit_file = _env("DLPSCAN_AUDIT_FILE")
    if audit_file is not None:
        config["audit_file"] = audit_file

    # -- Rate limiting --
    rate_limit = _env_int("DLPSCAN_RATE_LIMIT")
    if rate_limit is not None:
        config["rate_limit"] = rate_limit

    max_payload = _env_int("DLPSCAN_MAX_PAYLOAD")
    if max_payload is not None:
        config["max_payload"] = max_payload

    # -- Vault --
    vault_backend = _env("DLPSCAN_VAULT_BACKEND")
    if vault_backend is not None:
        config["vault_backend"] = vault_backend.strip().lower()

    vault_path = _env("DLPSCAN_VAULT_PATH")
    if vault_path is not None:
        config["vault_path"] = vault_path

    vault_key = _env("DLPSCAN_VAULT_ENCRYPTION_KEY")
    if vault_key is not None:
        config["vault_encryption_key"] = vault_key

    redis_url = _env("DLPSCAN_REDIS_URL")
    if redis_url is not None:
        config["redis_url"] = redis_url

    return config


def apply_env_to_guard_kwargs() -> dict:
    """Return kwargs dict ready to pass to ``InputGuard(**kwargs)``.

    Maps ``DLPSCAN_*`` environment variables to the keyword arguments
    accepted by :class:`~dlpscan.guard.InputGuard`.  Only keys whose
    corresponding env vars are set will appear in the result.

    Returns:
        A dict suitable for ``InputGuard(**apply_env_to_guard_kwargs())``.
    """
    env = load_env_config()
    kwargs: Dict[str, Any] = {}

    # Presets — convert string names to Preset enum values.
    if "presets" in env:
        try:
            from .guard.presets import Preset
            preset_list = []
            for name in env["presets"]:
                try:
                    preset_list.append(Preset(name.upper()))
                except ValueError:
                    # Try as attribute name (e.g. "PCI_DSS")
                    try:
                        preset_list.append(Preset[name.upper()])
                    except KeyError:
                        logger.warning("Unknown preset %r — skipping", name)
            if preset_list:
                kwargs["presets"] = preset_list
        except ImportError:
            logger.warning("Could not import Preset enum")

    # Action
    if "action" in env:
        try:
            from .guard.enums import Action
            kwargs["action"] = Action(env["action"].upper())
        except (ImportError, ValueError):
            logger.warning("Invalid action %r", env.get("action"))

    # Mode
    if "mode" in env:
        try:
            from .guard.enums import Mode
            kwargs["mode"] = Mode(env["mode"].upper())
        except (ImportError, ValueError):
            logger.warning("Invalid mode %r", env.get("mode"))

    # Simple pass-through keys
    if "min_confidence" in env:
        kwargs["min_confidence"] = env["min_confidence"]

    if "require_context" in env:
        kwargs["require_context"] = env["require_context"]

    if "categories" in env:
        kwargs["categories"] = set(env["categories"])

    if "redaction_char" in env:
        kwargs["redaction_char"] = env["redaction_char"]

    if "context_backend" in env:
        kwargs["context_backend"] = env["context_backend"]

    return kwargs


def configure_from_env() -> None:
    """One-call setup: configure logging, audit, and rate limiting from env.

    Reads ``DLPSCAN_*`` environment variables and applies them:

    * Configures the ``dlpscan`` logger (level, format).
    * Sets up an audit log file handler if ``DLPSCAN_AUDIT_FILE`` is set.
    * Creates and installs a global default rate limiter if
      ``DLPSCAN_RATE_LIMIT`` is set.

    Safe to call multiple times — idempotent.
    """
    env = load_env_config()

    # -- Logging --
    log_level = env.get("log_level", "WARNING")
    log_format = env.get("log_format", "json")
    json_format = log_format == "json"

    try:
        from .logging_config import configure_logging
        configure_logging(level=log_level, json_format=json_format)
    except ImportError:
        # Fallback: basic stdlib configuration.
        logging.getLogger("dlpscan").setLevel(
            getattr(logging, log_level, logging.WARNING)
        )

    # -- Audit file --
    audit_file = env.get("audit_file")
    if audit_file:
        audit_handler = logging.FileHandler(audit_file, encoding="utf-8")
        audit_handler.setLevel(logging.INFO)
        audit_formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
        audit_handler.setFormatter(audit_formatter)

        audit_logger = logging.getLogger("dlpscan.audit")
        # Avoid adding duplicate handlers on repeated calls.
        if not any(
            isinstance(h, logging.FileHandler) and getattr(h, "baseFilename", None) == os.path.abspath(audit_file)
            for h in audit_logger.handlers
        ):
            audit_logger.addHandler(audit_handler)
            audit_logger.setLevel(logging.INFO)

    # -- Rate limiting --
    rate_limit = env.get("rate_limit")
    if rate_limit is not None and rate_limit > 0:
        max_payload = env.get("max_payload", 10 * 1024 * 1024)
        try:
            from .rate_limit import RateLimiter, set_default_limiter
            limiter = RateLimiter(
                max_requests=rate_limit,
                window_seconds=60,
                max_payload_bytes=max_payload,
            )
            set_default_limiter(limiter)
        except ImportError:
            logger.warning("Could not import RateLimiter — rate limiting disabled")
