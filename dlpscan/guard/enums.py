"""Enums for InputGuard configuration."""

from enum import Enum


class Action(Enum):
    """What to do when sensitive data is detected."""
    REJECT = "reject"       # Raise InputGuardError
    REDACT = "redact"       # Return sanitized text with sensitive data replaced
    FLAG = "flag"           # Return ScanResult with findings, text unmodified
    TOKENIZE = "tokenize"   # Replace with reversible tokens (stored in TokenVault)
    OBFUSCATE = "obfuscate" # Replace with realistic-looking fake data (irreversible)


class Mode(Enum):
    """Guard operating mode."""
    DENYLIST = "denylist"    # Block the listed categories (default: all)
    ALLOWLIST = "allowlist"  # Allow only the listed categories; block everything else
