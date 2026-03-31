"""Core InputGuard class for scanning and sanitizing application inputs.

Usage::

    from dlpscan.guard import InputGuard, Preset, Action, Mode

    # Block PCI and SSN/SIN data — raise on detection
    guard = InputGuard(presets=[Preset.PCI_DSS, Preset.SSN_SIN])
    guard.scan("My card is 4532015112830366")  # raises InputGuardError

    # Redact credentials from user input
    guard = InputGuard(presets=[Preset.CREDENTIALS], action=Action.REDACT)
    result = guard.scan("key: ghp_abc123def456ghi789jkl012mno345pqr678")
    print(result.redacted_text)

    # Decorator
    guard = InputGuard(presets=[Preset.PCI_DSS])

    @guard.protect(param="comment")
    def save_comment(user_id: int, comment: str):
        db.save(user_id, comment)
"""

import functools
import inspect
import logging
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple, Union

from ..allowlist import Allowlist
from ..exceptions import EmptyInputError, ShortInputError
from ..models import Match
from ..scanner import (
    MAX_MATCHES,
    enhanced_scan_text,
    redact_sensitive_info,
    register_patterns,
    unregister_patterns,
)
from ..unicode_normalize import strip_zero_width
from .enums import Action, Mode
from .presets import PRESET_CATEGORIES, Preset
from .transforms import TokenVault, obfuscate_matches, tokenize_matches

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ScanResult
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    """Result of an InputGuard scan.

    Attributes:
        text: The original input text.
        is_clean: True if no findings after filtering.
        findings: List of Match objects found.
        redacted_text: Transformed text (redacted, tokenized, or obfuscated).
        categories_found: Set of unique category names detected.
        token_vault: TokenVault with mappings (set only when action=TOKENIZE).
        scan_truncated: True if the scan was cut short by match limits or timeout.
    """
    text: str
    is_clean: bool
    findings: List[Match] = field(default_factory=list)
    redacted_text: Optional[str] = None
    categories_found: Set[str] = field(default_factory=set)
    token_vault: Optional[TokenVault] = None
    scan_truncated: bool = False

    @property
    def scan_complete(self) -> bool:
        """True if the scan ran to completion without truncation."""
        return not self.scan_truncated

    @property
    def finding_count(self) -> int:
        """Number of findings."""
        return len(self.findings)

    def to_dict(self, redact: bool = True) -> dict:
        """Convert to a plain dictionary for JSON serialization."""
        return {
            'is_clean': self.is_clean,
            'finding_count': self.finding_count,
            'categories_found': sorted(self.categories_found),
            'findings': [f.to_dict(redact=redact) for f in self.findings],
            'redacted_text': self.redacted_text,
            'scan_truncated': self.scan_truncated,
        }


# ---------------------------------------------------------------------------
# InputGuardError
# ---------------------------------------------------------------------------

class InputGuardError(Exception):
    """Raised when action=REJECT and sensitive data is found in input.

    Attributes:
        result: The ScanResult containing findings.
    """
    def __init__(self, message: str, result: ScanResult):
        super().__init__(message)
        self.result = result


# ---------------------------------------------------------------------------
# InputGuard
# ---------------------------------------------------------------------------

class InputGuard:
    """Guard for scanning and sanitizing application inputs.

    Wraps dlpscan's scanning infrastructure into a simple developer-facing
    API with compliance presets, denylist/allowlist modes, and configurable
    actions.

    Args:
        presets: Compliance presets to activate. Combined via union.
        categories: Explicit category names to scan. Merged with presets.
        mode: DENYLIST (block listed categories) or ALLOWLIST (allow only
              listed categories, block everything else).
        action: What to do on detection — REJECT (raise), REDACT, or FLAG.
        min_confidence: Ignore findings below this threshold (0.0-1.0).
        require_context: If True, only flag matches with context keywords.
        redaction_char: Character for redaction (default 'X').
        allowlist: Optional Allowlist for suppressing known false positives.
        on_detect: Optional callback invoked when sensitive data is found.
                   Receives the ScanResult as argument.

    Thread Safety:
        InputGuard instances are safe to share across threads — all config
        is immutable after __init__, and enhanced_scan_text is thread-safe.

    Performance Note:
        ALLOWLIST mode scans all categories then filters, so it is inherently
        slower than DENYLIST mode with specific categories.

    Example::

        guard = InputGuard(
            presets=[Preset.PCI_DSS, Preset.SSN_SIN],
            action=Action.REJECT,
            min_confidence=0.5,
        )
        guard.scan("My card is 4532015112830366")  # raises InputGuardError
    """

    def __init__(
        self,
        *,
        presets: Optional[List[Preset]] = None,
        categories: Optional[Set[str]] = None,
        mode: Union[Mode, str] = Mode.DENYLIST,
        action: Union[Action, str] = Action.REJECT,
        min_confidence: float = 0.0,
        require_context: bool = False,
        redaction_char: str = 'X',
        allowlist: Optional[Allowlist] = None,
        on_detect: Optional[Callable[['ScanResult'], None]] = None,
        custom_patterns: Optional[Dict[str, Dict[str, str]]] = None,
        confidence_overrides: Optional[Dict[str, float]] = None,
        token_vault: Optional[TokenVault] = None,
    ):
        # Normalize enum values from strings.
        self.mode = Mode(mode) if isinstance(mode, str) else mode
        self.action = Action(action) if isinstance(action, str) else action
        self.min_confidence = min_confidence
        self.require_context = require_context
        self.redaction_char = redaction_char
        self.allowlist = allowlist
        self.on_detect = on_detect
        self._confidence_overrides = confidence_overrides or {}
        self._registered_categories: List[str] = []

        # Token vault for TOKENIZE action — auto-create if not provided.
        if token_vault is not None:
            self._token_vault = token_vault
        elif self.action == Action.TOKENIZE:
            self._token_vault = TokenVault()
        else:
            self._token_vault = TokenVault()  # Lazy — available for .tokenize() method

        # Register custom patterns if provided.
        if custom_patterns:
            for cat_name, sub_patterns in custom_patterns.items():
                compiled = {
                    name: re.compile(pattern) if isinstance(pattern, str) else pattern
                    for name, pattern in sub_patterns.items()
                }
                register_patterns(category=cat_name, patterns=compiled)
                self._registered_categories.append(cat_name)

        # Resolve categories from presets + explicit categories.
        resolved: Set[str] = set()
        if presets:
            for p in presets:
                resolved |= PRESET_CATEGORIES.get(p, frozenset())
        if categories:
            resolved |= categories
        # Include custom pattern categories in scan scope.
        if self._registered_categories:
            resolved |= set(self._registered_categories)

        if self.mode == Mode.DENYLIST:
            # In denylist mode, these are the categories to scan for.
            # If empty, scan all (None passed to enhanced_scan_text).
            self._scan_categories: Optional[Set[str]] = resolved if resolved else None
            self._allowed_categories: Optional[Set[str]] = None
        else:
            # In allowlist mode, scan everything, then filter out allowed categories.
            self._scan_categories = None  # Scan all
            self._allowed_categories = resolved

    def _do_scan(self, text: str) -> ScanResult:
        """Run scanning and build ScanResult (no action enforcement)."""
        # Run scanner.
        try:
            raw_matches = list(enhanced_scan_text(
                text,
                categories=self._scan_categories,
                require_context=self.require_context,
            ))
        except EmptyInputError:
            return ScanResult(text=text, is_clean=True)

        # Detect truncation: if scanner returned exactly MAX_MATCHES, it was likely truncated.
        scan_truncated = len(raw_matches) >= MAX_MATCHES

        # Apply allowlist filtering.
        if self.allowlist:
            raw_matches = self.allowlist.filter_matches(raw_matches)

        # Apply per-category confidence overrides.
        if self._confidence_overrides:
            filtered = []
            for m in raw_matches:
                threshold = self._confidence_overrides.get(m.category, self.min_confidence)
                if m.confidence >= threshold:
                    filtered.append(m)
            matches = filtered
        else:
            # Apply global confidence threshold.
            matches = [m for m in raw_matches if m.confidence >= self.min_confidence]

        # For allowlist mode: keep only findings NOT in the allowed set.
        if self.mode == Mode.ALLOWLIST and self._allowed_categories:
            matches = [m for m in matches if m.category not in self._allowed_categories]

        categories_found = {m.category for m in matches}
        is_clean = len(matches) == 0

        # Build transformed text if needed.
        redacted_text = None
        vault = None
        if not is_clean:
            if self.action == Action.REDACT:
                redacted_text = self._redact_matches(text, matches)
            elif self.action == Action.TOKENIZE:
                redacted_text = tokenize_matches(text, matches, self._token_vault)
                vault = self._token_vault
            elif self.action == Action.OBFUSCATE:
                redacted_text = obfuscate_matches(text, matches)

        return ScanResult(
            text=text,
            is_clean=is_clean,
            findings=matches,
            redacted_text=redacted_text,
            categories_found=categories_found,
            token_vault=vault,
            scan_truncated=scan_truncated,
        )

    def scan(self, text: str) -> ScanResult:
        """Scan text and apply the configured action.

        Returns:
            ScanResult with findings and optional redacted text.

        Raises:
            InputGuardError: If action=REJECT and sensitive data is found.
        """
        result = self._do_scan(text)

        # Invoke detection callback.
        if not result.is_clean and self.on_detect is not None:
            try:
                self.on_detect(result)
            except Exception:
                pass  # Never let callback crash the guard.

        if not result.is_clean and self.action == Action.REJECT:
            raise InputGuardError(
                f"Sensitive data detected: {sorted(result.categories_found)}",
                result=result,
            )

        return result

    def check(self, text: str) -> bool:
        """Quick boolean check. Returns True if text is clean.

        Does not raise even if action=REJECT.
        """
        result = self._do_scan(text)
        return result.is_clean

    def sanitize(self, text: str) -> str:
        """Scan and return redacted text, regardless of configured action.

        Always redacts detected sensitive data. Returns original text if clean.
        """
        result = self._do_scan(text)
        if result.is_clean:
            return text
        return self._redact_matches(text, result.findings)

    def tokenize(self, text: str) -> Tuple[str, TokenVault]:
        """Scan and replace sensitive data with reversible tokens.

        Returns:
            Tuple of (tokenized_text, TokenVault with mappings).
            Returns (original_text, empty_vault) if clean.
        """
        result = self._do_scan(text)
        if result.is_clean:
            return text, self._token_vault
        tokenized = tokenize_matches(text, result.findings, self._token_vault)
        return tokenized, self._token_vault

    def obfuscate(self, text: str) -> str:
        """Scan and replace sensitive data with realistic fake data.

        Returns obfuscated text. Irreversible. Returns original if clean.
        """
        result = self._do_scan(text)
        if result.is_clean:
            return text
        return obfuscate_matches(text, result.findings)

    def detokenize(self, text: str) -> str:
        """Reverse tokenization using the guard's token vault.

        Args:
            text: Text containing tokens from a previous tokenize/scan call.

        Returns:
            Text with tokens replaced by their original values.
        """
        return self._token_vault.detokenize_text(text)

    def protect(
        self,
        func: Optional[Callable] = None,
        *,
        param: Optional[str] = None,
        params: Optional[List[str]] = None,
    ):
        """Decorator that scans function string arguments before execution.

        Args:
            param: Single parameter name to scan.
            params: List of parameter names to scan.
                    If neither is specified, scans all string arguments.

        For REJECT action, raises InputGuardError before the function runs.
        For REDACT action, replaces the argument with sanitized text.
        For FLAG action, logs findings but passes original text through.

        Example::

            guard = InputGuard(presets=[Preset.PCI_DSS])

            @guard.protect(param="user_input")
            def process_form(user_id: int, user_input: str):
                ...

            @guard.protect(params=["name", "address"])
            def save_profile(name: str, address: str, age: int):
                ...

            @guard.protect()  # Scans all string args
            def handle_request(body: str):
                ...
        """
        target_params: Set[str] = set()
        if param:
            target_params.add(param)
        if params:
            target_params.update(params)

        def decorator(fn: Callable) -> Callable:
            sig = inspect.signature(fn)

            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()

                for name, value in bound.arguments.items():
                    if not isinstance(value, str):
                        continue
                    if target_params and name not in target_params:
                        continue

                    result = self.scan(value)

                    # For transform actions, replace the argument with transformed text.
                    if self.action in (Action.REDACT, Action.TOKENIZE, Action.OBFUSCATE) \
                            and result.redacted_text is not None:
                        bound.arguments[name] = result.redacted_text

                return fn(*bound.args, **bound.kwargs)

            return wrapper

        # Support both @guard.protect and @guard.protect()
        if func is not None:
            return decorator(func)
        return decorator

    def _redact_matches(self, text: str, matches: List[Match]) -> str:
        """Replace matched spans in text with redaction characters.

        Processes spans in reverse order to avoid offset drift.
        Zero-width / invisible characters in the matched span are stripped
        before computing the redacted replacement so that evasion characters
        do not leak into the output.
        """
        # Sort by span start descending for safe in-place replacement.
        sorted_matches = sorted(matches, key=lambda m: m.span[0], reverse=True)
        result = text

        for m in sorted_matches:
            start, end = m.span
            matched_text = result[start:end]
            # Strip zero-width chars so redaction output is clean.
            clean_text, _ = strip_zero_width(matched_text)
            try:
                redacted = redact_sensitive_info(clean_text, self.redaction_char)
            except (EmptyInputError, ShortInputError):
                # Very short matches — replace entirely.
                redacted = self.redaction_char * len(clean_text)
            result = result[:start] + redacted + result[end:]

        return result

    def close(self) -> None:
        """Unregister any custom patterns registered by this guard instance."""
        for cat in self._registered_categories:
            unregister_patterns(cat)
        self._registered_categories.clear()

    def __enter__(self) -> 'InputGuard':
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def __repr__(self) -> str:
        parts = [f"mode={self.mode.value}", f"action={self.action.value}"]
        if self._scan_categories:
            parts.append(f"categories={len(self._scan_categories)}")
        if self._allowed_categories:
            parts.append(f"allowed={len(self._allowed_categories)}")
        if self.min_confidence > 0:
            parts.append(f"min_confidence={self.min_confidence}")
        return f"InputGuard({', '.join(parts)})"
