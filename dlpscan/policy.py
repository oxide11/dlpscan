"""Policy-as-code YAML engine for declarative DLP scanning configuration.

Load scanning policies from YAML files and apply them via InputGuard.

Usage::

    from dlpscan.policy import load_policy, PolicyEngine

    policy = load_policy("/etc/dlpscan/pci-production.yml")
    engine = PolicyEngine(policy)
    result = engine.scan("My card is 4532015112830366")

YAML schema example::

    version: "1"
    name: "pci-production"
    description: "PCI-DSS production policy"

    scan:
      presets:
        - pci_dss
        - ssn_sin
      categories:
        - "Credit Card Numbers"
      action: redact
      mode: denylist
      min_confidence: 0.5
      require_context: false
      redaction_char: "X"

    rules:
      - name: "block-credit-cards"
        match:
          categories:
            - "Credit Card Numbers"
        action: reject
        min_confidence: 0.8

    audit:
      enabled: true
      file: "/var/log/dlp-audit.jsonl"

    rate_limit:
      max_requests: 100
      window_seconds: 60
"""

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from .guard.core import InputGuard, ScanResult
from .guard.enums import Action, Mode
from .guard.presets import Preset
from .rate_limit import RateLimiter

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Valid values for validation
# ---------------------------------------------------------------------------

_VALID_ACTIONS = {a.value for a in Action}
_VALID_MODES = {m.value for m in Mode}
_VALID_PRESETS = {p.value for p in Preset}

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class PolicyRule:
    """A per-category override rule within a policy.

    Attributes:
        name: Human-readable rule identifier.
        match_categories: Category names this rule applies to.
        match_sub_categories: Optional sub-category names for finer matching.
        action: Action to take when this rule matches (reject, redact, flag, etc.).
        min_confidence: Minimum confidence threshold for this rule.
    """

    name: str
    match_categories: List[str]
    match_sub_categories: Optional[List[str]] = None
    action: str = "reject"
    min_confidence: float = 0.0


@dataclass
class Policy:
    """A complete DLP scanning policy loaded from YAML.

    Attributes:
        name: Policy name (used as dict key when loading directories).
        description: Human-readable description of the policy.
        version: Schema version string.
        scan_config: Scan parameters (presets, categories, action, mode, etc.).
        rules: Per-category override rules.
        audit_config: Optional audit/logging configuration.
        rate_limit_config: Optional rate limiting configuration.
    """

    name: str
    description: str = ""
    version: str = "1"
    scan_config: Dict[str, Any] = field(default_factory=dict)
    rules: List[PolicyRule] = field(default_factory=list)
    audit_config: Optional[Dict[str, Any]] = None
    rate_limit_config: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# YAML loading helpers
# ---------------------------------------------------------------------------


def _yaml_safe_load(text: str) -> Any:
    """Load YAML using PyYAML if available, otherwise fall back to a minimal parser."""
    try:
        import yaml

        return yaml.safe_load(text)
    except ImportError:
        pass

    # Minimal YAML-subset parser for basic policy files.
    return _minimal_yaml_parse(text)


def _minimal_yaml_parse(text: str) -> Any:
    """Parse a minimal subset of YAML sufficient for policy files.

    Supports:
    - Top-level and nested mappings (key: value)
    - Lists (- item)
    - Quoted and unquoted strings
    - Integers, floats, booleans (true/false), null
    - Inline comments (# ...)

    Does NOT support:
    - Flow mappings/sequences ({}, [])
    - Multi-line strings (|, >)
    - Anchors/aliases
    - Complex keys
    """
    lines = text.split("\n")
    return _parse_block(lines, 0, 0)[0]


def _strip_comment(line: str) -> str:
    """Remove trailing comments, respecting quoted strings."""
    in_single = False
    in_double = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            return line[:i].rstrip()
    return line.rstrip()


def _parse_scalar(value: str) -> Any:
    """Parse a YAML scalar value."""
    value = value.strip()
    if not value or value == "null" or value == "~":
        return None
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False

    # Quoted string
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]

    # Number
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass

    return value


def _indent_level(line: str) -> int:
    """Count leading spaces."""
    return len(line) - len(line.lstrip(" "))


def _parse_block(lines: List[str], start: int, base_indent: int):
    """Parse a YAML block (mapping or list) starting at *start* with *base_indent*.

    Returns (parsed_value, next_line_index).
    """
    if start >= len(lines):
        return None, start

    # Skip blank/comment-only lines to find first meaningful line.
    idx = start
    while idx < len(lines):
        stripped = _strip_comment(lines[idx]).strip()
        if stripped:
            break
        idx += 1
    if idx >= len(lines):
        return None, idx

    first_stripped = _strip_comment(lines[idx]).strip()

    # Detect whether this block is a list or a mapping.
    if first_stripped.startswith("- ") or first_stripped == "-":
        return _parse_list(lines, idx, base_indent)
    elif ":" in first_stripped:
        return _parse_mapping(lines, idx, base_indent)
    else:
        return _parse_scalar(first_stripped), idx + 1


def _parse_mapping(lines: List[str], start: int, base_indent: int):
    """Parse a YAML mapping block."""
    result: Dict[str, Any] = {}
    idx = start

    while idx < len(lines):
        raw = lines[idx]
        stripped = _strip_comment(raw).strip()

        if not stripped:
            idx += 1
            continue

        current_indent = _indent_level(raw)
        if current_indent < base_indent:
            break

        if current_indent > base_indent:
            # Belongs to a parent with deeper nesting -- stop
            break

        # Must be a key: value line
        colon_pos = stripped.find(":")
        if colon_pos == -1:
            idx += 1
            continue

        key = stripped[:colon_pos].strip()
        rest = stripped[colon_pos + 1 :].strip()

        if rest:
            # Inline value
            result[key] = _parse_scalar(rest)
            idx += 1
        else:
            # Block value on subsequent lines -- find child indent
            child_idx = idx + 1
            while child_idx < len(lines):
                cs = _strip_comment(lines[child_idx]).strip()
                if cs:
                    break
                child_idx += 1

            if child_idx >= len(lines):
                result[key] = None
                idx = child_idx
            else:
                child_indent = _indent_level(lines[child_idx])
                if child_indent <= current_indent:
                    result[key] = None
                    idx = child_idx
                else:
                    value, idx = _parse_block(lines, child_idx, child_indent)
                    result[key] = value

    return result, idx


def _parse_list(lines: List[str], start: int, base_indent: int):
    """Parse a YAML list block."""
    result: List[Any] = []
    idx = start

    while idx < len(lines):
        raw = lines[idx]
        stripped = _strip_comment(raw).strip()

        if not stripped:
            idx += 1
            continue

        current_indent = _indent_level(raw)
        if current_indent < base_indent:
            break
        if current_indent > base_indent:
            break

        if not stripped.startswith("-"):
            break

        item_text = stripped[1:].strip() if len(stripped) > 1 else ""

        if not item_text:
            # Nested block under the list item
            child_idx = idx + 1
            while child_idx < len(lines):
                cs = _strip_comment(lines[child_idx]).strip()
                if cs:
                    break
                child_idx += 1
            if child_idx < len(lines):
                child_indent = _indent_level(lines[child_idx])
                if child_indent > current_indent:
                    value, idx = _parse_block(lines, child_idx, child_indent)
                    result.append(value)
                else:
                    result.append(None)
                    idx = child_idx
            else:
                result.append(None)
                idx = child_idx
        elif ":" in item_text:
            # Inline mapping as list element  e.g. "- name: foo"
            # Re-parse as a mapping starting from this logical content
            # We fake lines with the item content at a deeper indent.
            # Gather consecutive indented lines that belong to this item.
            fake_indent = current_indent + 2
            fake_lines = [" " * fake_indent + item_text]
            child_idx = idx + 1
            while child_idx < len(lines):
                cl = lines[child_idx]
                cs = _strip_comment(cl).strip()
                if not cs:
                    fake_lines.append("")
                    child_idx += 1
                    continue
                ci = _indent_level(cl)
                if ci > current_indent:
                    fake_lines.append(cl)
                    child_idx += 1
                else:
                    break
            value, _ = _parse_mapping(fake_lines, 0, fake_indent)
            result.append(value)
            idx = child_idx
        else:
            result.append(_parse_scalar(item_text))
            idx += 1

    return result, idx


# ---------------------------------------------------------------------------
# Policy construction from parsed YAML dict
# ---------------------------------------------------------------------------


def _build_policy(data: Dict[str, Any]) -> Policy:
    """Build a Policy dataclass from a parsed YAML dictionary."""
    if not isinstance(data, dict):
        raise ValueError("Policy YAML must be a mapping at the top level.")

    name = str(data.get("name", "unnamed"))
    description = str(data.get("description", ""))
    version = str(data.get("version", "1"))

    # Scan config
    scan_config: Dict[str, Any] = {}
    raw_scan = data.get("scan")
    if isinstance(raw_scan, dict):
        scan_config = dict(raw_scan)

    # Rules
    rules: List[PolicyRule] = []
    raw_rules = data.get("rules")
    if isinstance(raw_rules, list):
        for entry in raw_rules:
            if not isinstance(entry, dict):
                continue
            match_section = entry.get("match", {})
            if not isinstance(match_section, dict):
                match_section = {}
            cats = match_section.get("categories", [])
            if not isinstance(cats, list):
                cats = [str(cats)]
            sub_cats = match_section.get("sub_categories")
            if sub_cats is not None and not isinstance(sub_cats, list):
                sub_cats = [str(sub_cats)]

            rules.append(
                PolicyRule(
                    name=str(entry.get("name", "unnamed-rule")),
                    match_categories=[str(c) for c in cats],
                    match_sub_categories=[str(s) for s in sub_cats]
                    if sub_cats
                    else None,
                    action=str(entry.get("action", "reject")),
                    min_confidence=float(entry.get("min_confidence", 0.0)),
                )
            )

    # Audit
    audit_config = data.get("audit")
    if audit_config is not None and not isinstance(audit_config, dict):
        audit_config = None

    # Rate limit
    rate_limit_config = data.get("rate_limit")
    if rate_limit_config is not None and not isinstance(rate_limit_config, dict):
        rate_limit_config = None

    return Policy(
        name=name,
        description=description,
        version=version,
        scan_config=scan_config,
        rules=rules,
        audit_config=audit_config,
        rate_limit_config=rate_limit_config,
    )


# ---------------------------------------------------------------------------
# Public loaders
# ---------------------------------------------------------------------------


def load_policy(path: str) -> Policy:
    """Load a Policy from a YAML file on disk.

    Args:
        path: Filesystem path to a ``.yml`` / ``.yaml`` file.

    Returns:
        A fully-constructed :class:`Policy`.

    Raises:
        FileNotFoundError: If *path* does not exist.
        ValueError: If the YAML content is invalid.
    """
    with open(path, "r", encoding="utf-8") as fh:
        raw = fh.read()
    data = _yaml_safe_load(raw)
    if data is None:
        raise ValueError(f"Empty or unparseable policy file: {path}")
    return _build_policy(data)


def load_policy_from_string(yaml_string: str) -> Policy:
    """Parse a Policy from a YAML string.

    Args:
        yaml_string: Raw YAML text.

    Returns:
        A fully-constructed :class:`Policy`.

    Raises:
        ValueError: If the YAML content is invalid.
    """
    data = _yaml_safe_load(yaml_string)
    if data is None:
        raise ValueError("Empty or unparseable policy YAML string.")
    return _build_policy(data)


def load_policies_from_dir(dir_path: str) -> Dict[str, Policy]:
    """Load all ``.yml`` / ``.yaml`` policy files from a directory.

    Args:
        dir_path: Path to a directory containing policy files.

    Returns:
        Dictionary mapping policy *name* to :class:`Policy`.
        Files that fail to parse are logged and skipped.

    Raises:
        NotADirectoryError: If *dir_path* is not a directory.
    """
    if not os.path.isdir(dir_path):
        raise NotADirectoryError(f"Not a directory: {dir_path}")

    policies: Dict[str, Policy] = {}
    for entry in sorted(os.listdir(dir_path)):
        if not (entry.endswith(".yml") or entry.endswith(".yaml")):
            continue
        full_path = os.path.join(dir_path, entry)
        if not os.path.isfile(full_path):
            continue
        try:
            policy = load_policy(full_path)
            policies[policy.name] = policy
        except Exception as exc:
            logger.warning("Skipping policy file %s: %s", full_path, exc)
    return policies


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def validate_policy(policy: Policy) -> List[str]:
    """Validate a policy and return a list of warnings / errors.

    Returns an empty list when the policy is fully valid.
    """
    issues: List[str] = []

    # Version check
    if policy.version not in ("1",):
        issues.append(f"Unknown policy version: {policy.version!r} (expected '1').")

    # Name check
    if not policy.name or policy.name == "unnamed":
        issues.append("Policy has no name.")

    # Scan config validation
    sc = policy.scan_config

    action = sc.get("action")
    if action is not None and str(action) not in _VALID_ACTIONS:
        issues.append(
            f"Invalid scan action: {action!r}. "
            f"Valid actions: {sorted(_VALID_ACTIONS)}."
        )

    mode = sc.get("mode")
    if mode is not None and str(mode) not in _VALID_MODES:
        issues.append(
            f"Invalid scan mode: {mode!r}. Valid modes: {sorted(_VALID_MODES)}."
        )

    presets = sc.get("presets")
    if isinstance(presets, list):
        for p in presets:
            if str(p) not in _VALID_PRESETS:
                issues.append(
                    f"Unknown preset: {p!r}. "
                    f"Valid presets: {sorted(_VALID_PRESETS)}."
                )

    min_conf = sc.get("min_confidence")
    if min_conf is not None:
        try:
            mc = float(min_conf)
            if not (0.0 <= mc <= 1.0):
                issues.append(
                    f"min_confidence must be between 0.0 and 1.0, got {mc}."
                )
        except (TypeError, ValueError):
            issues.append(f"min_confidence is not a number: {min_conf!r}.")

    redaction_char = sc.get("redaction_char")
    if redaction_char is not None and len(str(redaction_char)) != 1:
        issues.append(
            f"redaction_char must be a single character, got {redaction_char!r}."
        )

    # Rules validation
    for rule in policy.rules:
        if not rule.name:
            issues.append("A rule has no name.")

        if not rule.match_categories:
            issues.append(f"Rule {rule.name!r} has no match categories.")

        if rule.action not in _VALID_ACTIONS:
            issues.append(
                f"Rule {rule.name!r} has invalid action: {rule.action!r}. "
                f"Valid actions: {sorted(_VALID_ACTIONS)}."
            )

        if not (0.0 <= rule.min_confidence <= 1.0):
            issues.append(
                f"Rule {rule.name!r} min_confidence out of range: "
                f"{rule.min_confidence}."
            )

    # Audit config validation
    if policy.audit_config is not None:
        ac = policy.audit_config
        if ac.get("enabled") not in (True, False, None):
            issues.append(
                f"audit.enabled must be a boolean, got {ac.get('enabled')!r}."
            )
        audit_file = ac.get("file")
        if ac.get("enabled") and not audit_file:
            issues.append("audit.enabled is true but no audit file is configured.")

    # Rate limit config validation
    if policy.rate_limit_config is not None:
        rl = policy.rate_limit_config
        mr = rl.get("max_requests")
        if mr is not None:
            try:
                if int(mr) < 1:
                    issues.append("rate_limit.max_requests must be >= 1.")
            except (TypeError, ValueError):
                issues.append(
                    f"rate_limit.max_requests is not an integer: {mr!r}."
                )
        ws = rl.get("window_seconds")
        if ws is not None:
            try:
                if float(ws) <= 0:
                    issues.append("rate_limit.window_seconds must be > 0.")
            except (TypeError, ValueError):
                issues.append(
                    f"rate_limit.window_seconds is not a number: {ws!r}."
                )

    return issues


# ---------------------------------------------------------------------------
# PolicyEngine
# ---------------------------------------------------------------------------


class PolicyEngine:
    """Apply a :class:`Policy` to scan text via :class:`InputGuard`.

    Args:
        policy: The policy to enforce.

    Example::

        engine = PolicyEngine(load_policy("policy.yml"))
        result = engine.scan("text with 4532015112830366")
    """

    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        self._audit_logger: Optional[logging.Logger] = None
        self._audit_handler: Optional[logging.FileHandler] = None

    # -- Guard creation -----------------------------------------------------

    def create_guard(self) -> InputGuard:
        """Build an :class:`InputGuard` from the policy's scan configuration.

        Translates the policy's ``scan`` block into ``InputGuard`` constructor
        parameters.
        """
        sc = self.policy.scan_config

        # Resolve presets
        presets: Optional[List[Preset]] = None
        raw_presets = sc.get("presets")
        if isinstance(raw_presets, list):
            presets = []
            for p in raw_presets:
                try:
                    presets.append(Preset(str(p)))
                except ValueError:
                    logger.warning("Ignoring unknown preset in policy: %s", p)

        # Resolve explicit categories
        categories: Optional[Set[str]] = None
        raw_cats = sc.get("categories")
        if isinstance(raw_cats, list):
            categories = {str(c) for c in raw_cats}

        # Action
        action: Action = Action.REJECT
        raw_action = sc.get("action")
        if raw_action is not None:
            try:
                action = Action(str(raw_action))
            except ValueError:
                logger.warning(
                    "Invalid action %r in policy, defaulting to REJECT.", raw_action
                )

        # Mode
        mode: Mode = Mode.DENYLIST
        raw_mode = sc.get("mode")
        if raw_mode is not None:
            try:
                mode = Mode(str(raw_mode))
            except ValueError:
                logger.warning(
                    "Invalid mode %r in policy, defaulting to DENYLIST.", raw_mode
                )

        # Numeric / boolean params
        min_confidence = float(sc.get("min_confidence", 0.0))
        require_context = bool(sc.get("require_context", False))
        redaction_char = str(sc.get("redaction_char", "X"))

        return InputGuard(
            presets=presets,
            categories=categories,
            mode=mode,
            action=action,
            min_confidence=min_confidence,
            require_context=require_context,
            redaction_char=redaction_char,
        )

    # -- Rule application ---------------------------------------------------

    def apply_rules(self, result: ScanResult) -> ScanResult:
        """Apply per-category rules to override the default action on findings.

        For each rule whose ``match_categories`` intersect with the findings'
        categories and whose ``min_confidence`` is met, the rule's action is
        applied.  Rules are evaluated in order; the first matching rule wins
        for each finding.

        A new :class:`ScanResult` is returned.  The original is not mutated.
        """
        if not self.policy.rules or result.is_clean:
            return result


        remaining_findings = list(result.findings)
        rejected_findings: List = []
        redacted_findings: List = []
        flagged_findings: List = []

        for finding in remaining_findings:
            matched_rule: Optional[PolicyRule] = None
            for rule in self.policy.rules:
                cats = set(rule.match_categories)
                sub_cats = set(rule.match_sub_categories or [])

                category_match = finding.category in cats
                sub_category_match = (
                    not sub_cats or getattr(finding, "sub_category", None) in sub_cats
                )
                confidence_ok = finding.confidence >= rule.min_confidence

                if category_match and sub_category_match and confidence_ok:
                    matched_rule = rule
                    break

            if matched_rule is not None:
                if matched_rule.action == Action.REJECT.value:
                    rejected_findings.append(finding)
                elif matched_rule.action == Action.REDACT.value:
                    redacted_findings.append(finding)
                else:
                    flagged_findings.append(finding)
            else:
                flagged_findings.append(finding)

        # If any rule triggers REJECT, mark accordingly by raising via
        # the caller (we only build the result here).
        # Produce redacted text for redact-rule findings.
        redacted_text = result.redacted_text
        if redacted_findings:
            sorted_matches = sorted(
                redacted_findings, key=lambda m: m.span[0], reverse=True
            )
            text = result.redacted_text if result.redacted_text else result.text
            for m in sorted_matches:
                start, end = m.span
                char = self.policy.scan_config.get("redaction_char", "X")
                text = text[:start] + str(char) * (end - start) + text[end:]
            redacted_text = text

        all_findings = rejected_findings + redacted_findings + flagged_findings

        return ScanResult(
            text=result.text,
            is_clean=len(all_findings) == 0,
            findings=all_findings,
            redacted_text=redacted_text,
            categories_found={f.category for f in all_findings},
            token_vault=result.token_vault,
        )

    # -- Convenience scan ---------------------------------------------------

    def scan(self, text: str) -> ScanResult:
        """Create a guard, scan text, and apply policy rules.

        This is a convenience method that chains :meth:`create_guard`,
        ``guard.scan``, and :meth:`apply_rules`.

        Note: For the convenience scan the guard uses ``Action.FLAG`` internally
        so that rule-level actions take precedence.  If no rules match a
        finding, the policy's default ``scan.action`` is applied.
        """
        # Build a guard that flags everything so rules can override per-finding.
        guard = self.create_guard()

        # Use _do_scan to avoid raising on REJECT before rules are applied.
        result = guard._do_scan(text)

        # Apply per-category rules.
        result = self.apply_rules(result)

        return result

    # -- Audit configuration ------------------------------------------------

    def configure_audit(self) -> None:
        """Set up audit logging from the policy's ``audit`` section.

        Creates a dedicated :class:`logging.Logger` named
        ``dlpscan.audit.<policy_name>`` that writes JSON lines to the
        configured file.
        """
        ac = self.policy.audit_config
        if not ac or not ac.get("enabled"):
            return

        audit_file = ac.get("file")
        if not audit_file:
            logger.warning("Audit enabled but no file configured for policy %s.",
                           self.policy.name)
            return

        audit_logger_name = f"dlpscan.audit.{self.policy.name}"
        self._audit_logger = logging.getLogger(audit_logger_name)
        self._audit_logger.setLevel(logging.INFO)

        # Avoid duplicate handlers on repeated calls.
        if not self._audit_logger.handlers:
            handler = logging.FileHandler(audit_file, encoding="utf-8")
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._audit_logger.addHandler(handler)
            self._audit_handler = handler

        logger.info(
            "Audit logging configured for policy %s -> %s",
            self.policy.name,
            audit_file,
        )

    def audit_log(self, result: ScanResult, **extra: Any) -> None:
        """Write an audit entry for a scan result.

        Only writes if audit is configured and enabled.
        """
        if self._audit_logger is None:
            return

        import time

        entry = {
            "timestamp": time.time(),
            "policy": self.policy.name,
            "is_clean": result.is_clean,
            "finding_count": result.finding_count,
            "categories_found": sorted(result.categories_found),
        }
        entry.update(extra)

        try:
            self._audit_logger.info(json.dumps(entry, default=str))
        except Exception:
            logger.debug("Failed to write audit log entry.", exc_info=True)

    # -- Rate limit configuration -------------------------------------------

    def configure_rate_limit(self) -> Optional[RateLimiter]:
        """Build a :class:`RateLimiter` from the policy's ``rate_limit`` section.

        Returns:
            A configured :class:`RateLimiter`, or ``None`` if the policy does
            not define rate limiting.
        """
        rl = self.policy.rate_limit_config
        if not rl:
            return None

        max_requests = int(rl.get("max_requests", 100))
        window_seconds = float(rl.get("window_seconds", 60))
        max_payload_bytes = int(rl.get("max_payload_bytes", 10 * 1024 * 1024))

        return RateLimiter(
            max_requests=max_requests,
            window_seconds=window_seconds,
            max_payload_bytes=max_payload_bytes,
        )

    def __repr__(self) -> str:
        return (
            f"PolicyEngine(policy={self.policy.name!r}, "
            f"rules={len(self.policy.rules)})"
        )
