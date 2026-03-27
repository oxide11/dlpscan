"""YAML-based scan rulesets for configuring what dlpscan detects.

A ruleset is a YAML file that selects patterns and keywords from the
dlpscan catalog, configures actions and confidence thresholds, and
optionally defines custom patterns and allowlists.

Usage::

    from dlpscan.rulesets import load_ruleset

    ruleset = load_ruleset("rulesets/pci-production.yaml")
    guard = ruleset.to_guard()
    result = guard.scan(text)

    # Or scan directly
    result = ruleset.scan(text)
"""

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Set

from .guard.core import InputGuard
from .guard.enums import Action, Mode
from .guard.presets import PRESET_CATEGORIES, Preset
from .patterns import PATTERNS
from .scanner import register_patterns

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Baseline -> category mappings
# ---------------------------------------------------------------------------

_BASELINE_CATEGORIES: Dict[str, FrozenSet[str]] = {
    "pii": frozenset({
        "Personal Identifiers", "Contact Information", "Biometric Identifiers",
        "Employment Identifiers", "Education Identifiers", "Geolocation",
        "Postal Codes", "Device Identifiers", "Social Media Identifiers",
        "Dates", "Vehicle Identification", "Insurance Identifiers",
        "Property Identifiers", "Legal Identifiers", "Authentication Tokens",
    }),
    "pii_regional": frozenset(
        k for k in PATTERNS if any(k.startswith(p) for p in (
            "North America", "Europe", "Asia-Pacific", "Latin America",
            "Middle East", "Africa",
        ))
    ),
    "pci": frozenset({
        "Credit Card Numbers", "Primary Account Numbers", "Card Expiration Dates",
        "Card Track Data", "PCI Sensitive Data", "Banking Authentication",
        "Check and MICR Data", "Payment Service Secrets",
    }),
    "phi": frozenset({
        "Medical Identifiers", "Biometric Identifiers", "Personal Identifiers",
        "Contact Information", "Insurance Identifiers", "Device Identifiers",
        "Privacy Classification",
    }),
    "internal_financial": frozenset({
        "Banking and Financial", "Internal Banking References",
        "Customer Financial Data", "Wire Transfer Data", "Loan and Mortgage Data",
        "Securities Identifiers", "Cryptocurrency", "Regulatory Identifiers",
        "Financial Regulatory Labels", "Supervisory Information",
        "Banking Authentication",
    }),
    "source_code_secrets": frozenset({
        "Generic Secrets", "Cloud Provider Secrets", "Code Platform Secrets",
        "Messaging Service Secrets", "Payment Service Secrets",
        "URLs with Credentials", "Authentication Tokens", "Banking Authentication",
    }),
    "confidential_documents": frozenset({
        "Corporate Classification", "Data Classification Labels",
        "Privacy Classification", "Privileged Information",
        "Financial Regulatory Labels", "Supervisory Information",
    }),
}


def available_categories() -> List[str]:
    """Return all available pattern category names from the catalog."""
    return sorted(PATTERNS.keys())


def available_baselines() -> List[str]:
    """Return all available baseline names."""
    return sorted(_BASELINE_CATEGORIES.keys())


def available_presets() -> List[str]:
    """Return all available preset names."""
    return [p.value for p in Preset]


# ---------------------------------------------------------------------------
# Ruleset data model
# ---------------------------------------------------------------------------

@dataclass
class CustomPattern:
    """A user-defined regex pattern within a ruleset."""
    name: str
    regex: str
    category: str
    confidence: float = 0.7
    keywords: Optional[List[str]] = None
    keyword_proximity: int = 50


@dataclass
class CategoryOverride:
    """Per-category configuration override."""
    category: str
    action: Optional[str] = None
    min_confidence: Optional[float] = None
    require_context: Optional[bool] = None
    enabled: bool = True


@dataclass
class Ruleset:
    """A complete scan ruleset loaded from YAML."""
    name: str
    description: str = ""
    version: str = "1"

    # Pattern selection
    baselines: List[str] = field(default_factory=list)
    presets: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    exclude_categories: List[str] = field(default_factory=list)

    # Global settings
    action: str = "flag"
    mode: str = "denylist"
    min_confidence: float = 0.0
    require_context: bool = False
    redaction_char: str = "X"

    # Per-category overrides
    overrides: List[CategoryOverride] = field(default_factory=list)

    # Custom patterns
    custom_patterns: List[CustomPattern] = field(default_factory=list)

    # Allowlist
    allowlist: List[str] = field(default_factory=list)

    # Metadata
    source_file: Optional[str] = None

    def resolve_categories(self) -> Set[str]:
        """Resolve all selected categories from baselines, presets, and explicit lists."""
        cats: Set[str] = set()

        for b in self.baselines:
            key = b.lower().replace("-", "_").replace(" ", "_")
            if key in _BASELINE_CATEGORIES:
                cats |= _BASELINE_CATEGORIES[key]
            else:
                logger.warning("Unknown baseline: %s (available: %s)", b, available_baselines())

        for p in self.presets:
            try:
                preset = Preset(p.lower())
                cats |= PRESET_CATEGORIES[preset]
            except (ValueError, KeyError):
                logger.warning("Unknown preset: %s (available: %s)", p, available_presets())

        for c in self.categories:
            if c in PATTERNS:
                cats.add(c)
            else:
                logger.warning("Unknown category: %s", c)

        # Apply exclusions
        for exc in self.exclude_categories:
            cats.discard(exc)

        # Apply per-category enabled/disabled
        for ov in self.overrides:
            if not ov.enabled:
                cats.discard(ov.category)

        return cats

    def register_custom_patterns(self) -> None:
        """Register any custom patterns defined in the ruleset."""
        for cp in self.custom_patterns:
            try:
                compiled = re.compile(cp.regex)
            except re.error as e:
                logger.error("Invalid regex in custom pattern '%s': %s", cp.name, e)
                continue

            context = None
            if cp.keywords:
                context = {cp.name: cp.keywords}

            register_patterns(
                category=cp.category,
                patterns={cp.name: compiled},
                context=context,
                specificity={cp.name: cp.confidence},
            )

    def to_guard(self) -> InputGuard:
        """Create an InputGuard configured from this ruleset."""
        from .allowlist import Allowlist

        self.register_custom_patterns()
        cats = self.resolve_categories()

        try:
            action = Action(self.action)
        except ValueError:
            raise ValueError(f"Invalid action: {self.action}. Valid: {[a.value for a in Action]}")

        try:
            mode = Mode(self.mode)
        except ValueError:
            raise ValueError(f"Invalid mode: {self.mode}. Valid: {[m.value for m in Mode]}")

        # Build confidence overrides from per-category settings
        confidence_overrides = {}
        for ov in self.overrides:
            if ov.min_confidence is not None:
                confidence_overrides[ov.category] = ov.min_confidence

        al = Allowlist(self.allowlist) if self.allowlist else None

        return InputGuard(
            categories=cats if cats else None,
            mode=mode,
            action=action,
            min_confidence=self.min_confidence,
            require_context=self.require_context,
            redaction_char=self.redaction_char,
            allowlist=al,
            confidence_overrides=confidence_overrides if confidence_overrides else None,
        )

    def scan(self, text: str):
        """Convenience: create guard and scan text."""
        guard = self.to_guard()
        return guard.scan(text)

    def summary(self) -> Dict[str, Any]:
        """Return a summary of what this ruleset will scan for."""
        cats = self.resolve_categories()
        return {
            "name": self.name,
            "description": self.description,
            "action": self.action,
            "mode": self.mode,
            "min_confidence": self.min_confidence,
            "baselines": self.baselines,
            "presets": self.presets,
            "total_categories": len(cats),
            "categories": sorted(cats),
            "custom_patterns": len(self.custom_patterns),
            "allowlist_entries": len(self.allowlist),
            "overrides": len(self.overrides),
        }


# ---------------------------------------------------------------------------
# YAML loading
# ---------------------------------------------------------------------------

def _load_yaml(path: str) -> Dict[str, Any]:
    """Load a YAML file, trying PyYAML first, falling back to JSON."""
    text = Path(path).read_text(encoding="utf-8")
    try:
        import yaml
        return yaml.safe_load(text)
    except ImportError:
        pass
    # Fallback: if the file is actually JSON
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Minimal YAML subset parser for simple key-value + lists
    raise ImportError(
        "PyYAML is required to load YAML rulesets. "
        "Install it with: pip install pyyaml"
    )


def _parse_custom_pattern(data: Dict[str, Any]) -> CustomPattern:
    """Parse a custom pattern definition from YAML data."""
    return CustomPattern(
        name=data["name"],
        regex=data["regex"],
        category=data.get("category", "Custom Patterns"),
        confidence=float(data.get("confidence", 0.7)),
        keywords=data.get("keywords"),
        keyword_proximity=int(data.get("keyword_proximity", 50)),
    )


def _parse_override(data: Dict[str, Any]) -> CategoryOverride:
    """Parse a category override from YAML data."""
    return CategoryOverride(
        category=data["category"],
        action=data.get("action"),
        min_confidence=float(data["min_confidence"]) if "min_confidence" in data else None,
        require_context=data.get("require_context"),
        enabled=data.get("enabled", True),
    )


def load_ruleset(path: str) -> Ruleset:
    """Load a Ruleset from a YAML file.

    Args:
        path: Path to the YAML ruleset file.

    Returns:
        A configured Ruleset instance.

    Raises:
        FileNotFoundError: If the file does not exist.
        ImportError: If PyYAML is not installed.
        ValueError: If the ruleset is invalid.
    """
    path = os.path.realpath(path)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Ruleset file not found: {path}")

    data = _load_yaml(path)
    if not isinstance(data, dict):
        raise ValueError(f"Ruleset must be a YAML mapping, got {type(data).__name__}")

    if "name" not in data:
        raise ValueError("Ruleset must have a 'name' field")

    # Parse scan section (can be top-level or nested under 'scan')
    scan = data.get("scan", data)

    ruleset = Ruleset(
        name=data["name"],
        description=data.get("description", ""),
        version=str(data.get("version", "1")),
        baselines=scan.get("baselines", []),
        presets=scan.get("presets", []),
        categories=scan.get("categories", []),
        exclude_categories=scan.get("exclude_categories", []),
        action=scan.get("action", "flag"),
        mode=scan.get("mode", "denylist"),
        min_confidence=float(scan.get("min_confidence", 0.0)),
        require_context=scan.get("require_context", False),
        redaction_char=scan.get("redaction_char", "X"),
        allowlist=scan.get("allowlist", []),
        source_file=path,
    )

    # Parse custom patterns
    for cp_data in data.get("custom_patterns", []):
        ruleset.custom_patterns.append(_parse_custom_pattern(cp_data))

    # Parse overrides
    for ov_data in data.get("overrides", []):
        ruleset.overrides.append(_parse_override(ov_data))

    return ruleset


def load_ruleset_from_string(yaml_string: str, name: str = "inline") -> Ruleset:
    """Load a Ruleset from a YAML string.

    Args:
        yaml_string: YAML content as a string.
        name: Name to use if not specified in the YAML.

    Returns:
        A configured Ruleset instance.
    """
    try:
        import yaml
        data = yaml.safe_load(yaml_string)
    except ImportError:
        data = json.loads(yaml_string)

    if not isinstance(data, dict):
        raise ValueError("Ruleset must be a YAML mapping")

    data.setdefault("name", name)

    scan = data.get("scan", data)

    ruleset = Ruleset(
        name=data["name"],
        description=data.get("description", ""),
        version=str(data.get("version", "1")),
        baselines=scan.get("baselines", []),
        presets=scan.get("presets", []),
        categories=scan.get("categories", []),
        exclude_categories=scan.get("exclude_categories", []),
        action=scan.get("action", "flag"),
        mode=scan.get("mode", "denylist"),
        min_confidence=float(scan.get("min_confidence", 0.0)),
        require_context=scan.get("require_context", False),
        redaction_char=scan.get("redaction_char", "X"),
        allowlist=scan.get("allowlist", []),
    )

    for cp_data in data.get("custom_patterns", []):
        ruleset.custom_patterns.append(_parse_custom_pattern(cp_data))
    for ov_data in data.get("overrides", []):
        ruleset.overrides.append(_parse_override(ov_data))

    return ruleset
