"""Data masking profiles for common compliance and development scenarios.

Profiles bundle InputGuard configuration into reusable, named objects that
can be serialized to/from JSON and managed via a thread-safe registry.

Usage::

    from dlpscan.profiles import get_profile, PCI_PRODUCTION

    # Use a built-in profile
    guard = PCI_PRODUCTION.to_guard()
    guard.scan("4532015112830366")

    # Look up by name
    profile = get_profile("pci_production")
    guard = profile.to_guard()
"""

import json
import threading
from dataclasses import dataclass, field
from typing import Dict, List

from .guard.core import InputGuard
from .guard.enums import Action, Mode
from .guard.presets import Preset


@dataclass
class MaskingProfile:
    """A reusable configuration bundle for InputGuard.

    Attributes:
        name: Unique identifier for this profile.
        description: Human-readable description.
        presets: Preset names (e.g. ``"pci_dss"``, ``"credentials"``).
        categories: Additional explicit category names to scan.
        action: Action string (``"reject"``, ``"redact"``, ``"flag"``,
                ``"tokenize"``, ``"obfuscate"``).
        mode: Operating mode (``"denylist"`` or ``"allowlist"``).
        min_confidence: Minimum confidence threshold (0.0 -- 1.0).
        require_context: Only flag matches that have context keywords.
        redaction_char: Character used for redaction.
        confidence_overrides: Per-category confidence thresholds.
    """

    name: str
    description: str = ""
    presets: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    action: str = "redact"
    mode: str = "denylist"
    min_confidence: float = 0.0
    require_context: bool = False
    redaction_char: str = "X"
    confidence_overrides: Dict[str, float] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Conversion helpers
    # ------------------------------------------------------------------

    def to_guard(self) -> InputGuard:
        """Create an :class:`InputGuard` from this profile's settings."""
        preset_enums = [Preset(p) for p in self.presets]
        category_set = set(self.categories) if self.categories else None
        return InputGuard(
            presets=preset_enums or None,
            categories=category_set,
            action=Action(self.action),
            mode=Mode(self.mode),
            min_confidence=self.min_confidence,
            require_context=self.require_context,
            redaction_char=self.redaction_char,
            confidence_overrides=self.confidence_overrides or None,
        )

    def to_dict(self) -> dict:
        """Serialize the profile to a plain dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "presets": list(self.presets),
            "categories": list(self.categories),
            "action": self.action,
            "mode": self.mode,
            "min_confidence": self.min_confidence,
            "require_context": self.require_context,
            "redaction_char": self.redaction_char,
            "confidence_overrides": dict(self.confidence_overrides),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MaskingProfile":
        """Deserialize a profile from a plain dictionary."""
        return cls(
            name=data["name"],
            description=data.get("description", ""),
            presets=list(data.get("presets", [])),
            categories=list(data.get("categories", [])),
            action=data.get("action", "redact"),
            mode=data.get("mode", "denylist"),
            min_confidence=float(data.get("min_confidence", 0.0)),
            require_context=bool(data.get("require_context", False)),
            redaction_char=data.get("redaction_char", "X"),
            confidence_overrides=dict(data.get("confidence_overrides", {})),
        )


# ---------------------------------------------------------------------------
# Built-in profiles
# ---------------------------------------------------------------------------

PCI_PRODUCTION = MaskingProfile(
    name="pci_production",
    description="PCI-DSS compliance for production — reject on detection.",
    presets=["pci_dss"],
    action="reject",
    min_confidence=0.7,
    require_context=True,
)

PCI_DEVELOPMENT = MaskingProfile(
    name="pci_development",
    description="PCI-DSS for development — obfuscate card data with fakes.",
    presets=["pci_dss"],
    action="obfuscate",
    min_confidence=0.3,
)

HIPAA_STRICT = MaskingProfile(
    name="hipaa_strict",
    description="HIPAA strict mode — reject any healthcare identifiers.",
    presets=["healthcare"],
    action="reject",
    min_confidence=0.5,
)

HIPAA_REDACT = MaskingProfile(
    name="hipaa_redact",
    description="HIPAA redaction — mask healthcare identifiers.",
    presets=["healthcare"],
    action="redact",
)

GDPR_COMPLIANCE = MaskingProfile(
    name="gdpr_compliance",
    description="GDPR — tokenize PII and contact information.",
    presets=["pii", "contact_info"],
    action="tokenize",
)

SOC2_SECRETS = MaskingProfile(
    name="soc2_secrets",
    description="SOC 2 — reject any detected credentials or secrets.",
    presets=["credentials"],
    action="reject",
)

FULL_SCAN = MaskingProfile(
    name="full_scan",
    description="Scan with all presets, flag only (no transformation).",
    presets=[p.value for p in Preset],
    action="flag",
    min_confidence=0.0,
)

DEVELOPMENT = MaskingProfile(
    name="development",
    description="Development-safe scan — obfuscate all sensitive data.",
    presets=[p.value for p in Preset],
    action="obfuscate",
    min_confidence=0.3,
)

CI_PIPELINE = MaskingProfile(
    name="ci_pipeline",
    description="CI pipeline gate — reject sensitive data with context check.",
    presets=[p.value for p in Preset],
    action="reject",
    min_confidence=0.5,
    require_context=True,
)

_BUILTIN_PROFILES: List[MaskingProfile] = [
    PCI_PRODUCTION,
    PCI_DEVELOPMENT,
    HIPAA_STRICT,
    HIPAA_REDACT,
    GDPR_COMPLIANCE,
    SOC2_SECRETS,
    FULL_SCAN,
    DEVELOPMENT,
    CI_PIPELINE,
]


# ---------------------------------------------------------------------------
# ProfileRegistry
# ---------------------------------------------------------------------------

class ProfileRegistry:
    """Thread-safe registry of :class:`MaskingProfile` instances.

    Pre-populated with all built-in profiles on construction.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._profiles: Dict[str, MaskingProfile] = {}
        for profile in _BUILTIN_PROFILES:
            self._profiles[profile.name] = profile

    def register(self, profile: MaskingProfile) -> None:
        """Register (or replace) a profile by its name."""
        with self._lock:
            self._profiles[profile.name] = profile

    def get(self, name: str) -> MaskingProfile:
        """Return a profile by name.

        Raises:
            KeyError: If no profile with *name* exists.
        """
        with self._lock:
            return self._profiles[name]

    def list(self) -> List[str]:
        """Return sorted list of registered profile names."""
        with self._lock:
            return sorted(self._profiles.keys())

    def remove(self, name: str) -> None:
        """Remove a profile by name.

        Raises:
            KeyError: If no profile with *name* exists.
        """
        with self._lock:
            del self._profiles[name]

    def load_from_file(self, path: str) -> None:
        """Load profiles from a JSON file and register them.

        The file should contain a JSON array of profile dictionaries, or a
        JSON object mapping names to profile dictionaries.
        """
        with open(path, "r") as fh:
            data = json.load(fh)

        if isinstance(data, list):
            profiles = [MaskingProfile.from_dict(d) for d in data]
        elif isinstance(data, dict):
            profiles = [MaskingProfile.from_dict(d) for d in data.values()]
        else:
            raise ValueError(f"Expected JSON array or object, got {type(data).__name__}")

        with self._lock:
            for profile in profiles:
                self._profiles[profile.name] = profile

    def save_to_file(self, path: str) -> None:
        """Export all registered profiles to a JSON file."""
        with self._lock:
            profiles = [p.to_dict() for p in self._profiles.values()]
        with open(path, "w") as fh:
            json.dump(profiles, fh, indent=2)


# ---------------------------------------------------------------------------
# Module-level convenience API
# ---------------------------------------------------------------------------

_default_registry = ProfileRegistry()


def get_profile(name: str) -> MaskingProfile:
    """Look up a profile by name in the default registry."""
    return _default_registry.get(name)


def list_profiles() -> List[str]:
    """Return sorted list of profile names in the default registry."""
    return _default_registry.list()


def register_profile(profile: MaskingProfile) -> None:
    """Register a profile in the default registry."""
    _default_registry.register(profile)
