"""Input guard subpackage for scanning and sanitizing application inputs.

Usage::

    from dlpscan.guard import InputGuard, Preset, Action, Mode

    guard = InputGuard(presets=[Preset.PCI_DSS, Preset.SSN_SIN])
    guard.scan("My card is 4532015112830366")  # raises InputGuardError
"""

from .core import (
    InputGuard,
    InputGuardError,
    ScanResult,
)
from .enums import (
    Action,
    Mode,
)
from .presets import (
    PRESET_CATEGORIES,
    Preset,
)
from .rbac import (
    Permission,
    PermissionDeniedError,
    RBACPolicy,
    Role,
    SecureTokenVault,
)
from .transforms import (
    TokenVault,
    get_obfuscation_rng,
    obfuscate_match,
    obfuscate_matches,
    set_obfuscation_seed,
    tokenize_matches,
)

__all__ = [
    'InputGuard',
    'ScanResult',
    'InputGuardError',
    'Preset',
    'PRESET_CATEGORIES',
    'Action',
    'Mode',
    'TokenVault',
    'tokenize_matches',
    'obfuscate_matches',
    'obfuscate_match',
    'set_obfuscation_seed',
    'get_obfuscation_rng',
    'Role',
    'Permission',
    'PermissionDeniedError',
    'RBACPolicy',
    'SecureTokenVault',
]
