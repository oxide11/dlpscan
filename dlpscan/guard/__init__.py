"""Input guard subpackage for scanning and sanitizing application inputs.

Usage::

    from dlpscan.guard import InputGuard, Preset, Action, Mode

    guard = InputGuard(presets=[Preset.PCI_DSS, Preset.SSN_SIN])
    guard.scan("My card is 4532015112830366")  # raises InputGuardError
"""

from .core import (
    InputGuard,
    ScanResult,
    InputGuardError,
)
from .presets import (
    Preset,
    PRESET_CATEGORIES,
)
from .enums import (
    Action,
    Mode,
)

__all__ = [
    'InputGuard',
    'ScanResult',
    'InputGuardError',
    'Preset',
    'PRESET_CATEGORIES',
    'Action',
    'Mode',
]
