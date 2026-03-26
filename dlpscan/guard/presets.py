"""Compliance presets mapping to pattern category sets."""

from enum import Enum
from typing import Dict, FrozenSet

from ..patterns import PATTERNS


class Preset(Enum):
    """Compliance presets mapping to sets of pattern categories."""
    PCI_DSS = "pci_dss"
    SSN_SIN = "ssn_sin"
    PII = "pii"
    PII_STRICT = "pii_strict"
    CREDENTIALS = "credentials"
    FINANCIAL = "financial"
    HEALTHCARE = "healthcare"
    CONTACT_INFO = "contact_info"


def _regional_categories() -> FrozenSet[str]:
    """Gather all regional pattern categories dynamically from PATTERNS."""
    prefixes = ('North America', 'Europe', 'Asia-Pacific', 'Latin America',
                'Middle East', 'Africa')
    return frozenset(k for k in PATTERNS if any(k.startswith(p) for p in prefixes))


PRESET_CATEGORIES: Dict[Preset, FrozenSet[str]] = {
    Preset.PCI_DSS: frozenset({
        'Credit Card Numbers',
        'Primary Account Numbers',
        'Card Track Data',
        'Card Expiration Dates',
        'PCI Sensitive Data',
    }),

    Preset.SSN_SIN: frozenset({
        'North America - United States',
        'North America - Canada',
    }),

    Preset.PII: frozenset({
        'Personal Identifiers',
        'Postal Codes',
        'Geolocation',
        'Device Identifiers',
        'Contact Information',
        'Social Media Identifiers',
        'Education Identifiers',
        'Employment Identifiers',
        'Legal Identifiers',
        'Biometric Identifiers',
        'Property Identifiers',
    }),

    # PII_STRICT includes all PII categories plus all regional IDs/passports/DLs.
    Preset.PII_STRICT: frozenset({
        'Personal Identifiers',
        'Postal Codes',
        'Geolocation',
        'Device Identifiers',
        'Contact Information',
        'Social Media Identifiers',
        'Education Identifiers',
        'Employment Identifiers',
        'Legal Identifiers',
        'Biometric Identifiers',
        'Property Identifiers',
        'Dates',
        'Vehicle Identification',
    }) | _regional_categories(),

    Preset.CREDENTIALS: frozenset({
        'Generic Secrets',
        'Cloud Provider Secrets',
        'Code Platform Secrets',
        'Payment Service Secrets',
        'Messaging Service Secrets',
        'Banking Authentication',
        'Authentication Tokens',
        'URLs with Credentials',
    }),

    Preset.FINANCIAL: frozenset({
        'Credit Card Numbers',
        'Primary Account Numbers',
        'Card Track Data',
        'Card Expiration Dates',
        'PCI Sensitive Data',
        'Banking and Financial',
        'Wire Transfer Data',
        'Check and MICR Data',
        'Securities Identifiers',
        'Loan and Mortgage Data',
        'Customer Financial Data',
        'Internal Banking References',
        'Regulatory Identifiers',
        'Cryptocurrency',
        'Financial Regulatory Labels',
    }),

    Preset.HEALTHCARE: frozenset({
        'Medical Identifiers',
        'Insurance Identifiers',
    }),

    Preset.CONTACT_INFO: frozenset({
        'Contact Information',
    }),
}
