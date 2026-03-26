"""
Aggregated PATTERNS dictionary.

Imports all pattern modules from generic/, custom/, and regions/ sub-packages
and merges them into a single PATTERNS dict consumed by the scanner.
"""

from .generic.credit_cards import CREDIT_CARDS_PATTERNS
from .generic.contact_info import CONTACT_INFO_PATTERNS
from .generic.banking import BANKING_PATTERNS
from .generic.cryptocurrency import CRYPTOCURRENCY_PATTERNS
from .generic.vehicles import VEHICLES_PATTERNS
from .generic.dates import DATES_PATTERNS
from .generic.urls import URLS_PATTERNS
from .generic.secrets import SECRETS_PATTERNS
from .generic.pii_identifiers import PII_IDENTIFIERS_PATTERNS
from .generic.classification_labels import CLASSIFICATION_LABELS_PATTERNS

from .custom.cloud_providers import CLOUD_PROVIDERS_PATTERNS
from .custom.code_platforms import CODE_PLATFORMS_PATTERNS
from .custom.payment_services import PAYMENT_SERVICES_PATTERNS
from .custom.messaging_services import MESSAGING_SERVICES_PATTERNS

from .regions.north_america import NORTH_AMERICA_PATTERNS
from .regions.europe import EUROPE_PATTERNS
from .regions.asia_pacific import ASIA_PACIFIC_PATTERNS
from .regions.latin_america import LATIN_AMERICA_PATTERNS
from .regions.middle_east import MIDDLE_EAST_PATTERNS
from .regions.africa import AFRICA_PATTERNS

PATTERNS: dict = {}

# Generic
PATTERNS.update(CREDIT_CARDS_PATTERNS)
PATTERNS.update(CONTACT_INFO_PATTERNS)
PATTERNS.update(BANKING_PATTERNS)
PATTERNS.update(CRYPTOCURRENCY_PATTERNS)
PATTERNS.update(VEHICLES_PATTERNS)
PATTERNS.update(DATES_PATTERNS)
PATTERNS.update(URLS_PATTERNS)
PATTERNS.update(SECRETS_PATTERNS)
PATTERNS.update(PII_IDENTIFIERS_PATTERNS)
PATTERNS.update(CLASSIFICATION_LABELS_PATTERNS)

# Custom
PATTERNS.update(CLOUD_PROVIDERS_PATTERNS)
PATTERNS.update(CODE_PLATFORMS_PATTERNS)
PATTERNS.update(PAYMENT_SERVICES_PATTERNS)
PATTERNS.update(MESSAGING_SERVICES_PATTERNS)

# Regions
PATTERNS.update(NORTH_AMERICA_PATTERNS)
PATTERNS.update(EUROPE_PATTERNS)
PATTERNS.update(ASIA_PACIFIC_PATTERNS)
PATTERNS.update(LATIN_AMERICA_PATTERNS)
PATTERNS.update(MIDDLE_EAST_PATTERNS)
PATTERNS.update(AFRICA_PATTERNS)
