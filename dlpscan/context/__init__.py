"""
Aggregated CONTEXT_KEYWORDS dictionary.

Imports all context modules from generic/, custom/, and regions/ sub-packages
and merges them into a single CONTEXT_KEYWORDS dict consumed by the scanner.
"""

from .generic.credit_cards import CREDIT_CARDS_CONTEXT
from .generic.contact_info import CONTACT_INFO_CONTEXT
from .generic.banking import BANKING_CONTEXT
from .generic.cryptocurrency import CRYPTOCURRENCY_CONTEXT
from .generic.vehicles import VEHICLES_CONTEXT
from .generic.dates import DATES_CONTEXT
from .generic.urls import URLS_CONTEXT
from .generic.secrets import SECRETS_CONTEXT
from .generic.pii_identifiers import PII_IDENTIFIERS_CONTEXT
from .generic.classification_labels import CLASSIFICATION_LABELS_CONTEXT

from .custom.cloud_providers import CLOUD_PROVIDERS_CONTEXT
from .custom.code_platforms import CODE_PLATFORMS_CONTEXT
from .custom.payment_services import PAYMENT_SERVICES_CONTEXT
from .custom.messaging_services import MESSAGING_SERVICES_CONTEXT

from .regions.north_america import NORTH_AMERICA_CONTEXT
from .regions.europe import EUROPE_CONTEXT
from .regions.asia_pacific import ASIA_PACIFIC_CONTEXT
from .regions.latin_america import LATIN_AMERICA_CONTEXT
from .regions.middle_east import MIDDLE_EAST_CONTEXT
from .regions.africa import AFRICA_CONTEXT

CONTEXT_KEYWORDS: dict = {}

# Generic
CONTEXT_KEYWORDS.update(CREDIT_CARDS_CONTEXT)
CONTEXT_KEYWORDS.update(CONTACT_INFO_CONTEXT)
CONTEXT_KEYWORDS.update(BANKING_CONTEXT)
CONTEXT_KEYWORDS.update(CRYPTOCURRENCY_CONTEXT)
CONTEXT_KEYWORDS.update(VEHICLES_CONTEXT)
CONTEXT_KEYWORDS.update(DATES_CONTEXT)
CONTEXT_KEYWORDS.update(URLS_CONTEXT)
CONTEXT_KEYWORDS.update(SECRETS_CONTEXT)
CONTEXT_KEYWORDS.update(PII_IDENTIFIERS_CONTEXT)
CONTEXT_KEYWORDS.update(CLASSIFICATION_LABELS_CONTEXT)

# Custom
CONTEXT_KEYWORDS.update(CLOUD_PROVIDERS_CONTEXT)
CONTEXT_KEYWORDS.update(CODE_PLATFORMS_CONTEXT)
CONTEXT_KEYWORDS.update(PAYMENT_SERVICES_CONTEXT)
CONTEXT_KEYWORDS.update(MESSAGING_SERVICES_CONTEXT)

# Regions
CONTEXT_KEYWORDS.update(NORTH_AMERICA_CONTEXT)
CONTEXT_KEYWORDS.update(EUROPE_CONTEXT)
CONTEXT_KEYWORDS.update(ASIA_PACIFIC_CONTEXT)
CONTEXT_KEYWORDS.update(LATIN_AMERICA_CONTEXT)
CONTEXT_KEYWORDS.update(MIDDLE_EAST_CONTEXT)
CONTEXT_KEYWORDS.update(AFRICA_CONTEXT)
