"""Match result dataclass and pattern metadata for dlpscan."""

from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass(frozen=True)
class Match:
    """Represents a single sensitive-data match found by the scanner.

    Attributes:
        text: The matched text from the input.
        category: Top-level pattern category (e.g., 'Credit Card Numbers').
        sub_category: Specific pattern name (e.g., 'Visa').
        has_context: Whether contextual keywords were found nearby.
        confidence: Confidence score from 0.0 to 1.0.
        span: (start, end) character offsets in the input text.
        context_required: Whether this pattern requires context to be reliable.
    """
    text: str
    category: str
    sub_category: str
    has_context: bool = False
    confidence: float = 0.0
    span: tuple = (0, 0)
    context_required: bool = False

    def to_dict(self) -> dict:
        """Convert to a plain dictionary for JSON serialization."""
        return asdict(self)

    def __iter__(self):
        """Allow tuple unpacking for backward compatibility.

        Supports: text, sub_category, has_context, category = match
        """
        return iter((self.text, self.sub_category, self.has_context, self.category))

    def __getitem__(self, index):
        """Allow index access for backward compatibility.

        m[0] = text, m[1] = sub_category, m[2] = has_context, m[3] = category
        """
        return (self.text, self.sub_category, self.has_context, self.category)[index]

    def __len__(self):
        """Length of the backward-compatible tuple representation."""
        return 4


# -- Pattern Specificity Scores --
#
# Each score (0.0-1.0) rates how specific a pattern is on its own,
# independent of context.  High-specificity patterns (like IBAN or SWIFT)
# rarely false-positive; low-specificity patterns (like bare digit
# sequences) need context to be meaningful.
#
# These are used as the base for confidence scoring.

PATTERN_SPECIFICITY: dict = {
    # -- Credit Cards (Luhn-validated, highly specific) --
    'Visa': 0.90,
    'MasterCard': 0.90,
    'Amex': 0.90,
    'Discover': 0.90,
    'JCB': 0.90,
    'Diners Club': 0.90,
    'UnionPay': 0.90,
    'PAN': 0.60,
    'Masked PAN': 0.85,
    'Track 1 Data': 0.95,
    'Track 2 Data': 0.95,
    'Card Expiry': 0.30,

    # -- Banking (structured patterns = high, digit-only = low) --
    'IBAN Generic': 0.90,
    'SWIFT/BIC': 0.85,
    'ABA Routing Number': 0.55,
    'US Bank Account Number': 0.20,
    'Canada Transit Number': 0.40,
    'Fedwire IMAD': 0.90,
    'CHIPS UID': 0.50,
    'Wire Reference Number': 0.50,
    'ACH Trace Number': 0.55,
    'ACH Batch Number': 0.20,
    'SEPA Reference': 0.50,
    'MICR Line': 0.90,
    'Check Number': 0.15,
    'Cashier Check Number': 0.20,
    'CUSIP': 0.70,
    'ISIN': 0.75,
    'SEDOL': 0.70,
    'FIGI': 0.90,
    'LEI': 0.80,
    'Ticker Symbol': 0.80,
    'Loan Number': 0.45,
    'MERS MIN': 0.50,
    'Universal Loan Identifier': 0.75,
    'LTV Ratio': 0.40,
    'SAR Filing Number': 0.30,
    'CTR Number': 0.30,
    'AML Case ID': 0.60,
    'OFAC SDN Entry': 0.15,
    'FinCEN Report Number': 0.30,
    'Compliance Case Number': 0.55,
    'PIN Block': 0.65,
    'HSM Key': 0.55,
    'Encryption Key': 0.50,
    'Account Balance': 0.50,
    'Balance with Currency Code': 0.55,
    'Income Amount': 0.40,
    'DTI Ratio': 0.45,
    'Internal Account Ref': 0.50,
    'Teller ID': 0.35,
    'Cardholder Name Pattern': 0.10,

    # -- Contact Info --
    'Email Address': 0.90,
    'Phone Number (E.164)': 0.70,
    'IPv4 Address': 0.60,
    'IPv6 Address': 0.80,
    'MAC Address': 0.80,

    # -- PII --
    'Date of Birth': 0.40,
    'Gender Marker': 0.25,
    'GPS Coordinates': 0.80,
    'GPS DMS': 0.85,
    'Geohash': 0.60,
    'US ZIP+4 Code': 0.55,
    'UK Postcode': 0.70,
    'Canada Postal Code': 0.75,
    'Japan Postal Code': 0.45,
    'Brazil CEP': 0.45,
    'IMEI': 0.55,
    'IMEISV': 0.55,
    'MEID': 0.70,
    'ICCID': 0.85,
    'IDFA/IDFV': 0.85,
    'Health Plan ID': 0.60,
    'DEA Number': 0.55,
    'ICD-10 Code': 0.50,
    'NDC Code': 0.65,
    'Insurance Policy Number': 0.50,
    'Insurance Claim Number': 0.45,
    'Session ID': 0.55,
    'Twitter Handle': 0.60,
    'Hashtag': 0.30,
    'EDU Email': 0.90,
    'US Federal Case Number': 0.80,
    'Court Docket Number': 0.45,
    'Employee ID': 0.35,
    'Work Permit Number': 0.50,
    'Biometric Hash': 0.70,
    'Biometric Template ID': 0.75,
    'Parcel Number': 0.60,
    'Title Deed Number': 0.40,

    # -- Secrets (prefix-based = highly specific) --
    'Bearer Token': 0.80,
    'JWT Token': 0.95,
    'Private Key': 0.95,
    'API Key Generic': 0.50,
    'Database Connection String': 0.90,
    'AWS Access Key': 0.95,
    'AWS Secret Key': 0.90,
    'Google API Key': 0.90,
    'GitHub Token (Classic)': 0.95,
    'GitHub Token (Fine-Grained)': 0.95,
    'GitHub OAuth Token': 0.95,
    'NPM Token': 0.95,
    'PyPI Token': 0.95,
    'Stripe Secret Key': 0.95,
    'Stripe Publishable Key': 0.85,
    'Slack Bot Token': 0.95,
    'Slack User Token': 0.95,
    'Slack Webhook URL': 0.90,
    'SendGrid API Key': 0.95,
    'Twilio API Key': 0.90,
    'Mailgun API Key': 0.90,

    # -- Cryptocurrency --
    'Bitcoin Address': 0.80,
    'Ethereum Address': 0.80,
    'Litecoin Address': 0.80,
    'Bitcoin Cash Address': 0.75,
    'Monero Address': 0.85,
    'Ripple Address': 0.80,

    # -- Vehicles --
    'VIN': 0.70,

    # -- URLs --
    'URL with Credentials': 0.90,
    'URL with Token Parameter': 0.75,
}

# Default specificity for patterns not listed above.
DEFAULT_SPECIFICITY = 0.40

# -- Patterns that REQUIRE context to be reported --
#
# These are patterns so broad (bare digit sequences, generic alphanumeric)
# that without context keywords nearby, they produce too many false positives.
# When context_required is set, the pattern is only reported if context
# keywords are found within proximity distance, regardless of the caller's
# require_context parameter.

CONTEXT_REQUIRED_PATTERNS: frozenset = frozenset({
    # Banking
    'US Bank Account Number',   # \d{8,17}
    'ACH Batch Number',         # \d{7}
    'Check Number',             # \d{4,6}
    'Cashier Check Number',     # \d{8,15}
    'OFAC SDN Entry',           # \d{4,6}
    'Cardholder Name Pattern',  # First Last — matches any two capitalized words

    # PII
    'Gender Marker',            # male/female — common words
    'Hashtag',                  # #word — extremely common
    'Card Expiry',              # MM/YY — matches dates
    'Date of Birth',            # MM/DD/YYYY — matches any date
    'LTV Ratio',                # ##.##% — matches any percentage
    'DTI Ratio',                # ##.##% — matches any percentage
})
