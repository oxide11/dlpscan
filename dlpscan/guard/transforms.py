"""Tokenization and obfuscation transforms for sensitive data.

Provides two strategies beyond simple redaction:

- **Tokenization**: Reversible replacement with deterministic tokens.
  A ``TokenVault`` stores the mapping so originals can be recovered.
- **Obfuscation**: Irreversible replacement with realistic-looking fake
  data of the same format/type.

Usage::

    from dlpscan.guard import InputGuard, Preset, Action

    # Tokenize — reversible
    guard = InputGuard(presets=[Preset.PCI_DSS], action=Action.TOKENIZE)
    result = guard.scan("Card: 4111-1111-1111-1111")
    print(result.redacted_text)            # "Card: TOK_CC_a8f3b2c1"
    print(guard.detokenize(result.redacted_text))  # "Card: 4111-1111-1111-1111"

    # Obfuscate — irreversible
    guard = InputGuard(presets=[Preset.PCI_DSS], action=Action.OBFUSCATE)
    result = guard.scan("Card: 4111-1111-1111-1111")
    print(result.redacted_text)            # "Card: 4539788421650347"
"""

import hashlib
import hmac
import random
import re
import string
import threading
from typing import Dict, List, Optional

from ..models import Match

# ---------------------------------------------------------------------------
# Obfuscation RNG (supports custom seeds for reproducible fake data)
# ---------------------------------------------------------------------------

_rng: random.Random = random.Random()


def set_obfuscation_seed(seed: Optional[int] = None) -> None:
    """Set the seed for obfuscation random number generation.

    When a seed is set, obfuscation output becomes deterministic and
    reproducible — useful for testing and audit-stable fake data.

    Args:
        seed: Integer seed. Pass ``None`` to reset to non-deterministic.
    """
    global _rng
    _rng = random.Random(seed)


def get_obfuscation_rng() -> random.Random:
    """Return the current obfuscation RNG instance."""
    return _rng


# ---------------------------------------------------------------------------
# Category abbreviation map for token prefixes
# ---------------------------------------------------------------------------

_CATEGORY_ABBREV: Dict[str, str] = {
    'Credit Card Numbers': 'CC',
    'Primary Account Numbers': 'PAN',
    'Card Track Data': 'TRACK',
    'Card Expiration Dates': 'EXPIRY',
    'Contact Information': 'CONTACT',
    'Banking and Financial': 'BANK',
    'Wire Transfer Data': 'WIRE',
    'Check and MICR Data': 'CHECK',
    'Securities Identifiers': 'SEC',
    'Loan and Mortgage Data': 'LOAN',
    'Regulatory Identifiers': 'REG',
    'Banking Authentication': 'AUTH',
    'Customer Financial Data': 'CUSTFIN',
    'Internal Banking References': 'INTREF',
    'PCI Sensitive Data': 'PCI',
    'Cryptocurrency': 'CRYPTO',
    'Vehicle Identification': 'VIN',
    'Dates': 'DATE',
    'URLs with Credentials': 'URL',
    'Generic Secrets': 'SECRET',
    'Cloud Provider Secrets': 'CLOUD',
    'Code Platform Secrets': 'CODE',
    'Payment Service Secrets': 'PAY',
    'Messaging Service Secrets': 'MSG',
    'Personal Identifiers': 'PID',
    'Geolocation': 'GEO',
    'Postal Codes': 'ZIP',
    'Device Identifiers': 'DEV',
    'Medical Identifiers': 'MED',
    'Insurance Identifiers': 'INS',
    'Authentication Tokens': 'AUTHTOK',
    'Social Media Identifiers': 'SOCIAL',
    'Education Identifiers': 'EDU',
    'Legal Identifiers': 'LEGAL',
    'Employment Identifiers': 'EMP',
    'Biometric Identifiers': 'BIO',
    'Property Identifiers': 'PROP',
}


def _abbreviate_category(category: str) -> str:
    """Get a short abbreviation for a category name."""
    if category in _CATEGORY_ABBREV:
        return _CATEGORY_ABBREV[category]
    # Regional categories: "North America - United States" → "NA_US"
    if ' - ' in category:
        region, country = category.split(' - ', 1)
        region_abbr = ''.join(w[0] for w in region.split())
        country_abbr = ''.join(w[0] for w in country.split())[:3]
        return f"{region_abbr}_{country_abbr}".upper()
    # Fallback: first letters of each word
    return ''.join(w[0] for w in category.split()).upper()


# ---------------------------------------------------------------------------
# TokenVault
# ---------------------------------------------------------------------------

class TokenVault:
    """Thread-safe vault for storing tokenization mappings.

    Tokens are deterministic: the same (value, category) pair always
    produces the same token. This is useful for consistent tokenization
    across multiple calls.

    Args:
        prefix: Prefix for generated tokens (default "TOK").
        secret: Optional secret for HMAC-based token generation.
                If None, uses plain SHA-256 hashing.
    """

    def __init__(self, prefix: str = "TOK", secret: Optional[str] = None):
        self.prefix = prefix
        self._secret = secret.encode() if secret else None
        self._token_to_original: Dict[str, str] = {}
        self._original_to_token: Dict[str, str] = {}
        self._lock = threading.Lock()

    def tokenize(self, value: str, category: str) -> str:
        """Replace a sensitive value with a deterministic token.

        Args:
            value: The sensitive text to tokenize.
            category: The pattern category (used for prefix and hashing).

        Returns:
            A token string like "TOK_CC_a8f3b2c1".
        """
        # Check if already tokenized.
        cache_key = (value, category)
        with self._lock:
            existing = self._original_to_token.get(str(cache_key))
            if existing:
                return existing

        abbrev = _abbreviate_category(category)

        # Generate deterministic hash.
        hash_input = f"{category}:{value}".encode()
        if self._secret:
            digest = hmac.new(self._secret, hash_input, hashlib.sha256).hexdigest()[:8]
        else:
            digest = hashlib.sha256(hash_input).hexdigest()[:8]

        token = f"{self.prefix}_{abbrev}_{digest}"

        with self._lock:
            self._token_to_original[token] = value
            self._original_to_token[str(cache_key)] = token

        return token

    def detokenize(self, token: str) -> Optional[str]:
        """Recover the original value from a token.

        Args:
            token: A token string (e.g., "TOK_CC_a8f3b2c1").

        Returns:
            The original sensitive value, or None if not found.
        """
        with self._lock:
            return self._token_to_original.get(token)

    def detokenize_text(self, text: str) -> str:
        """Replace all tokens in text with their original values.

        Scans text for any known tokens and replaces them.

        Args:
            text: Text containing tokens.

        Returns:
            Text with tokens replaced by originals.
        """
        with self._lock:
            tokens = dict(self._token_to_original)

        # Sort by length descending to avoid partial replacements.
        for token in sorted(tokens, key=len, reverse=True):
            text = text.replace(token, tokens[token])
        return text

    def clear(self) -> None:
        """Remove all stored token mappings."""
        with self._lock:
            self._token_to_original.clear()
            self._original_to_token.clear()

    def export_map(self) -> Dict[str, str]:
        """Export the token-to-original mapping as a plain dict.

        Returns:
            Dict mapping token strings to original values.
        """
        with self._lock:
            return dict(self._token_to_original)

    def import_map(self, mapping: Dict[str, str]) -> None:
        """Import a token-to-original mapping.

        Args:
            mapping: Dict mapping token strings to original values.
        """
        with self._lock:
            for token, original in mapping.items():
                self._token_to_original[token] = original

    @property
    def size(self) -> int:
        """Number of token mappings stored."""
        with self._lock:
            return len(self._token_to_original)

    def __repr__(self) -> str:
        return f"TokenVault(prefix={self.prefix!r}, entries={self.size})"


# ---------------------------------------------------------------------------
# Obfuscation generators
# ---------------------------------------------------------------------------

def _generate_luhn_number(length: int, prefix: str = '') -> str:
    """Generate a random number that passes Luhn validation."""
    digits = list(prefix)
    # Fill with random digits, leaving last for check digit.
    while len(digits) < length - 1:
        digits.append(str(_rng.randint(0, 9)))

    # Calculate Luhn check digit.
    total = 0
    for idx, d in enumerate(reversed(digits)):
        n = int(d)
        if idx % 2 == 0:  # Even positions from right (0-indexed) get doubled.
            n *= 2
            if n > 9:
                n -= 9
        total += n
    check = (10 - (total % 10)) % 10
    digits.append(str(check))
    return ''.join(digits)


def _obfuscate_credit_card(match: Match) -> str:
    """Generate a fake credit card number with valid Luhn checksum."""
    original = re.sub(r'[^0-9]', '', match.text)
    length = len(original)

    # Preserve the general card type prefix but change it.
    prefix_map = {
        'Visa': '4',
        'MasterCard': '5' + str(_rng.randint(1, 5)),
        'Amex': '3' + _rng.choice(['4', '7']),
        'Discover': '6011',
        'JCB': '35',
        'Diners Club': '36',
        'UnionPay': '62',
    }
    prefix = prefix_map.get(match.sub_category, str(_rng.randint(3, 6)))
    fake = _generate_luhn_number(length, prefix)

    # Reapply original formatting (dashes, spaces).
    result = []
    fake_idx = 0
    for c in match.text:
        if c.isdigit() and fake_idx < len(fake):
            result.append(fake[fake_idx])
            fake_idx += 1
        else:
            result.append(c)
    return ''.join(result)


def _obfuscate_email(match: Match) -> str:
    """Generate a fake email address."""
    user = ''.join(_rng.choices(string.ascii_lowercase, k=8))
    domain = _rng.choice(['example.net', 'example.org', 'test.invalid', 'sample.test'])
    return f"{user}@{domain}"


def _obfuscate_phone(match: Match) -> str:
    """Generate a fake phone number preserving format."""
    # Replace digits with random ones, keeping format characters.
    return ''.join(
        str(_rng.randint(0, 9)) if c.isdigit() else c
        for c in match.text
    )


def _obfuscate_ssn(match: Match) -> str:
    """Generate a fake SSN/SIN preserving format."""
    return ''.join(
        str(_rng.randint(0, 9)) if c.isdigit() else c
        for c in match.text
    )


def _obfuscate_iban(match: Match) -> str:
    """Generate a fake IBAN preserving country code and format."""
    text = match.text
    if len(text) >= 2 and text[:2].isalpha():
        country = text[:2]
        rest = ''.join(
            str(_rng.randint(0, 9)) if c.isdigit() else
            _rng.choice(string.ascii_uppercase) if c.isalpha() else c
            for c in text[2:]
        )
        return country + rest
    return _obfuscate_generic(match)


def _obfuscate_ip4(match: Match) -> str:
    """Generate a fake IPv4 address."""
    return f"{_rng.randint(10, 223)}.{_rng.randint(0, 255)}.{_rng.randint(0, 255)}.{_rng.randint(1, 254)}"


def _obfuscate_mac(match: Match) -> str:
    """Generate a fake MAC address preserving delimiter."""
    delim = ':' if ':' in match.text else '-'
    octets = [f"{_rng.randint(0, 255):02x}" for _ in range(6)]
    return delim.join(octets)


def _obfuscate_secret(match: Match) -> str:
    """Generate a fake secret/token of the same length."""
    text = match.text
    charset = string.ascii_letters + string.digits
    return ''.join(
        _rng.choice(charset) if c.isalnum() else c
        for c in text
    )


def _obfuscate_generic(match: Match) -> str:
    """Fallback: replace alphanumeric chars with random ones, keep format."""
    return ''.join(
        _rng.choice(string.digits) if c.isdigit() else
        _rng.choice(string.ascii_uppercase) if c.isupper() else
        _rng.choice(string.ascii_lowercase) if c.islower() else c
        for c in match.text
    )


# Dispatch table: (category, sub_category) or just category → generator.
_OBFUSCATORS: Dict[str, object] = {
    # Credit cards
    'Credit Card Numbers': _obfuscate_credit_card,
    'Primary Account Numbers': _obfuscate_credit_card,
    # Contact info
    'Email Address': _obfuscate_email,
    'E.164 Phone Number': _obfuscate_phone,
    'US Phone Number': _obfuscate_phone,
    'IPv4 Address': _obfuscate_ip4,
    'MAC Address': _obfuscate_mac,
    # Government IDs
    'USA SSN': _obfuscate_ssn,
    'USA ITIN': _obfuscate_ssn,
    'Canada SIN': _obfuscate_ssn,
    # Banking
    'IBAN Generic': _obfuscate_iban,
    # Secrets
    'Generic Secrets': _obfuscate_secret,
    'Cloud Provider Secrets': _obfuscate_secret,
    'Code Platform Secrets': _obfuscate_secret,
    'Payment Service Secrets': _obfuscate_secret,
    'Messaging Service Secrets': _obfuscate_secret,
    'Authentication Tokens': _obfuscate_secret,
    'Bearer Token': _obfuscate_secret,
    'JWT Token': _obfuscate_secret,
    'Generic API Key': _obfuscate_secret,
    'AWS Access Key': _obfuscate_secret,
    'AWS Secret Key': _obfuscate_secret,
    'Google API Key': _obfuscate_secret,
    'GitHub Token (Classic)': _obfuscate_secret,
    'GitHub Token (Fine-Grained)': _obfuscate_secret,
    'GitHub OAuth Token': _obfuscate_secret,
    'NPM Token': _obfuscate_secret,
    'PyPI Token': _obfuscate_secret,
    'Stripe Secret Key': _obfuscate_secret,
    'Stripe Publishable Key': _obfuscate_secret,
}


def obfuscate_match(match: Match) -> str:
    """Generate realistic fake data for a single match.

    Dispatches to a type-specific generator based on the match's
    category and sub_category. Falls back to generic format-preserving
    replacement.

    Args:
        match: A Match object with text, category, and sub_category.

    Returns:
        Fake replacement string of similar format.
    """
    # Try sub_category first (most specific), then category.
    generator = _OBFUSCATORS.get(match.sub_category) or _OBFUSCATORS.get(match.category)
    if generator:
        return generator(match)
    return _obfuscate_generic(match)


# ---------------------------------------------------------------------------
# Text transformation functions
# ---------------------------------------------------------------------------

def tokenize_matches(text: str, matches: List[Match], vault: TokenVault) -> str:
    """Replace matched spans with tokens using a TokenVault.

    Processes matches in reverse span order to avoid offset drift.

    Args:
        text: Original text containing sensitive data.
        matches: List of Match objects from scanning.
        vault: TokenVault to store mappings.

    Returns:
        Text with sensitive data replaced by tokens.
    """
    sorted_matches = sorted(matches, key=lambda m: m.span[0], reverse=True)
    result = text
    for m in sorted_matches:
        start, end = m.span
        token = vault.tokenize(result[start:end], m.category)
        result = result[:start] + token + result[end:]
    return result


def obfuscate_matches(text: str, matches: List[Match]) -> str:
    """Replace matched spans with realistic fake data.

    Processes matches in reverse span order to avoid offset drift.

    Args:
        text: Original text containing sensitive data.
        matches: List of Match objects from scanning.

    Returns:
        Text with sensitive data replaced by fake equivalents.
    """
    sorted_matches = sorted(matches, key=lambda m: m.span[0], reverse=True)
    result = text
    for m in sorted_matches:
        start, end = m.span
        fake = obfuscate_match(m)
        result = result[:start] + fake + result[end:]
    return result
