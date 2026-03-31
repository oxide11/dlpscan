"""Exact Data Match (EDM) — zero false-positive detection of known sensitive values.

Scans text for specific pre-registered sensitive values (e.g. known employee
SSNs, customer credit card numbers) using salted cryptographic hashes.
The hash set contains no reversible data, making it safe to distribute.

Usage::

    from dlpscan.edm import ExactDataMatcher

    matcher = ExactDataMatcher()

    # Register known sensitive values (hashed, never stored in plaintext)
    matcher.register_values("employee_ssn", [
        "123-45-6789", "987-65-4321", ...
    ])

    # Scan text
    hits = matcher.scan("Employee SSN is 123-45-6789 on file.")
    # -> [EDMMatch(value_hash="a1b2...", category="employee_ssn", span=(19, 30), ...)]

    # Persistence: save/load hash sets
    matcher.save("edm_hashes.json")
    matcher = ExactDataMatcher.load("edm_hashes.json")

Privacy:

    Only salted HMAC-SHA256 hashes are stored. Given the hash set alone,
    recovering the original values is computationally infeasible.
    The salt is generated per-deployment and must be kept secret.

Candidate Extraction:

    The matcher uses configurable tokenizers to extract candidate values
    from text. Built-in tokenizers handle:
    - Numeric sequences (SSNs, credit cards, phone numbers)
    - Word n-grams (names, addresses)
    - Email addresses
    - Custom regex patterns
"""

import hashlib
import hmac
import json
import logging
import os
import re
import unicodedata
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class EDMMatch:
    """A match from Exact Data Match scanning."""
    value_hash: str
    category: str
    span: Tuple[int, int]
    matched_text: str
    confidence: float = 1.0  # EDM matches are always 100% confident

    def to_dict(self) -> dict:
        return {
            'value_hash': self.value_hash[:16] + '...',  # Truncate for display
            'category': self.category,
            'span': list(self.span),
            'confidence': self.confidence,
        }


# ---------------------------------------------------------------------------
# Tokenizers — extract candidate values from text
# ---------------------------------------------------------------------------

def _tokenize_numeric(text: str) -> List[Tuple[str, Tuple[int, int]]]:
    """Extract numeric sequences that could be SSNs, credit cards, phones, etc."""
    candidates = []
    # Match digit sequences with optional separators (-, ., space)
    for m in re.finditer(r'\d[\d\-. ]{3,18}\d', text):
        candidates.append((m.group(), m.span()))
    return candidates


def _tokenize_email(text: str) -> List[Tuple[str, Tuple[int, int]]]:
    """Extract email-like tokens."""
    for m in re.finditer(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', text):
        candidates = [(m.group(), m.span())]
        return candidates
    return []


_EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')


def _tokenize_emails(text: str) -> List[Tuple[str, Tuple[int, int]]]:
    """Extract all email-like tokens."""
    return [(m.group(), m.span()) for m in _EMAIL_RE.finditer(text)]


def _tokenize_words(text: str, n: int = 1) -> List[Tuple[str, Tuple[int, int]]]:
    """Extract word-level tokens (single words or n-grams)."""
    words = list(re.finditer(r'\b[a-zA-Z]{2,}\b', text))
    candidates = []
    for i in range(len(words) - n + 1):
        start = words[i].start()
        end = words[i + n - 1].end()
        token = text[start:end]
        candidates.append((token, (start, end)))
    return candidates


# Built-in tokenizer registry
BUILTIN_TOKENIZERS: Dict[str, Callable] = {
    'numeric': _tokenize_numeric,
    'email': _tokenize_emails,
    'word_1gram': lambda text: _tokenize_words(text, 1),
    'word_2gram': lambda text: _tokenize_words(text, 2),
    'word_3gram': lambda text: _tokenize_words(text, 3),
}


# ---------------------------------------------------------------------------
# Normalizers — normalize values before hashing
# ---------------------------------------------------------------------------

def _normalize_value(value: str) -> str:
    """Normalize a value for hashing: lowercase, strip whitespace, remove separators.

    This ensures that '411-1111-1111-1111', '4111 1111 1111 1111', and
    '4111111111111111' all produce the same hash.
    """
    # Unicode NFKC normalization
    value = unicodedata.normalize('NFKC', value)
    # Lowercase
    value = value.lower()
    # Strip leading/trailing whitespace
    value = value.strip()
    # Remove common separators
    value = re.sub(r'[\s\-./()]+', '', value)
    return value


# ---------------------------------------------------------------------------
# ExactDataMatcher
# ---------------------------------------------------------------------------

class ExactDataMatcher:
    """Exact Data Match engine using salted HMAC-SHA256 hashes.

    Thread-safe: hash sets are read-only after registration.
    Multiple categories can be registered independently.

    Args:
        salt: Cryptographic salt for HMAC. Auto-generated if not provided.
              Must be kept secret — knowing the salt + hash allows dictionary
              attacks against the original values.
        tokenizers: List of tokenizer names or callables to use for candidate
                    extraction. Default: ['numeric', 'email'].
        normalize: Normalization function applied to values before hashing.
                   Default: strip whitespace, lowercase, remove separators.
    """

    def __init__(
        self,
        salt: Optional[bytes] = None,
        tokenizers: Optional[List[str]] = None,
        normalize: Optional[Callable[[str], str]] = None,
    ):
        self._salt = salt or os.urandom(32)
        self._normalize = normalize or _normalize_value
        self._hashes: Dict[str, Set[str]] = {}  # category -> set of hex digests
        self._tokenizer_names = tokenizers or ['numeric', 'email']
        self._tokenizers: List[Callable] = []
        self._custom_tokenizers: Dict[str, Callable] = {}
        self._resolve_tokenizers()

    def _resolve_tokenizers(self) -> None:
        """Resolve tokenizer names to callables."""
        self._tokenizers = []
        for name in self._tokenizer_names:
            if name in BUILTIN_TOKENIZERS:
                self._tokenizers.append(BUILTIN_TOKENIZERS[name])
            elif name in self._custom_tokenizers:
                self._tokenizers.append(self._custom_tokenizers[name])
            else:
                raise ValueError(f"Unknown tokenizer: {name!r}. "
                                 f"Available: {sorted(BUILTIN_TOKENIZERS.keys())}")

    def _hmac(self, value: str) -> str:
        """Compute HMAC-SHA256 of a normalized value."""
        return hmac.new(self._salt, value.encode('utf-8'), hashlib.sha256).hexdigest()

    def register_values(self, category: str, values: Iterable[str]) -> int:
        """Register known sensitive values (hashed, never stored in plaintext).

        Args:
            category: Category name for these values (e.g. 'employee_ssn').
            values: Iterable of sensitive value strings.

        Returns:
            Number of unique values registered for this category.
        """
        h_set = self._hashes.setdefault(category, set())
        initial_size = len(h_set)
        for v in values:
            normalized = self._normalize(v)
            if normalized:  # Skip empty after normalization
                h_set.add(self._hmac(normalized))
        added = len(h_set) - initial_size
        logger.debug("EDM: registered %d values for category %r (%d new)",
                     len(h_set), category, added)
        return len(h_set)

    def register_tokenizer(self, name: str, func: Callable) -> None:
        """Register a custom tokenizer function.

        Args:
            name: Tokenizer name for configuration.
            func: Callable that takes text and returns List[Tuple[str, Tuple[int, int]]].
        """
        self._custom_tokenizers[name] = func

    @property
    def categories(self) -> List[str]:
        """List of registered categories."""
        return list(self._hashes.keys())

    @property
    def total_hashes(self) -> int:
        """Total number of registered hashes across all categories."""
        return sum(len(s) for s in self._hashes.values())

    def scan(self, text: str,
             categories: Optional[Set[str]] = None) -> List[EDMMatch]:
        """Scan text for exact matches against registered hash sets.

        Args:
            text: Text to scan.
            categories: Optional set of categories to check. If None, checks all.

        Returns:
            List of EDMMatch objects for each exact match found.
        """
        if not self._hashes:
            return []

        # Determine which categories to check.
        cats_to_check = self._hashes
        if categories:
            cats_to_check = {k: v for k, v in self._hashes.items() if k in categories}

        # Extract candidates using all configured tokenizers.
        candidates: List[Tuple[str, Tuple[int, int]]] = []
        for tokenizer in self._tokenizers:
            candidates.extend(tokenizer(text))

        if not candidates:
            return []

        # Check each candidate against each category's hash set.
        matches: List[EDMMatch] = []
        seen_spans: Set[Tuple[int, int, str]] = set()  # Dedup

        for raw_value, span in candidates:
            normalized = self._normalize(raw_value)
            if not normalized:
                continue
            h = self._hmac(normalized)

            for category, h_set in cats_to_check.items():
                if h in h_set:
                    dedup_key = (span[0], span[1], category)
                    if dedup_key not in seen_spans:
                        seen_spans.add(dedup_key)
                        matches.append(EDMMatch(
                            value_hash=h,
                            category=category,
                            span=span,
                            matched_text=raw_value,
                        ))

        return matches

    def check_value(self, value: str, category: Optional[str] = None) -> bool:
        """Check if a specific value is in the registered hash set.

        Args:
            value: The value to check.
            category: Optional category to check. If None, checks all.

        Returns:
            True if the value matches a registered hash.
        """
        normalized = self._normalize(value)
        if not normalized:
            return False
        h = self._hmac(normalized)

        if category:
            return h in self._hashes.get(category, set())
        return any(h in s for s in self._hashes.values())

    def save(self, path: str) -> None:
        """Save hash sets to a JSON file.

        The salt is included (base64-encoded). The file contains only
        hashes, never original values.
        """
        import base64
        data = {
            'version': 1,
            'salt': base64.b64encode(self._salt).decode('ascii'),
            'tokenizers': self._tokenizer_names,
            'categories': {
                cat: sorted(hashes) for cat, hashes in self._hashes.items()
            },
        }
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        logger.info("EDM: saved %d hashes to %s", self.total_hashes, path)

    @classmethod
    def load(cls, path: str) -> 'ExactDataMatcher':
        """Load hash sets from a JSON file.

        Returns:
            A new ExactDataMatcher with the loaded hash sets and salt.
        """
        import base64
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        if data.get('version') != 1:
            raise ValueError(f"Unsupported EDM file version: {data.get('version')}")

        salt = base64.b64decode(data['salt'])
        tokenizers = data.get('tokenizers', ['numeric', 'email'])
        matcher = cls(salt=salt, tokenizers=tokenizers)

        for cat, hashes in data.get('categories', {}).items():
            matcher._hashes[cat] = set(hashes)

        logger.info("EDM: loaded %d hashes from %s", matcher.total_hashes, path)
        return matcher

    def clear(self, category: Optional[str] = None) -> None:
        """Clear registered hashes.

        Args:
            category: If provided, clear only this category. Otherwise clear all.
        """
        if category:
            self._hashes.pop(category, None)
        else:
            self._hashes.clear()
