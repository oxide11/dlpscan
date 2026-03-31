"""Rabin-Karp rolling hash for partial document matching.

Detects when fragments of sensitive documents appear in outgoing text.
Unlike LSH (whole-document similarity), Rabin-Karp catches someone
copying specific paragraphs from a classified document.

Usage::

    from dlpscan.rabin_karp import PartialDocumentMatcher

    matcher = PartialDocumentMatcher(window_size=50)

    # Register known sensitive documents
    matcher.register("contract_v1", contract_text)
    matcher.register("source_auth", auth_module_code)

    # Scan outgoing text for matching fragments
    hits = matcher.scan("Here is an email with copied contract text...")
    for hit in hits:
        print(f"Fragment from {hit.doc_id} at position {hit.doc_position}")

DLP Use Case:

    An employee copies 3 crucial paragraphs from a 100-page confidential
    contract into an email. Pattern matching won't catch it (no SSNs or
    credit cards). LSH might miss it (only 3% of the document). Rolling
    hash catches the exact fragment match.
"""

import logging
import re
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple

logger = logging.getLogger(__name__)

# Large prime for modular arithmetic (Mersenne prime)
_MOD = (1 << 61) - 1
_BASE = 256


@dataclass
class FragmentMatch:
    """A partial document match from Rabin-Karp scanning."""
    doc_id: str
    doc_position: int      # Position in the original registered document
    scan_position: int     # Position in the scanned text
    fragment_length: int   # Length of the matching fragment (in chars)
    confidence: float = 1.0

    def to_dict(self) -> dict:
        return {
            'doc_id': self.doc_id,
            'doc_position': self.doc_position,
            'scan_position': self.scan_position,
            'fragment_length': self.fragment_length,
            'confidence': self.confidence,
        }


def _normalize_text(text: str) -> str:
    """Normalize text for matching: lowercase, collapse whitespace."""
    text = text.lower()
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


class PartialDocumentMatcher:
    """Rolling hash engine for partial document matching.

    Pre-computes Rabin-Karp fingerprints for sliding windows across
    registered documents. Scanning computes the same rolling hash over
    incoming text and checks for matches in O(n) time.

    Args:
        window_size: Size of the rolling window in characters. Smaller
                     windows catch shorter fragments but produce more
                     false positives. Default: 50 characters.
        normalize: Whether to normalize text before hashing (lowercase,
                   collapse whitespace). Default: True.

    Memory: ~40 bytes per window position per registered document.
            A 10,000-char document with window_size=50 produces ~10,000
            hashes ≈ 400 KB.

    Thread Safety: Thread-safe for concurrent scanning after registration.
    """

    def __init__(self, window_size: int = 50, normalize: bool = True):
        if window_size < 10:
            raise ValueError("window_size must be ≥ 10")
        self._window = window_size
        self._normalize = normalize

        # hash -> list of (doc_id, position, text_slice) for verification
        self._hash_index: Dict[int, List[Tuple[str, int, str]]] = {}
        self._doc_ids: Set[str] = set()

        # Precompute base^window mod p for rolling hash removal
        self._base_pow = pow(_BASE, window_size, _MOD)

    def register(self, doc_id: str, text: str) -> int:
        """Register a document for partial matching.

        Args:
            doc_id: Unique identifier.
            text: Full document text.

        Returns:
            Number of hash fingerprints generated.
        """
        if self._normalize:
            text = _normalize_text(text)

        if len(text) < self._window:
            logger.warning("Document %r shorter than window_size (%d < %d); skipping",
                           doc_id, len(text), self._window)
            return 0

        self._doc_ids.add(doc_id)
        count = 0
        h = 0

        for i, ch in enumerate(text):
            h = (h * _BASE + ord(ch)) % _MOD

            if i >= self._window:
                # Remove leftmost character
                h = (h - ord(text[i - self._window]) * self._base_pow) % _MOD

            if i >= self._window - 1:
                start = i - self._window + 1
                # Store hash with verification slice
                entry = (doc_id, start, text[start:i + 1])
                if h not in self._hash_index:
                    self._hash_index[h] = []
                self._hash_index[h].append(entry)
                count += 1

        logger.debug("Registered %r: %d fingerprints (window=%d)",
                     doc_id, count, self._window)
        return count

    def unregister(self, doc_id: str) -> bool:
        """Remove a document from the matcher.

        Returns True if the document was found and removed.
        """
        if doc_id not in self._doc_ids:
            return False
        self._doc_ids.discard(doc_id)
        # Remove all entries for this doc_id
        empty_hashes = []
        for h, entries in self._hash_index.items():
            self._hash_index[h] = [e for e in entries if e[0] != doc_id]
            if not self._hash_index[h]:
                empty_hashes.append(h)
        for h in empty_hashes:
            del self._hash_index[h]
        return True

    def scan(self, text: str, min_consecutive: int = 1) -> List[FragmentMatch]:
        """Scan text for fragments matching registered documents.

        Args:
            text: Text to scan.
            min_consecutive: Minimum number of consecutive matching windows
                            to report as a match. Higher = fewer false positives
                            but misses shorter fragments. Default: 1.

        Returns:
            List of FragmentMatch objects, deduplicated by (doc_id, doc_position).
        """
        if not self._hash_index:
            return []

        if self._normalize:
            text = _normalize_text(text)

        if len(text) < self._window:
            return []

        matches: List[FragmentMatch] = []
        seen: Set[Tuple[str, int]] = set()  # dedup by (doc_id, doc_position)

        h = 0
        # Track consecutive matches per doc for min_consecutive filtering
        consecutive: Dict[str, int] = {}
        last_match_pos: Dict[str, int] = {}

        for i, ch in enumerate(text):
            h = (h * _BASE + ord(ch)) % _MOD

            if i >= self._window:
                h = (h - ord(text[i - self._window]) * self._base_pow) % _MOD

            if i >= self._window - 1:
                scan_start = i - self._window + 1
                scan_slice = text[scan_start:i + 1]

                if h in self._hash_index:
                    for doc_id, doc_pos, doc_slice in self._hash_index[h]:
                        # Verify (avoid hash collisions)
                        if scan_slice == doc_slice:
                            dedup_key = (doc_id, doc_pos)
                            if dedup_key not in seen:
                                seen.add(dedup_key)

                                # Track consecutive matches
                                if doc_id in last_match_pos and \
                                   scan_start - last_match_pos[doc_id] == 1:
                                    consecutive[doc_id] = consecutive.get(doc_id, 1) + 1
                                else:
                                    consecutive[doc_id] = 1
                                last_match_pos[doc_id] = scan_start

                                if consecutive.get(doc_id, 0) >= min_consecutive:
                                    matches.append(FragmentMatch(
                                        doc_id=doc_id,
                                        doc_position=doc_pos,
                                        scan_position=scan_start,
                                        fragment_length=self._window,
                                    ))

        return matches

    def contains_fragment(self, text: str) -> bool:
        """Quick boolean check: does this text contain any registered fragments?"""
        return len(self.scan(text)) > 0

    @property
    def document_count(self) -> int:
        return len(self._doc_ids)

    @property
    def fingerprint_count(self) -> int:
        return sum(len(entries) for entries in self._hash_index.values())

    @property
    def window_size(self) -> int:
        return self._window

    def clear(self) -> None:
        """Remove all registered documents."""
        self._hash_index.clear()
        self._doc_ids.clear()
