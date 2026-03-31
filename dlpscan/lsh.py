"""Locality-Sensitive Hashing (LSH) for fuzzy document similarity detection.

Detects documents that are *similar* to known sensitive documents, even after
editing, reformatting, cropping, or partial paraphrasing. Uses MinHash
signatures with LSH banding for sub-linear query time.

Usage::

    from dlpscan.lsh import DocumentVault

    vault = DocumentVault(threshold=0.8)

    # Register known sensitive documents
    vault.register("contract_v1", contract_text, sensitivity="confidential")
    vault.register("employee_handbook", handbook_text, sensitivity="internal")

    # Check if a document is similar to any registered document
    matches = vault.query(suspicious_text)
    for m in matches:
        print(f"Similar to {m.doc_id} ({m.similarity:.0%})")

    # Persistence
    vault.save("vault.json")
    vault = DocumentVault.load("vault.json")

Algorithm:

    1. **Shingling**: Break documents into overlapping word n-grams (shingles)
    2. **MinHash**: Generate compact signatures (128 hash values) that
       approximate Jaccard similarity of shingle sets
    3. **LSH Banding**: Split signatures into bands; documents sharing any
       band hash are candidate near-duplicates
    4. **Verification**: Compute exact Jaccard similarity for candidates

The threshold is tunable — 0.8 means 80% shingle overlap = "similar".
"""

import hashlib
import json
import logging
import struct
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_LARGE_PRIME = (1 << 61) - 1  # Mersenne prime for hash functions
_MAX_HASH = (1 << 32) - 1

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class SimilarityMatch:
    """A document similarity match from LSH query."""
    doc_id: str
    similarity: float
    sensitivity: str
    doc_metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            'doc_id': self.doc_id,
            'similarity': round(self.similarity, 4),
            'sensitivity': self.sensitivity,
            'metadata': self.doc_metadata,
        }


@dataclass
class _DocumentEntry:
    """Internal storage for a registered document."""
    doc_id: str
    signature: List[int]
    sensitivity: str
    metadata: dict = field(default_factory=dict)
    shingle_count: int = 0


# ---------------------------------------------------------------------------
# Shingling
# ---------------------------------------------------------------------------

def _shingle(text: str, k: int = 3) -> Set[str]:
    """Break text into overlapping word k-grams (shingles).

    Args:
        text: Input text.
        k: Number of words per shingle.

    Returns:
        Set of shingle strings.
    """
    # Normalize: lowercase, collapse whitespace
    words = text.lower().split()
    if len(words) < k:
        # For very short texts, use character shingles
        return {text[i:i + k * 4] for i in range(max(1, len(text) - k * 4 + 1))}
    return {' '.join(words[i:i + k]) for i in range(len(words) - k + 1)}


# ---------------------------------------------------------------------------
# MinHash
# ---------------------------------------------------------------------------

def _make_hash_funcs(num_hashes: int, seed: int = 42) -> List[Tuple[int, int]]:
    """Generate random hash function coefficients (a, b) for MinHash.

    Each hash function is h(x) = (a * x + b) mod LARGE_PRIME mod MAX_HASH.
    """
    import random
    rng = random.Random(seed)
    funcs = []
    for _ in range(num_hashes):
        a = rng.randint(1, _LARGE_PRIME - 1)
        b = rng.randint(0, _LARGE_PRIME - 1)
        funcs.append((a, b))
    return funcs


def _shingle_hash(shingle: str) -> int:
    """Hash a shingle string to a 32-bit integer."""
    return struct.unpack('<I', hashlib.md5(shingle.encode('utf-8')).digest()[:4])[0]


def _minhash(shingles: Set[str], hash_funcs: List[Tuple[int, int]]) -> List[int]:
    """Compute MinHash signature for a set of shingles.

    Args:
        shingles: Set of shingle strings.
        hash_funcs: List of (a, b) coefficient pairs.

    Returns:
        List of minimum hash values (one per hash function).
    """
    if not shingles:
        return [_MAX_HASH] * len(hash_funcs)

    # Pre-hash all shingles to integers
    hashed = [_shingle_hash(s) for s in shingles]

    signature = []
    for a, b in hash_funcs:
        min_val = _MAX_HASH
        for h in hashed:
            val = ((a * h + b) % _LARGE_PRIME) % (_MAX_HASH + 1)
            if val < min_val:
                min_val = val
        signature.append(min_val)

    return signature


def _jaccard_from_signatures(sig1: List[int], sig2: List[int]) -> float:
    """Estimate Jaccard similarity from two MinHash signatures."""
    if not sig1 or not sig2 or len(sig1) != len(sig2):
        return 0.0
    matches = sum(1 for a, b in zip(sig1, sig2) if a == b)
    return matches / len(sig1)


# ---------------------------------------------------------------------------
# DocumentVault
# ---------------------------------------------------------------------------

class DocumentVault:
    """LSH-based fuzzy document similarity detection.

    Maintains a vault of known sensitive documents and provides fast
    similarity queries against incoming text.

    Args:
        num_hashes: Number of hash functions for MinHash signatures.
                    More hashes = more accurate but slower. Default: 128.
        bands: Number of LSH bands. Must divide num_hashes evenly.
               More bands = lower threshold for candidate generation.
               Default: 16 (8 rows per band).
        threshold: Minimum Jaccard similarity to report as a match.
                   Default: 0.8 (80% similar).
        shingle_size: Number of words per shingle. Default: 3.

    Thread Safety:
        Registration and query are thread-safe.
    """

    def __init__(
        self,
        num_hashes: int = 128,
        bands: int = 16,
        threshold: float = 0.8,
        shingle_size: int = 3,
    ):
        if num_hashes % bands != 0:
            raise ValueError(f"num_hashes ({num_hashes}) must be divisible by bands ({bands})")
        if not 0.0 < threshold <= 1.0:
            raise ValueError(f"threshold must be in (0, 1], got {threshold}")

        self._num_hashes = num_hashes
        self._bands = bands
        self._rows = num_hashes // bands
        self._threshold = threshold
        self._shingle_size = shingle_size

        # Generate hash functions (deterministic for reproducibility)
        self._hash_funcs = _make_hash_funcs(num_hashes)

        # Document storage
        self._documents: Dict[str, _DocumentEntry] = {}

        # LSH band index: band_idx -> {band_hash -> set of doc_ids}
        self._band_index: List[Dict[int, Set[str]]] = [
            defaultdict(set) for _ in range(bands)
        ]

        self._lock = threading.Lock()

    @property
    def document_count(self) -> int:
        return len(self._documents)

    @property
    def threshold(self) -> float:
        return self._threshold

    def register(self, doc_id: str, text: str, sensitivity: str = "sensitive",
                 metadata: Optional[dict] = None) -> None:
        """Register a known sensitive document.

        Args:
            doc_id: Unique identifier for the document.
            text: Document text content.
            sensitivity: Sensitivity label (e.g. "confidential", "internal").
            metadata: Optional metadata dict.
        """
        shingles = _shingle(text, self._shingle_size)
        signature = _minhash(shingles, self._hash_funcs)

        entry = _DocumentEntry(
            doc_id=doc_id,
            signature=signature,
            sensitivity=sensitivity,
            metadata=metadata or {},
            shingle_count=len(shingles),
        )

        with self._lock:
            # Remove old entry if re-registering
            if doc_id in self._documents:
                self._remove_from_index(doc_id)

            self._documents[doc_id] = entry
            self._add_to_index(doc_id, signature)

        logger.debug("LSH: registered document %r (%d shingles)", doc_id, len(shingles))

    def unregister(self, doc_id: str) -> bool:
        """Remove a document from the vault.

        Returns True if the document existed and was removed.
        """
        with self._lock:
            if doc_id not in self._documents:
                return False
            self._remove_from_index(doc_id)
            del self._documents[doc_id]
        return True

    def query(self, text: str, threshold: Optional[float] = None) -> List[SimilarityMatch]:
        """Query the vault for documents similar to the given text.

        Args:
            text: Text to check for similarity.
            threshold: Override the default similarity threshold.

        Returns:
            List of SimilarityMatch objects, sorted by similarity (descending).
        """
        min_sim = threshold if threshold is not None else self._threshold

        shingles = _shingle(text, self._shingle_size)
        signature = _minhash(shingles, self._hash_funcs)

        # Phase 1: LSH candidate generation (sub-linear)
        candidates: Set[str] = set()
        for band_idx in range(self._bands):
            start = band_idx * self._rows
            end = start + self._rows
            band_hash = self._band_hash(signature[start:end])
            with self._lock:
                bucket = self._band_index[band_idx].get(band_hash, set())
                candidates |= bucket

        if not candidates:
            return []

        # Phase 2: Verify candidates with full signature comparison
        matches: List[SimilarityMatch] = []
        with self._lock:
            for doc_id in candidates:
                entry = self._documents.get(doc_id)
                if entry is None:
                    continue
                sim = _jaccard_from_signatures(signature, entry.signature)
                if sim >= min_sim:
                    matches.append(SimilarityMatch(
                        doc_id=entry.doc_id,
                        similarity=sim,
                        sensitivity=entry.sensitivity,
                        doc_metadata=entry.metadata,
                    ))

        # Sort by similarity descending
        matches.sort(key=lambda m: m.similarity, reverse=True)
        return matches

    def contains_similar(self, text: str, threshold: Optional[float] = None) -> bool:
        """Quick boolean check: is any registered document similar to this text?"""
        return len(self.query(text, threshold)) > 0

    # -- Index management --

    def _band_hash(self, band_values: List[int]) -> int:
        """Hash a band (sub-signature) to a bucket key."""
        return hash(tuple(band_values))

    def _add_to_index(self, doc_id: str, signature: List[int]) -> None:
        """Add a document's signature to the LSH band index."""
        for band_idx in range(self._bands):
            start = band_idx * self._rows
            end = start + self._rows
            band_hash = self._band_hash(signature[start:end])
            self._band_index[band_idx][band_hash].add(doc_id)

    def _remove_from_index(self, doc_id: str) -> None:
        """Remove a document from the LSH band index."""
        entry = self._documents.get(doc_id)
        if entry is None:
            return
        for band_idx in range(self._bands):
            start = band_idx * self._rows
            end = start + self._rows
            band_hash = self._band_hash(entry.signature[start:end])
            bucket = self._band_index[band_idx].get(band_hash)
            if bucket:
                bucket.discard(doc_id)

    # -- Persistence --

    def save(self, path: str) -> None:
        """Save the vault to a JSON file."""
        data = {
            'version': 1,
            'num_hashes': self._num_hashes,
            'bands': self._bands,
            'threshold': self._threshold,
            'shingle_size': self._shingle_size,
            'documents': {
                doc_id: {
                    'signature': entry.signature,
                    'sensitivity': entry.sensitivity,
                    'metadata': entry.metadata,
                    'shingle_count': entry.shingle_count,
                }
                for doc_id, entry in self._documents.items()
            },
        }
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f)
        logger.info("LSH: saved vault with %d documents to %s",
                     self.document_count, path)

    @classmethod
    def load(cls, path: str) -> 'DocumentVault':
        """Load a vault from a JSON file."""
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        if data.get('version') != 1:
            raise ValueError(f"Unsupported vault version: {data.get('version')}")

        vault = cls(
            num_hashes=data['num_hashes'],
            bands=data['bands'],
            threshold=data['threshold'],
            shingle_size=data.get('shingle_size', 3),
        )

        for doc_id, doc_data in data.get('documents', {}).items():
            entry = _DocumentEntry(
                doc_id=doc_id,
                signature=doc_data['signature'],
                sensitivity=doc_data['sensitivity'],
                metadata=doc_data.get('metadata', {}),
                shingle_count=doc_data.get('shingle_count', 0),
            )
            vault._documents[doc_id] = entry
            vault._add_to_index(doc_id, entry.signature)

        logger.info("LSH: loaded vault with %d documents from %s",
                     vault.document_count, path)
        return vault

    def clear(self) -> None:
        """Remove all documents from the vault."""
        with self._lock:
            self._documents.clear()
            self._band_index = [defaultdict(set) for _ in range(self._bands)]
