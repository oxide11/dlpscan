"""Pluggable storage backends for the TokenVault with optional encryption.

Provides several backend implementations that can be used with
:class:`~dlpscan.guard.transforms.TokenVault` for persistent or
encrypted token storage.

Backends
--------
- **InMemoryBackend** -- default dict-based storage (thread-safe).
- **FileBackend** -- append-only JSON-lines file with optional AES-256-GCM
  encryption (requires the ``cryptography`` package).
- **EncryptedVault** -- transparent encryption wrapper for any backend.
- **RedisBackend** -- Redis-backed storage with optional TTL
  (requires the ``redis`` package).

All backends satisfy the :class:`VaultBackend` protocol.
"""

import hashlib
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Dict, Optional, Protocol, runtime_checkable

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers -- optional dependency imports
# ---------------------------------------------------------------------------

_CRYPTOGRAPHY_INSTALL_MSG = (
    "The 'cryptography' package is required for encryption support. "
    "Install it with:  pip install cryptography"
)

_REDIS_INSTALL_MSG = (
    "The 'redis' package is required for RedisBackend. "
    "Install it with:  pip install redis"
)


def _require_cryptography() -> Any:
    """Import and return the ``cryptography`` primitives, or raise."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F811
        return AESGCM
    except ImportError:
        raise ImportError(_CRYPTOGRAPHY_INSTALL_MSG) from None


def _derive_key(key: str | bytes, salt: bytes | None = None) -> bytes:
    """Derive a 256-bit AES key from an arbitrary string using PBKDF2."""
    if isinstance(key, str):
        key = key.encode("utf-8")
    if salt is None:
        salt = os.urandom(16)
    return hashlib.pbkdf2_hmac("sha256", key, salt, iterations=600_000)


# ---------------------------------------------------------------------------
# VaultBackend protocol
# ---------------------------------------------------------------------------

@runtime_checkable
class VaultBackend(Protocol):
    """Abstract interface for token vault storage backends.

    Any object that implements these methods can be used as the backing
    store for a :class:`~dlpscan.guard.transforms.TokenVault`.
    """

    def store(self, token: str, original: str, category: str) -> None:
        """Persist a token -> original mapping.

        Args:
            token: The generated token string.
            original: The original sensitive value.
            category: The pattern category that matched.
        """
        ...  # pragma: no cover

    def lookup_by_token(self, token: str) -> Optional[str]:
        """Return the original value for *token*, or ``None``."""
        ...  # pragma: no cover

    def lookup_by_original(self, key: str) -> Optional[str]:
        """Return the token for *key* (original value), or ``None``."""
        ...  # pragma: no cover

    def clear(self) -> None:
        """Remove all stored mappings."""
        ...  # pragma: no cover

    def export_all(self) -> Dict[str, str]:
        """Export all token -> original mappings as a plain dict."""
        ...  # pragma: no cover

    def import_all(self, mapping: Dict[str, str]) -> None:
        """Bulk-import token -> original mappings."""
        ...  # pragma: no cover

    def size(self) -> int:
        """Return the number of stored mappings."""
        ...  # pragma: no cover


# ---------------------------------------------------------------------------
# InMemoryBackend
# ---------------------------------------------------------------------------

class InMemoryBackend:
    """Default in-memory backend backed by plain dicts.

    Thread-safe via :class:`threading.Lock`.
    """

    def __init__(self) -> None:
        self._token_to_original: Dict[str, str] = {}
        self._original_to_token: Dict[str, str] = {}
        self._lock = threading.Lock()

    # -- VaultBackend interface ---------------------------------------------

    def store(self, token: str, original: str, category: str) -> None:
        with self._lock:
            self._token_to_original[token] = original
            self._original_to_token[original] = token

    def lookup_by_token(self, token: str) -> Optional[str]:
        with self._lock:
            return self._token_to_original.get(token)

    def lookup_by_original(self, key: str) -> Optional[str]:
        with self._lock:
            return self._original_to_token.get(key)

    def clear(self) -> None:
        with self._lock:
            self._token_to_original.clear()
            self._original_to_token.clear()

    def export_all(self) -> Dict[str, str]:
        with self._lock:
            return dict(self._token_to_original)

    def import_all(self, mapping: Dict[str, str]) -> None:
        with self._lock:
            for token, original in mapping.items():
                self._token_to_original[token] = original
                self._original_to_token[original] = token

    def size(self) -> int:
        with self._lock:
            return len(self._token_to_original)

    def __repr__(self) -> str:
        return f"InMemoryBackend(entries={self.size()})"


# ---------------------------------------------------------------------------
# FileBackend
# ---------------------------------------------------------------------------

class FileBackend:
    """Append-only JSON-lines file backend with optional AES-256-GCM encryption.

    Each line in the file is a JSON object::

        {"token": "...", "original": "...", "category": "..."}

    When *encryption_key* is provided, the ``original`` value is encrypted
    with AES-256-GCM before being written.  The ``cryptography`` package
    must be installed for encryption.

    Args:
        path: Filesystem path for the JSON-lines file.
        encryption_key: Optional passphrase for encrypting original values.
            Requires the ``cryptography`` package.

    Raises:
        ImportError: If *encryption_key* is set but ``cryptography`` is not
            installed.
    """

    def __init__(
        self,
        path: str | Path,
        encryption_key: Optional[str] = None,
    ) -> None:
        self._path = Path(path).resolve()
        # Reject symlinks to prevent symlink attacks
        if self._path.exists() and self._path.is_symlink():
            raise ValueError(f"Refusing to use symlink path: {self._path}")
        self._lock = threading.Lock()

        # In-memory indices rebuilt from the file on init.
        self._token_to_original: Dict[str, str] = {}
        self._original_to_token: Dict[str, str] = {}

        # Encryption setup
        self._aesgcm: Any = None
        self._enc_key_raw: Optional[bytes] = None
        if encryption_key is not None:
            AESGCM = _require_cryptography()
            self._enc_key_raw = _derive_key(encryption_key)
            self._aesgcm = AESGCM(self._enc_key_raw)

        # Load existing entries.
        self._load()

    # -- encryption helpers -------------------------------------------------

    def _encrypt(self, plaintext: str) -> str:
        """Encrypt *plaintext* and return a hex-encoded ``nonce:ciphertext``."""
        nonce = os.urandom(12)
        ct = self._aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return nonce.hex() + ":" + ct.hex()

    def _decrypt(self, blob: str) -> str:
        """Decrypt a hex-encoded ``nonce:ciphertext`` string."""
        nonce_hex, ct_hex = blob.split(":", 1)
        nonce = bytes.fromhex(nonce_hex)
        ct = bytes.fromhex(ct_hex)
        return self._aesgcm.decrypt(nonce, ct, None).decode("utf-8")

    # -- persistence --------------------------------------------------------

    def _load(self) -> None:
        """Read all entries from the file into memory."""
        if not self._path.exists():
            return
        with open(self._path, "r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    logger.warning(
                        "FileBackend: skipping malformed line %d in %s",
                        lineno,
                        self._path,
                    )
                    continue
                token = entry["token"]
                original_raw = entry["original"]
                if self._aesgcm is not None:
                    try:
                        original = self._decrypt(original_raw)
                    except Exception:
                        logger.warning(
                            "FileBackend: failed to decrypt line %d in %s "
                            "(wrong key?)",
                            lineno,
                            self._path,
                        )
                        continue
                else:
                    original = original_raw
                self._token_to_original[token] = original
                self._original_to_token[original] = token

    def _append(self, token: str, original: str, category: str) -> None:
        """Append a single entry to the file."""
        original_stored = (
            self._encrypt(original) if self._aesgcm is not None else original
        )
        entry = {"token": token, "original": original_stored, "category": category}
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(self._path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def _rewrite(self) -> None:
        """Rewrite the entire file from the in-memory state.

        Used after :meth:`clear` or :meth:`import_all`.
        """
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(self._path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            for token, original in self._token_to_original.items():
                original_stored = (
                    self._encrypt(original)
                    if self._aesgcm is not None
                    else original
                )
                entry = {"token": token, "original": original_stored, "category": ""}
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

    # -- VaultBackend interface ---------------------------------------------

    def store(self, token: str, original: str, category: str) -> None:
        with self._lock:
            self._token_to_original[token] = original
            self._original_to_token[original] = token
            self._append(token, original, category)

    def lookup_by_token(self, token: str) -> Optional[str]:
        with self._lock:
            return self._token_to_original.get(token)

    def lookup_by_original(self, key: str) -> Optional[str]:
        with self._lock:
            return self._original_to_token.get(key)

    def clear(self) -> None:
        with self._lock:
            self._token_to_original.clear()
            self._original_to_token.clear()
            # Truncate the file.
            if self._path.exists():
                self._path.write_text("")

    def export_all(self) -> Dict[str, str]:
        with self._lock:
            return dict(self._token_to_original)

    def import_all(self, mapping: Dict[str, str]) -> None:
        with self._lock:
            for token, original in mapping.items():
                self._token_to_original[token] = original
                self._original_to_token[original] = token
            self._rewrite()

    def size(self) -> int:
        with self._lock:
            return len(self._token_to_original)

    def __repr__(self) -> str:
        return (
            f"FileBackend(path={str(self._path)!r}, "
            f"encrypted={self._aesgcm is not None}, "
            f"entries={self.size()})"
        )


# ---------------------------------------------------------------------------
# EncryptedVault -- encryption wrapper for any backend
# ---------------------------------------------------------------------------

class EncryptedVault:
    """Transparent AES-256-GCM encryption wrapper for any backend.

    Encrypts *original* values before delegating to the wrapped backend
    and decrypts them on retrieval.  Tokens and categories are stored
    in plaintext so lookups by token remain fast.

    Key derivation uses PBKDF2-HMAC-SHA256 with 600 000 iterations.

    Args:
        backend: The underlying :class:`VaultBackend` to delegate to.
        key: Passphrase used to derive the AES-256 key.

    Raises:
        ImportError: If the ``cryptography`` package is not installed.
    """

    def __init__(self, backend: VaultBackend, key: str | bytes) -> None:
        AESGCM = _require_cryptography()
        self._backend = backend
        self._derived_key = _derive_key(key)
        self._aesgcm = AESGCM(self._derived_key)
        self._lock = threading.Lock()

    # -- crypto helpers -----------------------------------------------------

    def _encrypt(self, plaintext: str) -> str:
        nonce = os.urandom(12)
        ct = self._aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return nonce.hex() + ":" + ct.hex()

    def _decrypt(self, blob: str) -> str:
        nonce_hex, ct_hex = blob.split(":", 1)
        return self._aesgcm.decrypt(
            bytes.fromhex(nonce_hex),
            bytes.fromhex(ct_hex),
            None,
        ).decode("utf-8")

    # -- VaultBackend interface ---------------------------------------------

    def store(self, token: str, original: str, category: str) -> None:
        encrypted_original = self._encrypt(original)
        with self._lock:
            self._backend.store(token, encrypted_original, category)

    def lookup_by_token(self, token: str) -> Optional[str]:
        with self._lock:
            encrypted = self._backend.lookup_by_token(token)
        if encrypted is None:
            return None
        try:
            return self._decrypt(encrypted)
        except Exception:
            logger.warning("EncryptedVault: decryption failed for token %s", token)
            return None

    def lookup_by_original(self, key: str) -> Optional[str]:
        # Since the backend stores *encrypted* originals, we cannot do a
        # direct lookup.  We must scan all entries, decrypt, and compare.
        all_entries = self._backend.export_all()
        for token, encrypted_original in all_entries.items():
            try:
                if self._decrypt(encrypted_original) == key:
                    return token
            except Exception:
                continue
        return None

    def clear(self) -> None:
        with self._lock:
            self._backend.clear()

    def export_all(self) -> Dict[str, str]:
        """Export all mappings with *decrypted* original values."""
        encrypted_map = self._backend.export_all()
        result: Dict[str, str] = {}
        for token, encrypted_original in encrypted_map.items():
            try:
                result[token] = self._decrypt(encrypted_original)
            except Exception:
                logger.warning(
                    "EncryptedVault: skipping undecryptable entry for token %s",
                    token,
                )
        return result

    def import_all(self, mapping: Dict[str, str]) -> None:
        """Import mappings, encrypting original values before storage."""
        encrypted: Dict[str, str] = {
            token: self._encrypt(original)
            for token, original in mapping.items()
        }
        with self._lock:
            self._backend.import_all(encrypted)

    def size(self) -> int:
        return self._backend.size()

    def __repr__(self) -> str:
        return f"EncryptedVault(backend={self._backend!r}, entries={self.size()})"


# ---------------------------------------------------------------------------
# RedisBackend
# ---------------------------------------------------------------------------

class RedisBackend:
    """Redis-backed token vault storage.

    Stores token mappings in Redis hashes.  Two hashes are maintained:

    - ``<prefix>token_to_original`` -- maps tokens to original values.
    - ``<prefix>original_to_token`` -- maps originals to tokens.

    A sorted set ``<prefix>categories`` tracks category metadata.

    Redis is inherently thread-safe for individual commands, so no
    additional locking is required.

    Args:
        url: Redis connection URL (e.g. ``redis://localhost:6379/0``).
        prefix: Key prefix for all Redis keys (default ``dlpscan:vault:``).
        ttl: Optional time-to-live in seconds.  When set, every stored
            mapping will expire after this duration.

    Raises:
        ImportError: If the ``redis`` package is not installed.
    """

    def __init__(
        self,
        url: str = "redis://localhost:6379/0",
        prefix: str = "dlpscan:vault:",
        ttl: Optional[int] = None,
    ) -> None:
        try:
            import redis as redis_pkg  # noqa: F811
        except ImportError:
            raise ImportError(_REDIS_INSTALL_MSG) from None

        self._client = redis_pkg.Redis.from_url(url, decode_responses=True)
        self._prefix = prefix
        self._ttl = ttl

        # Redis key names
        self._tok2orig_key = f"{prefix}token_to_original"
        self._orig2tok_key = f"{prefix}original_to_token"

    def _apply_ttl(self) -> None:
        """Set TTL on the hash keys if configured."""
        if self._ttl is not None:
            self._client.expire(self._tok2orig_key, self._ttl)
            self._client.expire(self._orig2tok_key, self._ttl)

    # -- VaultBackend interface ---------------------------------------------

    def store(self, token: str, original: str, category: str) -> None:
        pipe = self._client.pipeline(transaction=True)
        pipe.hset(self._tok2orig_key, token, original)
        pipe.hset(self._orig2tok_key, original, token)
        pipe.execute()
        self._apply_ttl()

    def lookup_by_token(self, token: str) -> Optional[str]:
        return self._client.hget(self._tok2orig_key, token)

    def lookup_by_original(self, key: str) -> Optional[str]:
        return self._client.hget(self._orig2tok_key, key)

    def clear(self) -> None:
        self._client.delete(self._tok2orig_key, self._orig2tok_key)

    def export_all(self) -> Dict[str, str]:
        return self._client.hgetall(self._tok2orig_key)

    def import_all(self, mapping: Dict[str, str]) -> None:
        if not mapping:
            return
        pipe = self._client.pipeline(transaction=True)
        for token, original in mapping.items():
            pipe.hset(self._tok2orig_key, token, original)
            pipe.hset(self._orig2tok_key, original, token)
        pipe.execute()
        self._apply_ttl()

    def size(self) -> int:
        return self._client.hlen(self._tok2orig_key)

    def __repr__(self) -> str:
        return (
            f"RedisBackend(prefix={self._prefix!r}, "
            f"ttl={self._ttl}, entries={self.size()})"
        )
