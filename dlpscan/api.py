"""FastAPI-based REST API server for dlpscan.

Provides HTTP endpoints for scanning, tokenizing, detokenizing, and
obfuscating text using the dlpscan InputGuard infrastructure.

Usage::

    # Run directly
    python -m dlpscan.api

    # Or programmatically
    from dlpscan.api import create_app
    app = create_app()
"""

from __future__ import annotations

import hmac
import logging
import os
import threading
import time
import uuid
from typing import Dict, List, Optional

try:
    from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
    from fastapi.responses import JSONResponse
except ImportError:
    raise ImportError(
        "FastAPI is required for the dlpscan API server. "
        "Install it with: pip install fastapi"
    )

try:
    from pydantic import BaseModel, Field
except ImportError:
    raise ImportError(
        "Pydantic is required for the dlpscan API server. "
        "Install it with: pip install pydantic"
    )

from . import __version__
from .audit import audit_event, event_from_scan
from .guard.core import InputGuard
from .guard.enums import Action
from .guard.transforms import TokenVault, set_obfuscation_seed

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pydantic request/response models
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    text: str = Field(..., max_length=1_000_000)
    presets: Optional[List[str]] = None
    categories: Optional[List[str]] = None
    action: str = "flag"
    min_confidence: float = 0.0
    require_context: bool = False


class ScanResponse(BaseModel):
    is_clean: bool
    finding_count: int
    categories_found: List[str]
    redacted_text: Optional[str] = None
    findings: List[dict]


class TokenizeRequest(BaseModel):
    text: str = Field(..., max_length=1_000_000)
    presets: Optional[List[str]] = None
    categories: Optional[List[str]] = None
    min_confidence: float = 0.0


class TokenizeResponse(BaseModel):
    tokenized_text: str
    token_count: int
    vault_id: str


class DetokenizeRequest(BaseModel):
    text: str
    vault_id: str


class DetokenizeResponse(BaseModel):
    original_text: str


class ObfuscateRequest(BaseModel):
    text: str = Field(..., max_length=1_000_000)
    presets: Optional[List[str]] = None
    categories: Optional[List[str]] = None
    min_confidence: float = 0.0
    seed: Optional[int] = None


class ObfuscateResponse(BaseModel):
    obfuscated_text: str
    finding_count: int


class HealthResponse(BaseModel):
    status: str
    version: str


class BatchScanRequest(BaseModel):
    items: List[ScanRequest]


class BatchScanResponse(BaseModel):
    results: List[ScanResponse]


# ---------------------------------------------------------------------------
# Vault storage (thread-safe, TTL-based cleanup)
# ---------------------------------------------------------------------------

_MAX_VAULTS = 1000
_VAULT_TTL_SECONDS = 3600  # 1 hour

_vaults: Dict[str, TokenVault] = {}
_vault_timestamps: Dict[str, float] = {}
_vault_lock = threading.Lock()


def _store_vault(vault: TokenVault) -> str:
    """Store a TokenVault and return its UUID key."""
    vault_id = str(uuid.uuid4())
    now = time.time()

    with _vault_lock:
        # TTL cleanup: remove expired vaults
        expired = [
            vid for vid, ts in _vault_timestamps.items()
            if now - ts > _VAULT_TTL_SECONDS
        ]
        for vid in expired:
            _vaults.pop(vid, None)
            _vault_timestamps.pop(vid, None)

        # Enforce max vault count: evict oldest if at capacity
        if len(_vaults) >= _MAX_VAULTS:
            oldest_id = min(_vault_timestamps, key=_vault_timestamps.get)
            _vaults.pop(oldest_id, None)
            _vault_timestamps.pop(oldest_id, None)

        _vaults[vault_id] = vault
        _vault_timestamps[vault_id] = now

    return vault_id


def _get_vault(vault_id: str) -> Optional[TokenVault]:
    """Retrieve a TokenVault by its UUID key."""
    with _vault_lock:
        vault = _vaults.get(vault_id)
        if vault is not None:
            # Refresh timestamp on access
            _vault_timestamps[vault_id] = time.time()
        return vault


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------

def _get_api_key():
    """Return the configured API key, or None if auth is disabled."""
    return os.environ.get("DLPSCAN_API_KEY")


def _verify_api_key(x_api_key: Optional[str] = Header(None)):
    """FastAPI dependency that checks the X-API-Key header."""
    expected = _get_api_key()
    if expected is None:
        # Auth disabled when env var is not set
        return
    if x_api_key is None or not hmac.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


from .rate_limit import RateLimiter


def _get_rate_limiter() -> RateLimiter:
    """Create or return the global rate limiter singleton."""
    if not hasattr(_get_rate_limiter, "_instance"):
        max_rpm = int(os.environ.get("DLPSCAN_API_RATE_LIMIT", "100"))
        _get_rate_limiter._instance = RateLimiter(
            max_requests=max_rpm, window_seconds=60
        )
    return _get_rate_limiter._instance


def _check_rate_limit():
    """FastAPI dependency that enforces rate limiting."""
    limiter = _get_rate_limiter()
    if not limiter.check():
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Please retry later.",
        )


# ---------------------------------------------------------------------------
# Helper: build InputGuard from request params
# ---------------------------------------------------------------------------

def _build_guard(
    presets: Optional[List[str]] = None,
    categories: Optional[List[str]] = None,
    action: str = "flag",
    min_confidence: float = 0.0,
    require_context: bool = False,
) -> InputGuard:
    """Construct an InputGuard from API request parameters."""
    from .guard.presets import Preset

    resolved_presets = None
    if presets:
        resolved_presets = []
        for name in presets:
            try:
                resolved_presets.append(Preset(name))
            except ValueError:
                # Try case-insensitive lookup
                found = False
                for p in Preset:
                    if p.value.lower() == name.lower() or p.name.lower() == name.lower():
                        resolved_presets.append(p)
                        found = True
                        break
                if not found:
                    raise HTTPException(
                        status_code=422,
                        detail=f"Unknown preset: {name}",
                    )

    resolved_categories = set(categories) if categories else None

    try:
        action_enum = Action(action)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown action: {action}. Valid actions: {[a.value for a in Action]}",
        )

    return InputGuard(
        presets=resolved_presets,
        categories=resolved_categories,
        action=action_enum,
        min_confidence=min_confidence,
        require_context=require_context,
    )


def _scan_to_response(result) -> ScanResponse:
    """Convert a ScanResult to a ScanResponse."""
    return ScanResponse(
        is_clean=result.is_clean,
        finding_count=result.finding_count,
        categories_found=sorted(result.categories_found),
        redacted_text=result.redacted_text,
        findings=[f.to_dict(redact=True) for f in result.findings],
    )


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""

    app = FastAPI(
        title="dlpscan API",
        version=__version__,
        description="REST API for dlpscan data loss prevention scanning.",
    )

    # -- Request ID middleware ----------------------------------------------

    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        request_id = str(uuid.uuid4())
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

    # -- Endpoints ---------------------------------------------------------

    @app.get("/health", response_model=HealthResponse)
    async def health():
        """Health check endpoint."""
        return HealthResponse(status="ok", version=__version__)

    @app.post(
        "/v1/scan",
        response_model=ScanResponse,
        dependencies=[Depends(_verify_api_key), Depends(_check_rate_limit)],
    )
    async def scan(req: ScanRequest):
        """Scan text for sensitive data."""
        start = time.monotonic()
        guard = _build_guard(
            presets=req.presets,
            categories=req.categories,
            action=req.action,
            min_confidence=req.min_confidence,
            require_context=req.require_context,
        )
        try:
            result = guard.scan(req.text)
        except Exception as exc:
            # InputGuardError (action=reject) — return findings as a normal response
            if hasattr(exc, "result"):
                result = exc.result
            else:
                logger.exception("Scan failed")
                raise HTTPException(status_code=500, detail="Internal scan error")

        elapsed_ms = (time.monotonic() - start) * 1000

        # Emit audit event
        try:
            event = event_from_scan(
                result, action=req.action, source="api", duration_ms=elapsed_ms
            )
            audit_event(event)
        except Exception:
            logger.debug("Failed to emit audit event", exc_info=True)

        return _scan_to_response(result)

    @app.post(
        "/v1/tokenize",
        response_model=TokenizeResponse,
        dependencies=[Depends(_verify_api_key), Depends(_check_rate_limit)],
    )
    async def tokenize(req: TokenizeRequest):
        """Tokenize sensitive data in text, returning reversible tokens."""
        guard = _build_guard(
            presets=req.presets,
            categories=req.categories,
            action="tokenize",
            min_confidence=req.min_confidence,
        )
        tokenized_text, vault = guard.tokenize(req.text)
        vault_id = _store_vault(vault)
        return TokenizeResponse(
            tokenized_text=tokenized_text,
            token_count=vault.size,
            vault_id=vault_id,
        )

    @app.post(
        "/v1/detokenize",
        response_model=DetokenizeResponse,
        dependencies=[Depends(_verify_api_key), Depends(_check_rate_limit)],
    )
    async def detokenize(req: DetokenizeRequest):
        """Reverse tokenization using a stored vault."""
        vault = _get_vault(req.vault_id)
        if vault is None:
            raise HTTPException(
                status_code=404,
                detail=f"Vault not found: {req.vault_id}. It may have expired.",
            )
        original_text = vault.detokenize_text(req.text)
        return DetokenizeResponse(original_text=original_text)

    @app.post(
        "/v1/obfuscate",
        response_model=ObfuscateResponse,
        dependencies=[Depends(_verify_api_key), Depends(_check_rate_limit)],
    )
    async def obfuscate(req: ObfuscateRequest):
        """Replace sensitive data with realistic fake data."""
        if req.seed is not None:
            set_obfuscation_seed(req.seed)

        guard = _build_guard(
            presets=req.presets,
            categories=req.categories,
            action="obfuscate",
            min_confidence=req.min_confidence,
        )
        result = guard.scan(req.text)

        # Reset seed to non-deterministic after use
        if req.seed is not None:
            set_obfuscation_seed(None)

        return ObfuscateResponse(
            obfuscated_text=result.redacted_text if result.redacted_text else req.text,
            finding_count=result.finding_count,
        )

    @app.post(
        "/v1/batch/scan",
        response_model=BatchScanResponse,
        dependencies=[Depends(_verify_api_key), Depends(_check_rate_limit)],
    )
    async def batch_scan(req: BatchScanRequest):
        """Scan multiple text items in a single request."""
        results = []
        for item in req.items:
            guard = _build_guard(
                presets=item.presets,
                categories=item.categories,
                action=item.action,
                min_confidence=item.min_confidence,
                require_context=item.require_context,
            )
            try:
                result = guard.scan(item.text)
            except Exception as exc:
                if hasattr(exc, "result"):
                    result = exc.result
                else:
                    logger.exception("Batch scan item failed")
                    raise HTTPException(status_code=500, detail="Internal scan error")
            results.append(_scan_to_response(result))

        return BatchScanResponse(results=results)

    return app


# ---------------------------------------------------------------------------
# Module-level app instance for convenience (e.g. uvicorn dlpscan.api:app)
# ---------------------------------------------------------------------------

app = create_app()

# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    try:
        import uvicorn
    except ImportError:
        raise ImportError(
            "Uvicorn is required to run the dlpscan API server. "
            "Install it with: pip install uvicorn"
        )

    uvicorn.run(
        "dlpscan.api:app",
        host=os.environ.get("DLPSCAN_API_HOST", "0.0.0.0"),
        port=int(os.environ.get("DLPSCAN_API_PORT", "8000")),
        reload=False,
    )
