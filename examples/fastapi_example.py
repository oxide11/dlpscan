"""FastAPI integration example for dlpscan's InputGuard.

Demonstrates three integration patterns:
  1. Application-wide middleware that scans all incoming request bodies.
  2. Dependency-injection-based scanning for individual routes.
  3. Manual scanning inside route handlers with proper error handling.

Requirements:
    pip install fastapi uvicorn dlpscan

Configuration (environment variables):
    DLPSCAN_PRESETS      Comma-separated presets (default: "PCI_DSS,SSN_SIN,CREDENTIALS")
    DLPSCAN_ACTION       Action on detection: reject | redact | flag (default: "reject")
    DLPSCAN_CONFIDENCE   Minimum confidence threshold 0.0-1.0 (default: "0.7")
    DLPSCAN_REDACT_CHAR  Redaction character (default: "X")

Run:
    uvicorn examples.fastapi_example:app --reload
"""

import logging
import os
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from dlpscan.guard import Action, InputGuard, InputGuardError, Mode, Preset, ScanResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Guard configuration from environment
# ---------------------------------------------------------------------------

def build_guard() -> InputGuard:
    """Create an InputGuard instance from environment variables."""
    preset_names = os.environ.get("DLPSCAN_PRESETS", "PCI_DSS,SSN_SIN,CREDENTIALS")
    presets: List[Preset] = []
    for name in preset_names.split(","):
        name = name.strip().upper()
        if name:
            presets.append(Preset(name.lower()))

    action_str = os.environ.get("DLPSCAN_ACTION", "reject").lower()
    confidence = float(os.environ.get("DLPSCAN_CONFIDENCE", "0.7"))
    redact_char = os.environ.get("DLPSCAN_REDACT_CHAR", "X")

    return InputGuard(
        presets=presets,
        mode=Mode.DENYLIST,
        action=Action(action_str),
        min_confidence=confidence,
        redaction_char=redact_char,
    )


# Module-level guard instance, shared across the application.
guard = build_guard()


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class CommentCreate(BaseModel):
    user_id: int
    text: str


class FeedbackCreate(BaseModel):
    subject: str
    body: str


class NoteCreate(BaseModel):
    content: str
    tags: Optional[List[str]] = None


class ErrorResponse(BaseModel):
    error: str
    categories: List[str] = []
    finding_count: int = 0


# ---------------------------------------------------------------------------
# Pattern 1: Application-wide middleware
# ---------------------------------------------------------------------------

class DLPScanMiddleware(BaseHTTPMiddleware):
    """Middleware that scans every incoming request body for sensitive data.

    - Skips GET, HEAD, and OPTIONS requests.
    - When action=REJECT and sensitive data is found, returns 422 immediately.
    - When action=REDACT, the original body is replaced with sanitized text
      and passed downstream. The original scan result is stored in
      request.state.dlp_result.
    - When action=FLAG, the scan result is stored in request.state.dlp_result
      for route handlers to inspect.
    """

    def __init__(self, app, guard: InputGuard):
        super().__init__(app)
        self.guard = guard

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return await call_next(request)

        # Read body once and cache it.
        body_bytes = await request.body()
        if not body_bytes:
            return await call_next(request)

        body_text = body_bytes.decode("utf-8", errors="replace")

        try:
            result = self.guard.scan(body_text)
        except InputGuardError as exc:
            logger.warning(
                "DLP middleware rejected %s %s: %s",
                request.method,
                request.url.path,
                sorted(exc.result.categories_found),
            )
            return JSONResponse(
                status_code=422,
                content={
                    "error": "Request blocked: sensitive data detected",
                    "categories": sorted(exc.result.categories_found),
                    "finding_count": exc.result.finding_count,
                },
            )

        # Store the scan result for downstream handlers.
        request.state.dlp_result = result

        return await call_next(request)


# ---------------------------------------------------------------------------
# Pattern 2: Dependency injection
# ---------------------------------------------------------------------------

def get_guard() -> InputGuard:
    """FastAPI dependency that provides the InputGuard instance."""
    return guard


def scanned_body(field: str):
    """Factory that returns a FastAPI dependency to scan a specific JSON field.

    Usage:
        @app.post("/endpoint")
        async def handler(clean_text: str = Depends(scanned_body("text"))):
            ...

    If action=REJECT and the field contains sensitive data, raises HTTPException 422.
    If action=REDACT, returns the sanitized text.
    Otherwise, returns the original field value.
    """
    async def dependency(request: Request) -> str:
        try:
            data = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")

        value = data.get(field, "")
        if not isinstance(value, str) or not value:
            return value

        try:
            result = guard.scan(value)
        except InputGuardError as exc:
            raise HTTPException(
                status_code=422,
                detail={
                    "error": f"Field '{field}' contains sensitive data",
                    "categories": sorted(exc.result.categories_found),
                    "finding_count": exc.result.finding_count,
                },
            )

        if result.redacted_text is not None:
            return result.redacted_text
        return value

    return dependency


class ScannedModel:
    """Dependency class that validates a Pydantic model and scans its string
    fields for sensitive data.

    Usage:
        @app.post("/endpoint")
        async def handler(data: FeedbackCreate = Depends(ScannedModel(FeedbackCreate, ["subject", "body"]))):
            ...
    """

    def __init__(self, model_cls, scan_fields: List[str]):
        self.model_cls = model_cls
        self.scan_fields = scan_fields

    async def __call__(self, request: Request):
        try:
            raw = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")

        instance = self.model_cls(**raw)

        for field_name in self.scan_fields:
            value = getattr(instance, field_name, None)
            if not isinstance(value, str) or not value:
                continue

            try:
                result = guard.scan(value)
            except InputGuardError as exc:
                raise HTTPException(
                    status_code=422,
                    detail={
                        "error": f"Field '{field_name}' contains sensitive data",
                        "categories": sorted(exc.result.categories_found),
                        "finding_count": exc.result.finding_count,
                    },
                )

            # Replace field with redacted text when in REDACT mode.
            if result.redacted_text is not None:
                object.__setattr__(instance, field_name, result.redacted_text)

        return instance


# ---------------------------------------------------------------------------
# Application setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="DLP-Protected API",
    description="Example FastAPI application with dlpscan InputGuard integration",
)

# Register the middleware. Disable this if you prefer per-route scanning only.
# app.add_middleware(DLPScanMiddleware, guard=guard)
#
# Note: The middleware and per-route scanning can coexist. The middleware
# provides a safety net, while per-route dependencies give fine-grained
# control. To enable the middleware, uncomment the line above.


# ---------------------------------------------------------------------------
# Global exception handler for InputGuardError
# ---------------------------------------------------------------------------

@app.exception_handler(InputGuardError)
async def guard_error_handler(request: Request, exc: InputGuardError) -> JSONResponse:
    """Catch any InputGuardError that escapes route handlers."""
    logger.warning("InputGuardError on %s %s: %s", request.method, request.url.path, exc)
    return JSONResponse(
        status_code=422,
        content={
            "error": "Sensitive data detected in request",
            "categories": sorted(exc.result.categories_found),
            "finding_count": exc.result.finding_count,
        },
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

# --- Dependency injection: scan a single field ---

@app.post("/comments", response_model=Dict[str, Any])
async def create_comment(
    clean_text: str = Depends(scanned_body("text")),
):
    """Create a comment. The 'text' field is scanned via dependency injection.
    If sensitive data is found, a 422 response is returned before this
    function body executes."""
    return {"status": "ok", "text": clean_text}


# --- Dependency injection: scan multiple fields on a Pydantic model ---

@app.post("/feedback", response_model=Dict[str, Any])
async def submit_feedback(
    data: FeedbackCreate = Depends(ScannedModel(FeedbackCreate, ["subject", "body"])),
):
    """Submit feedback. Both subject and body are scanned for sensitive data."""
    return {
        "status": "ok",
        "subject": data.subject,
        "body": data.body,
    }


# --- Manual scanning inside a route handler ---

@app.post("/notes", response_model=Dict[str, Any])
async def create_note(note: NoteCreate, dlp: InputGuard = Depends(get_guard)):
    """Create a note with manual DLP scanning inside the handler.

    This pattern gives you full control over how to handle findings.
    """
    # Option A: Quick boolean check.
    if not dlp.check(note.content):
        raise HTTPException(
            status_code=422,
            detail="Note content contains sensitive data",
        )

    # Option B: Sanitize instead of rejecting.
    # note.content = dlp.sanitize(note.content)

    return {
        "status": "ok",
        "content": note.content,
        "tags": note.tags,
    }


# --- Decorator-based protection ---

@guard.protect(param="message")
def process_message(user_id: int, message: str) -> Dict[str, Any]:
    """Process a message. The decorator scans 'message' before this runs."""
    return {"user_id": user_id, "message": message}


@app.post("/messages", response_model=Dict[str, Any])
async def send_message(request: Request):
    """Send a message using the decorator-protected helper function.

    InputGuardError from the decorator is caught by the global exception
    handler and returned as a 422 response.
    """
    data = await request.json()
    return process_message(
        user_id=data.get("user_id", 0),
        message=data.get("message", ""),
    )


# --- Health endpoint ---

@app.get("/health")
async def health():
    return {"status": "ok", "dlp_guard": repr(guard)}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "examples.fastapi_example:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
    )
