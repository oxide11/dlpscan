"""Django integration example for dlpscan's InputGuard.

Demonstrates three integration patterns:
  1. Application-wide middleware that scans all incoming request bodies.
  2. View-level decorator for protecting individual views.
  3. Manual scanning inside view functions with proper error handling.

Requirements:
    pip install django dlpscan

Configuration (environment variables):
    DLPSCAN_PRESETS      Comma-separated presets (default: "PCI_DSS,SSN_SIN,CREDENTIALS")
    DLPSCAN_ACTION       Action on detection: reject | redact | flag (default: "reject")
    DLPSCAN_CONFIDENCE   Minimum confidence threshold 0.0-1.0 (default: "0.7")
    DLPSCAN_REDACT_CHAR  Redaction character (default: "X")

Setup:
    1. Add 'examples.django_example' to INSTALLED_APPS (or copy the middleware class).
    2. Add 'examples.django_example.DLPScanMiddleware' to MIDDLEWARE.
    3. Include the URL patterns in your root urlconf.

Run (standalone with this file):
    python examples/django_example.py runserver
"""

import json
import logging
import os
from functools import wraps
from typing import List

import django
from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

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
# Pattern 1: Application-wide middleware
# ---------------------------------------------------------------------------

class DLPScanMiddleware:
    """Django middleware that scans every incoming request body for sensitive data.

    - Skips GET, HEAD, and OPTIONS requests (no body expected).
    - When action=REJECT and sensitive data is found, returns 422 immediately.
    - When action=REDACT, the sanitized body is stored in request.dlp_sanitized_body
      for downstream views to use instead of the raw body.
    - When action=FLAG, the ScanResult is stored in request.dlp_result for
      views to inspect.

    Add to settings.MIDDLEWARE:
        MIDDLEWARE = [
            ...
            'examples.django_example.DLPScanMiddleware',
            ...
        ]
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.guard = guard

    def __call__(self, request: HttpRequest) -> HttpResponse:
        # Skip methods that typically have no body.
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return self.get_response(request)

        body = request.body.decode("utf-8", errors="replace")
        if not body:
            return self.get_response(request)

        try:
            result = self.guard.scan(body)
        except InputGuardError as exc:
            logger.warning(
                "DLP middleware rejected %s %s: %s",
                request.method,
                request.path,
                sorted(exc.result.categories_found),
            )
            return JsonResponse(
                {
                    "error": "Request blocked: sensitive data detected",
                    "categories": sorted(exc.result.categories_found),
                    "finding_count": exc.result.finding_count,
                },
                status=422,
            )

        # Attach scan metadata to the request for downstream views.
        request.dlp_result = result

        if not result.is_clean and result.redacted_text is not None:
            # In REDACT mode, provide sanitized body to views.
            request.dlp_sanitized_body = result.redacted_text
        else:
            request.dlp_sanitized_body = body

        return self.get_response(request)


# ---------------------------------------------------------------------------
# Pattern 2: View-level decorator
# ---------------------------------------------------------------------------

def dlp_protect(*field_names: str):
    """Decorator that scans specific JSON fields before a view runs.

    Usage:
        @csrf_exempt
        @require_POST
        @dlp_protect("subject", "body")
        def submit_feedback(request, subject="", body=""):
            ...

    When action=REJECT, returns a 422 JsonResponse.
    When action=REDACT, passes sanitized text as keyword arguments.
    When action=FLAG, passes the original text through (check request.dlp_result).
    """
    def decorator(view_fn):
        @wraps(view_fn)
        def wrapper(request: HttpRequest, *args, **kwargs):
            try:
                data = json.loads(request.body)
            except (json.JSONDecodeError, ValueError):
                return JsonResponse({"error": "Invalid JSON body"}, status=400)

            for name in field_names:
                value = data.get(name, "")
                if not isinstance(value, str) or not value:
                    kwargs[name] = value
                    continue

                try:
                    result = guard.scan(value)
                except InputGuardError as exc:
                    return JsonResponse(
                        {
                            "error": f"Field '{name}' contains sensitive data",
                            "categories": sorted(exc.result.categories_found),
                            "finding_count": exc.result.finding_count,
                        },
                        status=422,
                    )

                # In REDACT mode, pass the sanitized text to the view.
                if result.redacted_text is not None:
                    kwargs[name] = result.redacted_text
                else:
                    kwargs[name] = value

            return view_fn(request, *args, **kwargs)
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Pattern 2b: Using guard.protect decorator directly
# ---------------------------------------------------------------------------

@guard.protect(param="message")
def _process_message(user_id: int, message: str) -> dict:
    """Helper function protected by the InputGuard decorator.

    The decorator scans 'message' before this function body runs.
    In REJECT mode, InputGuardError is raised if sensitive data is found.
    In REDACT mode, the message is replaced with sanitized text.
    """
    return {"user_id": user_id, "message": message}


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------

@csrf_exempt
@require_POST
@dlp_protect("subject", "body")
def submit_feedback(request: HttpRequest, subject: str = "", body: str = "") -> JsonResponse:
    """Submit feedback. The subject and body fields are scanned for
    sensitive data before this view runs."""
    return JsonResponse({
        "status": "ok",
        "subject": subject,
        "body": body,
    })


@csrf_exempt
@require_POST
def create_comment(request: HttpRequest) -> JsonResponse:
    """Create a comment using the guard.protect-decorated helper.

    InputGuardError from the decorator is caught and returned as a
    422 response.
    """
    try:
        data = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return JsonResponse({"error": "Invalid JSON body"}, status=400)

    try:
        result = _process_message(
            user_id=data.get("user_id", 0),
            message=data.get("message", ""),
        )
    except InputGuardError as exc:
        return JsonResponse(
            {
                "error": "Sensitive data detected in message",
                "categories": sorted(exc.result.categories_found),
                "finding_count": exc.result.finding_count,
            },
            status=422,
        )

    return JsonResponse({"status": "ok", **result})


# ---------------------------------------------------------------------------
# Pattern 3: Manual scanning inside a view
# ---------------------------------------------------------------------------

@csrf_exempt
@require_POST
def create_note(request: HttpRequest) -> JsonResponse:
    """Manually scan specific fields with full control over error handling."""
    try:
        data = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return JsonResponse({"error": "Invalid JSON body"}, status=400)

    content = data.get("content", "")
    if not content:
        return JsonResponse({"error": "Missing 'content' field"}, status=400)

    # Option A: Quick boolean check.
    if not guard.check(content):
        return JsonResponse(
            {"error": "Content contains sensitive data"},
            status=422,
        )

    # Option B: Use sanitize() to always get clean text.
    # content = guard.sanitize(content)

    # Option C: Full scan with detailed result inspection.
    # try:
    #     result = guard.scan(content)
    # except InputGuardError as exc:
    #     logger.warning("Note blocked: %s", sorted(exc.result.categories_found))
    #     return JsonResponse(
    #         {
    #             "error": "Note content contains sensitive data",
    #             "categories": sorted(exc.result.categories_found),
    #         },
    #         status=422,
    #     )

    return JsonResponse({"status": "ok", "content": content})


def health(request: HttpRequest) -> JsonResponse:
    """Health check endpoint."""
    return JsonResponse({
        "status": "ok",
        "dlp_guard": repr(guard),
    })


# ---------------------------------------------------------------------------
# URL configuration
# ---------------------------------------------------------------------------

urlpatterns = [
    path("feedback", submit_feedback, name="submit_feedback"),
    path("comments", create_comment, name="create_comment"),
    path("notes", create_note, name="create_note"),
    path("health", health, name="health"),
]


# ---------------------------------------------------------------------------
# Standalone Django configuration (allows running this file directly)
# ---------------------------------------------------------------------------

if not settings.configured:
    settings.configure(
        DEBUG=True,
        SECRET_KEY="dlpscan-example-not-for-production",
        ROOT_URLCONF=__name__,
        MIDDLEWARE=[
            "django.middleware.common.CommonMiddleware",
            # Enable DLP scanning middleware for all requests:
            __name__ + ".DLPScanMiddleware",
        ],
        ALLOWED_HOSTS=["*"],
        INSTALLED_APPS=[
            "django.contrib.contenttypes",
        ],
    )
    django.setup()


if __name__ == "__main__":
    from django.core.management import execute_from_command_line
    import sys

    execute_from_command_line(["django_example", "runserver", "127.0.0.1:8000"])
