"""Flask integration example for dlpscan's InputGuard.

Demonstrates three integration patterns:
  1. Application-wide middleware that scans all incoming request bodies.
  2. Route-level scanning via the @guard.protect decorator.
  3. Manual scanning inside route handlers with proper error handling.

Requirements:
    pip install flask dlpscan

Configuration (environment variables):
    DLPSCAN_PRESETS      Comma-separated presets (default: "PCI_DSS,SSN_SIN,CREDENTIALS")
    DLPSCAN_ACTION       Action on detection: reject | redact | flag (default: "reject")
    DLPSCAN_CONFIDENCE   Minimum confidence threshold 0.0-1.0 (default: "0.7")
    DLPSCAN_REDACT_CHAR  Redaction character (default: "X")

Run:
    FLASK_APP=examples.flask_example flask run --debug
"""

import json
import logging
import os
from functools import wraps
from typing import List

from flask import Flask, Response, g, jsonify, request

from dlpscan.guard import Action, InputGuard, InputGuardError, Mode, Preset

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Guard configuration from environment
# ---------------------------------------------------------------------------

def _build_guard() -> InputGuard:
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


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_app() -> Flask:
    app = Flask(__name__)
    guard = _build_guard()

    # Store the guard on the app so it is accessible everywhere.
    app.config["DLP_GUARD"] = guard

    # ------------------------------------------------------------------
    # Pattern 1: Application-wide middleware (before_request hook)
    # ------------------------------------------------------------------
    @app.before_request
    def scan_request_body():
        """Scan every incoming request body for sensitive data.

        - GET/HEAD/OPTIONS requests are skipped (no body).
        - Only text-like content types are scanned (JSON, form data, plain text).
        - When action=REJECT, returns 422 with finding details.
        - When action=REDACT, stores sanitized body in g.sanitized_body.
        - When action=FLAG, stores the ScanResult in g.dlp_result for
          downstream handlers to inspect.
        """
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return None

        body = request.get_data(as_text=True)
        if not body:
            return None

        try:
            result = guard.scan(body)
        except InputGuardError as exc:
            logger.warning(
                "DLP middleware rejected request to %s: %s",
                request.path,
                sorted(exc.result.categories_found),
            )
            return jsonify({
                "error": "Request blocked: sensitive data detected",
                "categories": sorted(exc.result.categories_found),
                "finding_count": exc.result.finding_count,
            }), 422

        # Store scan metadata for downstream handlers.
        g.dlp_result = result

        if not result.is_clean and result.redacted_text is not None:
            # In REDACT mode, make sanitized body available to route handlers.
            g.sanitized_body = result.redacted_text
        else:
            g.sanitized_body = body

        return None

    # ------------------------------------------------------------------
    # Pattern 2: Route-level decorator
    # ------------------------------------------------------------------

    @app.route("/comments", methods=["POST"])
    @guard.protect(param="comment_text")
    def create_comment(comment_text: str = ""):
        """Create a comment. The guard.protect decorator scans comment_text
        before this function body runs.

        Note: With Flask, the decorator approach works best when you extract
        the parameter yourself. See the helper below for a practical pattern.
        """
        return jsonify({"status": "ok", "comment": comment_text})

    # A more practical pattern: combine decorator with request parsing.
    def dlp_protect(*param_names: str):
        """Flask-friendly decorator that extracts JSON fields, scans them,
        and passes them as keyword arguments to the route handler."""
        def decorator(fn):
            @wraps(fn)
            def wrapper(*args, **kwargs):
                data = request.get_json(silent=True) or {}
                for name in param_names:
                    value = data.get(name, "")
                    if isinstance(value, str) and value:
                        try:
                            result = guard.scan(value)
                        except InputGuardError as exc:
                            return jsonify({
                                "error": f"Field '{name}' contains sensitive data",
                                "categories": sorted(exc.result.categories_found),
                            }), 422
                        # In REDACT mode, pass the sanitized text.
                        if result.redacted_text is not None:
                            kwargs[name] = result.redacted_text
                        else:
                            kwargs[name] = value
                    else:
                        kwargs[name] = value
                return fn(*args, **kwargs)
            return wrapper
        return decorator

    @app.route("/feedback", methods=["POST"])
    @dlp_protect("subject", "body")
    def submit_feedback(subject: str = "", body: str = ""):
        """Submit feedback. The subject and body fields are scanned for
        sensitive data before the handler runs."""
        return jsonify({
            "status": "ok",
            "subject": subject,
            "body": body,
        })

    # ------------------------------------------------------------------
    # Pattern 3: Manual scanning inside a route handler
    # ------------------------------------------------------------------

    @app.route("/notes", methods=["POST"])
    def create_note():
        """Manually scan specific fields with full control over error handling."""
        data = request.get_json(silent=True)
        if not data or "content" not in data:
            return jsonify({"error": "Missing 'content' field"}), 400

        content = data["content"]

        # Option A: Use check() for a quick pass/fail.
        if not guard.check(content):
            return jsonify({"error": "Content contains sensitive data"}), 422

        # Option B: Use sanitize() to always get clean text.
        # clean_content = guard.sanitize(content)

        return jsonify({"status": "ok", "content": content})

    # ------------------------------------------------------------------
    # Health / info endpoint
    # ------------------------------------------------------------------

    @app.route("/health")
    def health():
        return jsonify({
            "status": "ok",
            "dlp_guard": repr(guard),
        })

    # ------------------------------------------------------------------
    # Global error handler for InputGuardError (catches decorator raises
    # and any unhandled guard errors in route handlers)
    # ------------------------------------------------------------------

    @app.errorhandler(InputGuardError)
    def handle_guard_error(exc: InputGuardError) -> Response:
        logger.warning("InputGuardError: %s", exc)
        return jsonify({
            "error": "Sensitive data detected in request",
            "categories": sorted(exc.result.categories_found),
            "finding_count": exc.result.finding_count,
        }), 422

    return app


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=5000, debug=True)
