"""Plugin system for custom validators and post-processors.

Allows enterprises to register custom validation functions that run
after regex matching, enabling domain-specific checks like internal
ID format validation, checksum verification, or business rule filtering.

Usage::

    from dlpscan.plugins import register_validator, register_post_processor

    # Validator: return True to keep the match, False to discard it.
    def validate_employee_id(match):
        \"\"\"Check that employee ID passes internal checksum.\"\"\"
        return my_checksum(match.text)

    register_validator('Employee ID', validate_employee_id)

    # Post-processor: transform matches after scanning.
    def enrich_with_department(matches):
        \"\"\"Add department info to employee ID matches.\"\"\"
        for m in matches:
            if m.sub_category == 'Employee ID':
                # ... enrich ...
                pass
        return matches

    register_post_processor(enrich_with_department)
"""

import threading
from typing import Callable, Dict, List, Optional

from .models import Match

# -- Validators --
# Map of sub_category -> list of validator functions.
# Each validator takes a Match and returns bool (True = keep).
_validators: Dict[str, List[Callable[[Match], bool]]] = {}
_validator_lock = threading.Lock()


def register_validator(
    sub_category: str,
    validator: Callable[[Match], bool],
) -> None:
    """Register a custom validator for a specific sub_category.

    The validator is called after regex matching. If it returns False,
    the match is discarded.

    Args:
        sub_category: Pattern sub_category name to validate.
        validator: Callable that takes a Match and returns True to keep.

    Example::

        def check_luhn(match):
            return luhn_check(match.text)

        register_validator('Custom Card', check_luhn)
    """
    if not callable(validator):
        raise TypeError("validator must be callable.")
    with _validator_lock:
        _validators.setdefault(sub_category, []).append(validator)


def unregister_validators(sub_category: str) -> None:
    """Remove all validators for a sub_category."""
    with _validator_lock:
        _validators.pop(sub_category, None)


def run_validators(match: Match) -> bool:
    """Run all registered validators for a match.

    Returns True if the match passes all validators (or has none).
    """
    with _validator_lock:
        validators = _validators.get(match.sub_category, [])

    for v in validators:
        try:
            if not v(match):
                return False
        except Exception:
            return False  # Fail-closed: discard match on validator error.

    return True


# -- Post-processors --
# List of functions that transform the full match list after scanning.
_post_processors: List[Callable[[List[Match]], List[Match]]] = []
_post_processor_lock = threading.Lock()


def register_post_processor(
    processor: Callable[[List[Match]], List[Match]],
) -> None:
    """Register a post-processor that transforms the match list.

    Post-processors run after all scanning and deduplication. They
    receive the full list of matches and must return a (possibly
    modified) list.

    Args:
        processor: Callable that takes and returns a list of Matches.

    Example::

        def remove_test_data(matches):
            return [m for m in matches if 'test' not in m.text.lower()]

        register_post_processor(remove_test_data)
    """
    if not callable(processor):
        raise TypeError("processor must be callable.")
    with _post_processor_lock:
        _post_processors.append(processor)


def unregister_post_processors() -> None:
    """Remove all registered post-processors."""
    with _post_processor_lock:
        _post_processors.clear()


def run_post_processors(matches: List[Match]) -> List[Match]:
    """Run all registered post-processors sequentially.

    Returns the final transformed match list.
    """
    with _post_processor_lock:
        processors = list(_post_processors)

    result = matches
    for p in processors:
        try:
            result = p(result)
        except Exception:
            pass  # Don't let a broken processor crash the scan.

    return result
