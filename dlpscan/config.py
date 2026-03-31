"""Configuration file support for dlpscan.

Loads settings from pyproject.toml [tool.dlpscan] or .dlpscanrc (JSON).
CLI arguments override config file settings.

Supported config keys:
    min_confidence: float (0.0-1.0)
    require_context: bool
    deduplicate: bool
    max_matches: int
    format: str (text/json/csv/sarif)
    categories: list[str]
    allowlist: list[str]         — exact text values to ignore
    ignore_patterns: list[str]   — sub_category names to ignore
    ignore_paths: list[str]      — file path globs to skip in directory scanning
"""

import copy
import json
from pathlib import Path
from typing import Any, Dict, Optional

_DEFAULTS: Dict[str, Any] = {
    'min_confidence': 0.0,
    'require_context': False,
    'deduplicate': True,
    'max_matches': 50_000,
    'format': 'text',
    'categories': None,
    'allowlist': [],
    'ignore_patterns': [],
    'ignore_paths': [],
    'context_backend': 'regex',  # 'regex' or 'ahocorasick'
}


def _find_config_file(start_dir: Optional[str] = None) -> Optional[Path]:
    """Walk up from *start_dir* looking for a config file.

    Search order at each directory level:
      1. pyproject.toml (must contain [tool.dlpscan])
      2. .dlpscanrc (JSON)

    Returns the first matching path, or None.
    """
    directory = Path(start_dir) if start_dir else Path.cwd()

    for parent in [directory] + list(directory.parents):
        # Check pyproject.toml
        pyproject = parent / 'pyproject.toml'
        if pyproject.is_file():
            try:
                content = pyproject.read_text(encoding='utf-8')
                if '[tool.dlpscan]' in content:
                    return pyproject
            except OSError:
                pass

        # Check .dlpscanrc
        rc = parent / '.dlpscanrc'
        if rc.is_file():
            return rc

    return None


def _parse_pyproject_toml(path: Path) -> Dict[str, Any]:
    """Extract [tool.dlpscan] section from a pyproject.toml file.

    Uses a minimal TOML parser that handles the subset we need,
    avoiding a dependency on tomllib (Python 3.11+) or tomli.
    """
    try:
        # Python 3.11+
        import tomllib
        with open(path, 'rb') as f:
            data = tomllib.load(f)
    except ImportError:
        try:
            import tomli
            with open(path, 'rb') as f:
                data = tomli.load(f)
        except ImportError:
            # Fallback: basic line parser for flat key-value pairs
            data = _parse_toml_fallback(path)

    tool = data.get('tool', {})
    return tool.get('dlpscan', {})


def _parse_toml_fallback(path: Path) -> Dict[str, Any]:
    """Minimal fallback TOML parser for [tool.dlpscan] section only.

    Handles flat key = value pairs (strings, numbers, booleans, arrays).
    """
    result: Dict[str, Any] = {}
    in_section = False
    dlpscan_config: Dict[str, Any] = {}

    for line in path.read_text(encoding='utf-8').splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue

        if stripped == '[tool.dlpscan]':
            in_section = True
            continue
        elif stripped.startswith('['):
            in_section = False
            continue

        if in_section and '=' in stripped:
            key, _, value = stripped.partition('=')
            key = key.strip()
            value = value.strip()

            # Parse value
            if value.lower() == 'true':
                dlpscan_config[key] = True
            elif value.lower() == 'false':
                dlpscan_config[key] = False
            elif value.startswith('"') and value.endswith('"'):
                dlpscan_config[key] = value[1:-1]
            elif value.startswith('[') and value.endswith(']'):
                # Simple array of strings
                inner = value[1:-1].strip()
                if not inner:
                    dlpscan_config[key] = []
                else:
                    items = [s.strip().strip('"').strip("'") for s in inner.split(',')]
                    dlpscan_config[key] = [i for i in items if i]
            else:
                try:
                    dlpscan_config[key] = float(value) if '.' in value else int(value)
                except ValueError:
                    dlpscan_config[key] = value

    result['tool'] = {'dlpscan': dlpscan_config}
    return result


def _parse_dlpscanrc(path: Path) -> Dict[str, Any]:
    """Parse a .dlpscanrc JSON config file."""
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def load_config(path: Optional[str] = None, start_dir: Optional[str] = None) -> Dict[str, Any]:
    """Load dlpscan configuration, merging defaults with file settings.

    Args:
        path: Explicit config file path. If None, auto-discovers.
        start_dir: Starting directory for config file search.

    Returns:
        Merged configuration dictionary.
    """
    config = copy.deepcopy(_DEFAULTS)

    if path:
        config_path = Path(path)
    else:
        config_path = _find_config_file(start_dir)

    if config_path and config_path.is_file():
        if config_path.name == 'pyproject.toml':
            file_config = _parse_pyproject_toml(config_path)
        elif config_path.suffix == '.toml':
            file_config = _parse_pyproject_toml(config_path)
        else:
            file_config = _parse_dlpscanrc(config_path)

        for key, value in file_config.items():
            if key in config:
                config[key] = value

    return config


def apply_config_to_args(config: Dict[str, Any], args) -> None:
    """Apply config file settings as defaults for CLI args.

    CLI args take precedence — only fill in values that weren't
    explicitly set on the command line.  Config values are type-checked
    before assignment to prevent downstream TypeErrors.
    """
    mc = config.get('min_confidence', 0.0)
    if isinstance(mc, (int, float)) and 0.0 <= mc <= 1.0:
        if getattr(args, 'min_confidence', None) == 0.0 and mc > 0:
            args.min_confidence = float(mc)

    if not getattr(args, 'require_context', False) and config.get('require_context') is True:
        args.require_context = True

    if getattr(args, 'no_dedup', False) is False and config.get('deduplicate') is False:
        args.no_dedup = True

    mm = config.get('max_matches', 50000)
    if isinstance(mm, int) and mm > 0 and getattr(args, 'max_matches', 50000) == 50000:
        args.max_matches = mm

    fmt = config.get('format', 'text')
    if isinstance(fmt, str) and fmt in ('text', 'json', 'csv', 'sarif'):
        if getattr(args, 'format', 'text') == 'text' and fmt != 'text':
            args.format = fmt

    cats = config.get('categories')
    if isinstance(cats, list) and getattr(args, 'categories', None) is None:
        args.categories = cats
