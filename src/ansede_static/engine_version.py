"""
ansede_static.engine_version
────────────────────────────
Shared engine and schema version helpers.
"""
from __future__ import annotations

ENGINE_NAME = "ansede-static"
SCHEMA_VERSION = "1.0"


def get_engine_version() -> str:
    """Return the installed package version, or ``dev`` when unavailable."""
    try:
        from importlib.metadata import PackageNotFoundError
    except ImportError:
        PackageNotFoundError = Exception  # type: ignore[misc,assignment]
    try:
        from importlib.metadata import version
        return version(ENGINE_NAME)
    except (ImportError, PackageNotFoundError):
        return "dev"


def get_engine_record() -> dict[str, str]:
    """Return a compact engine metadata record for report envelopes."""
    return {
        "name": ENGINE_NAME,
        "version": get_engine_version(),
        "schema_version": SCHEMA_VERSION,
    }