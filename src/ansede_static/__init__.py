"""
ansede_static
─────────────
Zero-dependency SAST security scanner for Python and JavaScript.

Quick start:
    from ansede_static import scan_file, scan_code

    result = scan_file("myapp.py")
    for finding in result.sorted_findings():
        print(finding.severity.value, finding.title, finding.line)
"""
from __future__ import annotations

from ansede_static._types import AnalysisResult, Finding, Severity
from ansede_static.engine_version import SCHEMA_VERSION, get_engine_version
from ansede_static.python_analyzer import analyze_python, analyze_file as _py_file
from ansede_static.js_analyzer import analyze_js, analyze_file as _js_file

from pathlib import Path


__all__ = [
    "scan_file",
    "scan_code",
    "AnalysisResult",
    "Finding",
    "Severity",
    "SCHEMA_VERSION",
]

__version__ = get_engine_version()


_PYTHON_EXTS = frozenset({".py", ".pyi", ".pyw"})
_JS_EXTS     = frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"})


def scan_file(path: str | Path) -> AnalysisResult:
    """
    Scan a file and return an AnalysisResult.

    Language is detected from the file extension.
    Raises ValueError for unsupported file types.
    """
    p = Path(path)
    ext = p.suffix.lower()
    if ext in _PYTHON_EXTS:
        return _py_file(p)
    if ext in _JS_EXTS:
        return _js_file(p)
    raise ValueError(f"Unsupported file extension: {ext!r}. Supported: .py, .js, .ts (and variants).")


def scan_code(code: str, language: str, filename: str = "") -> AnalysisResult:
    """
    Scan source code provided as a string.

    Args:
        code:     Source code.
        language: "python" or "javascript".
        filename: Optional file name for error messages.

    Raises:
        ValueError: if language is not supported.
    """
    if language == "python":
        return analyze_python(code, filename=filename)
    if language in ("javascript", "typescript", "js", "ts"):
        return analyze_js(code, filename=filename)
    raise ValueError(f"Unsupported language: {language!r}. Must be 'python' or 'javascript'.")
