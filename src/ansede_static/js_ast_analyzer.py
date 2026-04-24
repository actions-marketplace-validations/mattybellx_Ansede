from __future__ import annotations

import json
import subprocess
from ansede_static._types import AnalysisResult
from ansede_static.js_analyzer import analyze_js
import logging

_log = logging.getLogger(__name__)

def analyze_js_ast(code: str, filename: str = '') -> AnalysisResult:
    result = AnalysisResult(
        file_path=filename,
        language='javascript',
        lines_scanned=len(code.splitlines()),
    )
    try:
        proc = subprocess.run(
            ['node', '--check', '-e', code],
            capture_output=True,
            text=True,
            timeout=5
        )
        if proc.returncode != 0:
            err = proc.stderr.strip().splitlines()[0] if proc.stderr else ''
            # If syntax error, skip AST parsing, just rely on regex fallback
            pass
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Phase 1 scaffolding complete. Pass to the regex analyzer until a 0-dependency AST binary is installed.
    fallback = analyze_js(code, filename)
    result.findings.extend(fallback.findings)
    return result
