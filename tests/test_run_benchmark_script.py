from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_module():
    script_path = Path(__file__).resolve().parents[1] / "scripts" / "run_benchmark.py"
    spec = importlib.util.spec_from_file_location("run_benchmark", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_collect_detected_sets_extracts_rules_and_cwes():
    mod = _load_module()
    payload = {
        "summary": {"files_scanned": 2},
        "results": [
            {"findings": [{"rule_id": "PY-020", "cwe": "CWE-862"}]},
            {"findings": [{"rule_id": "JS-039", "cwe": "CWE-601"}]},
        ],
    }

    rules, cwes, findings, files_scanned = mod._collect_detected_sets(payload)

    assert rules == {"PY-020", "JS-039"}
    assert cwes == {"CWE-862", "CWE-601"}
    assert findings == 2
    assert files_scanned == 2


def test_safe_float_and_f1_handle_edge_cases():
    mod = _load_module()

    assert mod._safe_float(3.0, 0.0) is None
    assert mod._safe_float(3.0, 6.0) == 0.5
    assert mod._f1(None, 0.5) is None
    assert mod._f1(0.5, 0.5) == 0.5


def test_match_finding_specs_supports_path_line_and_rule():
    mod = _load_module()
    scan_root = Path("C:/repo")
    detected = {
        ("app/routes.py", 42, "PY-020", "CWE-862"),
        ("app/auth.py", 8, "PY-046", "CWE-601"),
    }
    specs = [
        {"path": "app/routes.py", "line": 42, "rule_id": "PY-020", "cwe": "CWE-862"},
        {"path": "app/auth.py", "rule_id": "PY-046"},
        {"path": "missing.py", "rule_id": "PY-999"},
    ]

    matched, missing = mod._match_finding_specs(specs, detected, scan_root)

    assert matched == 2
    assert missing == 1
