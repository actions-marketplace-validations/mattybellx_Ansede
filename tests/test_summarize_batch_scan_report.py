from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


def _load_module():
    script_path = Path(__file__).resolve().parents[1] / "tools" / "summarize_batch_scan_report.py"
    spec = importlib.util.spec_from_file_location("summarize_batch_scan_report", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_build_markdown_includes_key_aggregate_fields():
    mod = _load_module()
    payload = {
        "summary": {
            "repos_scanned": 2,
            "files_scanned": 30,
            "lines_scanned": 400,
            "findings_count": 20,
            "average_findings_per_repo": 10.0,
            "estimated_fp_rate": 0.15,
            "top_cwes": [["CWE-862", 7]],
        },
        "repos": [
            {"repo": "a/b", "files_scanned": 10, "lines_scanned": 100, "findings_count": 8, "estimated_fp_rate": 0.2}
        ],
    }

    output = mod.build_markdown(payload)

    assert "Repositories scanned | 2" in output
    assert "Average findings / repo | 10.00" in output
    assert "Estimated false-positive rate | 0.1500" in output
    assert "| CWE-862 | 7 |" in output
    assert "| a/b | 10 | 100 | 8 | 0.2000 |" in output


def test_main_writes_markdown_file(tmp_path: Path):
    mod = _load_module()
    source = tmp_path / "in.json"
    dest = tmp_path / "out.md"
    source.write_text(json.dumps({"summary": {}, "repos": []}), encoding="utf-8")

    old_argv = sys.argv
    try:
        sys.argv = [
            "summarize_batch_scan_report.py",
            "--input",
            str(source),
            "--output",
            str(dest),
        ]
        mod.main()
    finally:
        sys.argv = old_argv

    assert dest.exists()
    assert "# Batch Scan Report" in dest.read_text(encoding="utf-8")
