"""
benchmarks.three_tool_report — Generate 3-tool comparison report.

Reads cached CodeQL results, runs ansede + semgrep on the fly,
and produces a structured comparison.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from cve_corpus import CVE_CORPUS
from head_to_head import (
    run_ansede_on_snippet,
    run_semgrep_on_snippet,
    _lang_to_ext,
)
from codeql_runner import (
    run_codeql_all_languages,
)

_REPORT_PATH = Path(__file__).resolve().parent / "three_tool_comparison.json"
_CACHE_PATH = Path(__file__).resolve().parent / "codeql_cache_results.json"


def _load_codeql_cache() -> dict[str, list[dict[str, Any]]] | None:
    if _CACHE_PATH.exists():
        return json.loads(_CACHE_PATH.read_text(encoding="utf-8"))
    return None


def _save_codeql_cache(results: dict[str, list[dict[str, Any]]]) -> None:
    _CACHE_PATH.write_text(json.dumps(results, indent=2), encoding="utf-8")


def run_comparison(
    *,
    force_codeql: bool = False,
) -> dict[str, Any]:
    """Generate 3-tool comparison data."""
    results: dict[str, Any] = {
        "generated": "2026-06-26",
        "ansede_version": "2.3.1",
        "semgrep_version": "1.157.0",
        "codeql_version": "2.25.6",
        "per_cve": {},
        "summary": {},
    }

    # Load or run CodeQL
    codeql_cache = _load_codeql_cache()
    if codeql_cache is None or force_codeql:
        print("Running CodeQL analysis...", file=sys.stderr)
        codeql_cache = run_codeql_all_languages(timeout=300)
        _save_codeql_cache(codeql_cache)

    for entry in CVE_CORPUS:
        cve_id = entry.cve_id
        lang = entry.language
        snippet = entry.snippet

        # Run ansede
        ansede_result = run_ansede_on_snippet(cve_id, lang, snippet)
        ansede_detected = bool(
            re.search(entry.expected_hit, " ".join(ansede_result.get("detected_cwes", [])), re.IGNORECASE)
        )

        # Run semgrep
        semgrep_result = run_semgrep_on_snippet(cve_id, lang, snippet)
        semgrep_detected = bool(
            re.search(entry.expected_hit, " ".join(semgrep_result.get("detected_cwes", [])), re.IGNORECASE)
        )

        # Get CodeQL result
        codeql_result = None
        if codeql_cache and lang in codeql_cache:
            for cr in codeql_cache[lang]:
                if cr.get("cve_id") == cve_id:
                    codeql_result = cr
                    break

        codeql_detected = codeql_result.get("detected", False) if codeql_result else False

        results["per_cve"][cve_id] = {
            "language": lang,
            "cwe": entry.cwe,
            "ansede": {
                "detected": ansede_detected,
                "findings": ansede_result.get("total_findings", 0),
                "cwes": ansede_result.get("detected_cwes", []),
            },
            "semgrep": {
                "detected": semgrep_detected,
                "findings": semgrep_result.get("total_findings", 0),
                "cwes": semgrep_result.get("detected_cwes", []),
            },
            "codeql": {
                "detected": codeql_detected,
                "findings": codeql_result.get("total_findings", 0) if codeql_result else 0,
                "cwes": codeql_result.get("detected_cwes", []) if codeql_result else [],
            },
        }

    # Compute summary
    langs = ["python", "javascript", "go", "java", "csharp"]
    summary: dict[str, Any] = {}
    for lang in langs:
        entries = [v for v in results["per_cve"].values() if v["language"] == lang]
        ansede_ok = sum(1 for v in entries if v["ansede"]["detected"])
        semgrep_ok = sum(1 for v in entries if v["semgrep"]["detected"])
        codeql_ok = sum(1 for v in entries if v["codeql"]["detected"])
        total = len(entries)
        summary[lang] = {
            "total": total,
            "ansede": {"detected": ansede_ok, "pct": round(ansede_ok / total * 100, 1) if total else 0},
            "semgrep": {"detected": semgrep_ok, "pct": round(semgrep_ok / total * 100, 1) if total else 0},
            "codeql": {"detected": codeql_ok, "pct": round(codeql_ok / total * 100, 1) if total else 0},
        }

    # Overall
    all_entries = list(results["per_cve"].values())
    total_all = len(all_entries)
    summary["overall"] = {
        "total": total_all,
        "ansede": {
            "detected": sum(1 for v in all_entries if v["ansede"]["detected"]),
        },
        "semgrep": {
            "detected": sum(1 for v in all_entries if v["semgrep"]["detected"]),
        },
        "codeql": {
            "detected": sum(1 for v in all_entries if v["codeql"]["detected"]),
        },
    }
    a = summary["overall"]["ansede"]["detected"]
    s = summary["overall"]["semgrep"]["detected"]
    c = summary["overall"]["codeql"]["detected"]
    summary["overall"]["ansede"]["pct"] = round(a / total_all * 100, 1)
    summary["overall"]["semgrep"]["pct"] = round(s / total_all * 100, 1)
    summary["overall"]["codeql"]["pct"] = round(c / total_all * 100, 1)

    results["summary"] = summary
    _REPORT_PATH.write_text(json.dumps(results, indent=2), encoding="utf-8")
    return results


def print_report(results: dict[str, Any]) -> None:
    """Pretty-print the comparison report."""
    summary = results["summary"]
    print("=" * 65)
    print("  3-TOOL COMPARISON: Ansede vs Semgrep OSS vs CodeQL")
    print("=" * 65)
    print()
    print(f"{'Language':<15} {'Total':<8} {'Ansede':<15} {'Semgrep':<15} {'CodeQL':<15}")
    print("-" * 65)
    for lang in ["python", "javascript", "go", "java", "csharp"]:
        if lang in summary:
            s = summary[lang]
            print(
                f"{lang:<15} {s['total']:<8} "
                f"{s['ansede']['detected']}/{s['total']} ({s['ansede']['pct']}%)  "
                f"{s['semgrep']['detected']}/{s['total']} ({s['semgrep']['pct']}%)  "
                f"{s['codeql']['detected']}/{s['total']} ({s['codeql']['pct']}%)"
            )
    print("-" * 65)
    ov = summary["overall"]
    print(
        f"{'OVERALL':<15} {ov['total']:<8} "
        f"{ov['ansede']['detected']}/{ov['total']} ({ov['ansede']['pct']}%)  "
        f"{ov['semgrep']['detected']}/{ov['total']} ({ov['semgrep']['pct']}%)  "
        f"{ov['codeql']['detected']}/{ov['total']} ({ov['codeql']['pct']}%)"
    )
    print()
    print(f"Report saved to: {_REPORT_PATH}")


if __name__ == "__main__":
    force = "--force" in sys.argv
    results = run_comparison(force_codeql=force)
    print_report(results)
