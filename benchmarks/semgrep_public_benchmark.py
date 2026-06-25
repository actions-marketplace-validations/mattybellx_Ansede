"""
benchmarks.semgrep_public_benchmark
─────────────────────────────────────
Scaffold for running the Semgrep public benchmark suite against ansede-static.

Requires:
  - semgrep CLI: `pip install semgrep`
  - Semgrep benchmark suite: cloned from https://github.com/semgrep/semgrep-benchmark

Usage:
  python -m benchmarks.semgrep_public_benchmark --suite /path/to/semgrep-benchmark

This is a scaffolding runner — actual results depend on the specific commit of
the Semgrep benchmark suite and the version of both tools.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))


def _detect_language(path: Path) -> str | None:
    ext = path.suffix.lower()
    mapping = {
        ".py": "python", ".pyi": "python",
        ".js": "javascript", ".ts": "javascript", ".jsx": "javascript", ".tsx": "javascript",
        ".go": "go",
        ".java": "java",
        ".cs": "csharp",
        ".rb": "ruby",
        ".php": "php",
    }
    return mapping.get(ext)


def run_ansede_on_dir(target_dir: Path) -> dict[str, Any]:
    """Run ansede-static on a directory and return aggregate stats."""
    from ansede_static import scan_file

    files = sorted(f for f in target_dir.rglob("*") if f.is_file() and _detect_language(f))
    total_findings = 0
    total_lines = 0
    total_time = 0.0
    findings_by_cwe: dict[str, int] = {}

    for f in files:
        try:
            t0 = time.perf_counter()
            result = scan_file(f)
            elapsed = time.perf_counter() - t0
            total_time += elapsed
            total_lines += result.lines_scanned
            total_findings += len(result.findings)
            for finding in result.findings:
                if finding.cwe:
                    cwe = finding.cwe.strip().upper()
                    findings_by_cwe[cwe] = findings_by_cwe.get(cwe, 0) + 1
        except Exception:
            pass

    return {
        "tool": "ansede-static",
        "files": len(files),
        "lines": total_lines,
        "findings": total_findings,
        "time_seconds": round(total_time, 3),
        "loc_per_s": round(total_lines / total_time, 0) if total_time else 0,
        "cwes_found": findings_by_cwe,
    }


def run_semgrep_on_dir(target_dir: Path) -> dict[str, Any]:
    """Run Semgrep OSS on a directory and return aggregate stats."""
    try:
        subprocess.run(["semgrep", "--version"], capture_output=True, timeout=10)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {"tool": "semgrep-oss", "error": "Semgrep not installed"}

    t0 = time.perf_counter()
    result = subprocess.run(
        ["semgrep", "scan", "--config=auto", "--no-git-ignore", "--quiet", "--json", str(target_dir)],
        capture_output=True, text=True, timeout=300,
    )
    elapsed = time.perf_counter() - t0

    findings = 0
    findings_by_cwe: dict[str, int] = {}
    if result.returncode in (0, 1):
        try:
            data = json.loads(result.stdout)
            for r in data.get("results", []):
                findings += 1
                extra = r.get("extra", {})
                metadata = extra.get("metadata", {})
                cwe_list = metadata.get("cwe", [])
                if isinstance(cwe_list, list):
                    for c in cwe_list:
                        c_str = str(c).strip().upper()
                        if ":" in c_str:
                            c_str = c_str.split(":")[0].strip()
                        if c_str.startswith("CWE-"):
                            findings_by_cwe[c_str] = findings_by_cwe.get(c_str, 0) + 1
        except json.JSONDecodeError:
            pass

    return {
        "tool": "semgrep-oss",
        "findings": findings,
        "time_seconds": round(elapsed, 3),
        "cwes_found": findings_by_cwe,
        "error": None,
    }


def run_comparison(suite_dir: Path) -> dict[str, Any]:
    """Run both tools on the Semgrep benchmark suite and compare results."""
    if not suite_dir.exists():
        return {"error": f"Suite directory not found: {suite_dir}"}

    print(f"Running benchmark suite: {suite_dir}")
    print()

    ansede_result = run_ansede_on_dir(suite_dir)
    print(f"Ansede-static:")
    print(f"  Files: {ansede_result['files']} | Lines: {ansede_result['lines']}")
    print(f"  Findings: {ansede_result['findings']} | Time: {ansede_result['time_seconds']}s")
    print(f"  Throughput: {ansede_result['loc_per_s']} LOC/s")
    top_cwes = sorted(ansede_result["cwes_found"].items(), key=lambda x: -x[1])[:5]
    if top_cwes:
        print(f"  Top CWEs: {', '.join(f'{c}({n})' for c, n in top_cwes)}")
    print()

    semgrep_result = run_semgrep_on_dir(suite_dir)
    if semgrep_result.get("error"):
        print(f"Semgrep OSS: {semgrep_result['error']}")
        print("  Install: pip install semgrep")
    else:
        print(f"Semgrep OSS:")
        print(f"  Findings: {semgrep_result['findings']} | Time: {semgrep_result['time_seconds']}s")
        top_cwes_sg = sorted(semgrep_result["cwes_found"].items(), key=lambda x: -x[1])[:5]
        if top_cwes_sg:
            print(f"  Top CWEs: {', '.join(f'{c}({n})' for c, n in top_cwes_sg)}")
    print()

    return {
        "suite": str(suite_dir),
        "ansede": ansede_result,
        "semgrep": semgrep_result,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Semgrep public benchmark runner")
    parser.add_argument("--suite", type=Path, required=True, help="Path to semgrep-benchmark suite checkout")
    parser.add_argument("--output", type=Path, default=None, help="Write JSON report to file")
    args = parser.parse_args()

    report = run_comparison(args.suite)
    if args.output:
        args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"Results written to {args.output}")
