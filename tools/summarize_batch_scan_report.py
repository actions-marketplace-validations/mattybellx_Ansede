from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _safe_float(value: Any) -> float | None:
    try:
        if value is None:
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def build_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {}) if isinstance(report, dict) else {}
    repos = report.get("repos", []) if isinstance(report, dict) else []

    repos_scanned = int(summary.get("repos_scanned", len(repos) or 0))
    files_scanned = int(summary.get("files_scanned", 0))
    lines_scanned = int(summary.get("lines_scanned", 0))
    findings_count = int(summary.get("findings_count", 0))
    avg_findings = _safe_float(summary.get("average_findings_per_repo"))
    est_fp_rate = _safe_float(summary.get("estimated_fp_rate"))

    top_cwes = summary.get("top_cwes", [])
    if not isinstance(top_cwes, list):
        top_cwes = []

    lines: list[str] = []
    lines.append("# Batch Scan Report")
    lines.append("")
    lines.append("## Aggregate")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---:|")
    lines.append(f"| Repositories scanned | {repos_scanned} |")
    lines.append(f"| Files scanned | {files_scanned} |")
    lines.append(f"| Lines scanned | {lines_scanned} |")
    lines.append(f"| Findings | {findings_count} |")
    lines.append(f"| Average findings / repo | {(avg_findings if avg_findings is not None else 0.0):.2f} |")
    if est_fp_rate is not None:
        lines.append(f"| Estimated false-positive rate | {est_fp_rate:.4f} |")
    lines.append("")

    lines.append("## Top CWEs")
    lines.append("")
    lines.append("| CWE | Count |")
    lines.append("|---|---:|")
    for item in top_cwes[:10]:
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            lines.append(f"| {item[0]} | {item[1]} |")
    if len(lines) > 0 and lines[-1] == "|---|---:|":
        lines.append("| _none_ | 0 |")

    lines.append("")
    lines.append("## Repositories")
    lines.append("")
    lines.append("| Repository | Files | Lines | Findings | Est. FP rate |")
    lines.append("|---|---:|---:|---:|---:|")
    for repo in repos:
        if not isinstance(repo, dict):
            continue
        name = str(repo.get("repo", ""))
        files = int(repo.get("files_scanned", 0))
        lines_scanned_repo = int(repo.get("lines_scanned", 0))
        findings_repo = int(repo.get("findings_count", 0))
        fp_rate_repo = _safe_float(repo.get("estimated_fp_rate"))
        fp_str = f"{fp_rate_repo:.4f}" if fp_rate_repo is not None else "n/a"
        lines.append(f"| {name} | {files} | {lines_scanned_repo} | {findings_repo} | {fp_str} |")

    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize a batch scan JSON report into Markdown")
    parser.add_argument("--input", type=Path, required=True, help="Path to batch scan report JSON")
    parser.add_argument("--output", type=Path, required=True, help="Path to write markdown report")
    args = parser.parse_args()

    report = json.loads(args.input.read_text(encoding="utf-8"))
    markdown = build_markdown(report)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(markdown, encoding="utf-8")


if __name__ == "__main__":
    main()
