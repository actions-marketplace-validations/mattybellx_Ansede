"""Generate private advisory files (NOT public posts) for repos with confirmed vulns.

IMPORTANT — Responsible Disclosure:
    Security vulnerabilities MUST be reported PRIVATELY via GitHub Security
    Advisories. This tool generates advisory files for MANUAL submission.
    NEVER post security findings as public GitHub Issues.

Each advisory includes:
    - Stripped relative paths (no local machine leak)
    - Project context info (browser vs Node.js runtime detection)
    - Actionable remediation suggestions
    - Humble, non-promotional tone
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# Add source to path for project_context import
_src = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(_src))

# ── Local path prefixes to strip (case-insensitive on Windows) ──────
_LOCAL_PREFIXES: list[str] = [
    r"c:\Users\matth\OneDrive\Desktop\ansede-static-focus\tmp\clones\",
    r"C:\Users\matth\OneDrive\Desktop\ansede-static-focus\tmp\clones\",
    "/tmp/",
    "/home/",
    "/Users/matth/",
]

# We'll try to import project_context; if not available, skip enrichment
try:
    from ansede_static.js_engine.project_context import classify_runtime as _classify
    _HAS_CONTEXT = True
except ImportError:
    _HAS_CONTEXT = False


def _strip_local_path(filepath: str) -> str:
    """Remove local machine prefix from a file path, case-insensitive."""
    # Try exact and lowercase matches for Windows drives
    for prefix in _LOCAL_PREFIXES:
        if filepath.startswith(prefix):
            return filepath[len(prefix):]
        if filepath.lower().startswith(prefix.lower()):
            return filepath[len(prefix):]
    # Fallback: just take the last 3 path components
    parts = filepath.replace("\\", "/").split("/")
    if len(parts) > 3:
        return "/".join(parts[-3:])
    return filepath


def _infer_runtime_hint(filepath: str) -> str:
    """Return a short runtime hint string based on the file path."""
    norm = filepath.replace("\\", "/").lower()
    if "/test" in norm or "/spec" in norm or "/__tests__" in norm:
        return "test file"
    if "/frontend" in norm or "/public/" in norm or "/static/" in norm:
        return "likely browser-side code"
    if "/server" in norm or "/api/" in norm or "/routes/" in norm:
        return "likely server-side code"
    if "/ui/" in norm:
        return "likely browser/admin UI code"
    return ""


def _classify_finding(finding: dict) -> str:
    """If possible, classify this file's runtime and return a note."""
    fp = finding.get("file", "")
    if not fp:
        return ""
    # Try path-based heuristics first
    hint = _infer_runtime_hint(fp)
    if hint:
        return hint
    # Try reading the file for context detection
    if _HAS_CONTEXT and fp and Path(fp).exists():
        try:
            code = Path(fp).read_text(encoding="utf-8", errors="replace")
            ctx = _classify(code, fp)
            if ctx.is_browser:
                return "browser-side code"
            if ctx.is_node:
                return "server-side (Node.js) code"
            if ctx.is_test:
                return "test file"
        except Exception:
            pass
    return ""


def main() -> None:
    triage_path = Path(
        r"c:\Users\matth\OneDrive\Desktop\ansede-static-focus\tmp\triage\triage_results_20260521_110614.json"
    )
    data = json.loads(triage_path.read_text(encoding="utf-8"))
    confirmed = [f for f in data["findings"] if f.get("verdict") == "confirmed"]

    by_repo: dict[str, list[dict]] = {}
    for f in confirmed:
        repo = f.get("repo_id", "unknown")
        by_repo.setdefault(repo, []).append(f)

    out_dir = Path(
        r"c:\Users\matth\OneDrive\Desktop\ansede-static-focus\tmp\disclosure"
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    for repo, findings in sorted(by_repo.items()):
        # Group by severity
        by_sev: dict[str, list[dict]] = {
            "critical": [], "high": [], "medium": [], "low": []
        }
        for f in findings:
            sev = f.get("severity", "medium").lower()
            by_sev.setdefault(sev, []).append(f)

        total_confirmed = len(findings)
        lines = [
            f"# Potential Security Findings — {repo}",
            "",
            f"Hello! I ran an automated SAST scan on {repo} and wanted to share",
            "some findings that may need attention. Each item includes the file",
            "location, what the scanner detected, and a suggested fix.",
            "",
            "These findings have not been manually validated — some may be false",
            "positives. Please review at your discretion.",
            "",
            "---",
            "",
            "## Summary",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        for sev in ("critical", "high", "medium", "low"):
            c = len(by_sev.get(sev, []))
            if c > 0:
                lines.append(f"| {sev.capitalize()} | {c} |")

        lines.extend([
            "",
            "---",
            "",
            "## Findings",
            "",
        ])
        for i, f in enumerate(findings, 1):
            cwe = f.get("cwe", "?")
            severity = f.get("severity", "?").upper()
            filepath = _strip_local_path(f.get("file", "?"))
            rule_id = f.get("rule_id", "?")
            suggestion = f.get("suggestion", "")
            if not suggestion:
                suggestion = "Review the flagged code and apply appropriate input validation or sanitization."

            # Add runtime context hint
            runtime_hint = _classify_finding(f)
            rt_line = ""
            if runtime_hint:
                rt_line = f"| **Context** | this file appears to be {runtime_hint} |\n"

            # Format the code snippet if available
            code_ctx = f.get("code_context", "") or f.get("triggering_code", "") or ""
            code_block = ""
            if code_ctx:
                # Truncate long snippets
                if len(code_ctx) > 200:
                    code_ctx = code_ctx[:200] + "..."
                code_block = f"\n**Code:**\n```javascript\n{code_ctx}\n```\n"

            lines.extend([
                f"### {i}. {f.get('title', '?')}",
                "",
                "| Detail | Value |",
                "|--------|-------|",
                f"| **Rule** | `{rule_id}` |",
                f"| **CWE** | {cwe} |",
                f"| **Severity** | {severity} |",
                f"| **Confidence** | {f.get('confidence', 0):.2f} |",
                f"| **File** | `{filepath}:{f.get('line', '?')}` |",
                f"| **Analysis** | {f.get('analysis_kind', '?')} |",
                f"{rt_line}",
                f"**What the scanner found:** {f.get('title', '?')}",
                "",
                f"**Suggested fix:** {suggestion}",
                f"{code_block}",
                "---",
                "",
            ])

        lines.extend([
            "---",
            "",
            "*These findings were generated by ansede-static, an open-source SAST",
            "engine. To reproduce locally: `pip install ansede-static &&",
            "ansede-static /path/to/repo`*",
            "",
        ])

        content = "\n".join(lines)
        safe_name = repo.replace("/", "_").replace(" ", "_")
        path = out_dir / f"advisory_{safe_name}.md"
        path.write_text(content, encoding="utf-8")
        print(f"  ✅ {path.name} — {total_confirmed} findings")

    print(f"\nDone! {len(by_repo)} advisory files generated in {out_dir}/")
    print("Review each file, then submit privately via GitHub Security Advisories.")


if __name__ == "__main__":
    main()
