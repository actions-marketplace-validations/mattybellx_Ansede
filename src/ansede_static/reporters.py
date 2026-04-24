"""
ansede_static.reporters
────────────────────────
Output formatters for AnalysisResult.

Supported formats:
  - plaintext  (default — human-readable terminal output)
  - json       (machine-readable, one object per file)
  - sarif      (SARIF 2.1.0 — upload to GitHub Code Scanning)

Usage:
    from ansede_static.reporters import format_text, format_json, format_sarif
    print(format_text(result))
    with open("results.sarif") as f:
        f.write(format_sarif([result1, result2]))
"""
from __future__ import annotations

import hashlib
import json as _json
from typing import Any

from ansede_static._types import AnalysisResult, Finding, Severity
from ansede_static.engine_version import get_engine_version
from ansede_static.schema import build_report

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.tree import Tree
    from rich.text import Text
    from rich.style import Style
    from rich.syntax import Syntax
    from rich.markdown import Markdown
    console = Console()
except ImportError:
    console = None


# ──────────────────────────────────────────────────────────────────────────────
# Plain-text / Rich formatter
# ──────────────────────────────────────────────────────────────────────────────

_SEV_COLOUR_RICH = {
    "critical": "bold red",
    "high":     "yellow",
    "medium":   "cyan",
    "low":      "green",
    "info":     "white",
}

_SEV_COLOUR: dict[str, str] = {
    "critical": "\033[91m",  # bright red
    "high":     "\033[33m",  # yellow
    "medium":   "\033[36m",  # cyan
    "low":      "\033[32m",  # green
    "info":     "\033[37m",  # white
}
_RESET = "\033[0m"


def format_text(result: AnalysisResult, colour: bool = True, verbose: bool = False) -> str:
    """Return a human-readable string for one AnalysisResult. When 'rich' is available, prints directly and returns empty."""
    if console and colour:
        if result.parse_error:
            console.print(f"[bold red]  [ERROR] {result.parse_error}[/bold red]")
            return ""

        if not result.findings:
            console.print(f"[dim]  OK  No issues found ({result.lines_scanned} lines scanned)[/dim]")
            return ""
            
        for f in result.sorted_findings():
            sev_str = f.severity.value.upper()
            rich_col = _SEV_COLOUR_RICH.get(f.severity.value, "white")
            
            cwe_str = f" ({f.cwe})" if f.cwe else ""
            location = f"L{f.line}" if f.line else "?"
            
            header = Text()
            header.append(f"[{sev_str}]", style=f"reverse {rich_col}")
            header.append(f" {location:<6} ", style="dim")
            header.append(f"{f.title}{cwe_str}", style="bold")
            
            body = Text()
            if verbose:
                body.append(f"-> {f.description[:120]}\n")
                body.append(f"meta: {f.effective_rule_id} · {f.analysis_kind} · confidence {f.confidence:.2f}\n", style="dim")
                if f.suggestion:
                    body.append(f"* {f.suggestion[:100]}\n", style="italic cyan")
                
            panel_content = body
            
            # If we have a trace, build a visual tree
            if verbose and f.trace:
                tree = Tree("Data Flow / Trace")
                for frame in f.trace:
                    loc = f"L{frame.line}" if frame.line else "?"
                    node_style = "bold red" if frame.kind == "sink" else ("bold green" if frame.kind == "source" else "yellow")
                    tree.add(Text(f"{frame.kind.upper()}: {frame.label} ({loc})", style=node_style))
                
                # We can't put a Tree inside a Text easily, so we print the panel, then the tree
                console.print(Panel(panel_content, title=header, title_align="left", border_style=rich_col))
                console.print(tree)
                if hasattr(f, "explanation") and f.explanation:
                    console.print(Panel(Markdown(f.explanation), title="Vulnerability Explanation", border_style="blue"))
                if f.auto_fix:
                    fix_code = Syntax(f.auto_fix, result.language or "python", theme="monokai", line_numbers=False)
                    console.print(Panel(fix_code, title="Suggested Auto-Fix", border_style="green"))
                console.print("")
            else:
                if f.auto_fix and verbose:
                    panel_content.append("\nSuggested Auto-Fix:\n", style="bold green")
                    panel_content.append(f.auto_fix)
                console.print(Panel(panel_content, title=header, title_align="left", border_style=rich_col))
                if verbose and hasattr(f, "explanation") and f.explanation:
                    console.print(Panel(Markdown(f.explanation), title="Vulnerability Explanation", border_style="blue"))
                
        return ""
    
    # Fallback to legacy ANSI string output if rich is absent
    lines: list[str] = []

    if result.parse_error:
        lines.append(f"  [ERROR] {result.parse_error}")
        return "\n".join(lines)

    if not result.findings:
        lines.append(f"  OK  No issues found ({result.lines_scanned} lines scanned)")
        return "\n".join(lines)

    for f in result.sorted_findings():
        sev_str = f.severity.value.upper()
        padded = f"[{sev_str}]".ljust(10)
        if colour:
            col = _SEV_COLOUR.get(f.severity.value, "")
            sev_label = f"{col}{padded}{_RESET}"
        else:
            sev_label = padded

        location = f"L{f.line}" if f.line else "?"
        cwe = f" ({f.cwe})" if f.cwe else ""
        lines.append(f"  {sev_label}  {location:<6}  {f.title}{cwe}")

        if verbose:
            lines.append(f"             -> {f.description[:120]}")
            lines.append(
                f"             meta: {f.effective_rule_id} · {f.analysis_kind} · confidence {f.confidence:.2f}"
            )
            if f.suggestion:
                lines.append(f"             * {f.suggestion[:100]}")
            if f.trace:
                lines.append("             flow:")
                for frame in f.trace:
                    loc = f"L{frame.line}" if frame.line else "?"
                    lines.append(f"               - {frame.kind}: {frame.label} ({loc})")
            if f.auto_fix:
                for fix_line in f.auto_fix.splitlines():
                    lines.append(f"               {fix_line}")
            lines.append("")

    c = sum(1 for f in result.findings if f.severity.value in ("critical",))
    h = result.high_count
    m = sum(1 for f in result.findings if f.severity.value == "medium")
    lines.append(
        f"\n  Summary: {len(result.findings)} findings -- "
        f"{result.security_count} security, {result.quality_count} quality; "
        f"{c} critical, {h} high, {m} medium"
    )
    return "\n".join(lines)


def format_text_multi(
    results: list[AnalysisResult],
    colour: bool = True,
    verbose: bool = False,
    show_clean: bool = False,
) -> str:
    """Return a full report for multiple files."""
    if console and colour:
        total_findings = sum(len(r.findings) for r in results)
        total_critical = sum(r.critical_count for r in results)
        total_high = sum(r.high_count for r in results)
        
        console.print(f"\n[bold]{'─' * 74}[/bold]")
        console.print(f"[bold cyan]  ansede-static[/bold cyan]  --  {len(results)} file(s) scanned")
        console.print(f"[bold]{'─' * 74}[/bold]\n")

        for result in results:
            if not result.findings and not show_clean:
                continue
            label = f"{result.file_path or '<stdin>'}  ({result.language})"
            console.print(f"[bold underline]{label}[/bold underline]")
            format_text(result, colour=colour, verbose=verbose)

        console.print(f"[bold]{'─' * 74}[/bold]")
        summary_msg = Text(f"  Total: {total_findings} findings across {len(results)} file(s) -- ")
        
        c_style = "bold red" if total_critical > 0 else "dim"
        h_style = "yellow" if total_high > 0 else "dim"
        
        summary_msg.append(f"{total_critical} critical", style=c_style)
        summary_msg.append(f", {total_high} high", style=h_style)
        
        console.print(summary_msg)
        console.print(f"[bold]{'─' * 74}[/bold]")
        return ""

    # Legacy return string (for JSON/File redirection fallback without Rich TTY)
    parts: list[str] = []
    total_findings = sum(len(r.findings) for r in results)
    total_critical = sum(r.critical_count for r in results)
    total_high = sum(r.high_count for r in results)
    total_security = sum(r.security_count for r in results)
    total_quality = sum(r.quality_count for r in results)

    sep = "-" * 72
    parts.append(sep)
    parts.append(f"  ansede-static  --  {len(results)} file(s) scanned")
    parts.append(sep)
    parts.append("")

    for result in results:
        if not result.findings and not show_clean:
            continue
        label = f"{result.file_path or '<stdin>'}  ({result.language})"
        parts.append(f"  {label}")
        parts.append(format_text(result, colour=colour, verbose=verbose))
        parts.append("")

    parts.append(sep)
    parts.append(
        f"  Total: {total_findings} findings across {len(results)} file(s) -- "
        f"{total_security} security, {total_quality} quality; "
        f"{total_critical} critical, {total_high} high"
    )
    parts.append(sep)
    return "\n".join(parts)


# ──────────────────────────────────────────────────────────────────────────────
# JSON formatter
# ──────────────────────────────────────────────────────────────────────────────

def format_json(results: list[AnalysisResult], indent: int = 2) -> str:
    """Return a JSON string with all results."""
    payload: dict[str, Any] = build_report(results)
    return _json.dumps(payload, indent=indent, default=str)


def format_ciso_report(results: list[AnalysisResult]) -> str:
    """Generate the 'Security Debt Executive Summary' for Phase 4."""
    if not console:
        return "Install rich library for CISO reports."
        
    from rich.table import Table
    from rich.panel import Panel
    
    total_files = len(results)
    total_vulns = sum(len(r.findings) for r in results)
    critical_vulns = sum(r.critical_count for r in results)
    high_vulns = sum(r.high_count for r in results)
    
    # Calculate simplistic financial risk (mock algorithm for the CISO view)
    base_cost_per_critical = 15000 
    base_cost_per_high = 5000
    financial = (critical_vulns * base_cost_per_critical) + (high_vulns * base_cost_per_high)
    
    cwe_counts = {}
    for r in results:
        for f in r.findings:
            cwe = f.cwe or "Unknown"
            cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
            
    # Draw table
    table = Table(title="🏢 Ansede-Static Executive Risk Profile", title_justify="left", show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="dim", width=30)
    table.add_column("Value")
    
    table.add_row("Total Files Scanned", str(total_files))
    table.add_row("Total Vulnerabilities", f"[bold red]{total_vulns}[/bold red]")
    table.add_row("Critical Deficits (SLA 24hr)", f"[bold red]{critical_vulns}[/bold red]")
    table.add_row("High Deficits (SLA 7d)", f"[bold yellow]{high_vulns}[/bold yellow]")
    table.add_row("Estimated Remediation Debt", f"[bold green]${financial:,}[/bold green]")
    
    # Draw impact map
    impact_table = Table(title="Threat Landscape by CWE", show_header=True, header_style="bold blue")
    impact_table.add_column("Category")
    impact_table.add_column("Count")
    
    for cwe, count in sorted(cwe_counts.items(), key=lambda item: item[1], reverse=True):
        impact_table.add_row(str(cwe), str(count))
        
    console.print("\n")
    console.print(table)
    console.print()
    console.print(impact_table)
    console.print("\n")
    
    return ""


# ──────────────────────────────────────────────────────────────────────────────
# SARIF 2.1.0 formatter (GitHub Code Scanning compatible)
# ──────────────────────────────────────────────────────────────────────────────

_SARIF_LEVEL: dict[str, str] = {
    "critical": "error",
    "high":     "error",
    "medium":   "warning",
    "low":      "note",
    "info":     "note",
}

_SARIF_PRECISION_ORDER: dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
}


def format_sarif(results: list[AnalysisResult]) -> str:
    """
    Return a SARIF 2.1.0 JSON string.
    Upload to GitHub: `gh upload-scan-result results.sarif`
    """
    # Collect all unique rules
    rules_by_id: dict[str, dict] = {}
    for result in results:
        for f in result.findings:
            rule_id = f.effective_rule_id
            precision = _sarif_precision(f.confidence)
            if rule_id not in rules_by_id:
                tags = [f.finding_class, f.category]
                properties: dict[str, Any] = {
                    "tags": tags,
                    "precision": precision,
                    "confidence": f.confidence,
                    "cwe": f.cwe,
                }
                if f.finding_class == "security":
                    properties["security-severity"] = _cwe_to_cvss(f.cwe)
                rules_by_id[rule_id] = {
                    "id": rule_id,
                    "name": f.title[:80],
                    "shortDescription": {"text": f.description[:200]},
                    "fullDescription": {"text": f.description},
                    "helpUri": _cwe_help_uri(f.cwe),
                    "defaultConfiguration": {
                        "level": _SARIF_LEVEL.get(f.severity.value, "warning")
                    },
                    "help": {"text": f.suggestion or "Review and fix this finding."},
                    "properties": properties,
                }
            else:
                existing_properties = rules_by_id[rule_id].setdefault("properties", {})
                existing_precision = str(existing_properties.get("precision", precision))
                existing_properties["precision"] = _more_conservative_precision(existing_precision, precision)
                if "confidence" in existing_properties:
                    existing_properties["confidence"] = min(float(existing_properties["confidence"]), f.confidence)

    sarif_results: list[dict] = []
    for result in results:
        for f in result.sorted_findings():
            rule_id = f.effective_rule_id
            physical: dict[str, Any] = {
                "artifactLocation": {
                    "uri": (result.file_path or "").lstrip("/\\"),
                    "uriBaseId": "%SRCROOT%",
                },
            }
            if f.line:
                physical["region"] = {
                    "startLine": f.line,
                    "startColumn": 1,
                }
            sarif_results.append({
                "ruleId": rule_id,
                "level": _SARIF_LEVEL.get(f.severity.value, "warning"),
                "message": {"text": f.description},
                "locations": [{
                    "physicalLocation": physical,
                }],
                **({"codeFlows": [_trace_to_sarif_codeflow(result.file_path, f)]} if f.trace else {}),
                "partialFingerprints": {
                    "primaryLocationLineHash": _finding_fingerprint(result.file_path, f),
                },
                "properties": {
                    "ruleId": rule_id,
                    "category": f.category,
                    "cwe": f.cwe,
                    "findingClass": f.finding_class,
                    "confidence": f.confidence,
                    "analysisKind": f.analysis_kind,
                    "suggestion": f.suggestion,
                    "autoFix": f.auto_fix,
                },
            })

    sarif: dict[str, Any] = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ansede-static",
                    "version": get_engine_version(),
                    "informationUri": "https://github.com/ansede/ansede-static",
                    "rules": list(rules_by_id.values()),
                }
            },
            "results": sarif_results,
            "automationDetails": {
                "id": "ansede-static/",
            },
        }],
    }
    return _json.dumps(sarif, indent=2, default=str)


def _finding_fingerprint(file_path: str, finding: Finding) -> str:
    payload = f"{file_path}|{finding.line}|{finding.effective_rule_id}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _trace_to_sarif_codeflow(file_path: str, finding: Finding) -> dict[str, Any]:
    locations: list[dict[str, Any]] = []
    for frame in finding.trace:
        physical_location: dict[str, Any] = {
            "artifactLocation": {
                "uri": (file_path or "").lstrip("/\\"),
                "uriBaseId": "%SRCROOT%",
            },
        }
        if frame.line:
            physical_location["region"] = {
                "startLine": frame.line,
                "startColumn": frame.start_column,
            }
        locations.append({
            "location": {
                "physicalLocation": physical_location,
                "message": {"text": frame.label},
            },
            "importance": "essential" if frame.kind in {"source", "sink"} else "important",
        })
    return {
        "threadFlows": [{
            "locations": locations,
        }],
    }


def _sarif_precision(confidence: float) -> str:
    if confidence >= 0.95:
        return "high"
    if confidence >= 0.8:
        return "medium"
    return "low"


def _more_conservative_precision(existing: str, new: str) -> str:
    existing_order = _SARIF_PRECISION_ORDER.get(existing, _SARIF_PRECISION_ORDER["medium"])
    new_order = _SARIF_PRECISION_ORDER.get(new, _SARIF_PRECISION_ORDER["medium"])
    return existing if existing_order <= new_order else new

def _cwe_help_uri(cwe: str) -> str:
    if not cwe:
        return "https://cwe.mitre.org/"
    return f"https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html"


def _cwe_to_cvss(cwe: str) -> str:
    """Return a rough CVSS-equivalent score string for SARIF tag."""
    severe = {"CWE-78", "CWE-89", "CWE-95", "CWE-502", "CWE-798", "CWE-287", "CWE-285"}
    high   = {"CWE-918", "CWE-22", "CWE-639", "CWE-79", "CWE-345"}
    if cwe in severe:
        return "9.8"
    if cwe in high:
        return "8.1"
    return "5.5"
