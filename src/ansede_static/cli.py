"""
ansede_static.cli
─────────────────
Command-line interface for ansede-static.

    ansede-static path/to/file.py
    ansede-static src/ --format sarif --output results.sarif
    ansede-static --stdin --lang python < app.py
    ansede-static src/ --fail-on high

Zero external dependencies — pure stdlib only.
"""
from __future__ import annotations

import argparse
import json
import sys
import textwrap
import time
from pathlib import Path

from ansede_static._types import AnalysisResult, Finding, Severity
from ansede_static.python_analyzer import analyze_python
from ansede_static.js_analyzer import analyze_js
from ansede_static.reporters import format_text_multi, format_json, format_sarif, format_ciso_report
from ansede_static import _PYTHON_EXTS, _JS_EXTS

from ansede_static.ir.global_graph import GlobalGraph
from ansede_static.engine.triage import run_ai_triage

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.panel import Panel
    console = Console()
except ImportError:
    console = None
    Progress = None

def _detect_language(path: Path) -> str | None:
    ext = path.suffix.lower()
    if ext in _PYTHON_EXTS:
        return "python"
    if ext in _JS_EXTS:
        return "javascript"
    return None


def _collect_files(paths: list[Path], exclude_patterns: list[str]) -> list[Path]:
    """Recursively expand directories into individual source files."""
    files: list[Path] = []
    for p in paths:
        if p.is_file():
            if _detect_language(p):
                files.append(p)
        elif p.is_dir():
            for child in sorted(p.rglob("*")):
                if not child.is_file():
                    continue
                if _detect_language(child) is None:
                    continue
                # Skip excluded paths
                rel = str(child)
                if any(pat in rel for pat in exclude_patterns):
                    continue
                files.append(child)
    return files


def _analyze_file(path: Path) -> AnalysisResult:
    lang = _detect_language(path)
    try:
        code = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        result = AnalysisResult(file_path=str(path), language=lang or "unknown")
        result.parse_error = str(exc)
        return result

    if lang == "python":
        return analyze_python(code, filename=str(path))
    elif lang == "javascript":
        return analyze_js(code, filename=str(path))
    else:
        return AnalysisResult(file_path=str(path), language="unknown")


def _should_fail(results: list[AnalysisResult], fail_on: str) -> bool:
    """Return True if any finding is at or above the fail_on severity."""
    thresholds: dict[str, int] = {
        "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4
    }
    threshold = thresholds.get(fail_on.lower(), 1)
    for r in results:
        for f in r.findings:
            if f.severity.sort_key <= threshold:
                return True
    return False


def _finding_fingerprint(file_path: str, f: "Finding") -> str:
    """Generate a stable fingerprint for a finding (for baseline diffing)."""
    if f.rule_id:
        return f"rule:{f.rule_id}|{file_path}|{f.line}"
    cwe = f.cwe or ""
    title = f.title[:60].lower()
    return f"legacy:{cwe}|{title}|{file_path}|{f.line}"


def _finding_fingerprints(file_path: str, f: "Finding") -> set[str]:
    """Generate both stable and legacy fingerprints for backwards-compatible baselines."""
    fingerprints: set[str] = set()
    if f.rule_id:
        fingerprints.add(f"rule:{f.rule_id}|{file_path}|{f.line}")
    cwe = f.cwe or ""
    title = f.title[:60].lower()
    fingerprints.add(f"legacy:{cwe}|{title}|{file_path}|{f.line}")
    return fingerprints


def _load_baseline(path: Path) -> set[str]:
    """Load a baseline JSON file and return a set of fingerprints."""
    data = json.loads(path.read_text(encoding="utf-8"))
    fingerprints: set[str] = set()
    results_list = data.get("results", data) if isinstance(data, dict) else data
    if isinstance(results_list, list):
        for entry in results_list:
            fp = entry.get("file_path", entry.get("file", ""))
            for finding in entry.get("findings", []):
                rule_id = finding.get("rule_id", "")
                cwe = finding.get("cwe", "")
                title = finding.get("title", "")[:60].lower()
                line = finding.get("line", 0)
                if rule_id:
                    fingerprints.add(f"rule:{rule_id}|{fp}|{line}")
                fingerprints.add(f"legacy:{cwe}|{title}|{fp}|{line}")
    return fingerprints


def _apply_baseline(results: list[AnalysisResult], baseline: set[str]) -> list[AnalysisResult]:
    """Remove findings already present in the baseline."""
    for r in results:
        r.findings = [
            f for f in r.findings
            if _finding_fingerprints(r.file_path, f).isdisjoint(baseline)
        ]
    return results


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ansede-static",
        description="Zero-dependency SAST scanner for Python and JavaScript",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              ansede-static app.py
              ansede-static src/ tests/
              ansede-static src/ --format json --output report.json
              ansede-static src/ --format sarif --output results.sarif
              ansede-static --stdin --lang python < app.py
              ansede-static src/ --fail-on high
              ansede-static src/ --exclude .venv --exclude __pycache__

            Exit codes:
              0   No findings at or above --fail-on severity (default: high)
              1   One or more findings at or above --fail-on severity
              2   Usage error or no files found
        """),
    )
    parser.add_argument(
        "paths", nargs="*", type=Path,
        metavar="PATH",
        help="File(s) or directory/directories to scan. Recursively scans directories.",
    )
    parser.add_argument(
        "--stdin", action="store_true",
        help="Read source code from stdin (requires --lang).",
    )
    parser.add_argument(
        "--lang", choices=["python", "javascript"],
        help="Force language detection (useful with --stdin).",
    )
    parser.add_argument(
        "--format", "-f", choices=["text", "json", "sarif", "ciso"], default="text",
        help="Output format (default: text). Use 'ciso' for executive summary.",
    )
    parser.add_argument(
        "--ai-triage", action="store_true",
        help="Enable Zero-False-Positive LLM Verification (requires active Ollama container).",
    )
    parser.add_argument(
        "--experimental-js-ast", action="store_true",
        help="Phase 1: Route JS/TS scanning to the new structurally-aware AST hybrid engine (Beta).",
    )
    parser.add_argument(
        "--output", "-o", type=Path, default=None, metavar="FILE",
        help="Write output to FILE instead of stdout.",
    )
    parser.add_argument(
        "--fail-on", default="high", metavar="SEVERITY",
        choices=["critical", "high", "medium", "low", "info", "never"],
        help="Exit with code 1 if any finding is at or above this severity (default: high).",
    )
    parser.add_argument(
        "--exclude", action="append", default=[], metavar="STRING",
        help="Skip files whose path contains STRING. Can be repeated.",
    )
    parser.add_argument(
        "--baseline", type=Path, default=None, metavar="FILE",
        help="Path to a JSON baseline report. Only new findings not in the baseline are reported.",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show finding descriptions and fix suggestions in text output.",
    )
    parser.add_argument(
        "--no-colour", "--no-color", dest="colour", action="store_false", default=True,
        help="Disable ANSI colour codes in text output.",
    )
    parser.add_argument(
        "--version", action="version",
        version=_get_version_str(),
    )
    return parser


def _get_version_str() -> str:
    try:
        from importlib.metadata import PackageNotFoundError
    except ImportError:
        PackageNotFoundError = Exception  # type: ignore[misc,assignment]
    try:
        from importlib.metadata import version
        v = version("ansede-static")
    except (ImportError, PackageNotFoundError):
        v = "dev"
    return f"ansede-static {v}"


def main() -> None:
    parser = build_parser()
    parser.add_argument(
        "--apply-fixes", action="store_true",
        help="Apply auto-fixes directly to the source files when possible (Warning: overwrites code)",
    )
    
    args = parser.parse_args()

    # Disable colour if not a tty or explicitly disabled
    colour = args.colour and sys.stdout.isatty()

    results: list[AnalysisResult] = []

    # ── stdin mode ─────────────────────────────────────────────────────────
    if args.stdin:
        if not args.lang:
            parser.error("--stdin requires --lang")
        code = sys.stdin.read()
        if args.lang == "python":
            results.append(analyze_python(code, filename="<stdin>"))
        else:
            results.append(analyze_js(code, filename="<stdin>"))

    # ── file/directory mode ────────────────────────────────────────────────
    elif args.paths:
        exclude_extra = [".venv", "node_modules", "__pycache__", ".git",
                         "site-packages", "dist", "build", ".tox"] + args.exclude
        files = _collect_files(args.paths, exclude_extra)
        if not files:
            if console:
                console.print(f"[bold red]ansede-static: no Python or JavaScript files found in: {', '.join(str(p) for p in args.paths)}[/bold red]")
            else:
                print(f"ansede-static: no Python or JavaScript files found in: {', '.join(str(p) for p in args.paths)}", file=sys.stderr)
            sys.exit(2)

        global_graph = GlobalGraph()
        
        # Two-Pass Orchestration with Rich UI
        if Progress and args.format == "text":
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                
                # Pass 1: Discovery & Graph Building (Stubbed in engine for now, preparing for next phase)
                discovery_task = progress.add_task("[cyan]Pass 1: Building Global Symbol Graph...", total=len(files))
                for fpath in files:
                    # index global references into global_graph here
                    lang = _detect_language(fpath)
                    try:
                        code = fpath.read_text(encoding="utf-8", errors="replace")
                        if lang == "python":
                            from ansede_static.python_analyzer import index_python_file
                            index_python_file(code, str(fpath), global_graph)
                        elif lang == "javascript":
                            # Future extension: index JS AST using oxc/tree-sitter
                            pass
                    except OSError:
                        pass
                    progress.advance(discovery_task)
                
                # Pass 2: Taint Engine Evaluation
                eval_task = progress.add_task("[yellow]Pass 2: Evaluating Taint Reachability...", total=len(files))
                for fpath in files:
                    # Pass the global_graph into analysis for inter-procedural queries
                    lang = _detect_language(fpath)
                    try:
                        code = fpath.read_text(encoding="utf-8", errors="replace")
                    except OSError as exc:
                        result = AnalysisResult(file_path=str(fpath), language=lang or "unknown")
                        result.parse_error = str(exc)
                        results.append(result)
                        progress.advance(eval_task)
                        continue

                    if lang == "python":
                        results.append(analyze_python(code, filename=str(fpath), global_graph=global_graph))
                    elif lang == "javascript":
                        if getattr(args, "experimental_js_ast", False):
                            from ansede_static.js_ast_analyzer import analyze_js_ast
                            results.append(analyze_js_ast(code, filename=str(fpath)))
                        else:
                            results.append(analyze_js(code, filename=str(fpath)))
                    else:
                        results.append(AnalysisResult(file_path=str(fpath), language="unknown"))
                        
                    progress.advance(eval_task)
        else:
            # Fallback for CI / non-text formats
            for fpath in files:
                results.append(_analyze_file(fpath))

    else:
        parser.print_help()
        sys.exit(0)

    # ── Apply baseline filter ───────────────────────────────────────────────
    if args.baseline:
        if not args.baseline.is_file():
            if console:
                console.print(f"[bold red]ansede-static: baseline file not found: {args.baseline}[/bold red]")
            else:
                print(f"ansede-static: baseline file not found: {args.baseline}", file=sys.stderr)
            sys.exit(2)
        baseline_fps = _load_baseline(args.baseline)
        results = _apply_baseline(results, baseline_fps)

    # ── AI Triage (Zero-False-Positive Phase) ──────────────────────────────
    if getattr(args, "ai_triage", False):
        code_map = {}
        for fpath in (files if args.paths else []):
            try:
                code_map[str(fpath)] = fpath.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
        results = run_ai_triage(results, code_map)

    # ── Offline Heuristic Auto-Remediation Engine (Explanations) ───────────
    from ansede_static.engine.explain import get_explanation
    for r in results:
        for f in r.findings:
            if f.cwe:
                f.explanation = get_explanation(f.cwe)

    # ── Format output ───────────────────────────────────────────────────────
    
    if getattr(args, "apply_fixes", False):
        if console:
            console.print("[bold yellow]🛠️  Applying Interactive Code Auto-Fixes...[/bold yellow]")
        for r in results:
            if not r.findings:
                continue
            try:
                with open(r.file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                lines = content.splitlines()
                modified = False
                # Sort descending by line number to avoid messing up offsets
                for finding in sorted(r.findings, key=lambda x: x.line or 0, reverse=True):
                    if finding.auto_fix and finding.line:
                        # Simple BEFORE/AFTER block parsing
                        if "BEFORE:" in finding.auto_fix and "AFTER:" in finding.auto_fix:
                            parts = finding.auto_fix.split("AFTER:", 1)
                            before = parts[0].replace("BEFORE:", "").strip()
                            after = parts[1].strip("\n ")
                            
                            idx = finding.line - 1
                            if 0 <= idx < len(lines) and before in lines[idx]:
                                lines[idx] = lines[idx].replace(before, after.replace("\n        ", "\n"))
                                modified = True
                                if console:
                                    console.print(f"  [green]✔ Fixed[/green] [bold]{finding.title}[/bold] in {r.file_path}:{finding.line}")
                
                if modified:
                    with open(r.file_path, "w", encoding="utf-8") as f:
                        f.write("\n".join(lines) + "\n")
            except Exception as e:
                if console:
                    console.print(f"  [red]✖ Failed to apply fixes[/red] to {r.file_path}: {e}")

    if args.format == "text":
        if console and sys.stdout.isatty():
             output = format_text_multi(results, colour=colour, verbose=args.verbose)
        else:
             output = format_text_multi(results, colour=colour, verbose=args.verbose)
    elif args.format == "json":
        output = format_json(results)
    elif args.format == "sarif":
        output = format_sarif(results)
    elif args.format == "ciso":
        output = format_ciso_report(results)
    else:
        output = format_text_multi(results, colour=colour, verbose=args.verbose)

    # ── Write output ────────────────────────────────────────────────────────
    if args.output:
        try:
            args.output.write_text(output, encoding="utf-8")
            if args.format == "text":
                total = sum(len(r.findings) for r in results)
                msg = f"ansede-static: {total} findings written to {args.output}"
                if console:
                    console.print(f"[bold green]✓[/bold green] {msg}")
                else:
                    print(msg)
        except OSError as exc:
            msg = f"ansede-static: cannot write to {args.output}: {exc}"
            if console:
                console.print(f"[bold red]{msg}[/bold red]")
            else:
                print(msg, file=sys.stderr)
            sys.exit(2)
    else:
        # For rich text formatter, the output string is usually empty because the reporter handles stdout rendering.
        # But for json and sarif, we must write to stdout buffer.
        if output:
            out_bytes = output.encode("utf-8", errors="replace")
            try:
                sys.stdout.buffer.write(out_bytes + b"\n")
                sys.stdout.buffer.flush()
            except AttributeError:
                print(output)

    # ── Exit code ───────────────────────────────────────────────────────────
    if args.fail_on != "never" and _should_fail(results, args.fail_on):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
