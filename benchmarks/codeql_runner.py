"""
benchmarks.codeql_runner — Run CodeQL security queries on CVE corpus snippets.

Approach:
  1. Write all snippets for a language to a temp directory as individual files
  2. Create a single CodeQL database from that directory (source-only for Python/JS)
  3. Run security-extended query suite
  4. Parse SARIF output to detect which CVEs CodeQL catches
  5. Return structured results for 3-tool comparison
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import time as _time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))  # for benchmarks package imports

from cve_corpus import CVE_CORPUS, CVEEntry

_CODEQL_CLI = Path(os.environ.get("TEMP", "/tmp")) / "codeql" / "codeql" / "codeql.exe"

# Languages that support source-only database creation (no build required)
_SOURCE_ONLY_LANGS = {"python", "javascript"}

# Map cve_corpus language names to CodeQL language names
_LANG_MAP = {
    "python": "python",
    "javascript": "javascript",
    "go": "go",
    "java": "java",
    "csharp": "csharp",
}

_EXT_MAP = {
    "python": ".py",
    "javascript": ".js",
    "go": ".go",
    "java": ".java",
    "csharp": ".cs",
}


def _is_codeql_available() -> bool:
    return _CODEQL_CLI.exists()


def _codeql(*args: str, timeout: int = 300, **kwargs: Any) -> subprocess.CompletedProcess:
    """Run codeql CLI with given arguments."""
    cmd = [str(_CODEQL_CLI), *args]
    env = os.environ.copy()
    env["CODEQL_SUITES_PATH"] = str(Path.home() / ".codeql" / "packages")
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, env=env, **kwargs,
    )


def _security_suite_path(language: str) -> str | None:
    """Get the path to the security-extended query suite for a language."""
    lang = _LANG_MAP.get(language)
    if not lang:
        return None

    pack_dir = Path.home() / ".codeql" / "packages" / "codeql" / f"{lang}-queries"
    if not pack_dir.exists():
        # Find latest version
        candidates = sorted(pack_dir.parent.glob(f"{lang}-queries/*"), reverse=True)
        if not candidates:
            return None
        pack_dir = candidates[0]

    suites = list(pack_dir.rglob(f"{lang}-security-extended.qls"))
    if not suites:
        # Try codeql-suites directory
        suites = list(pack_dir.rglob("codeql-suites/*security-extended*"))
    return str(suites[0]) if suites else None


def _write_snippets(snippets: list[tuple[str, str, str]], output_dir: Path) -> dict[str, str]:
    """Write snippets to a temp directory. Returns {cve_id: file_path}."""
    file_map: dict[str, str] = {}
    for cve_id, language, snippet in snippets:
        ext = _EXT_MAP.get(language, ".txt")
        safe_id = re.sub(r'[^a-zA-Z0-9_-]', '_', cve_id)
        file_path = output_dir / f"{safe_id}{ext}"
        file_path.write_text(snippet, encoding="utf-8")
        file_map[cve_id] = str(file_path)
    return file_map


def run_codeql_on_language(
    language: str,
    *,
    timeout: int = 600,
) -> list[dict[str, Any]]:
    """Run CodeQL security-extended analysis on all CVE snippets for a language.

    Returns a list of results, one per CVE entry, with detection info.
    """
    if not _is_codeql_available():
        return [{"tool": "codeql", "error": "CodeQL CLI not found"}]

    suite = _security_suite_path(language)
    if not suite:
        return [{"tool": "codeql", "error": f"No security-extended suite for {language}"}]

    # Collect all CVE entries for this language
    cve_entries = [e for e in CVE_CORPUS if e.language == language]
    if not cve_entries:
        return [{"tool": "codeql", "language": language, "error": f"No CVE entries for {language}"}]

    # Create temp workspace
    with tempfile.TemporaryDirectory(prefix=f"codeql_cve_{language}_") as tmp_dir:
        tmp = Path(tmp_dir)
        source_dir = tmp / "src"
        source_dir.mkdir()

        # Write all snippets
        snippets = [(e.cve_id, e.language, e.snippet) for e in cve_entries]
        file_map = _write_snippets(snippets, source_dir)

        db_dir = tmp / "db"
        results_file = tmp / "results.sarif"

        # ── Step 1: Create database ──
        print(f"  Creating CodeQL database for {language} ({len(cve_entries)} snippets)...", file=sys.stderr)
        t0 = _time.perf_counter()

        codeql_lang = _LANG_MAP.get(language, language)
        print(f"  Command: codeql database create --language {codeql_lang} --source-root {source_dir} {db_dir}", file=sys.stderr)
        try:
            result = _codeql(
                "database", "create",
                "--language", codeql_lang,
                "--source-root", str(source_dir),
                str(db_dir),
                timeout=timeout,
            )
            db_time = _time.perf_counter() - t0
            print(f"  stdout: {result.stdout[:500]}", file=sys.stderr)
            print(f"  stderr: {result.stderr[:500]}", file=sys.stderr)
            if result.returncode != 0:
                return [{
                    "tool": "codeql",
                    "language": language,
                    "error": f"Database creation failed: {result.stderr[:500]}",
                    "stderr": result.stderr[:1000],
                }]
            print(f"  Database created in {db_time:.1f}s", file=sys.stderr)
        except subprocess.TimeoutExpired:
            return [{
                "tool": "codeql",
                "language": language,
                "error": f"Database creation timed out after {timeout}s",
            }]
        except FileNotFoundError:
            return [{"tool": "codeql", "language": language, "error": "CodeQL CLI not found"}]

        # ── Step 2: Run analysis ──
        print(f"  Running security-extended queries for {language}...", file=sys.stderr)
        t1 = _time.perf_counter()
        try:
            result = _codeql(
                "database", "analyze",
                str(db_dir),
                str(suite),
                "--format", "sarif-latest",
                "--output", str(results_file),
                "--quiet",
                timeout=timeout,
            )
            analyze_time = _time.perf_counter() - t1
            if result.returncode != 0:
                return [{
                    "tool": "codeql",
                    "language": language,
                    "error": f"Analysis failed: {result.stderr[:500]}",
                    "stderr": result.stderr[:1000],
                }]
            print(f"  Analysis complete in {analyze_time:.1f}s", file=sys.stderr)
        except subprocess.TimeoutExpired:
            return [{
                "tool": "codeql",
                "language": language,
                "error": f"Analysis timed out after {timeout}s",
            }]

        # ── Step 3: Parse SARIF ──
        print(f"  Parsing SARIF results...", file=sys.stderr)
        # Save SARIF for inspection (but don't error if copy fails)
        try:
            import shutil
            debug_sarif = Path(tempfile.gettempdir()) / f"codeql_{language}_sarif.json"
            shutil.copy2(str(results_file), str(debug_sarif))
        except Exception:
            pass
        return _parse_sarif_results(results_file, cve_entries, file_map, language)


def _parse_sarif_results(
    sarif_path: Path,
    cve_entries: list[CVEEntry],
    file_map: dict[str, str],
    language: str,
) -> list[dict[str, Any]]:
    """Parse SARIF output and match results back to CVE entries."""
    try:
        sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, FileNotFoundError) as e:
        return [{"tool": "codeql", "language": language, "error": f"SARIF parse failed: {e}"}]

    runs = sarif.get("runs", [])
    if not runs:
        return [{"tool": "codeql", "language": language, "error": "No runs in SARIF output"}]

    # Build per-file result map: {filename: [result dicts]}
    file_results: dict[str, list[dict[str, Any]]] = {}

    # Build a CWE map from rule definitions
    rule_cwe_map: dict[str, str] = {}
    for run in runs:
        tool_driver = run.get("tool", {}).get("driver", {})
        for rule_def in tool_driver.get("rules", []):
            rule_id = rule_def.get("id", "")
            rule_props = rule_def.get("properties", {})
            # CodeQL stores CWE in tags like "external/cwe/cwe-089", "external/cwe/cwe-078"
            tags = rule_props.get("tags", []) if isinstance(rule_props.get("tags"), list) else []
            for tag in tags:
                tag_str = str(tag).lower()
                # Match patterns: "external/cwe/cwe-089", "cwe-89", "CWE-89"
                m = re.search(r'(?:external/)?cwe[-_]?(\d+)', tag_str)
                if m:
                    cwe_num = m.group(1)
                    # Normalize: strip leading zeros so CWE-078 -> CWE-78
                    cwe_num_stripped = str(int(cwe_num))
                    rule_cwe_map[rule_id] = f"CWE-{cwe_num_stripped}"
                    break
            # Also check problem.severity and precision
            if rule_id not in rule_cwe_map:
                # Try to infer from kind
                kind = rule_props.get("kind", "")
                if kind == "problem":
                    rule_cwe_map[rule_id] = "CWE-unknown"

    for run in runs:
        results = run.get("results", [])
        for r in results:
            locations = r.get("locations", [])
            if not locations:
                continue
            phys_loc = locations[0].get("physicalLocation", {})
            art_loc = phys_loc.get("artifactLocation", {})
            uri = art_loc.get("uri", "")
            if not uri:
                continue
            fname = Path(uri).name

            # Extract CWE from rule
            rule_id = r.get("ruleId", "")
            message = r.get("message", {}).get("text", "")

            # Try to extract CWE from rule index if not already mapped
            if rule_id not in rule_cwe_map:
                rule_idx = r.get("rule", {}).get("index", -1)
                if rule_idx >= 0:
                    rules_list = run.get("tool", {}).get("driver", {}).get("rules", [])
                    if rule_idx < len(rules_list):
                        def_props = rules_list[rule_idx].get("properties", {})
                        def_tags = def_props.get("tags", []) if isinstance(def_props.get("tags"), list) else []
                        for tag in def_tags:
                            tag_str = str(tag).lower()
                            m = re.search(r'(?:external/)?cwe[-_]?(\d+)', tag_str)
                            if m:
                                cwe_num = m.group(1)
                                cwe_num_stripped = str(int(cwe_num))
                                rule_cwe_map[rule_id] = f"CWE-{cwe_num_stripped}"
                                break

            # Extract CWE from rule definition (more reliable than per-result props)
            cwe = rule_cwe_map.get(rule_id, "CWE-unknown")

            if fname not in file_results:
                file_results[fname] = []
            file_results[fname].append({
                "rule_id": rule_id,
                "message": message[:200],
                "cwe": cwe,
                "line": phys_loc.get("region", {}).get("startLine"),
            })

    # Map back to CVE entries
    output: list[dict[str, Any]] = []
    for entry in cve_entries:
        safe_id = re.sub(r'[^a-zA-Z0-9_-]', '_', entry.cve_id)
        fname = f"{safe_id}{_EXT_MAP.get(language, '.txt')}"

        hits = file_results.get(fname, [])

        # Check if any hit matches the expected CWE
        detected_cwes = sorted(set(h["cwe"] for h in hits))
        expected_pattern = re.compile(entry.expected_hit, re.IGNORECASE)

        detected = False
        for hit in hits:
            combined = f"{hit['rule_id']} {hit['message']} {hit['cwe']}"
            if expected_pattern.search(combined):
                detected = True
                break
            # Also check line number match
            if entry.sink_line and hit.get("line"):
                if abs(hit["line"] - entry.sink_line) <= 1:
                    if expected_pattern.search(hit["cwe"]):
                        detected = True
                        break

        output.append({
            "tool": "codeql",
            "cve_id": entry.cve_id,
            "language": language,
            "detected": detected,
            "total_findings": len(hits),
            "detected_cwes": detected_cwes,
            "detected_rules": sorted(set(h["rule_id"] for h in hits)),
            "error": None,
        })

    return output


def run_codeql_all_languages(
    languages: list[str] | None = None,
    *,
    timeout: int = 600,
) -> dict[str, list[dict[str, Any]]]:
    """Run CodeQL on all (or specified) languages and return results."""
    if languages is None:
        languages = list(_LANG_MAP.keys())

    all_results: dict[str, list[dict[str, Any]]] = {}
    for lang in languages:
        print(f"\n{'='*60}", file=sys.stderr)
        print(f"CodeQL: {lang}", file=sys.stderr)
        print(f"{'='*60}", file=sys.stderr)
        results = run_codeql_on_language(lang, timeout=timeout)
        all_results[lang] = results

        # Print summary
        total = len(results)
        detected = sum(1 for r in results if r.get("detected"))
        errors = sum(1 for r in results if r.get("error"))
        print(f"  {lang}: {detected}/{total} detected ({errors} errors)", file=sys.stderr)

    return all_results


if __name__ == "__main__":
    # Run on Python and JavaScript
    import sys as _sys
    langs = _sys.argv[1:] if len(_sys.argv) > 1 else ["python", "javascript"]
    print(f"CodeQL Runner — Testing {', '.join(langs)}...", file=sys.stderr)
    results = run_codeql_all_languages(langs, timeout=180)
    for lang, lang_results in results.items():
        detected = sum(1 for r in lang_results if r.get("detected"))
        total = len(lang_results)
        print(f"\n{lang}: {detected}/{total} detected", file=sys.stderr)
        for r in lang_results:
            if "error" in r and r["error"]:
                print(f"  ! {r.get('cve_id', 'N/A')}: ERROR - {r['error'][:100]}", file=sys.stderr)
            else:
                status = "✓" if r.get("detected") else "✗"
                print(f"  {status} {r['cve_id']}: {r.get('total_findings', 0)} findings  CWEs: {r.get('detected_cwes', [])}", file=sys.stderr)
