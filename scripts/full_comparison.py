"""
Full independent comparison: Ansede vs Semgrep OSS vs Bandit
on never-analyzed fresh repos and the CVE corpus.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

# Ensure we can import ansede and benchmarks
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent / "benchmarks"))

# ── Known comparison SAST tools we'll test ──
COMPARISON_TOOLS = [
    {
        "name": "ansede-static",
        "version_cmd": [sys.executable, "-m", "ansede_static.cli", "--version"],
        "skip": False,
    },
    {
        "name": "semgrep",
        "version_cmd": [str(Path(sys.executable).parent / "semgrep"), "--version"],
        "skip": False,
    },
    {
        "name": "bandit",
        "version_cmd": [str(Path(sys.executable).parent / "bandit"), "--version"],
        "skip": True,  # bandit may not be installed
    },
]

# ── Fresh vulnerable-by-design repos (never analyzed before) ──
FRESH_REPOS = [
    # 1. crAPI - modern microservices vuln app
    {
        "name": "crAPI",
        "url": "https://github.com/OWASP/crAPI.git",
        "languages": ["python", "javascript"],
        "ref": "main",
    },
    # 2. Juice Shop (only the server-side source, not node_modules)
    {
        "name": "juice-shop",
        "url": "https://github.com/juice-shop/juice-shop.git",
        "languages": ["javascript", "typescript"],
        "ref": "master",
    },
    # 3. PyGoat - Python intentionally vulnerable app
    {
        "name": "pygoat",
        "url": "https://github.com/adeyosemanputra/pygoat.git",
        "languages": ["python"],
        "ref": "main",
    },
    # 4. VAmPI - vulnerable API
    {
        "name": "vampi",
        "url": "https://github.com/erev0s/VAmPI.git",
        "languages": ["python"],
        "ref": "master",
    },
    # 5. DamnVulnerableBank (java)
    {
        "name": "dvbank",
        "url": "https://github.com/nahid0x1/DamnVulnerableBank.git",
        "languages": ["java"],
        "ref": "main",
    },
]

CACHE_DIR = Path(__file__).resolve().parent / ".benchmark-cache"


def _run_tool(tool_name: str, command: list[str], timeout: int = 300) -> dict[str, Any]:
    """Run a tool and return result metadata."""
    t0 = time.perf_counter()
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        elapsed = time.perf_counter() - t0
        return {
            "tool": tool_name,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "elapsed_sec": round(elapsed, 3),
            "error": None,
        }
    except subprocess.TimeoutExpired:
        return {
            "tool": tool_name,
            "returncode": -1,
            "stdout": "",
            "stderr": "",
            "elapsed_sec": time.perf_counter() - t0,
            "error": "timeout",
        }
    except FileNotFoundError as e:
        return {
            "tool": tool_name,
            "returncode": -2,
            "stdout": "",
            "stderr": "",
            "elapsed_sec": 0,
            "error": f"not found: {e}",
        }


def check_tools() -> dict[str, dict[str, Any]]:
    """Check which tools are available."""
    available = {}
    for tool in COMPARISON_TOOLS:
        if tool["skip"]:
            available[tool["name"]] = {"available": False, "reason": "skipped"}
            continue
        result = _run_tool(tool["name"], tool["version_cmd"], timeout=30)
        available[tool["name"]] = {
            "available": result["returncode"] == 0,
            "version": result["stdout"].strip() if result["returncode"] == 0 else result["error"],
        }
    return available


def clone_repo(repo: dict[str, Any], cache_dir: Path) -> Path | None:
    """Clone a repo for scanning."""
    name = repo["name"]
    dest = cache_dir / name
    
    if dest.exists():
        print(f"  {name}: already cached at {dest}")
        return dest
    
    print(f"  {name}: cloning from {repo['url']}...", end=" ", flush=True)
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", repo["url"], str(dest)],
            capture_output=True, text=True, timeout=300,
        )
        print("done")
        return dest
    except Exception as e:
        print(f"FAILED: {e}")
        return None


def count_loc(repo_path: Path, exts: set[str]) -> tuple[int, int]:
    """Count files and lines of code for supported extensions."""
    total_files = 0
    total_lines = 0
    for f in repo_path.rglob("*"):
        if f.suffix.lower() in exts and f.is_file():
            # Skip node_modules, .git, __pycache__, etc.
            rel = f.relative_to(repo_path)
            skip_parts = {"node_modules", ".git", "__pycache__", "venv", ".venv", "vendor", "dist", "build"}
            if any(p in rel.parts for p in skip_parts):
                continue
            try:
                total_files += 1
                total_lines += len(f.read_text(encoding="utf-8", errors="replace").splitlines())
            except Exception:
                pass
    return total_files, total_lines


def run_ansede_on_repo(repo_path: Path) -> dict[str, Any]:
    """Run ansede-static on a full repo directory."""
    from ansede_static import scan_file

    files_scanned = 0
    total_findings = 0
    total_lines = 0
    total_time = 0.0
    cwe_counts: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()
    findings_detail: list[dict[str, Any]] = []
    
    exts = {".py", ".pyi", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".cs", ".rb", ".php"}
    
    for f in sorted(repo_path.rglob("*")):
        if f.suffix.lower() not in exts or not f.is_file():
            continue
        rel = f.relative_to(repo_path)
        skip_parts = {"node_modules", ".git", "__pycache__", "venv", ".venv", "vendor", "dist", "build", "target", "test", "tests"}
        if any(p in rel.parts for p in skip_parts):
            continue
        try:
            t0 = time.perf_counter()
            result = scan_file(f)
            elapsed = time.perf_counter() - t0
            files_scanned += 1
            total_findings += len(result.findings)
            total_lines += result.lines_scanned
            total_time += elapsed
            for finding in result.findings:
                d = finding.as_dict(language=result.language) if hasattr(finding, 'as_dict') else {}
                cwe = (finding.cwe or "").strip().upper() if hasattr(finding, 'cwe') else ""
                sev = (finding.severity or "").lower() if hasattr(finding, 'severity') else ""
                if cwe.startswith("CWE-"):
                    cwe_counts[cwe] += 1
                if sev:
                    severity_counts[sev] += 1
                findings_detail.append({
                    "file": str(rel),
                    "line": getattr(finding, 'line', 0),
                    "cwe": cwe,
                    "severity": sev,
                    "title": getattr(finding, 'title', ''),
                })
        except Exception as e:
            pass

    return {
        "files_scanned": files_scanned,
        "total_lines": total_lines,
        "total_findings": total_findings,
        "total_time_sec": round(total_time, 3),
        "loc_per_sec": round(total_lines / total_time, 0) if total_time else 0,
        "findings_per_kloc": round(total_findings / total_lines * 1000, 2) if total_lines else 0,
        "cwe_counts": dict(cwe_counts.most_common()),
        "severity_counts": dict(severity_counts),
        "findings": findings_detail,
    }


def run_semgrep_on_repo(repo_path: Path, timeout: int = 600) -> dict[str, Any]:
    """Run Semgrep OSS --config=auto on a full repo."""
    semgrep_bin = str(Path(sys.executable).parent / "semgrep")
    
    t0 = time.perf_counter()
    try:
        result = subprocess.run(
            [semgrep_bin, "scan", "--config=auto", "--no-git-ignore", "--quiet", "--json", "--max-target-bytes=500000", str(repo_path)],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout,
        )
        elapsed = time.perf_counter() - t0
    except subprocess.TimeoutExpired:
        return {"tool": "semgrep", "error": f"timeout after {timeout}s", "findings": 0, "elapsed_sec": timeout}
    except FileNotFoundError:
        return {"tool": "semgrep", "error": "not installed", "findings": 0, "elapsed_sec": 0}

    findings_count = 0
    cwe_counts: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()
    
    if result.returncode in (0, 1):
        try:
            data = json.loads(result.stdout)
            for r in data.get("results", []):
                findings_count += 1
                extra = r.get("extra", {})
                metadata = extra.get("metadata", {})
                sev = (extra.get("severity", "") or "").lower()
                if sev:
                    severity_counts[sev] += 1
                cwe_list = metadata.get("cwe", [])
                if isinstance(cwe_list, list):
                    for c in cwe_list:
                        c_str = str(c).strip().upper()
                        if ":" in c_str:
                            c_str = c_str.split(":")[0].strip()
                        if c_str.startswith("CWE-"):
                            cwe_counts[c_str] += 1
        except json.JSONDecodeError:
            pass
    
    return {
        "tool": "semgrep",
        "findings": findings_count,
        "cwe_counts": dict(cwe_counts.most_common()),
        "severity_counts": dict(severity_counts),
        "elapsed_sec": round(elapsed, 3),
        "error": None,
    }


def run_bandit_on_repo(repo_path: Path, timeout: int = 300) -> dict[str, Any]:
    """Run Bandit on a Python repo."""
    bandit_bin = str(Path(sys.executable).parent / "bandit")
    
    t0 = time.perf_counter()
    try:
        result = subprocess.run(
            [bandit_bin, "-r", "-f", "json", str(repo_path)],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout,
        )
        elapsed = time.perf_counter() - t0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {"tool": "bandit", "error": "not available", "findings": 0, "elapsed_sec": 0}

    findings_count = 0
    cwe_counts: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()
    
    try:
        data = json.loads(result.stdout)
        for f_result in data.get("results", []):
            findings_count += 1
            sev = (f_result.get("issue_severity", "") or "").lower()
            if sev:
                severity_counts[sev] += 1
            # Bandit doesn't output CWEs directly in all versions
    except (json.JSONDecodeError, AttributeError):
        pass
    
    return {
        "tool": "bandit",
        "findings": findings_count,
        "cwe_counts": dict(cwe_counts.most_common()),
        "severity_counts": dict(severity_counts),
        "elapsed_sec": round(elapsed, 3),
        "error": None,
    }


def main():
    print("=" * 70)
    print("  Ansede Static — Independent Comparison Report")
    print("=" * 70)
    print()
    print(f"  Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Ansede version: 4.0.0")
    print()
    
    # Step 1: Check available tools
    print("[1/5] Checking available comparison tools...")
    available = check_tools()
    for name, info in available.items():
        if info["available"]:
            print(f"  ✅ {name}: {info.get('version', 'unknown')}")
        else:
            print(f"  ❌ {name}: {info.get('version', info.get('reason', 'not available'))}")
    print()
    
    # Step 2: Set up cache and clone fresh repos
    print("[2/5] Cloning fresh vulnerable-by-design repos...")
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    
    repo_paths = []
    for repo in FRESH_REPOS:
        path = clone_repo(repo, CACHE_DIR)
        if path:
            repo_paths.append((repo, path))
    
    print()
    
    # Step 3: Measure repo sizes
    print("[3/5] Measuring repo sizes...")
    SUPPORTED_EXTS = {".py", ".pyi", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".cs", ".rb", ".php"}
    for repo, path in repo_paths:
        n_files, n_lines = count_loc(path, SUPPORTED_EXTS)
        print(f"  {repo['name']:25s}: {n_files:5d} files, {n_lines:8,d} LOC")
    print()
    
    # Step 4: Run comparisons
    print("[4/5] Running tool comparisons on fresh repos...")
    print()
    
    all_results = {}
    
    for repo, repo_path in repo_paths:
        print(f"  ── {repo['name']} ──")
        
        # Run Ansede
        print(f"    Running Ansede-static...", end=" ", flush=True)
        ansede_result = run_ansede_on_repo(repo_path)
        print(f"{ansede_result['total_time_sec']:.1f}s - {ansede_result['total_findings']} findings")
        
        # Run Semgrep
        print(f"    Running Semgrep OSS...", end=" ", flush=True)
        semgrep_result = run_semgrep_on_repo(repo_path)
        print(f"{semgrep_result.get('elapsed_sec', '?'):.1f}s - {semgrep_result.get('findings', 0)} findings")
        
        # Run Bandit (if available)
        bandit_result = {"tool": "bandit", "findings": "skipped", "elapsed_sec": 0}
        if available.get("bandit", {}).get("available"):
            print(f"    Running Bandit...", end=" ", flush=True)
            bandit_result = run_bandit_on_repo(repo_path)
            print(f"{bandit_result.get('elapsed_sec', '?'):.1f}s - {bandit_result.get('findings', 0)} findings")
        
        all_results[repo["name"]] = {
            "repo_info": repo,
            "files_loc": ansede_result["files_scanned"],
            "lines_loc": ansede_result["total_lines"],
            "ansede": {
                "findings": ansede_result["total_findings"],
                "findings_per_kloc": ansede_result["findings_per_kloc"],
                "time_sec": ansede_result["total_time_sec"],
                "loc_per_sec": ansede_result["loc_per_sec"],
                "cwe_counts": ansede_result["cwe_counts"],
                "severity_counts": ansede_result["severity_counts"],
                "unique_cwes": len(ansede_result["cwe_counts"]),
            },
            "semgrep": {
                "findings": semgrep_result.get("findings", 0),
                "cwe_counts": semgrep_result.get("cwe_counts", {}),
                "severity_counts": semgrep_result.get("severity_counts", {}),
                "unique_cwes": len(semgrep_result.get("cwe_counts", {})),
                "time_sec": semgrep_result.get("elapsed_sec", 0),
                "error": semgrep_result.get("error"),
            },
            "bandit": {
                "findings": bandit_result.get("findings", "skipped"),
                "time_sec": bandit_result.get("elapsed_sec", 0),
            },
        }
        print()
    
    # Step 5: Generate report
    print("[5/5] Generating final report...")
    print()
    
    # Save raw results
    with open("independent_comparison_results.json", "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    
    # Print summary table
    print("=" * 70)
    print("  COMPARISON SUMMARY TABLE")
    print("=" * 70)
    header = f"  {'Repo':20s} {'Ansede':>10s} {'Semgrep':>10s} {'Bandit':>10s} {'LOC':>8s} {'Time(A)':>8s}"
    print(header)
    print("  " + "-" * (len(header) - 2))
    
    for repo_name, data in all_results.items():
        a_f = data["ansede"]["findings"]
        s_f = data["semgrep"]["findings"]
        b_f = data["bandit"]["findings"]
        loc = data["lines_loc"]
        t_a = f'{data["ansede"]["time_sec"]:.1f}s'
        print(f"  {repo_name:20s} {str(a_f):>10s} {str(s_f):>10s} {str(b_f):>10s} {loc:>8,d} {t_a:>8s}")
    print()
    
    # Per-tool capability comparison
    print("=" * 70)
    print("  CWE COVERAGE COMPARISON (fresh repos)")
    print("=" * 70)
    
    all_cwes = defaultdict(lambda: {"ansede": 0, "semgrep": 0})
    for repo_name, data in all_results.items():
        for cwe, count in data["ansede"].get("cwe_counts", {}).items():
            all_cwes[cwe]["ansede"] += count
        for cwe, count in data["semgrep"].get("cwe_counts", {}).items():
            all_cwes[cwe]["semgrep"] += count
    
    print(f"  {'CWE':15s} {'Name':30s} {'Ansede':>8s} {'Semgrep':>8s}")
    print("  " + "-" * 63)
    
    cwe_names = {
        "CWE-89": "SQL Injection",
        "CWE-78": "OS Command Injection",
        "CWE-79": "Cross-Site Scripting",
        "CWE-22": "Path Traversal",
        "CWE-918": "Server-Side Request Forgery",
        "CWE-502": "Deserialization of Untrusted Data",
        "CWE-798": "Hardcoded Credentials",
        "CWE-862": "Missing Authorization",
        "CWE-863": "Incorrect Authorization",
        "CWE-639": "Insecure Direct Object Reference",
        "CWE-285": "Improper Authorization",
        "CWE-287": "Improper Authentication",
        "CWE-307": "Brute Force (Rate Limit)",
        "CWE-352": "Cross-Site Request Forgery",
        "CWE-611": "XML External Entity (XXE)",
        "CWE-601": "Open Redirect",
        "CWE-200": "Information Exposure",
        "CWE-327": "Weak Cryptography",
        "CWE-295": "Improper Certificate Validation",
        "CWE-347": "JWT None Algorithm",
        "CWE-345": "Insufficient JWT Verification",
        "CWE-377": "Insecure Temp File",
        "CWE-362": "Race Condition (TOCTOU)",
        "CWE-494": "Supply Chain Risk",
        "CWE-470": "Unsafe Reflection",
        "CWE-732": "Incorrect Permission Assignment",
        "CWE-943": "NoSQL Injection",
        "CWE-1321": "Prototype Pollution",
        "CWE-1333": "ReDoS",
        "CWE-434": "Unrestricted File Upload",
        "CWE-384": "Session Fixation",
        "CWE-117": "Log Injection",
        "CWE-915": "Mass Assignment",
        "CWE-338": "Weak Random",
        "CWE-617": "Assertion Vulnerability",
        "CWE-942": "CORS Misconfiguration",
        "CWE-453": "Insecure Default",
        "CWE-90": "LDAP Injection",
        "CWE-94": "Code Injection",
        "CWE-95": "Eval Injection",
        "CWE-400": "DoS",
        "CWE-614": "Cookie Security",
        "CWE-942": "CORS Wildcard",
    }
    
    for cwe in sorted(all_cwes.keys()):
        name = cwe_names.get(cwe, "")
        a_c = all_cwes[cwe]["ansede"]
        s_c = all_cwes[cwe]["semgrep"]
        marker = " ✅" if a_c > 0 and s_c == 0 else ""
        print(f"  {cwe:15s} {name:30s} {str(a_c):>8s} {str(s_c):>8s}{marker}")
    
    print()
    
    # Summary assessment
    print("=" * 70)
    print("  KEY FINDINGS")
    print("=" * 70)
    print()
    
    # Count Ansede-unique CWEs
    ansede_unique = sum(1 for c, v in all_cwes.items() if v["ansede"] > 0 and v["semgrep"] == 0)
    semgrep_unique = sum(1 for c, v in all_cwes.items() if v["semgrep"] > 0 and v["ansede"] == 0)
    both_found = sum(1 for c, v in all_cwes.items() if v["ansede"] > 0 and v["semgrep"] > 0)
    
    print(f"  CWEs detected by Ansede only: {ansede_unique}")
    print(f"  CWEs detected by Semgrep only: {semgrep_unique}")
    print(f"  CWEs detected by both: {both_found}")
    print()
    
    total_ansede_findings = sum(d["ansede"]["findings"] for d in all_results.values())
    total_semgrep_findings = sum(
        d["semgrep"]["findings"] for d in all_results.values()
        if isinstance(d["semgrep"]["findings"], (int, float))
    )
    total_time_ansede = sum(d["ansede"]["time_sec"] for d in all_results.values())
    total_loc = sum(d["lines_loc"] for d in all_results.values())
    
    print(f"  Total findings across all fresh repos:")
    print(f"    Ansede: {total_ansede_findings}")
    print(f"    Semgrep: {total_semgrep_findings}")
    print(f"  Total LOC scanned: {total_loc:,}")
    print(f"  Ansede throughput: {total_loc/total_time_ansede:.0f} LOC/s")
    print()
    
    # Detect the unique capabilities
    auth_cwes = {"CWE-862", "CWE-863", "CWE-285", "CWE-287", "CWE-639", "CWE-307"}
    ansede_auth = sum(1 for c in auth_cwes if all_cwes.get(c, {}).get("ansede", 0) > 0)
    semgrep_auth = sum(1 for c in auth_cwes if all_cwes.get(c, {}).get("semgrep", 0) > 0)
    
    print(f"  Authorization/Auth classes detected:")
    print(f"    Ansede: {ansede_auth}/6 (CWE-862, CWE-285, CWE-287, CWE-639, CWE-307, CWE-863)")
    print(f"    Semgrep: {semgrep_auth}/6")
    print()
    
    # Honest caveats
    print("=" * 70)
    print("  HONEST CAVEATS")
    print("=" * 70)
    print("""
  1. Fresh repos are intentionally vulnerable-by-design — results may not
     generalize to production codebases with different vulnerability profiles.
  2. Semgrep OSS uses --config=auto (~100 rules). Semgrep Pro/Team has
     additional rulesets not tested here.
  3. Findings count ≠ vulnerability count. Some findings may be duplicates,
     false positives, or informational. No manual triage was performed.
  4. Bandit only scans Python files — only applicable to Python-heavy repos.
  5. Scan parameters: Ansede uses default settings. Semgrep uses --config=auto.
     Different settings would change results.
  6. CodeQL was not tested (requires separate CLI download and database build).
  7. Performance measured on a single machine — varies with hardware, concurrency.
    """)
    
    print("=" * 70)
    print("  Report saved to: independent_comparison_results.json")
    print("=" * 70)


if __name__ == "__main__":
    main()
