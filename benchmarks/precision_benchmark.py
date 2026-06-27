"""
precision_benchmark.py — Measures per-CWE false-positive rates on known-clean real repos.

Run: python -m ansede_static.benchmarks.precision_benchmark [--repos REPOS_JSON]

Produces: benchmarks/precision_results.json
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TMP_DIR = REPO_ROOT / "tmp"
RESULTS_DIR = REPO_ROOT / "benchmarks"

# Known-clean repos by language (these are well-maintained, low-vuln projects)
# Using small-to-medium repos for fast benchmarking
DEFAULT_TARGETS: dict[str, list[str]] = {
    "python": [
        "https://github.com/pallets/flask.git",
        "https://github.com/psf/requests.git",
    ],
    "javascript": [
        "https://github.com/expressjs/express.git",
        "https://github.com/lodash/lodash.git",
    ],
    "java": [
        "https://github.com/spring-projects/spring-petclinic.git",
    ],
    "csharp": [
        "https://github.com/ardalis/CleanArchitecture.git",
    ],
}

# CWEs that are known to produce high FP rates in certain contexts
# We track these separately for precision analysis
_TRACKED_CWES: frozenset[str] = frozenset({
    "CWE-78", "CWE-89", "CWE-98", "CWE-22", "CWE-79",
    "CWE-918", "CWE-601", "CWE-862", "CWE-352", "CWE-798",
    "CWE-1321", "CWE-1333", "CWE-328", "CWE-502",
})


def clone_or_pull(repo_url: str, target_dir: Path) -> bool:
    """Clone a repo or pull if it already exists."""
    if (target_dir / ".git").exists():
        result = subprocess.run(
            ["git", "-C", str(target_dir), "pull", "--ff-only"],
            capture_output=True, text=True,
        )
        return result.returncode == 0
    else:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, str(target_dir)],
            capture_output=True, text=True,
        )
        return result.returncode == 0


def scan_repo(repo_path: Path, language: str | None = None) -> dict:
    """Scan a repo and return parsed JSON results."""
    cmd = [
        sys.executable, "-m", "ansede_static.cli",
        str(repo_path),
        "--format", "json",
        "--fail-on", "never",
    ]
    if language:
        cmd.extend(["--language", language])

    start = time.perf_counter()
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT))
    elapsed = time.perf_counter() - start

    try:
        # Find JSON in stdout (it may have warnings mixed in)
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("{"):
                data = json.loads(line)
                data["_scan_time_s"] = round(elapsed, 2)
                return data
        # Try parsing the whole stdout
        data = json.loads(result.stdout)
        data["_scan_time_s"] = round(elapsed, 2)
        return data
    except json.JSONDecodeError:
        return {"error": "Failed to parse output", "stderr": result.stderr[:500],
                "_scan_time_s": round(elapsed, 2)}


def compute_precision_metrics(results: dict, repo_name: str) -> dict:
    """Compute per-CWE metrics from scan results."""
    cwe_counts: Counter[str] = Counter()
    total_files = 0
    total_lines = 0
    total_findings = 0

    for r in results.get("results", []):
        total_files += 1
        total_lines += r.get("lines_scanned", 0)
        for f in r.get("findings", []):
            cwe = f.get("cwe", "UNKNOWN")
            cwe_counts[cwe] += 1
            total_findings += 1

    return {
        "repo": repo_name,
        "files": total_files,
        "lines": total_lines,
        "findings": total_findings,
        "findings_per_1kloc": round(total_findings / max(total_lines, 1) * 1000, 2),
        "cwe_distribution": dict(cwe_counts.most_common()),
        "high_fp_cwes": {
            cwe: count for cwe, count in cwe_counts.items()
            if cwe in _TRACKED_CWES
        },
    }


def run_benchmark(targets: dict[str, list[str]] | None = None) -> dict:
    """Run the full precision benchmark across all languages."""
    if targets is None:
        targets = DEFAULT_TARGETS

    results: dict[str, list[dict]] = defaultdict(list)
    summary: dict[str, dict] = {}

    for language, repos in targets.items():
        print(f"\n{'='*60}")
        print(f"  Language: {language}")
        print(f"{'='*60}")

        for repo_url in repos:
            repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
            repo_dir = TMP_DIR / f"precision_{language}_{repo_name}"

            print(f"\n  Cloning {repo_name}...")
            if not clone_or_pull(repo_url, repo_dir):
                print(f"    FAILED to clone {repo_url}")
                continue

            print(f"  Scanning {repo_name}...")
            scan_data = scan_repo(repo_dir, language=language)

            if "error" in scan_data:
                print(f"    SCAN ERROR: {scan_data['error']}")
                continue

            metrics = compute_precision_metrics(scan_data, repo_name)
            metrics["language"] = language
            metrics["scan_time_s"] = scan_data.get("_scan_time_s", 0)

            results[language].append(metrics)

            fp_rate = metrics["findings_per_1kloc"]
            print(f"    {metrics['files']} files, {metrics['lines']:,} lines")
            print(f"    {metrics['findings']} findings ({fp_rate}/1kLOC)")
            print(f"    Time: {metrics['scan_time_s']:.1f}s")
            if metrics["high_fp_cwes"]:
                print(f"    Tracked CWEs: {metrics['high_fp_cwes']}")

    # Compute summary
    for language, lang_results in results.items():
        total_findings = sum(r["findings"] for r in lang_results)
        total_lines = sum(r["lines"] for r in lang_results)
        total_files = sum(r["files"] for r in lang_results)
        total_time = sum(r["scan_time_s"] for r in lang_results)

        # Aggregate CWE distribution
        cwe_agg: Counter[str] = Counter()
        for r in lang_results:
            cwe_agg.update(r["cwe_distribution"])

        summary[language] = {
            "repos_scanned": len(lang_results),
            "total_files": total_files,
            "total_lines": total_lines,
            "total_findings": total_findings,
            "fp_rate_per_1kloc": round(total_findings / max(total_lines, 1) * 1000, 2),
            "total_scan_time_s": round(total_time, 2),
            "throughput_loc_per_s": round(total_lines / max(total_time, 0.01)),
            "cwe_distribution": dict(cwe_agg.most_common(10)),
            "per_repo": [
                {
                    "repo": r["repo"],
                    "findings": r["findings"],
                    "fp_rate": r["findings_per_1kloc"],
                }
                for r in lang_results
            ],
        }

        print(f"\n  {language} SUMMARY: {summary[language]['total_findings']} findings "
              f"across {summary[language]['total_files']} files "
              f"({summary[language]['fp_rate_per_1kloc']}/1kLOC)")

    # Save results
    output_path = RESULTS_DIR / "precision_results.json"
    output = {
        "benchmark_version": "1.0.0",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "per_language": dict(results),
        "summary": dict(summary),
    }
    output_path.write_text(json.dumps(output, indent=2))

    # Also produce a short markdown report
    md_path = RESULTS_DIR / "precision_report.md"
    lines = [
        "# Precision Benchmark Report",
        f"Generated: {output['timestamp']}",
        "",
        "## Summary",
        "",
        "| Language | Repos | Files | Lines | Findings | FP/1kLOC | Time | LOC/s |",
        "|----------|-------|-------|-------|----------|----------|------|-------|",
    ]
    for lang, s in summary.items():
        lines.append(
            f"| {lang} | {s['repos_scanned']} | {s['total_files']} | "
            f"{s['total_lines']:,} | {s['total_findings']} | "
            f"{s['fp_rate_per_1kloc']} | {s['total_scan_time_s']:.1f}s | "
            f"{s['throughput_loc_per_s']:,} |"
        )
    lines.append("")
    lines.append("## Per-Repo Details")
    for lang, lang_results in results.items():
        lines.append(f"\n### {lang}")
        for r in lang_results:
            lines.append(f"- **{r['repo']}**: {r['findings']} findings, "
                         f"{r['findings_per_1kloc']}/1kLOC, {r['scan_time_s']:.1f}s")
            if r["high_fp_cwes"]:
                cwes = ", ".join(f"{k}:{v}" for k, v in sorted(r["high_fp_cwes"].items()))
                lines.append(f"  - Tracked: {cwes}")
    lines.append("")

    md_path.write_text("\n".join(lines))
    print(f"\nResults saved to {output_path}")
    print(f"Report saved to {md_path}")

    return output


if __name__ == "__main__":
    # Allow custom targets via JSON file
    import argparse
    ap = argparse.ArgumentParser(description="Precision benchmark for Ansede Static")
    ap.add_argument("--repos", help="JSON file with {language: [urls]} mapping")
    ap.add_argument("--quick", action="store_true", help="Only scan one small repo per language")
    args = ap.parse_args()

    targets = DEFAULT_TARGETS
    if args.repos:
        targets = json.loads(Path(args.repos).read_text())
    if args.quick:
        targets = {lang: [repos[0]] for lang, repos in targets.items()}

    run_benchmark(targets)
