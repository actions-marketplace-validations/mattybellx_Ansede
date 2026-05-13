"""
tools.generate_scorecard
─────────────────────────
All-in-one scorecard command: unit tests, quality checks, and CVE recall.

    python tools/generate_scorecard.py
    python tools/generate_scorecard.py --output final_scorecard.json
    python tools/generate_scorecard.py --web-wild-report web_wild_current.json

This is the single entry-point recommended by the Phase 4 blueprint to
verify the engine's world-best claims in one shot.
"""

if __name__ != "__main__":
    raise ImportError("generate_scorecard is a standalone tool, not importable")

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import argparse
import json
import subprocess

PYTHON_EXE = Path(__file__).resolve().parent.parent / ".venv" / "Scripts" / "python.exe"
if not PYTHON_EXE.exists():
    # Try the workspace's venv
    candidates = [
        Path.cwd() / ".venv" / "Scripts" / "python.exe",
        Path(__file__).resolve().parent.parent / ".venv" / "bin" / "python",
    ]
    for c in candidates:
        if c.exists():
            PYTHON_EXE = c
            break
    if not PYTHON_EXE.exists():
        PYTHON_EXE = Path(sys.executable)


def _run(cmd: list[str], label: str) -> dict[str, object]:
    """Run a subcommand and return timing + success."""
    import time
    t0 = time.perf_counter()
    result = subprocess.run(
        [str(PYTHON_EXE), *cmd],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
    )
    elapsed = time.perf_counter() - t0
    return {
        "label": label,
        "command": " ".join(cmd),
        "exit_code": result.returncode,
        "elapsed_s": round(elapsed, 2),
        "stdout_tail": result.stdout.strip().split("\n")[-5:] if result.stdout.strip() else [],
        "stderr_tail": result.stderr.strip().split("\n")[-3:] if result.stderr.strip() else [],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="All-in-one Ansede scorecard generator")
    parser.add_argument("--output", type=Path, default=Path("final_scorecard.json"), metavar="FILE",
                        help="Output JSON path (default: final_scorecard.json)")
    parser.add_argument("--web-wild-report", type=Path, default=None, metavar="JSON",
                        help="Path to a web-wild harness report for noise quotient embedding")
    parser.add_argument("--skip-tests", action="store_true",
                        help="Skip the pytest regression suite")
    parser.add_argument("--skip-nvd", action="store_true",
                        help="Skip the CVE recall benchmark")
    parser.add_argument("--skip-quality", action="store_true",
                        help="Skip the quality benchmark")
    parser.add_argument("--skip-external", action="store_true",
                        help="Skip the external corpus benchmark")
    parser.add_argument("--json", action="store_true",
                        help="Print final scorecard JSON to stdout")
    args = parser.parse_args()

    steps: list[dict[str, object]] = []

    # 1. Full test suite
    if not args.skip_tests:
        steps.append(_run(["pytest", "tests", "-q", "--tb=short"], "pytest full suite"))

    # 2. CVE recall
    if not args.skip_nvd:
        steps.append(_run(["-m", "benchmarks.nvd_benchmark", "--quiet"], "CVE recall (NVD benchmark)"))

    # 3. Quality benchmark
    if not args.skip_quality:
        steps.append(_run(["-m", "benchmarks.quality_benchmark", "--fail-under", "100"], "Quality benchmark"))

    # 4. External corpus
    if not args.skip_external:
        steps.append(_run(
            ["-m", "benchmarks.external_corpus", "--manifest", "benchmarks/external_manifest.json", "--fail-under", "100"],
            "External corpus benchmark",
        ))

    # 5. Generate final scorecard JSON
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from benchmarks.final_scorecard import generate_final_scorecard
    scorecard = generate_final_scorecard(
        external_manifest="benchmarks/external_manifest.json",
        web_wild_report=args.web_wild_report,
    )

    # Embellish with run metadata
    scorecard["run_metadata"] = {
        "python": sys.version.split()[0],
        "steps": steps,
        "all_steps_passed": all(int(s.get("exit_code", 1) or 0) == 0 for s in steps),
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(scorecard, indent=2), encoding="utf-8")
    print(f"Scorecard written to {args.output}")

    # Summary
    passed = sum(1 for s in steps if int(s.get("exit_code", 1) or 0) == 0)
    total = len(steps)
    print(f"\nSteps: {passed}/{total} passed")

    if args.json:
        print(json.dumps(scorecard, indent=2))


if __name__ == "__main__":
    main()
