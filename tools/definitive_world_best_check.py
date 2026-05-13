from __future__ import annotations

"""
Deterministic, statistics-backed world-best claim checker for ansede-static.

What it does:
1) Runs benchmarks.world_best_report across multiple seeds (large web-wild samples).
2) Aggregates TP/FP/FN and computes Wilson 95% confidence intervals.
3) Runs curated real-world comparison baseline (ansede vs semgrep_style baseline).
4) Performs a paired sign test on per-case F1 deltas.
5) Emits a strict verdict: PROVEN on this benchmark, or NOT PROVEN.

This script cannot prove "best in the world" universally; it can only prove/disprove
that claim on the benchmark protocol executed here.
"""

import argparse
import json
import math
import sys
from pathlib import Path
from statistics import mean, pstdev
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from benchmarks.external_corpus import _git_cache_key, load_manifest
from benchmarks.real_world_compare import run_real_world_compare
from benchmarks.world_best_report import build_world_best_report


def _safe_div(n: float, d: float) -> float:
    return n / d if d else 0.0


def _f1(tp: int, fp: int, fn: int) -> float:
    p = _safe_div(tp, tp + fp)
    r = _safe_div(tp, tp + fn)
    return _safe_div(2.0 * p * r, p + r)


def _wilson_interval(successes: int, total: int, z: float = 1.959963984540054) -> tuple[float, float]:
    if total <= 0:
        return (0.0, 0.0)
    phat = successes / total
    z2 = z * z
    denom = 1.0 + z2 / total
    center = (phat + z2 / (2.0 * total)) / denom
    half = (z / denom) * math.sqrt((phat * (1.0 - phat) / total) + (z2 / (4.0 * total * total)))
    return (max(0.0, center - half), min(1.0, center + half))


def _binomial_two_sided_pvalue(wins: int, losses: int) -> float:
    n = wins + losses
    if n == 0:
        return 1.0
    k = min(wins, losses)
    # exact two-sided sign test for p=0.5
    tail = sum(math.comb(n, i) for i in range(0, k + 1)) / (2 ** n)
    return min(1.0, 2.0 * tail)


def _extract_web_counts(report: dict[str, Any]) -> tuple[int, int, int]:
    summary = (
        report.get("web_wild", {})
        .get("post_suppression", {})
        .get("summary", {})
    )
    return (
        int(summary.get("tp", 0) or 0),
        int(summary.get("fp", 0) or 0),
        int(summary.get("fn", 0) or 0),
    )


def _extract_cve_counts(report: dict[str, Any]) -> tuple[int, int, int]:
    summary = (
        report.get("cve", {})
        .get("post_suppression", {})
        .get("summary", {})
    )
    return (
        int(summary.get("tp", 0) or 0),
        int(summary.get("fp", 0) or 0),
        int(summary.get("fn", 0) or 0),
    )


def _extract_noise(report: dict[str, Any]) -> float:
    return float(report.get("honesty", {}).get("noise_quotient_findings_per_1k_loc", 0.0) or 0.0)


def _extract_gold_ready(report: dict[str, Any]) -> bool:
    return bool(report.get("honesty", {}).get("gold_ready", False))


def _preflight_compare_cache(*, compare_manifest: Path, compare_cache_dir: Path, compare_offline: bool) -> None:
    if not compare_offline:
        return

    manifest = load_manifest(compare_manifest)
    missing: list[str] = []
    for entry in manifest.entries:
        if entry.source.kind != "git":
            continue
        key = _git_cache_key(entry.source)
        checkout_dir = compare_cache_dir / key
        if not checkout_dir.exists():
            missing.append(f"{entry.case_id} -> {checkout_dir.name}")

    if missing:
        preview = "\n  - " + "\n  - ".join(missing[:8])
        if len(missing) > 8:
            preview += f"\n  - ... and {len(missing) - 8} more"
        raise RuntimeError(
            "Offline compare preflight failed: missing cached repos in compare cache dir"
            f"\ncache: {compare_cache_dir}"
            f"\nmanifest: {compare_manifest}"
            f"\nmissing:{preview}"
            "\n\nFix options:"
            "\n  1) Re-run without --compare-offline once to warm cache, or"
            "\n  2) pass --compare-cache-dir pointing at the warmed cache (e.g., .tmp/ansede-corpus)."
        )


def run_proof(
    *,
    runs: int,
    start_seed: int,
    web_n_files: int,
    web_min_labeled: int,
    web_cache_dir: Path,
    web_refresh_first: bool,
    web_offline: bool,
    web_max_file_bytes: int,
    web_severity_min: str,
    web_js_backend: str,
    suppression_min_occurrences: int,
    suppression_max_enable: int,
    suppression_cve_budget: int,
    compare_manifest: Path,
    compare_offline: bool,
    compare_cache_dir: Path | None,
    skip_compare: bool,
    output: Path,
    work_dir: Path,
) -> dict[str, Any]:
    work_dir.mkdir(parents=True, exist_ok=True)

    resolved_compare_cache = compare_cache_dir.resolve() if compare_cache_dir is not None else Path(".tmp/ansede-corpus").resolve()
    if not skip_compare:
        _preflight_compare_cache(
            compare_manifest=compare_manifest,
            compare_cache_dir=resolved_compare_cache,
            compare_offline=compare_offline,
        )

    seed_reports: list[dict[str, Any]] = []
    web_tps = web_fps = web_fns = 0
    cve_tps = cve_fps = cve_fns = 0
    noise_values: list[float] = []
    gold_ready_values: list[bool] = []

    print(f"[proof] Starting {runs} seed run(s) — n_files={web_n_files} min_labeled={web_min_labeled}", flush=True)

    for i in range(max(1, runs)):
        seed = start_seed + i
        print(f"[proof] Seed {i+1}/{runs} (seed={seed}): running world_best_report ...", flush=True)
        suppression_output = work_dir / f"suppression_seed_{seed}.json"
        report = build_world_best_report(
            web_n_files=web_n_files,
            web_min_labeled=web_min_labeled,
            web_seed=seed,
            web_cache_dir=web_cache_dir,
            web_refresh=(web_refresh_first and i == 0),
            web_offline=web_offline,
            web_max_file_bytes=web_max_file_bytes,
            web_severity_min=web_severity_min,
            web_js_backend=web_js_backend,
            suppression_output=suppression_output,
            suppression_min_occurrences=suppression_min_occurrences,
            suppression_max_enable=suppression_max_enable,
            suppression_cve_budget=suppression_cve_budget,
            quiet=True,
        )

        (wtp, wfp, wfn) = _extract_web_counts(report)
        (ctp, cfp, cfn) = _extract_cve_counts(report)
        noise = _extract_noise(report)
        gold = _extract_gold_ready(report)

        web_tps += wtp
        web_fps += wfp
        web_fns += wfn
        cve_tps += ctp
        cve_fps += cfp
        cve_fns += cfn
        noise_values.append(noise)
        gold_ready_values.append(gold)

        seed_record = {
            "seed": seed,
            "web": {
                "tp": wtp,
                "fp": wfp,
                "fn": wfn,
                "recall": round(100.0 * _safe_div(wtp, wtp + wfn), 2),
                "precision": round(100.0 * _safe_div(wtp, wtp + wfp), 2),
                "f1": round(100.0 * _f1(wtp, wfp, wfn), 2),
                "fp_rate": round(100.0 * _safe_div(wfp, wtp + wfp), 2),
            },
            "cve": {
                "tp": ctp,
                "fp": cfp,
                "fn": cfn,
                "recall": round(100.0 * _safe_div(ctp, ctp + cfn), 2),
                "precision": round(100.0 * _safe_div(ctp, ctp + cfp), 2),
                "f1": round(100.0 * _f1(ctp, cfp, cfn), 2),
                "fp_rate": round(100.0 * _safe_div(cfp, ctp + cfp), 2),
            },
            "noise_quotient_per_1k_loc": round(noise, 3),
            "gold_ready": gold,
            "report_file": str((work_dir / f"world_best_seed_{seed}.json").resolve()),
        }

        (work_dir / f"world_best_seed_{seed}.json").write_text(
            json.dumps(report, indent=2),
            encoding="utf-8",
        )
        seed_reports.append(seed_record)
        print(f"[proof] Seed {seed} done: web recall={seed_record['web']['recall']:.1f}% cve recall={seed_record['cve']['recall']:.1f}% gold={gold}", flush=True)

    web_recall_ci = _wilson_interval(web_tps, web_tps + web_fns)
    web_precision_ci = _wilson_interval(web_tps, web_tps + web_fps)
    web_fp_rate_ci = _wilson_interval(web_fps, web_tps + web_fps)

    cve_recall_ci = _wilson_interval(cve_tps, cve_tps + cve_fns)
    cve_precision_ci = _wilson_interval(cve_tps, cve_tps + cve_fps)
    cve_fp_rate_ci = _wilson_interval(cve_fps, cve_tps + cve_fps)

    if not skip_compare:
        print("[proof] Running real-world comparison ...", flush=True)
        compare_report: dict[str, Any] | None = run_real_world_compare(
            compare_manifest,
            cache_dir=resolved_compare_cache,
            offline=compare_offline,
            quiet=True,
        )
        print("[proof] Comparison done. Computing statistics ...", flush=True)

        ansede_cases = {
            str(c["case_id"]): c
            for c in compare_report["engines"]["ansede"]["cases"]
        }
        baseline_cases = {
            str(c["case_id"]): c
            for c in compare_report["engines"]["semgrep_style"]["cases"]
        }

        wins = losses = ties = 0
        paired_deltas: list[float] = []
        for case_id in sorted(set(ansede_cases.keys()) & set(baseline_cases.keys())):
            a = ansede_cases[case_id]
            b = baseline_cases[case_id]
            af1 = _f1(int(a["tp"]), int(a["fp"]), int(a["fn"]))
            bf1 = _f1(int(b["tp"]), int(b["fp"]), int(b["fn"]))
            delta = af1 - bf1
            paired_deltas.append(delta)
            if delta > 0:
                wins += 1
            elif delta < 0:
                losses += 1
            else:
                ties += 1

        p_value = _binomial_two_sided_pvalue(wins, losses)
        ansede_summary = compare_report["engines"]["ansede"]["summary"]
        baseline_summary = compare_report["engines"]["semgrep_style"]["summary"]
        compare_block: dict[str, Any] = {
            "ansede_summary": ansede_summary,
            "baseline_summary": baseline_summary,
            "delta": compare_report.get("delta", {}),
            "paired_sign_test": {
                "wins": wins,
                "losses": losses,
                "ties": ties,
                "n_non_ties": wins + losses,
                "p_value_two_sided": round(p_value, 8),
                "mean_case_f1_delta": round(mean(paired_deltas), 6) if paired_deltas else 0.0,
            },
        }
        compare_checks: dict[str, bool | None] = {
            "ansede_f1_gt_baseline": float(ansede_summary["f1"]) > float(baseline_summary["f1"]),
            "paired_sign_test_p_lt_0_05": p_value < 0.05,
        }
    else:
        print("[proof] Skipping real-world comparison (--skip-compare).", flush=True)
        compare_report = None
        compare_block = {"skipped": True}
        compare_checks = {
            "ansede_f1_gt_baseline": None,
            "paired_sign_test_p_lt_0_05": None,
        }

    verdict_checks: dict[str, bool | None] = {
        "all_runs_gold_ready": all(gold_ready_values),
        "cve_recall_lb95_gte_90": (100.0 * cve_recall_ci[0]) >= 90.0,
        "cve_fp_rate_ub95_lte_10": (100.0 * cve_fp_rate_ci[1]) <= 10.0,
        "web_recall_lb95_gte_60": (100.0 * web_recall_ci[0]) >= 60.0,
        "web_fp_rate_ub95_lte_20": (100.0 * web_fp_rate_ci[1]) <= 20.0,
        **compare_checks,
    }

    proven_on_benchmark = all(v is True for v in verdict_checks.values() if v is not None)

    result = {
        "kind": "ansede-definitive-world-best-check",
        "version": 1,
        "scope_notice": (
            "This is definitive only for this benchmark protocol and selected datasets. "
            "It is not a universal proof across all software in the world."
        ),
        "config": {
            "runs": runs,
            "start_seed": start_seed,
            "web_n_files": web_n_files,
            "web_min_labeled": web_min_labeled,
            "web_cache_dir": str(web_cache_dir),
            "web_offline": web_offline,
            "web_max_file_bytes": web_max_file_bytes,
            "web_severity_min": web_severity_min,
            "web_js_backend": web_js_backend,
            "compare_manifest": str(compare_manifest),
            "compare_offline": compare_offline,
        },
        "per_seed": seed_reports,
        "aggregate": {
            "web": {
                "tp": web_tps,
                "fp": web_fps,
                "fn": web_fns,
                "recall_pct": round(100.0 * _safe_div(web_tps, web_tps + web_fns), 2),
                "precision_pct": round(100.0 * _safe_div(web_tps, web_tps + web_fps), 2),
                "f1_pct": round(100.0 * _f1(web_tps, web_fps, web_fns), 2),
                "fp_rate_pct": round(100.0 * _safe_div(web_fps, web_tps + web_fps), 2),
                "recall_ci95_pct": [round(100.0 * web_recall_ci[0], 2), round(100.0 * web_recall_ci[1], 2)],
                "precision_ci95_pct": [round(100.0 * web_precision_ci[0], 2), round(100.0 * web_precision_ci[1], 2)],
                "fp_rate_ci95_pct": [round(100.0 * web_fp_rate_ci[0], 2), round(100.0 * web_fp_rate_ci[1], 2)],
            },
            "cve": {
                "tp": cve_tps,
                "fp": cve_fps,
                "fn": cve_fns,
                "recall_pct": round(100.0 * _safe_div(cve_tps, cve_tps + cve_fns), 2),
                "precision_pct": round(100.0 * _safe_div(cve_tps, cve_tps + cve_fps), 2),
                "f1_pct": round(100.0 * _f1(cve_tps, cve_fps, cve_fns), 2),
                "fp_rate_pct": round(100.0 * _safe_div(cve_fps, cve_tps + cve_fps), 2),
                "recall_ci95_pct": [round(100.0 * cve_recall_ci[0], 2), round(100.0 * cve_recall_ci[1], 2)],
                "precision_ci95_pct": [round(100.0 * cve_precision_ci[0], 2), round(100.0 * cve_precision_ci[1], 2)],
                "fp_rate_ci95_pct": [round(100.0 * cve_fp_rate_ci[0], 2), round(100.0 * cve_fp_rate_ci[1], 2)],
            },
            "noise_quotient_per_1k_loc": {
                "mean": round(mean(noise_values), 3) if noise_values else 0.0,
                "stddev": round(pstdev(noise_values), 3) if len(noise_values) > 1 else 0.0,
                "min": round(min(noise_values), 3) if noise_values else 0.0,
                "max": round(max(noise_values), 3) if noise_values else 0.0,
            },
            "gold_ready_rate": {
                "passed": int(sum(1 for x in gold_ready_values if x)),
                "total": int(len(gold_ready_values)),
                "pct": round(100.0 * _safe_div(sum(1 for x in gold_ready_values if x), len(gold_ready_values)), 2)
                if gold_ready_values
                else 0.0,
            },
        },
        "comparison": compare_block,
        "verdict": {
            "checks": verdict_checks,
            "proven_world_best_on_this_benchmark": proven_on_benchmark,
            "label": "PROVEN (on this benchmark)" if proven_on_benchmark else "NOT PROVEN",
        },
    }

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Definitive benchmark proof runner for ansede-static")
    parser.add_argument("--runs", type=int, default=5, help="Number of independent seeds")
    parser.add_argument("--start-seed", type=int, default=1337, help="Starting seed; script uses start_seed..start_seed+runs-1")
    parser.add_argument("--web-n-files", type=int, default=2000, help="Sample size per seed for web-wild")
    parser.add_argument("--web-min-labeled", type=int, default=300, help="Minimum labeled files per seed")
    parser.add_argument("--web-cache-dir", type=Path, default=Path("benchmarks/online_random_samples"), help="Cache directory for web repos")
    parser.add_argument("--web-refresh-first", action="store_true", help="Refresh cache on the first seed run only")
    parser.add_argument("--web-offline", action="store_true", help="Use only local cache for web repos")
    parser.add_argument("--web-max-file-bytes", type=int, default=256000, help="Max file size for web-wild")
    parser.add_argument("--web-severity-min", choices=["critical", "high", "medium", "low", "info"], default="high")
    parser.add_argument("--web-js-backend", choices=["auto", "classic", "structural"], default="auto")
    parser.add_argument("--suppression-min-occurrences", type=int, default=3)
    parser.add_argument("--suppression-max-enable", type=int, default=8)
    parser.add_argument("--suppression-cve-budget", type=int, default=0)
    parser.add_argument("--compare-manifest", type=Path, default=Path("benchmarks/real_world_manifest.json"))
    parser.add_argument("--compare-offline", action="store_true")
    parser.add_argument("--skip-compare", action="store_true",
                        help="Skip the real-world comparison step entirely (never touches network/git)")
    parser.add_argument("--compare-cache-dir", type=Path, default=None, metavar="DIR",
                        help="Cache dir for real_world_compare repos (default: .tmp/ansede-corpus)")
    parser.add_argument("--work-dir", type=Path, default=Path(".tmp/proof_runs"), help="Where per-seed intermediate files are stored")
    parser.add_argument("--output", type=Path, default=Path("world_best_definitive_report.json"), help="Final JSON report path")
    parser.add_argument("--json", action="store_true", help="Print the final report JSON")
    args = parser.parse_args()

    compare_cache = args.compare_cache_dir.resolve() if args.compare_cache_dir else Path(".tmp/ansede-corpus").resolve()
    report = run_proof(
        runs=args.runs,
        start_seed=args.start_seed,
        web_n_files=args.web_n_files,
        web_min_labeled=args.web_min_labeled,
        web_cache_dir=args.web_cache_dir.resolve(),
        web_refresh_first=args.web_refresh_first,
        web_offline=args.web_offline,
        web_max_file_bytes=args.web_max_file_bytes,
        web_severity_min=args.web_severity_min,
        web_js_backend=args.web_js_backend,
        suppression_min_occurrences=args.suppression_min_occurrences,
        suppression_max_enable=args.suppression_max_enable,
        suppression_cve_budget=args.suppression_cve_budget,
        compare_manifest=args.compare_manifest,
        compare_offline=args.compare_offline,
        skip_compare=args.skip_compare,
        compare_cache_dir=compare_cache,
        output=args.output,
        work_dir=args.work_dir,
    )

    verdict = report["verdict"]
    agg_web = report["aggregate"]["web"]
    agg_cve = report["aggregate"]["cve"]

    print("\n=== Definitive World-Best Check ===")
    print(f"Verdict: {verdict['label']}")
    print(
        f"Web recall={agg_web['recall_pct']:.2f}% (95% CI {agg_web['recall_ci95_pct'][0]:.2f}..{agg_web['recall_ci95_pct'][1]:.2f}), "
        f"precision={agg_web['precision_pct']:.2f}% (95% CI {agg_web['precision_ci95_pct'][0]:.2f}..{agg_web['precision_ci95_pct'][1]:.2f})"
    )
    print(
        f"CVE recall={agg_cve['recall_pct']:.2f}% (95% CI {agg_cve['recall_ci95_pct'][0]:.2f}..{agg_cve['recall_ci95_pct'][1]:.2f}), "
        f"fp_rate={agg_cve['fp_rate_pct']:.2f}% (95% CI {agg_cve['fp_rate_ci95_pct'][0]:.2f}..{agg_cve['fp_rate_ci95_pct'][1]:.2f})"
    )
    print(f"Output written to: {args.output}")

    if args.json:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
