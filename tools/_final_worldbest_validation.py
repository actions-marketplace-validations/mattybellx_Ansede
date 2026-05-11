"""
Final world-best comprehensive validation.
  - 20 independent random seeds
  - 60 files per run (50% more than standard)
  - min-labeled = 15 per run
  - All 5 repos (OWASP/NodeGoat, pallets/flask, expressjs/express, django/django, tiangolo/fastapi)
  - Hybrid label mode, severity-min high, structural JS backend
  - World-best gates: recall >= 85%, fp_rate < 10%
  - CVE benchmark gate inline at the end
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from benchmarks.web_wild_harness import run_web_wild_harness, RepoSpec, _default_cache_dir

SEEDS = [
    11, 22, 33, 44, 55, 66, 77, 88, 99, 111,
    222, 333, 444, 555, 666, 888, 999, 1111, 2222, 3333,
]
REPOS = [
    RepoSpec("OWASP/NodeGoat"),
    RepoSpec("pallets/flask"),
    RepoSpec("expressjs/express"),
    RepoSpec("django/django"),
    RepoSpec("tiangolo/fastapi"),
]
N_FILES = 60
MIN_LABELED = 15
RECALL_GATE = 85.0
FPRATE_GATE = 10.0

cache = _default_cache_dir()
label_manifest = Path("benchmarks/real_world_manifest.json")

print()
print("  ╔══════════════════════════════════════════════════════════════════════════╗")
print("  ║         ansede-static  ·  WORLD-BEST FINAL VALIDATION                  ║")
print(f"  ║         {len(SEEDS)} seeds · {N_FILES} files/run · min-labeled {MIN_LABELED} · 5 repos                ║")
print("  ╚══════════════════════════════════════════════════════════════════════════╝")
print()
print(f"  {'Seed':>5}  {'Labeled':>7}  {'TP':>3} {'FP':>3} {'FN':>3}  {'Recall':>8}  {'FP-rate':>8}  {'F1':>7}  {'Gate':>6}  {'Time':>6}")
print("  " + "─" * 76)

results = []
total_start = time.time()

for seed in SEEDS:
    t0 = time.time()
    report = run_web_wild_harness(
        repos=REPOS,
        n_files=N_FILES,
        seed=seed,
        cache_dir=cache,
        refresh=False,
        offline=True,
        max_file_bytes=256_000,
        min_labeled=MIN_LABELED,
        severity_min="high",
        js_backend="structural",
        suppression_config=None,
        sampling_mode="global",
        vendor_mode="include",
        label_mode="hybrid",
        label_manifest=label_manifest,
        quiet=True,
    )
    s = report["summary"]
    elapsed = time.time() - t0
    gate = "PASS" if s["recall"] >= RECALL_GATE and s["fp_rate"] < FPRATE_GATE else "FAIL"
    results.append((seed, s["labeled_files"], s["tp"], s["fp"], s["fn"],
                    s["recall"], s["fp_rate"], s["f1"], gate, elapsed))
    print(f"  {seed:>5}  {s['labeled_files']:>7}  {s['tp']:>3} {s['fp']:>3} {s['fn']:>3}  "
          f"{s['recall']:>7.2f}%  {s['fp_rate']:>7.2f}%  {s['f1']:>6.2f}%  "
          f"{gate:>6}  {elapsed:>5.0f}s")

total_web = time.time() - total_start
passes = sum(1 for r in results if r[8] == "PASS")

print("  " + "─" * 76)
avg_recall = sum(r[5] for r in results) / len(results)
avg_fp = sum(r[6] for r in results) / len(results)
avg_f1 = sum(r[7] for r in results) / len(results)
total_tp = sum(r[2] for r in results)
total_fp = sum(r[3] for r in results)
total_fn = sum(r[4] for r in results)
print(f"  {'TOTAL':>5}  {'':>7}  {total_tp:>3} {total_fp:>3} {total_fn:>3}  "
      f"{avg_recall:>7.2f}%  {avg_fp:>7.2f}%  {avg_f1:>6.2f}%  {'':>6}  {total_web:>5.0f}s")
print()
print(f"  Web-wild result:  {passes}/{len(SEEDS)} seeds PASS  "
      f"(recall gate ≥{RECALL_GATE:.0f}%  fp_rate gate <{FPRATE_GATE:.0f}%)")
print()

# ── CVE gate ──────────────────────────────────────────────────────────────────
print("  Running CVE corpus recall gate…")
cve_start = time.time()
try:
    from benchmarks.cve_recall_runner import run_cve_recall
    cve = run_cve_recall(quiet=True)
    cs = cve.get("summary", {})
    cve_recall = float(cs.get("recall", 0))
    cve_fp = float(cs.get("fp_rate", 0))
    cve_gate = "PASS" if cve_recall >= 90 and cve_fp < 10 else "FAIL"
    print(f"  CVE recall={cve_recall:.2f}%  fp_rate={cve_fp:.2f}%  [{cve_gate}]  "
          f"({time.time()-cve_start:.0f}s)")
except Exception as exc:
    cve_gate = "ERROR"
    print(f"  CVE gate ERROR: {exc}")

print()
web_verdict = "WORLD-BEST ✓" if passes == len(SEEDS) else f"DEGRADED — {len(SEEDS)-passes} seed(s) failed"
cve_verdict = "WORLD-BEST ✓" if cve_gate == "PASS" else "BELOW GATE ✗"
overall = "DEFINITIVELY WORLD-BEST" if passes == len(SEEDS) and cve_gate == "PASS" else "NOT YET WORLD-BEST"
print("  ┌────────────────────────────────────────────────────┐")
print(f"  │  Web-wild ({len(SEEDS)} seeds):  {web_verdict:<31}│")
print(f"  │  CVE corpus:        {cve_verdict:<31}│")
print(f"  │  OVERALL:           {overall:<31}│")
print("  └────────────────────────────────────────────────────┘")
print()
