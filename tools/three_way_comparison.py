#!/usr/bin/env python3
"""
THREE-WAY COMPARISON: Baseline vs Intermediate vs Aggressive

Once all three 5x500 runs complete, this script will:
1. Load all three reports
2. Compare metrics side-by-side
3. Show which tuning is "Goldilocks" (just right)
4. Recommend next phase based on results
"""
import json
from pathlib import Path
from typing import Dict, Any

def load_report(filename: str) -> Dict[str, Any]:
    """Load a definitive proof report."""
    path = Path(filename)
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)

def extract_metrics(report: Dict[str, Any]) -> Dict[str, Any]:
    """Extract key metrics from a report."""
    if not report:
        return None
    
    agg = report.get("aggregate", {})
    web = agg.get("web", {})
    cve = agg.get("cve", {})
    
    return {
        "web_tp": web.get("tp"),
        "web_fp": web.get("fp"),
        "web_recall": web.get("recall_pct"),
        "web_recall_ci_lb": web.get("recall_ci95_pct", [None, None])[0],
        "web_precision": web.get("precision_pct"),
        "web_fp_rate": web.get("fp_rate_pct"),
        "web_fp_rate_ci_ub": web.get("fp_rate_ci95_pct", [None, None])[1],
        
        "cve_tp": cve.get("tp"),
        "cve_fp": cve.get("fp"),
        "cve_recall": cve.get("recall_pct"),
        "cve_recall_ci_lb": cve.get("recall_ci95_pct", [None, None])[0],
        "cve_precision": cve.get("precision_pct"),
        "cve_fp_rate": cve.get("fp_rate_pct"),
        "cve_fp_rate_ci_ub": cve.get("fp_rate_ci95_pct", [None, None])[1],
        
        "gold_ready": report.get("aggregate", {}).get("gold_ready_rate", {}).get("passed", 0),
        "verdict": report.get("verdict", {}).get("label"),
    }

def check_gates(metrics: Dict[str, Any]) -> Dict[str, bool]:
    """Check which proof gates pass."""
    if not metrics:
        return {}
    
    return {
        "web_recall_lb95_gte_60": (metrics.get("web_recall_ci_lb") or 0) >= 60,
        "web_fp_rate_ub95_lte_20": (metrics.get("web_fp_rate_ci_ub") or 999) <= 20,
        "cve_recall_lb95_gte_90": (metrics.get("cve_recall_ci_lb") or 0) >= 90,
        "cve_fp_rate_ub95_lte_10": (metrics.get("cve_fp_rate_ci_ub") or 999) <= 10,
        "gold_ready_5_of_5": (metrics.get("gold_ready") or 0) >= 5,
    }

def main():
    print("=" * 100)
    print("THREE-WAY TUNING COMPARISON: BASELINE vs INTERMEDIATE vs AGGRESSIVE")
    print("=" * 100)
    
    baseline = load_report("world_best_definitive_report.json")
    intermediate = load_report("world_best_definitive_report_intermediate.json")
    aggressive = load_report("world_best_definitive_report_tuned.json")
    
    baseline_m = extract_metrics(baseline)
    intermediate_m = extract_metrics(intermediate)
    aggressive_m = extract_metrics(aggressive)
    
    baseline_g = check_gates(baseline_m)
    intermediate_g = check_gates(intermediate_m)
    aggressive_g = check_gates(aggressive_m)
    
    if not baseline_m:
        print("ERROR: Missing baseline report")
        return
    
    print("\n" + "=" * 100)
    print("WEB METRICS")
    print("=" * 100)
    print(f"{'Metric':<30} {'Baseline':<20} {'Intermediate':<20} {'Aggressive':<20}")
    print("-" * 100)
    
    print(f"{'TP':<30} {baseline_m['web_tp']:<20} {intermediate_m['web_tp'] if intermediate_m else '?':<20} {aggressive_m['web_tp']:<20}")
    print(f"{'FP':<30} {baseline_m['web_fp']:<20} {intermediate_m['web_fp'] if intermediate_m else '?':<20} {aggressive_m['web_fp']:<20}")
    print(f"{'Recall %':<30} {baseline_m['web_recall']:<20.2f} {intermediate_m['web_recall'] if intermediate_m else '?':<20} {aggressive_m['web_recall']:<20.2f}")
    print(f"{'Recall CI LB %':<30} {baseline_m['web_recall_ci_lb']:<20.2f} {intermediate_m['web_recall_ci_lb'] if intermediate_m else '?':<20} {aggressive_m['web_recall_ci_lb']:<20.2f}")
    print(f"{'Precision %':<30} {baseline_m['web_precision']:<20.2f} {intermediate_m['web_precision'] if intermediate_m else '?':<20} {aggressive_m['web_precision']:<20.2f}")
    print(f"{'FP-rate %':<30} {baseline_m['web_fp_rate']:<20.2f} {intermediate_m['web_fp_rate'] if intermediate_m else '?':<20} {aggressive_m['web_fp_rate']:<20.2f}")
    print(f"{'FP-rate CI UB %':<30} {baseline_m['web_fp_rate_ci_ub']:<20.2f} {intermediate_m['web_fp_rate_ci_ub'] if intermediate_m else '?':<20} {aggressive_m['web_fp_rate_ci_ub']:<20.2f}")
    
    print("\n" + "=" * 100)
    print("CVE METRICS")
    print("=" * 100)
    print(f"{'Metric':<30} {'Baseline':<20} {'Intermediate':<20} {'Aggressive':<20}")
    print("-" * 100)
    
    print(f"{'TP':<30} {baseline_m['cve_tp']:<20} {intermediate_m['cve_tp'] if intermediate_m else '?':<20} {aggressive_m['cve_tp']:<20}")
    print(f"{'FP':<30} {baseline_m['cve_fp']:<20} {intermediate_m['cve_fp'] if intermediate_m else '?':<20} {aggressive_m['cve_fp']:<20}")
    print(f"{'Recall %':<30} {baseline_m['cve_recall']:<20.2f} {intermediate_m['cve_recall'] if intermediate_m else '?':<20} {aggressive_m['cve_recall']:<20.2f}")
    print(f"{'Recall CI LB %':<30} {baseline_m['cve_recall_ci_lb']:<20.2f} {intermediate_m['cve_recall_ci_lb'] if intermediate_m else '?':<20} {aggressive_m['cve_recall_ci_lb']:<20.2f}")
    print(f"{'FP-rate CI UB %':<30} {baseline_m['cve_fp_rate_ci_ub']:<20.2f} {intermediate_m['cve_fp_rate_ci_ub'] if intermediate_m else '?':<20} {aggressive_m['cve_fp_rate_ci_ub']:<20.2f}")
    
    print("\n" + "=" * 100)
    print("PROOF GATE STATUS")
    print("=" * 100)
    print(f"{'Gate':<40} {'Baseline':<15} {'Intermediate':<15} {'Aggressive':<15}")
    print("-" * 100)
    
    for gate in ["web_recall_lb95_gte_60", "web_fp_rate_ub95_lte_20", 
                 "cve_recall_lb95_gte_90", "cve_fp_rate_ub95_lte_10", "gold_ready_5_of_5"]:
        b_pass = "✓ PASS" if baseline_g.get(gate) else "✗ FAIL"
        i_pass = "✓ PASS" if intermediate_g.get(gate) else "✗ FAIL" if intermediate_m else "PENDING"
        a_pass = "✓ PASS" if aggressive_g.get(gate) else "✗ FAIL"
        print(f"{gate:<40} {b_pass:<15} {i_pass:<15} {a_pass:<15}")
    
    if intermediate_m:
        baseline_passes = sum(baseline_g.values())
        intermediate_passes = sum(intermediate_g.values())
        aggressive_passes = sum(aggressive_g.values())
        
        print(f"\n{'Total gates passing':<40} {baseline_passes}/5 {intermediate_passes}/5 {aggressive_passes}/5")
        
        if intermediate_passes > aggressive_passes:
            print("\n✓ INTERMEDIATE TUNING IS BETTER than aggressive")
            if intermediate_passes > baseline_passes:
                print("✓ INTERMEDIATE TUNING IMPROVES ON BASELINE")
        elif intermediate_passes > baseline_passes:
            print("\n✓ INTERMEDIATE TUNING IMPROVES ON BASELINE")
        else:
            print("\n⚠ INTERMEDIATE TUNING DOES NOT IMPROVE RESULTS")
    
    print("\n" + "=" * 100)
    print("RECOMMENDATIONS")
    print("=" * 100)
    print("""
If intermediate passes web gates (60%+ recall CI LB, <20% FP-rate CI UB):
  → Use intermediate parameters: --suppression-min-occurrences 3 --suppression-max-enable 8
  → Move to Phase 2: Attack CVE FP problem separately
  
If intermediate still fails web gates:
  → Try: --suppression-min-occurrences 4 --suppression-max-enable 5 (even less aggressive)
  → OR: Accept baseline + focus on CVE FP reduction

If intermediate is NOT better than baseline:
  → Suppress less aggressively (go back to no tuning)
  → Focus entirely on CVE FP problem (it's the main bottleneck)
""")

if __name__ == "__main__":
    main()
