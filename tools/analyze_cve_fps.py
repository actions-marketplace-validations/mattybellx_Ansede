#!/usr/bin/env python3
"""
PHASE 2: CVE FALSE POSITIVE ANALYSIS

Goal: Understand WHY we have 80 CVE false positives and what to suppress/refine.

This tool will:
1. Load a seed report's CVE findings
2. Categorize FPs by CWE
3. Identify suppression patterns that could reduce FP without losing TPs
4. Recommend specific triage refinements
"""
import json
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Tuple, Any

def load_cve_findings(seed_num: int = 1337) -> Dict[str, List]:
    """Load CVE findings from a seed report."""
    seed_path = Path(f".tmp/proof_runs/world_best_seed_{seed_num}.json")
    if not seed_path.exists():
        print(f"Error: {seed_path} not found")
        return {"tp": [], "fp": []}
    
    report = json.load(open(seed_path))
    cve_data = report.get("cve", {})
    pre_supp = cve_data.get("pre_suppression", {})
    post_supp = cve_data.get("post_suppression", {})
    
    # Extract TPs and FPs
    pre_cases = pre_supp.get("cases", [])
    post_cases = post_supp.get("cases", [])
    
    tp_findings = []
    fp_findings = []
    
    # Collect all findings with their status
    for case in post_cases:
        if case.get("passed"):  # TP
            findings = case.get("findings", [])
            for f in findings:
                tp_findings.append({
                    "cve_id": case.get("cve_id"),
                    "cwe": case.get("expected_cwe"),
                    "finding": f,
                })
        else:  # FP (was found but shouldn't have been)
            findings = case.get("findings", [])
            fp_cases = case.get("findings_considered", 0) - case.get("tp", 0)
            if fp_cases > 0 and findings:
                for f in findings[:fp_cases]:  # Approximate first N as FP
                    fp_findings.append({
                        "cve_id": case.get("cve_id"),
                        "cwe": case.get("expected_cwe"),
                        "finding": f,
                    })
    
    return {"tp": tp_findings, "fp": fp_findings}

def analyze_cve_fps():
    """Analyze CVE false positives by CWE and rule."""
    print("=" * 100)
    print("PHASE 2: CVE FALSE POSITIVE ANALYSIS")
    print("=" * 100)
    
    findings = load_cve_findings()
    tp_list = findings["tp"]
    fp_list = findings["fp"]
    
    print(f"\nLoaded {len(tp_list)} TP findings and {len(fp_list)} FP findings")
    
    # Group by CWE
    tp_by_cwe = defaultdict(int)
    fp_by_cwe = defaultdict(int)
    
    for tp in tp_list:
        cwe = tp.get("cwe", "UNKNOWN")
        tp_by_cwe[cwe] += 1
    
    for fp in fp_list:
        cwe = fp.get("cwe", "UNKNOWN")
        fp_by_cwe[cwe] += 1
    
    print("\n" + "=" * 100)
    print("FALSE POSITIVES BY CWE")
    print("=" * 100)
    print(f"{'CWE':<20} {'TP Count':<15} {'FP Count':<15} {'FP%':<10}")
    print("-" * 100)
    
    for cwe in sorted(set(list(tp_by_cwe.keys()) + list(fp_by_cwe.keys()))):
        tp_count = tp_by_cwe.get(cwe, 0)
        fp_count = fp_by_cwe.get(cwe, 0)
        total = tp_count + fp_count
        fp_pct = 100 * fp_count / total if total > 0 else 0
        print(f"{cwe:<20} {tp_count:<15} {fp_count:<15} {fp_pct:<10.1f}%")
    
    # Find worst offenders
    worst_cwe = max(fp_by_cwe.items(), key=lambda x: x[1])[0] if fp_by_cwe else None
    
    print(f"\n" + "=" * 100)
    print("RECOMMENDATIONS")
    print("=" * 100)
    print(f"""
Highest FP CWE: {worst_cwe}
Action items for Phase 2:

1. Inspect triage rules for {worst_cwe} in src/ansede_static/engine/triage.py
   - Are the suppression guards too permissive?
   - Can we tighten confidence thresholds?
   - Are there framework-specific patterns we're missing?

2. For each high-FP CWE:
   - Add test context suppression (if applicable)
   - Refine taint analysis precision
   - Add safe-pattern detection

3. CVE-specific suppression parameters:
   - Consider: --suppression-min-occurrences 2 (for CVE, not web)
   - Add CWE-specific suppression rules

4. Run targeted CVE test:
   python -m benchmarks.nvd_benchmark --verbose
   to see per-CWE metrics and identify which are over-detected.
""")

if __name__ == "__main__":
    analyze_cve_fps()
