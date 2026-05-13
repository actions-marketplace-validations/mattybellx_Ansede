#!/usr/bin/env python3
"""
Deep CVE FP analysis: Which CVEs have FP findings? What patterns?
"""
import json
from pathlib import Path
from collections import defaultdict

seed_path = Path(".tmp/proof_runs/world_best_seed_1337.json")
report = json.load(open(seed_path))

cve_data = report.get("cve", {})
post_supp = cve_data.get("post_suppression", {})
cases = post_supp.get("cases", [])

print("=" * 100)
print("CVE-BY-CVE BREAKDOWN: TRUE POSITIVES vs FALSE POSITIVES")
print("=" * 100)

cve_summary = []
for case in cases:
    cve_id = case.get("cve_id", "?")
    expected_cwe = case.get("expected_cwe", "?")
    passed = case.get("passed", False)  # True = TP, False = FP
    tp_count = case.get("tp", 0)
    fp_count = case.get("fp", 0)
    fn_count = case.get("fn", 0)
    findings_total = case.get("findings_total", 0)
    findings_suppressed = case.get("findings_suppressed", 0)
    
    status = "✓ TP" if passed else "✗ FP"
    
    print(f"\n{status} {cve_id} [{expected_cwe}]")
    print(f"    Detected: {tp_count} TP, {fp_count} FP, {fn_count} FN")
    print(f"    Total findings: {findings_total}, Suppressed: {findings_suppressed}")
    
    if not passed:
        # This is an FP case - show details
        findings = case.get("findings", [])
        if findings:
            f = findings[0]
            print(f"    Example finding: {f.get('rule_id')} at line {f.get('line')}")
            print(f"    Title: {f.get('title', '')[:60]}...")
        
        cve_summary.append({
            "cve_id": cve_id,
            "cwe": expected_cwe,
            "passed": passed,
            "status": "FP",
        })
    else:
        cve_summary.append({
            "cve_id": cve_id,
            "cwe": expected_cwe,
            "passed": passed,
            "status": "TP",
        })

print("\n\n" + "=" * 100)
print("SUMMARY: WHICH CVEs ARE FALSE POSITIVES?")
print("=" * 100)

fp_cves = [s for s in cve_summary if s["status"] == "FP"]
tp_cves = [s for s in cve_summary if s["status"] == "TP"]

print(f"\nTrue Positives: {len(tp_cves)}/{len(cve_summary)}")
print(f"False Positives: {len(fp_cves)}/{len(cve_summary)}")

if fp_cves:
    print(f"\nFP cases (should be TP but detected as FP):")
    for cve in fp_cves:
        print(f"  - {cve['cve_id']} [{cve['cwe']}]")

# Group by CWE
cwe_stats = defaultdict(lambda: {"tp": 0, "fp": 0})
for s in cve_summary:
    if s["status"] == "TP":
        cwe_stats[s["cwe"]]["tp"] += 1
    else:
        cwe_stats[s["cwe"]]["fp"] += 1

print(f"\n\nFP rate by CWE:")
for cwe in sorted(cwe_stats.keys()):
    tp = cwe_stats[cwe]["tp"]
    fp = cwe_stats[cwe]["fp"]
    total = tp + fp
    fp_pct = 100 * fp / total if total > 0 else 0
    if fp > 0:
        print(f"  {cwe}: {tp} TP, {fp} FP ({fp_pct:.1f}% FP rate) ← PROBLEM")
