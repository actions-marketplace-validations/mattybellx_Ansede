#!/usr/bin/env python3
"""
Inspect actual findings within a high-FP CVE to understand what's being over-detected.
"""
import json
from pathlib import Path

seed_path = Path(".tmp/proof_runs/world_best_seed_1337.json")
report = json.load(open(seed_path))

cve_data = report.get("cve", {})
post_supp = cve_data.get("post_suppression", {})
cases = post_supp.get("cases", [])

# Find CVE-2022-JWT-HARDCODED which has 1 TP + 2 FP
target_cve = "CVE-2022-JWT-HARDCODED"

for case in cases:
    if case.get("cve_id") != target_cve:
        continue
    
    print(f"=" * 100)
    print(f"Analyzing {target_cve} [CWE-798]")
    print(f"=" * 100)
    
    findings = case.get("findings", [])
    print(f"\nTotal findings in this case: {len(findings)}")
    print(f"TP: {case.get('tp')}, FP: {case.get('fp')}, FN: {case.get('fn')}")
    
    print(f"\nAll findings:")
    for i, f in enumerate(findings):
        print(f"\n  Finding {i+1}:")
        print(f"    Rule ID: {f.get('rule_id')}")
        print(f"    Title: {f.get('title')}")
        print(f"    Line: {f.get('line')}")
        print(f"    Description: {f.get('description', '')[:100]}")
        print(f"    Severity: {f.get('severity')}")
        print(f"    Confidence: {f.get('confidence')}")
        
        # Check if this is the TP or FP
        matched = i in case.get("matched_finding_indexes", [])
        suppressed = i in case.get("suppression", [])
        
        if matched:
            print(f"    → Status: TRUE POSITIVE (matched expected CWE)")
        elif suppressed:
            print(f"    → Status: SUPPRESSED by rule")
        else:
            print(f"    → Status: FALSE POSITIVE (not matched, not suppressed)")
