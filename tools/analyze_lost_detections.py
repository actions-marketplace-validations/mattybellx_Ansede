#!/usr/bin/env python3
"""
Analyze which web detections were lost between baseline and tuned runs.
Identify patterns in suppressed findings to guide targeted tuning.
"""
import json
import sys
from pathlib import Path
from collections import defaultdict
from typing import Any, Dict, List, Set, Tuple

def load_seed_report(seed_path: str) -> Dict[str, Any]:
    """Load a seed report JSON file."""
    with open(seed_path) as f:
        return json.load(f)

def extract_web_findings(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract all web findings from a seed report, preserving finding details."""
    findings_list = []
    web_data = report.get("web", {})
    
    # The web section typically has repos -> each repo has cases with findings
    for repo_name, repo_data in web_data.items():
        if not isinstance(repo_data, dict):
            continue
        
        for case_idx, case_data in enumerate(repo_data.items() if isinstance(repo_data, dict) else []):
            if isinstance(case_data, tuple):
                case_key, case_val = case_data
            else:
                continue
            
            if not isinstance(case_val, dict):
                continue
            
            # Extract findings from this case
            findings = case_val.get("findings", [])
            for finding in findings:
                findings_list.append({
                    "repo": repo_name,
                    "case_key": case_key,
                    "finding": finding,
                    "matched": finding in case_val.get("matched_finding_indexes", []),
                    "suppressed": finding in case_val.get("suppression", []),
                })
    
    return findings_list

def create_finding_signature(finding: Dict[str, Any]) -> str:
    """Create a unique signature for a finding for comparison."""
    # Use rule_id, line, title as signature
    return f"{finding.get('rule_id')}:{finding.get('line')}:{finding.get('title', '')}"

def compare_seed_runs(baseline_seed: int, tuned_seed: int) -> Dict[str, Any]:
    """Compare a single seed between baseline and tuned runs."""
    baseline_path = f".tmp/proof_runs/world_best_seed_{baseline_seed}.json"
    tuned_path = f".tmp/proof_runs/world_best_seed_{tuned_seed}.json"
    
    baseline_report = load_seed_report(baseline_path)
    tuned_report = load_seed_report(tuned_path)
    
    # Extract web findings
    baseline_findings = extract_web_findings(baseline_report)
    tuned_findings = extract_web_findings(tuned_report)
    
    # Create signature -> finding maps
    baseline_sigs = {create_finding_signature(f["finding"]): f for f in baseline_findings}
    tuned_sigs = {create_finding_signature(f["finding"]): f for f in tuned_findings}
    
    # Find lost findings (in baseline but not in tuned)
    lost_sigs = set(baseline_sigs.keys()) - set(tuned_sigs.keys())
    new_sigs = set(tuned_sigs.keys()) - set(baseline_sigs.keys())
    
    print(f"\n=== Seed {baseline_seed} Comparison ===")
    print(f"Baseline findings: {len(baseline_sigs)}")
    print(f"Tuned findings: {len(tuned_sigs)}")
    print(f"Lost findings: {len(lost_sigs)}")
    print(f"New findings: {len(new_sigs)}")
    
    if lost_sigs:
        print(f"\nLOST FINDINGS ({len(lost_sigs)}):")
        for sig in sorted(lost_sigs):
            f = baseline_sigs[sig]["finding"]
            print(f"  - [{f.get('rule_id')}] Line {f.get('line')}: {f.get('title')}")
            print(f"    Repo: {baseline_sigs[sig]['repo']}")
            # Check if it was suppressed in tuned
            if sig in tuned_sigs:
                print(f"    Status in tuned: SUPPRESSED")
            print()
    
    if new_sigs:
        print(f"\nNEW FINDINGS ({len(new_sigs)}):")
        for sig in sorted(new_sigs):
            f = tuned_sigs[sig]["finding"]
            print(f"  - [{f.get('rule_id')}] Line {f.get('line')}: {f.get('title')}")
            print()
    
    return {
        "seed": baseline_seed,
        "baseline_count": len(baseline_sigs),
        "tuned_count": len(tuned_sigs),
        "lost_count": len(lost_sigs),
        "new_count": len(new_sigs),
        "lost_findings": list(lost_sigs),
        "new_findings": list(new_sigs),
    }

def main():
    print("Analyzing lost web detections between baseline and tuned runs...")
    
    seeds = [1337, 1338, 1339, 1340, 1341]
    total_lost = 0
    rule_loss_counts = defaultdict(int)
    
    for seed in seeds:
        try:
            result = compare_seed_runs(seed, seed)
            total_lost += result["lost_count"]
            
            # Categorize lost findings by rule
            for sig in result["lost_findings"]:
                rule_id = sig.split(":")[0]
                rule_loss_counts[rule_id] += 1
        except Exception as e:
            print(f"Error analyzing seed {seed}: {e}")
    
    print(f"\n\n=== SUMMARY ===")
    print(f"Total lost web detections across all seeds: {total_lost}")
    print(f"Average per seed: {total_lost / len(seeds):.1f}")
    print(f"\nLost findings by rule ID:")
    for rule_id in sorted(rule_loss_counts.keys(), key=lambda x: rule_loss_counts[x], reverse=True):
        count = rule_loss_counts[rule_id]
        print(f"  {rule_id}: {count} losses")

if __name__ == "__main__":
    main()
