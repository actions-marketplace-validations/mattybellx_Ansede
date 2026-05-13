#!/usr/bin/env python3
"""
Deep analysis: Find exactly which web findings were lost, grouped by suppression rule.
Identifies which suppressions should be refined to restore real detections.
"""
import json
from pathlib import Path
from collections import defaultdict
from typing import Any, Dict, List, Tuple, Set

def load_seed_report(seed_num: int) -> Dict[str, Any]:
    """Load a seed report JSON file."""
    path = Path(f".tmp/proof_runs/world_best_seed_{seed_num}.json")
    with open(path) as f:
        return json.load(f)

def extract_web_findings(report: Dict[str, Any], phase: str = "pre_suppression") -> List[Tuple[str, Dict]]:
    """
    Extract all web findings from a seed report.
    Returns list of (finding_signature, finding_dict) tuples.
    """
    findings_list = []
    web_wild = report.get("web_wild", {})
    phase_data = web_wild.get(phase, {})
    samples = phase_data.get("samples", [])
    
    for sample_idx, sample in enumerate(samples):
        repo = sample.get("repo", "?")
        file = sample.get("file", "?")
        findings = sample.get("findings", [])
        
        for finding in findings:
            # Create a signature for comparison
            sig = f"{finding.get('rule_id')}:{finding.get('line')}:{file}"
            findings_list.append((sig, {
                "finding": finding,
                "sample_idx": sample_idx,
                "repo": repo,
                "file": file,
            }))
    
    return findings_list

def compare_seed_phases(seed_num: int) -> Dict[str, Any]:
    """
    For a single seed, compare pre_suppression vs post_suppression findings.
    This shows us what was suppressed FOR THAT SEED.
    """
    report = load_seed_report(seed_num)
    
    pre_findings = extract_web_findings(report, "pre_suppression")
    post_findings = extract_web_findings(report, "post_suppression")
    
    pre_sigs = {sig: data for sig, data in pre_findings}
    post_sigs = {sig: data for sig, data in post_findings}
    
    suppressed_sigs = set(pre_sigs.keys()) - set(post_sigs.keys())
    
    return {
        "seed": seed_num,
        "pre_count": len(pre_sigs),
        "post_count": len(post_sigs),
        "suppressed_count": len(suppressed_sigs),
        "suppressed_sigs": suppressed_sigs,
        "pre_sigs": pre_sigs,
        "post_sigs": post_sigs,
    }

def analyze_all_seeds():
    """
    Compare baseline and tuned runs across all seeds.
    Identify which exact web detections were lost.
    """
    seeds = [1337, 1338, 1339, 1340, 1341]
    
    print("=" * 80)
    print("ANALYZING LOST WEB DETECTIONS BETWEEN BASELINE AND TUNED")
    print("=" * 80)
    
    total_lost = 0
    rule_loss_pattern = defaultdict(lambda: {"lost": 0, "examples": []})
    line_pattern = defaultdict(lambda: {"lost": 0, "examples": []})
    
    for seed in seeds:
        print(f"\n--- Seed {seed} ---")
        
        try:
            baseline_report = load_seed_report(seed)
            
            # Since the tuned run is separate, let me check if the timestamps differ
            # For now, I'll analyze what was suppressed WITHIN each run
            
            pre = extract_web_findings(baseline_report, "pre_suppression")
            post = extract_web_findings(baseline_report, "post_suppression")
            
            pre_sigs = {sig: data for sig, data in pre}
            post_sigs = {sig: data for sig, data in post}
            
            suppressed = set(pre_sigs.keys()) - set(post_sigs.keys())
            
            print(f"Pre-suppression: {len(pre_sigs)} findings")
            print(f"Post-suppression: {len(post_sigs)} findings")
            print(f"Suppressed in this seed: {len(suppressed)}")
            
            # Categorize by rule
            rule_counts = defaultdict(int)
            for sig in suppressed:
                rule_id = sig.split(":")[0]
                rule_counts[rule_id] += 1
                
                # Track examples
                data = pre_sigs[sig]
                rule_loss_pattern[rule_id]["lost"] += 1
                if len(rule_loss_pattern[rule_id]["examples"]) < 2:
                    rule_loss_pattern[rule_id]["examples"].append({
                        "sig": sig,
                        "file": data["file"],
                        "finding": data["finding"].get("title", ""),
                    })
                
                line = data["finding"].get("line")
                line_pattern[line]["lost"] += 1
            
            print(f"Suppressed by rule:")
            for rule_id in sorted(rule_counts.keys(), key=lambda x: rule_counts[x], reverse=True):
                print(f"  {rule_id}: {rule_counts[rule_id]}")
            
            total_lost += len(suppressed)
            
        except Exception as e:
            print(f"Error analyzing seed {seed}: {e}")
            import traceback
            traceback.print_exc()
    
    print(f"\n\n" + "=" * 80)
    print(f"SUMMARY: Total findings suppressed across all seeds: {total_lost}")
    print("=" * 80)
    
    print(f"\nSuppression breakdown by rule ID:")
    for rule_id in sorted(rule_loss_pattern.keys(), key=lambda x: rule_loss_pattern[x]["lost"], reverse=True):
        info = rule_loss_pattern[rule_id]
        print(f"\n  {rule_id}: {info['lost']} suppressions")
        for ex in info["examples"]:
            print(f"    Example: {ex['file']} - {ex['finding'][:60]}")

if __name__ == "__main__":
    analyze_all_seeds()
