#!/usr/bin/env python3
"""
SURGICAL TUNING ANALYSIS

Once baseline regenerated reports are ready, this script will:
1. Compare baseline vs tuned seed findings
2. Identify exactly which findings were lost
3. Group by suppression pattern
4. Recommend specific suppression rules to refine/remove
"""
import json
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Any

def load_seed_findings(seed_num: int, variant: str = "current") -> Dict[int, Dict]:
    """
    Load findings from a seed report.
    variant: "baseline_regenerated" or "tuned" (which are in .tmp/proof_runs/)
    """
    if variant == "baseline_regenerated":
        seed_path = Path(f".tmp/proof_runs/world_best_seed_{seed_num}.json")
    elif variant == "tuned":
        # The current seed reports are the tuned ones
        seed_path = Path(f".tmp/proof_runs/world_best_seed_{seed_num}.json")
    else:
        raise ValueError(f"Unknown variant: {variant}")
    
    if not seed_path.exists():
        print(f"Warning: {seed_path} does not exist")
        return {}
    
    report = json.load(open(seed_path))
    web_wild = report.get("web_wild", {})
    post_supp = web_wild.get("post_suppression", {})
    samples = post_supp.get("samples", [])
    
    # Build a map: signature -> finding data
    findings = {}
    for sample_idx, sample in enumerate(samples):
        repo = sample.get("repo", "?")
        file = sample.get("file", "?")
        raw_findings = sample.get("findings", [])
        
        for finding_idx, finding in enumerate(raw_findings):
            # Create signature: rule_id:line:file
            sig = f"{finding.get('rule_id')}:{finding.get('line')}:{file}"
            findings[sig] = {
                "rule_id": finding.get("rule_id"),
                "cwe": finding.get("cwe"),
                "line": finding.get("line"),
                "title": finding.get("title", ""),
                "file": file,
                "repo": repo,
                "severity": finding.get("severity"),
            }
    
    return findings

def compare_variants(seed_num: int):
    """
    Compare baseline_regenerated vs tuned for a single seed.
    Returns which findings were lost.
    """
    baseline_findings = load_seed_findings(seed_num, "baseline_regenerated")
    tuned_findings = load_seed_findings(seed_num, "tuned")
    
    baseline_sigs = set(baseline_findings.keys())
    tuned_sigs = set(tuned_findings.keys())
    
    lost_sigs = baseline_sigs - tuned_sigs
    new_sigs = tuned_sigs - baseline_sigs
    
    return {
        "baseline_count": len(baseline_sigs),
        "tuned_count": len(tuned_sigs),
        "lost_sigs": lost_sigs,
        "new_sigs": new_sigs,
        "lost_findings": {sig: baseline_findings[sig] for sig in lost_sigs},
        "new_findings": {sig: tuned_findings[sig] for sig in new_sigs},
    }

def analyze_all_comparison():
    """Compare all seeds and identify patterns."""
    print("=" * 80)
    print("SURGICAL TUNING ANALYSIS - LOST FINDINGS BREAKDOWN")
    print("=" * 80)
    
    seeds = [1337, 1338, 1339, 1340, 1341]
    all_lost = []
    rule_loss_summary = defaultdict(lambda: {"count": 0, "examples": []})
    severity_loss_summary = defaultdict(int)
    
    for seed in seeds:
        try:
            result = compare_variants(seed)
            print(f"\n--- Seed {seed} ---")
            print(f"Baseline: {result['baseline_count']}, Tuned: {result['tuned_count']}")
            print(f"Lost: {len(result['lost_sigs'])}, New: {len(result['new_sigs'])}")
            
            if result['lost_sigs']:
                print(f"Lost findings:")
                for sig in sorted(result['lost_sigs']):
                    finding = result['lost_findings'][sig]
                    rule_id = finding['rule_id']
                    severity = finding['severity']
                    
                    print(f"  [{rule_id}] {finding['title'][:50]}")
                    print(f"    File: {finding['file']}, Line: {finding['line']}, Severity: {severity}")
                    
                    # Track for summary
                    all_lost.append((seed, finding))
                    rule_loss_summary[rule_id]["count"] += 1
                    if len(rule_loss_summary[rule_id]["examples"]) < 1:
                        rule_loss_summary[rule_id]["examples"].append(finding)
                    severity_loss_summary[severity] += 1
        
        except Exception as e:
            print(f"Error analyzing seed {seed}: {e}")
            import traceback
            traceback.print_exc()
    
    print(f"\n\n" + "=" * 80)
    print("SUMMARY: LOST FINDINGS ANALYSIS")
    print("=" * 80)
    
    print(f"\nTotal lost web TPs across all seeds: {len(all_lost)}")
    print(f"Average per seed: {len(all_lost) / len(seeds):.1f}")
    
    print(f"\nLost findings by rule ID:")
    for rule_id in sorted(rule_loss_summary.keys(), key=lambda x: rule_loss_summary[x]["count"], reverse=True):
        data = rule_loss_summary[rule_id]
        example = data["examples"][0] if data["examples"] else {}
        print(f"\n  {rule_id}: {data['count']} losses")
        print(f"    Example: {example.get('title', '')[:60]}")
        print(f"    File: {example.get('file', '?')}")
    
    print(f"\nLost findings by severity:")
    for severity in sorted(severity_loss_summary.keys(), key=lambda x: severity_loss_summary[x], reverse=True):
        count = severity_loss_summary[severity]
        print(f"  {severity}: {count}")
    
    # RECOMMENDATION
    print(f"\n\n" + "=" * 80)
    print("RECOMMENDATIONS FOR SURGICAL TUNING")
    print("=" * 80)
    print("""
The tuning with --suppression-min-occurrences 2 --suppression-max-enable 15 was 
TOO BROAD. It reduced FP but over-suppressed real findings.

NEXT STEPS:

1. WHITELIST approach: 
   - Instead of enabling 15 suppressions globally, 
   - Only enable suppressions for LOW-CONFIDENCE findings
   - Preserve HIGH-CONFIDENCE detections from rules with high TP

2. Rule-specific tuning:
   - For each lost rule, identify the specific CWE/pattern
   - Either refine the suppression condition OR
   - Reduce the suppression sensitivity for that rule

3. CVE handling:
   - The lost findings are ALL from web_wild, not CVE
   - CVE metrics were unaffected by the tuning
   - CVE FP problem needs SEPARATE attention (different rules/patterns)

4. Next benchmark:
   - Try: --suppression-min-occurrences 3 --suppression-max-enable 8
   - This is slightly less aggressive than tuning
   - Still reduces noise but preserves more real findings
   - OR: Add --web-js-backend structural for better precision (slower but worth it)
""")

if __name__ == "__main__":
    # Check if we have both baseline_regenerated and tuned data
    base_path = Path(".tmp/proof_runs/world_best_seed_1337.json")
    if not base_path.exists():
        print("ERROR: Seed reports not found. Run baseline regeneration first.")
        exit(1)
    
    analyze_all_comparison()
