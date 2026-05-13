#!/usr/bin/env python3
"""Analyze suppressions that were enabled in the tuned run"""
import json
from pathlib import Path

print("ANALYZING SUPPRESSIONS APPLIED IN TUNED RUN\n")

for seed in [1337, 1338, 1339, 1340, 1341]:
    seed_path = Path(f".tmp/proof_runs/world_best_seed_{seed}.json")
    report = json.load(open(seed_path))
    sr = report.get("suppression_rollout", {})
    
    enabled = sr.get("suppressions_enabled", [])
    print(f"Seed {seed}: {len(enabled)} suppressions enabled")
    
    for supp in enabled:
        cwe = supp.get("cwe", "?")
        rule_id = supp.get("rule_id", "?")
        pattern = supp.get("pattern", "?")[:50]
        occurrences = supp.get("occurrences", 0)
        print(f"  [{cwe}] {rule_id}: pattern='{pattern}...' occurrences={occurrences}")

print("\n" + "=" * 80)
print("ANALYZING WHAT WAS SUPPRESSED IN EACH SEED\n")

# Check web_wild suppression records
for seed in [1337, 1338, 1339, 1340, 1341]:
    seed_path = Path(f".tmp/proof_runs/world_best_seed_{seed}.json")
    report = json.load(open(seed_path))
    
    pre = report.get("web_wild", {}).get("pre_suppression", {})
    post = report.get("web_wild", {}).get("post_suppression", {})
    
    pre_samples = pre.get("samples", [])
    post_samples = post.get("samples", [])
    
    # Count findings
    pre_total = sum(len(s.get("findings", [])) for s in pre_samples)
    post_total = sum(len(s.get("findings", [])) for s in post_samples)
    
    suppressed = pre_total - post_total
    
    print(f"Seed {seed}:")
    print(f"  Pre-suppression findings: {pre_total}")
    print(f"  Post-suppression findings: {post_total}")
    print(f"  Findings suppressed: {suppressed}")
