#!/usr/bin/env python3
import json

r = json.load(open('.tmp/proof_runs/world_best_seed_1337.json'))
cases = r['cve']['post_suppression']['cases']
c = [x for x in cases if x['cve_id']=='CVE-2022-JWT-HARDCODED'][0]

print(f"CVE-ID: {c['cve_id']}")
print(f"Expected CWE: {c.get('expected_cwe')}")
print(f"Matched finding indexes: {c.get('matched_finding_indexes')}")
print(f"\nCWEs in findings:")
for i, f in enumerate(c['findings']):
    print(f"  [{i}] {f.get('cwe')}: {f.get('rule_id')} - {f.get('title')[:50]}")
