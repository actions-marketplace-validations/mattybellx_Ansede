"""Analyze head-to-head results."""
import json
from collections import Counter

with open('head_to_head_results.json') as f:
    data = json.load(f)

print('=== ANSEDE vs SEMGREP HEAD-TO-HEAD ===')
print()
print(f'Total CVEs in corpus: {data["total_cves"]}')
print(f'Ansede hits: {data["ansede_hits"]}')
print(f'Ansede misses: {len(data["ansede_misses"])}')
print(f'Semgrep hits: {data["semgrep_hits"]}')
print(f'Semgrep misses: {len(data["semgrep_misses"])}')
print(f'Ansede recall: {data["ansede_recall_pct"]}%')
print(f'Semgrep recall: {data["semgrep_recall_pct"]}%')
print()

# Per-language breakdown
results = data.get('results', [])
total_by_lang = Counter()
ansede_hits_by_lang = Counter()
semgrep_hits_by_lang = Counter()

for r in results:
    lang = r.get('language', '?')
    total_by_lang[lang] += 1
    if r.get('ansede_detected'):
        ansede_hits_by_lang[lang] += 1
    if r.get('semgrep_detected'):
        semgrep_hits_by_lang[lang] += 1

print('Per-Language Breakdown:')
print('-----------------------')
for lang in sorted(total_by_lang):
    t = total_by_lang[lang]
    a = ansede_hits_by_lang[lang]
    s = semgrep_hits_by_lang[lang]
    ansede_pct = a / t * 100 if t else 0
    semgrep_pct = s / t * 100 if t else 0
    print(f'  {lang:>10}: {t:3d} total | Ansede {a:2d}/{t:2d} ({ansede_pct:5.1f}%) | Semgrep {s:2d}/{t:2d} ({semgrep_pct:5.1f}%)')

print()

# What Ansede catches that Semgrep misses
ansede_only = [r for r in results if r.get('ansede_detected') and not r.get('semgrep_detected')]
semgrep_only = [r for r in results if not r.get('ansede_detected') and r.get('semgrep_detected')]
both = [r for r in results if r.get('ansede_detected') and r.get('semgrep_detected')]
neither = [r for r in results if not r.get('ansede_detected') and not r.get('semgrep_detected')]

print(f'Ansede-only detects: {len(ansede_only)}')
print(f'Semgrep-only detects: {len(semgrep_only)}')
print(f'Both detect: {len(both)}')
print(f'Neither detects: {len(neither)}')

print()
print('Ansede-only CVEs (Semgrep missed):')
for r in ansede_only:
    print(f'  {r["cve_id"]:45s} ({r["language"]:>10s}) expected: {r["expected_cwe"]}')

print()
print('Semgrep-only CVEs (Ansede missed):')
for r in semgrep_only:
    print(f'  {r["cve_id"]:45s} ({r["language"]:>10s}) expected: {r["expected_cwe"]}')

print()
print('Both missed:')
for r in neither:
    print(f'  {r["cve_id"]:45s} ({r["language"]:>10s}) expected: {r["expected_cwe"]}')
