#!/usr/bin/env python3
"""Analyze the 12 remaining false positives after sink-centric matching."""
import json
from pathlib import Path

# Load the last CVE runner output
cve_file = Path("benchmarks/cve_corpus.py")
report_sample = Path(".tmp/proof_runs/world_best_seed_1337.json")

# If no cached run, we'll parse from the recent terminal output
print("=" * 80)
print("REMAINING FALSE POSITIVES: 12 FPs across 66 CVEs (16.44% FP-rate)")
print("=" * 80)
print()

fp_cases = [
    ("CVE-2022-NOSQL-INJECTION", "CWE-943", "0 TP, 1 FP", "NoSQL detector missing"),
    ("CVE-2022-GRAPHQL-INTROSPECTION", "CWE-200", "0 TP, 1 FP", "GraphQL introspection detector missing"),
    ("CVE-2023-PY-TRACEBACK-LEAK", "CWE-200", "0 TP, 1 FP", "debug=True pattern not matched"),
    ("CVE-2023-GO-CMD-INJECTION", "CWE-78", "0 TP, 1 FP (1 FN)", "Go detector finding wrong CWE (CWE-918 SSRF)"),
    ("CVE-2022-JWT-HARDCODED", "CWE-798", "1 TP, 2 FP", "CWE-307, CWE-352 at same sink (JS)"),
    ("CVE-2023-PY-RATE-LIMIT", "CWE-307", "1 TP, 1 FP", "Collateral route finding"),
    ("CVE-2022-XXE-PYTHON", "CWE-611", "1 TP, 1 FP", "Collateral finding"),
    ("CVE-2022-UPLOAD-RCE", "CWE-434", "1 TP, 1 FP", "Collateral finding"),
    ("CVE-2022-XXE-EXPRESS", "CWE-611", "1 TP, 1 FP", "Collateral finding"),
    ("CVE-2022-TLS-VERIFY-FALSE", "CWE-295", "1 TP, 2 FP", "CWE-307, CWE-352 at same sink (JS)"),
    ("CVE-2022-COOKIE-SECURE-FALSE", "CWE-614", "1 TP, 2 FP", "CWE-307, CWE-352 at same sink (JS)"),
    ("CVE-2019-10744", "CWE-1321", "1 TP, 1 FP", "Collateral finding"),
]

print("TOP FP SOURCES:\n")
print(f"{'CVE ID':<40} {'CWE':<12} {'Verdict':<15} {'Root Cause':<40}")
print("─" * 110)

for cve_id, cwe, verdict, root_cause in fp_cases:
    print(f"{cve_id:<40} {cwe:<12} {verdict:<15} {root_cause:<40}")

print()
print("=" * 80)
print("CATEGORIZATION")
print("=" * 80)

categories = {
    "Missing Detectors (3 FPs)": [
        "CVE-2022-NOSQL-INJECTION [CWE-943]: NoSQL detector",
        "CVE-2022-GRAPHQL-INTROSPECTION [CWE-200]: GraphQL introspection",
        "CVE-2023-PY-TRACEBACK-LEAK [CWE-200]: Pattern not matched",
    ],
    "CWE Mismatch in Go (1 FP)": [
        "CVE-2023-GO-CMD-INJECTION: Detected CWE-918 SSRF instead of CWE-78 CMD",
    ],
    "Overlapping Findings at Same Sink (3 FPs)": [
        "CVE-2022-JWT-HARDCODED: CWE-307, CWE-352 at line 6",
        "CVE-2022-TLS-VERIFY-FALSE: CWE-307, CWE-352 at same sink",
        "CVE-2022-COOKIE-SECURE-FALSE: CWE-307, CWE-352 at same sink",
    ],
    "Collateral Findings (5 FPs)": [
        "CVE-2023-PY-RATE-LIMIT: Collateral route/auth finding",
        "CVE-2022-XXE-PYTHON: Collateral finding",
        "CVE-2022-UPLOAD-RCE: Collateral finding",
        "CVE-2022-XXE-EXPRESS: Collateral finding",
        "CVE-2019-10744: Collateral finding",
    ],
}

for category, items in categories.items():
    print(f"\n{category}")
    print("─" * 80)
    for item in items:
        print(f"  • {item}")

print()
print("=" * 80)
print("RECOMMENDED FIXES (Priority Order)")
print("=" * 80)
print("""
1. **Fix Overlapping Route/Auth Findings (3 FPs)**: 
   → Strengthen the route_hygiene_secondary bucket to suppress CWE-307/CWE-352 
     when CWE-798/CWE-295/CWE-614 are found at the same sink.
   → Status: Already partially fixed by sink-centric matching, but need to tighten.

2. **Fix Go CWE-78 Detection (1 FP)**:
   → Go analyzer detects SSRF (CWE-918) when test expects CMD (CWE-78).
   → Status: Go analyzer gap; low priority (only 1/3 Go cases).

3. **Fix Missing CWE-200 Pattern Matching (1 FP)**:
   → CVE-2023-PY-TRACEBACK-LEAK finds PY-039 (CWE-200) but expected_hit 
     regex doesn't match.
   → Status: Check expected_hit pattern in cve_corpus.py.

4. **Implement NoSQL (CWE-943) Detector (1 FP)**:
   → Add PyMongo/MongoDB detection to python_analyzer.
   → Status: infrastructure exists, just needs enabling.

5. **Suppress Collateral Route Findings (5 FPs)**:
   → When matching one CWE, suppress collateral route/auth alerts.
   → Status: Existing bucket logic; may need refinement.
""")
