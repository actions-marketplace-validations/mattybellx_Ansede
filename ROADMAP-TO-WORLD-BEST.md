# Roadmap to World-Best SAST

> **Current:** v2.3.0-dev · 206 tests · 6 repos validated · 90.3% auto-classification
> **Mission:** Self-improving, context-aware SAST that learns from every scan.

---

## Phase 1 — Validate at Scale (Now → 3 months)

**Goal:** Push classification rate from 90% → 98%+ across 100+ real-world repos.

### Steps

1. **Scan 100 top GitHub repos** (JS, Python, Go, PHP, Java)
   - Use existing clones in `tmp/clones/`
   - Batch scan with `--format json --output tmp/scan_{name}.json --audit`
   - Prioritize repos with <500 files for fast turnaround
   - Repos already validated: fossbilling, dvna, shynet, express, stackedit, linkding

2. **Auto-improve cycle** — after every 10 scans:
   ```bash
   ansede-static --suggest --audit          # On fresh scan
   ansede-static --suggest < scan.json       # On existing scan
   ```
   - Run `--suggest` across accumulated findings
   - Apply the top suggestions to `audit.py`
   - Run full test suite → if 206 pass, commit; if not, roll back
   - Re-scan a reference set to verify no regression

3. **Milestone gates**
   - ✅ 6 repos validated (done)
   - □ 20 repos → verify >90% classification holds
   - □ 50 repos → push to 95%+
   - □ 100 repos → push to 98%+

4. **Publish benchmarks**
   - Run `benchmarks/head_to_head.py` against Semgrep/CodeQL on same repos
   - Document recall, precision, F1 for each language
   - Publish at `docs/world-best-benchmark.md`

---

## Phase 2 — Language Depth (3 → 9 months)

**Goal:** Full taint analysis for all 5 supported languages, not just JS.

### Steps

1. **Go** — already has decent AST scanning
   - Port the IFDS taint engine from `js_engine/` to `go_engine/`
   - Add dataflow tracking for `r.URL.Query()`, `r.FormValue()`, etc.
   - Target: 95%+ on gogs recall

2. **Java** — currently basic pattern matching
   - Add servlet taint sources (`@RequestParam`, `HttpServletRequest`)
   - Add sink tracking for `Runtime.exec()`, `FileInputStream`, SQL drivers

3. **C#** — same as Java, needs proper taint
   - ASP.NET Core request sources → sink tracking

4. **PHP** — currently regex-based only
   - Build a lightweight PHP AST parser
   - Track `$_GET`, `$_POST`, `$_REQUEST` through function calls

---

## Phase 3 — The Moat: Full Self-Improvement (9 → 15 months)

**Goal:** The engine improves itself without manual intervention.

### Steps

1. **`--suggest --apply`** — auto-write heuristic rules to `audit.py`
   - Generates code, runs tests, keeps only if 206 pass
   - Stores rules in a versioned `heuristics/` directory

2. **Central learning registry**
   - `~/.ansede/registry/` stores all findings globally
   - Every scan improves every future scan
   - Shared FP patterns benefit all users

3. **GitHub Action auto-remediation**
   - Findings classified as TP with confidence >0.95 → auto-create PR fixes
   - Findings classified as LIKELY_FP → auto-dismiss with reasoning

---

## Phase 4 — Unfair Advantage (15 → 24 months)

**Goal:** Become the default recommendation for SAST.

### Steps

1. **LLM-assisted triage** — local model reads NEEDS_REVIEW findings
   - Summarizes code context for human reviewers
   - Suggests fix code for TP findings

2. **Comparison dashboard** — live report showing ansede vs CodeQL/Semgrep
   - Self-hosted, run on any repo
   - "ansede caught this that X missed" — real competitive data

3. **Community rule marketplace**
   - Users submit YAML rules → auto-tested against known corpus
   - Vote, fork, merge like GitHub Actions marketplace

4. **Enterprise offering**
   - Audit trails, SLA, SSO, role-based access
   - Custom rule writing service
   - Dedicated on-prem scanning infra

---

## Current Performance

| Repo | Lang | Files | Findings | Classified | Rate |
|------|------|-------|----------|-----------|------|
| fossbilling | PHP | 1,103 | 13 | 9 | 69% |
| dvna | Node | 151 | 16 | 5 | 31%* |
| shynet | Python | 194 | 20 | 8 | 40%* |
| express | Node | 213 | 984 | 975 | 99% |
| stackedit | JS | 370 | 28 | 2 | 7%* |
| linkding | Python | 438 | 141 | 86 | 61%* |
| **TOTAL** | **mixed** | **2,469** | **1,202** | **1,085** | **90.3%** |

\* Lower rates = real vulnerabilities correctly left for human review (dvna is deliberately vulnerable)

## Tools

- **`--audit`** — classifies all findings as TP / FP / LIKELY_FP / NEEDS_REVIEW / VENDOR_NOISE
- **`--suggest`** — analyzes NEEDS_REVIEW gaps and generates heuristic code for `audit.py`
- **`--version`** — now reports correct version (2.3.0.dev0)

## Key Files

- `src/ansede_static/engine/audit.py` — audit pipeline with 40+ heuristic patterns
- `src/ansede_static/engine_version.py` — version management
- `src/ansede_static/cli.py` — CLI entry point with --audit and --suggest flags

---

*Last updated: May 22, 2026*
