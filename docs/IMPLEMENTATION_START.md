## Immediate Next Steps (Pick one to start)

1. **Add Python CWE-453 rule** (`def fn(x=[])`) — simplest gap to fix, pure AST check
2. **Add Python CWE-617 rule** (`assert used for security`) — also simple
3. **Add Go CWE-798 rule** (hardcoded secrets regex) — pattern already proven in Python
4. **Add Go CWE-79 rule** (XSS in templates) — regex-based, medium effort
5. **Set up CodeQL pack resolution** — `codeql pack install` + query download

## Current state

- `docs/FULL_ROADMAP.md` — created with all 9 phases, 66 items
- Phase 1 item count: 16 CVE gaps identified, 0 fixed
- Phase 3 (CodeQL): CLI downloaded, queries downloaded but pack structure needs resolution

## Code locations for new rules

| Rule | File | Pattern |
|------|------|---------|
| Python rules | `src/ansede_static/python_analyzer.py` | Add `_rule_XX` function + register in dispatch list |
| Python contracts | `src/ansede_static/rules.py` | Add to `_PY_RULE_CONTRACTS` dict + `_KNOWN_RULE_IDS` |
| Go rules | `src/ansede_static/go_engine/go_analyzer.py` | Add sinks to `_GO_DANGEROUS_SINKS` or new heuristic method |
| Go contracts | `src/ansede_static/rules.py` | Add to `_GO_RULE_CONTRACTS` |
| C# rules | `src/ansede_static/csharp_analyzer.py` | Add heuristic check method |
| C# contracts | `src/ansede_static/rules.py` | Add to `_CSHARP_RULE_CONTRACTS` |
